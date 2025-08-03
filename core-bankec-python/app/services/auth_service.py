"""
Servicio de autenticación - maneja login y registro de usuarios
"""
import logging
import re
from flask import request
from flask_restx import Api, Resource, abort
from datetime import datetime, timezone, timedelta

from ..db import get_connection
from ..security import (
    generate_jwt, verify_password, hash_password, 
    validate_ecuadorian_cedula, validate_phone_number,
    validate_username, validate_strong_password, validate_email,
    validate_sql_safe, sanitize_input, validate_and_sanitize_string,
    get_client_ip
)

class AuthService:
    """Servicio para operaciones de autenticación"""
    
    @staticmethod
    def login(username, password):
        """Procesa el login de un usuario"""
        # Sanitizar datos de entrada
        username = sanitize_input(username, allow_special_chars=False)
        password = str(password)  # No sanitizar completamente la contraseña
        
        # Validar campos requeridos
        if not username or not password:
            return {"error": "Username y contraseña son requeridos"}, 400
        
        # Validación adicional de seguridad
        if not validate_sql_safe(username):
            client_ip = get_client_ip()
            logging.warning(f"Intento de inyección SQL en login: {username[:50]}, IP: {client_ip}")
            return {"error": "Username contiene caracteres no permitidos"}, 400
        
        # Verificar patrones de inyección en la contraseña
        injection_patterns = [
            r'(\b(SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER|EXEC|EXECUTE|UNION|SCRIPT)\b)',
            r'(--|\/\*|\*\/)',
            r'(<script|javascript:|vbscript:)',
        ]
        
        for pattern in injection_patterns:
            if re.search(pattern, password, re.IGNORECASE):
                client_ip = get_client_ip()
                logging.warning(f"Intento de inyección en password de login: {pattern}, IP: {client_ip}")
                return {"error": "Credenciales contienen caracteres no permitidos"}, 400

        conn = get_connection()
        cur = conn.cursor()
        
        try:
            # Usar parámetros para prevenir inyección SQL
            cur.execute("SELECT id, username, password, role, full_name, email, password_created_at FROM bank.users WHERE username = %s", (username,))
            user = cur.fetchone()
            
            if user and verify_password(password, user[2]):
                token_payload = {
                    "user_id": user[0],
                    "username": user[1],
                    "role": user[3],
                    "full_name": user[4],
                    "email": user[5]
                }
                # Tiempo de expiración
                token = generate_jwt(token_payload)
                pwd_created_at = user[6]  # TIMESTAMPTZ o None
                now_utc = datetime.now(timezone.utc)
                expired = False
                if pwd_created_at is None:
                    expired = True
                else:
                    if (now_utc - pwd_created_at) > timedelta(days=90):
                        expired = True

                # Log del login exitoso
                client_ip = get_client_ip()
                if expired:
                    logging.warning(
                        f"Login denegado por contraseña expirada (>3 meses) o sin fecha: {username}, IP: {client_ip}"
                    )
                    return {
                        "error": "Contraseña expirada (más de 3 meses). Debes actualizarla.",
                        "password_expired": True
                    }, 403
                    logging.info(f"Login exitoso: {username}, IP: {client_ip}")
                
                return {"message": "Login successful", "token": token}, 200
            else:
                # Log del intento fallido
                client_ip = get_client_ip()
                logging.warning(f"Intento de login fallido: {username}, IP: {client_ip}")
                return {"error": "Credenciales inválidas"}, 401
                
        except Exception as e:
            logging.error(f"Error en login: {str(e)}")
            return {"error": "Error interno del servidor"}, 500
        
        finally:
            cur.close()
            conn.close()
    
    @staticmethod
    def register(data):
        """Procesa el registro de un nuevo cliente"""
        # Extraer y sanitizar datos del request
        try:
            first_name_valid, first_name = validate_and_sanitize_string(
                data.get('first_name', ''), min_length=2, max_length=50, allow_special=False
            )
            if not first_name_valid:
                return {"error": f"Nombre: {first_name}"}, 400
            
            last_name_valid, last_name = validate_and_sanitize_string(
                data.get('last_name', ''), min_length=2, max_length=50, allow_special=False
            )
            if not last_name_valid:
                return {"error": f"Apellido: {last_name}"}, 400
            
            address_valid, address = validate_and_sanitize_string(
                data.get('address', ''), min_length=10, max_length=200, allow_special=True
            )
            if not address_valid:
                return {"error": f"Dirección: {address}"}, 400
            
            # Sanitizar cédula, teléfono, username, email (validación específica después)
            cedula = sanitize_input(data.get('cedula', ''), allow_special_chars=False)
            phone = sanitize_input(data.get('phone', ''), allow_special_chars=False)
            username = sanitize_input(data.get('username', ''), allow_special_chars=False)
            password = str(data.get('password', ''))  # No sanitizar completamente la contraseña
            email = sanitize_input(data.get('email', ''), allow_special_chars=True)
            
        except Exception as e:
            logging.error(f"Error en sanitización de datos: {str(e)}")
            return {"error": "Datos de entrada inválidos"}, 400
        
        # Validar campos requeridos después de sanitización
        if not all([first_name, last_name, address, cedula, phone, username, password, email]):
            return {"error": "Todos los campos son requeridos"}, 400
        
        # Crear objeto con información personal para validaciones
        personal_info = {
            'first_name': first_name,
            'last_name': last_name,
            'cedula': cedula,
            'phone': phone,
            'email': email
        }
        
        # Validaciones de seguridad mejoradas
        try:
            # 1. Validar cédula ecuatoriana
            if not validate_ecuadorian_cedula(cedula):
                return {"error": "Cédula ecuatoriana inválida"}, 400
            
            # 2. Validar número celular
            if not validate_phone_number(phone):
                return {"error": "Número celular debe tener formato 09XXXXXXXX"}, 400
            
            # 3. Validar email
            is_valid_email, email_result = validate_email(email)
            if not is_valid_email:
                return {"error": email_result}, 400
            email = email_result  # Usar email sanitizado
            
            # 4. Validar username
            is_valid_username, username_result = validate_username(username, personal_info)
            if not is_valid_username:
                return {"error": username_result}, 400
            username = username_result  # Usar username sanitizado
            
            # 5. Validar contraseña robusta
            is_valid_password, password_msg = validate_strong_password(password, personal_info)
            if not is_valid_password:
                return {"error": password_msg}, 400
                
        except Exception as e:
            logging.error(f"Error en validaciones de seguridad: {str(e)}")
            return {"error": "Error en validación de datos"}, 400
        
        # Obtener IP del cliente
        client_ip = get_client_ip()
        
        # Log del intento de registro
        logging.info(f"Intento de registro: {username}, IP: {client_ip}")
        
        # Verificar si ya existen registros duplicados
        conn = get_connection()
        cur = conn.cursor()
        
        try:
            # Verificar username único (usando parámetros para prevenir inyección)
            cur.execute("SELECT id FROM bank.users WHERE username = %s", (username,))
            if cur.fetchone():
                return {"error": "Username ya existe"}, 400
            
            # Verificar email único
            cur.execute("SELECT id FROM bank.users WHERE email = %s", (email,))
            if cur.fetchone():
                return {"error": "Email ya está registrado"}, 400
            
            # Verificar cédula única
            cur.execute("SELECT id FROM bank.clients WHERE cedula = %s", (cedula,))
            if cur.fetchone():
                return {"error": "Cédula ya está registrada"}, 400
            
            # Hashear contraseña
            hashed_password = hash_password(password)
            
            # Insertar usuario (usando parámetros para prevenir inyección SQL)
            cur.execute("""
                INSERT INTO bank.users (username, password, role, full_name, email, password_created_at)
                VALUES (%s, %s, %s, %s, %s, NOW()) RETURNING id;
            """, (username, hashed_password, 'cliente', f"{first_name} {last_name}", email))
            
            user_id = cur.fetchone()[0]
            
            # Insertar información del cliente (usando parámetros)
            cur.execute("""
                INSERT INTO bank.clients (first_name, last_name, address, cedula, phone, registration_ip, user_id)
                VALUES (%s, %s, %s, %s, %s, %s, %s);
            """, (first_name, last_name, address, cedula, phone, client_ip, user_id))
            
            # Crear cuenta bancaria con saldo inicial 0
            cur.execute("""
                INSERT INTO bank.accounts (balance, user_id)
                VALUES (%s, %s);
            """, (0, user_id))
            
            # Crear tarjeta de crédito
            cur.execute("""
                INSERT INTO bank.credit_cards (limit_credit, balance, user_id)
                VALUES (%s, %s, %s);
            """, (5000, 0, user_id))
            
            conn.commit()
            
            # Log del registro exitoso
            logging.info(f"Usuario registrado exitosamente: {username}, IP: {client_ip}")
            
            return {
                "message": "Cliente registrado exitosamente",
                "username": username,
                "user_id": user_id
            }, 201
            
        except Exception as e:
            conn.rollback()
            logging.error(f"Error en registro: {str(e)}, IP: {client_ip}")
            return {"error": "Error interno del servidor durante el registro"}, 500
        
        finally:
            cur.close()
            conn.close()


    @staticmethod
    def update_password(data):
        """Actualiza la contraseña de un usuario"""
        try:
            username = sanitize_input(data.get('username', ''), allow_special_chars=False)
            current_password = str(data.get('current_password', ''))
            new_password = str(data.get('new_password', ''))
        except Exception as e:
            logging.error(f"Error en sanitización de datos para cambio de contraseña: {str(e)}")
            return {"error": "Datos de entrada inválidos"}, 400

        # Validar que todos los campos estén presentes
        if not all([username, current_password, new_password]):
            return {"error": "Todos los campos son requeridos"}, 400

        conn = get_connection()
        cur = conn.cursor()

        try:
            # 1. Verificar si el usuario existe y obtener hash actual
            cur.execute("SELECT id, password, full_name, email FROM bank.users WHERE username = %s", (username,))
            row = cur.fetchone()
            if not row:
                return {"error": "Usuario no encontrado"}, 404
            
            user_id, current_hash, full_name, email = row

            # 2. Verificar la contraseña actual
            if not verify_password(current_password, current_hash):
                return {"error": "Contraseña actual incorrecta"}, 401

            cur.execute("SELECT first_name, last_name, cedula, phone FROM bank.clients WHERE user_id = %s", (user_id,))
            row_data = cur.fetchone()
            if not row_data:
                return {"error": "Usuario no encontrado"}, 404
            first_name, last_name, cedula, phone = row_data

            # 3. Validar que la nueva contraseña sea robusta
            personal_info = {
                "first_name": first_name,
                "last_name": last_name,
                "cedula": cedula,
                "phone": phone,
                "email": email,
            }
            is_valid_password, password_msg = validate_strong_password(new_password, personal_info)
            if not is_valid_password:
                return {"error": password_msg}, 400

            # 4. Hashear la nueva contraseña
            new_hashed_password = hash_password(new_password)

            # 5. Actualizar la contraseña
            cur.execute("""
                UPDATE bank.users
                SET password = %s,
                    password_created_at = NOW()
                WHERE id = %s
            """, (new_hashed_password, user_id))

            conn.commit()
            logging.info(f"Contraseña actualizada para usuario: {username}")

            return {"message": "Contraseña actualizada exitosamente"}, 200

        except Exception as e:
            conn.rollback()
            logging.error(f"Error al actualizar contraseña para {username}: {str(e)}")
            return {"error": "Error interno del servidor {e}"}, 500

        finally:
            cur.close()
            conn.close()
