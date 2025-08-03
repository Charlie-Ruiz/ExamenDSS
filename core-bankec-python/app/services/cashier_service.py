"""
Servicio de cajeros - maneja registro y autenticación con OTP
"""
import logging
import re
from flask import request
from flask_restx import abort

from ..db import get_connection
from ..security import (
    generate_jwt, verify_password, hash_password, 
    validate_cashier_username, validate_cashier_password,
    validate_sql_safe, sanitize_input, validate_and_sanitize_string,
    get_client_ip, generate_otp_secret, generate_qr_code, verify_otp_token
)

class CashierService:
    """Servicio para operaciones de cajeros"""
    
    @staticmethod
    def register_cashier(data):
        """Registra un nuevo cajero con OTP"""
        try:
            # Sanitizar datos de entrada
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
            
            # Sanitizar campos específicos
            username = sanitize_input(data.get('username', ''), allow_special_chars=False)
            password = str(data.get('password', ''))  # No sanitizar completamente la contraseña
            email = sanitize_input(data.get('email', ''), allow_special_chars=True)
            
        except Exception as e:
            logging.error(f"Error en sanitización de datos de cajero: {str(e)}")
            return {"error": "Datos de entrada inválidos"}, 400
        
        # Validar campos requeridos
        if not all([first_name, last_name, username, password, email]):
            return {"error": "Todos los campos son requeridos (first_name, last_name, username, password, email)"}, 400
        
        # Validaciones específicas para cajeros
        try:
            # Validar username de cajero (solo letras y números)
            username_valid, username_result = validate_cashier_username(username)
            if not username_valid:
                return {"error": username_result}, 400
            username = username_result
            
            # Validar contraseña de cajero (más estricta)
            password_valid, password_result = validate_cashier_password(password)
            if not password_valid:
                return {"error": password_result}, 400
            
            # Validar email básico
            from ..security.validation import validate_email
            email_valid, email_result = validate_email(email)
            if not email_valid:
                return {"error": email_result}, 400
            email = email_result
            
        except Exception as e:
            logging.error(f"Error en validaciones de cajero: {str(e)}")
            return {"error": "Error en validación de datos"}, 400
        
        # Procesar en base de datos
        conn = None
        try:
            conn = get_connection()
            cursor = conn.cursor()
            
            # Verificar si el username ya existe en usuarios
            cursor.execute("SELECT id FROM bank.users WHERE username = %s", (username,))
            if cursor.fetchone():
                return {"error": "Username ya existe"}, 400
            
            # Verificar si el email ya existe
            cursor.execute("SELECT id FROM bank.users WHERE email = %s", (email,))
            if cursor.fetchone():
                return {"error": "Email ya registrado"}, 400
            
            # Generar secreto OTP
            otp_secret = generate_otp_secret()
            
            # Hashear contraseña
            hashed_password = hash_password(password)
            
            # Crear usuario principal
            full_name = f"{first_name} {last_name}"
            cursor.execute("""
                INSERT INTO bank.users (username, password, email, full_name, role)
                VALUES (%s, %s, %s, %s, %s)
                RETURNING id
            """, (username, hashed_password, email, full_name, 'cajero'))
            
            user_id = cursor.fetchone()[0]
            
            # Crear registro de cajero con OTP
            cursor.execute("""
                INSERT INTO bank.cashiers (user_id, otp_secret)
                VALUES (%s, %s)
            """, (user_id, otp_secret))
            
            conn.commit()
            
            # Generar código QR para OTP
            qr_data = generate_qr_code(username, otp_secret)
            
            # Log de éxito
            client_ip = get_client_ip()
            logging.info(f"Cajero registrado exitosamente: {username}, ID: {user_id}, IP: {client_ip}")
            
            return {
                "message": "Cajero registrado exitosamente",
                "user_id": user_id,
                "username": username,
                "otp_setup": {
                    "secret": otp_secret,
                    "qr_code": qr_data["qr_code"] if qr_data else None,
                    "manual_entry_key": otp_secret,
                    "instructions": "Escanea el código QR con Google Authenticator o ingresa manualmente la clave secreta"
                }
            }, 201
            
        except Exception as e:
            if conn:
                conn.rollback()
            client_ip = get_client_ip()
            logging.error(f"Error registrando cajero: {str(e)}, IP: {client_ip}")
            return {"error": "Error interno del servidor"}, 500
        finally:
            if conn:
                conn.close()
    
    @staticmethod
    def login_with_otp(username, password, otp_token):
        """Autentica cajero con username, password y OTP"""
        
        try:
            # Basic validation without complex sanitization  
            username = str(username).strip()
            password = str(password)
            otp_token = str(otp_token).strip()
            
            # Validar campos requeridos
            if not username or not password or not otp_token:
                return {"error": "Username, contraseña y código OTP son requeridos"}, 400
            
            # Validar formato del OTP (6 dígitos)
            if not re.match(r'^\d{6}$', otp_token):
                return {"error": "Código OTP debe tener 6 dígitos"}, 400
            
            conn = None
            try:
                conn = get_connection()
                cursor = conn.cursor()
                
                # Buscar cajero con join a users
                cursor.execute("""
                    SELECT u.id, u.username, u.password, u.email, u.full_name, u.role,
                           c.otp_secret
                    FROM bank.users u
                    INNER JOIN bank.cashiers c ON u.id = c.user_id
                    WHERE u.username = %s AND u.role = 'cajero'
                """, (username,))
                
                user_data = cursor.fetchone()
                if not user_data:
                    return {"error": "Credenciales inválidas"}, 401
                
                user_id, db_username, db_password, email, full_name, role, otp_secret = user_data
                
                # Verificar contraseña
                if not verify_password(password, db_password):
                    return {"error": "Credenciales inválidas"}, 401
                
                # Verificar OTP
                if not verify_otp_token(otp_secret, otp_token):
                    return {"error": "Código OTP inválido o expirado"}, 401
                
                # Generar token JWT
                payload = {
                    "user_id": user_id,
                    "username": db_username,
                    "role": role,
                    "full_name": full_name,
                    "email": email
                }
                
                token = generate_jwt(payload)
                
                return {
                    "message": "Login exitoso",
                    "token": token,
                    "user": {
                        "id": user_id,
                        "username": db_username,
                        "email": email,
                        "full_name": full_name,
                        "role": role
                    }
                }, 200
                
            except Exception as db_error:
                if conn:
                    conn.rollback()
                return {"error": "Error interno del servidor"}, 500
            finally:
                if conn:
                    conn.close()
                    
        except Exception as e:
            return {"error": "Error interno del servidor"}, 500
