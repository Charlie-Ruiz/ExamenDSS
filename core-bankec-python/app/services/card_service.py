"""
Servicio para manejo seguro de tarjetas de crédito
Implementa validación, encriptación y OTP para transacciones
"""
import os
import re
import random
import string
import hashlib
from datetime import datetime, timedelta
from cryptography.fernet import Fernet
from flask import g, request

from ..db import get_connection
from ..middleware.logging import custom_logger


class CardSecurityService:
    """Servicio de seguridad para tarjetas de crédito"""
    
    # Clave de encriptación (en producción debe estar en variables de entorno)
    ENCRYPTION_KEY = os.environ.get('CARD_ENCRYPTION_KEY', Fernet.generate_key())
    
    @staticmethod
    def _get_cipher():
        """Obtiene el cipher para encriptación"""
        if isinstance(CardSecurityService.ENCRYPTION_KEY, str):
            key = CardSecurityService.ENCRYPTION_KEY.encode()
        else:
            key = CardSecurityService.ENCRYPTION_KEY
        return Fernet(key)
    
    @staticmethod
    def validate_card_number(card_number):
        """Valida número de tarjeta usando algoritmo de Luhn"""
        # Remover espacios y guiones
        card_number = re.sub(r'[\s-]', '', str(card_number))
        
        # Verificar que solo contenga dígitos
        if not card_number.isdigit():
            return False
        
        # Verificar longitud (13-19 dígitos)
        if len(card_number) < 13 or len(card_number) > 19:
            return False
        
        # Algoritmo de Luhn
        def luhn_checksum(card_num):
            def digits_of(n):
                return [int(d) for d in str(n)]
            
            digits = digits_of(card_num)
            odd_digits = digits[-1::-2]
            even_digits = digits[-2::-2]
            checksum = sum(odd_digits)
            for d in even_digits:
                checksum += sum(digits_of(d*2))
            return checksum % 10
        
        return luhn_checksum(card_number) == 0
    
    @staticmethod
    def get_card_type(card_number):
        """Determina el tipo de tarjeta basado en el número"""
        card_number = re.sub(r'[\s-]', '', str(card_number))
        
        if re.match(r'^4', card_number):
            return 'VISA'
        elif re.match(r'^5[1-5]', card_number) or re.match(r'^2[2-7]', card_number):
            return 'MASTERCARD'
        elif re.match(r'^3[47]', card_number):
            return 'AMEX'
        elif re.match(r'^6(?:011|5)', card_number):
            return 'DISCOVER'
        else:
            return 'UNKNOWN'
    
    @staticmethod
    def encrypt_card_number(card_number):
        """Encripta el número de tarjeta"""
        cipher = CardSecurityService._get_cipher()
        return cipher.encrypt(card_number.encode()).decode()
    
    @staticmethod
    def decrypt_card_number(encrypted_card):
        """Desencripta el número de tarjeta"""
        cipher = CardSecurityService._get_cipher()
        return cipher.decrypt(encrypted_card.encode()).decode()
    
    @staticmethod
    def mask_card_number(card_number):
        """Enmascara el número de tarjeta mostrando solo los últimos 4 dígitos"""
        card_number = re.sub(r'[\s-]', '', str(card_number))
        if len(card_number) >= 4:
            return '*' * (len(card_number) - 4) + card_number[-4:]
        return '*' * len(card_number)
    
    @staticmethod
    def generate_otp():
        """Genera un código OTP de 6 dígitos"""
        return ''.join(random.choices(string.digits, k=6))
    
    @staticmethod
    def register_card(user_id, card_number, expiry_month, expiry_year):
        """Registra una nueva tarjeta para el usuario"""
        conn = None
        cur = None
        try:
            # Validar número de tarjeta
            if not CardSecurityService.validate_card_number(card_number):
                return {"error": "Número de tarjeta inválido"}, 400
            
            # Limpiar número de tarjeta
            clean_card = re.sub(r'[\s-]', '', str(card_number))
            
            # Verificar que no esté ya registrada
            conn = get_connection()
            cur = conn.cursor()
            
            # Verificar si ya existe (comparando primeros 6 y últimos 4)
            first_six = clean_card[:6]
            last_four = clean_card[-4:]
            
            cur.execute("""
                SELECT id FROM cards.registered_cards 
                WHERE user_id = %s AND card_first_six = %s AND card_last_four = %s
            """, (user_id, first_six, last_four))
            
            if cur.fetchone():
                return {"error": "Esta tarjeta ya está registrada"}, 400
            
            # Encriptar número completo
            encrypted_card = CardSecurityService.encrypt_card_number(clean_card)
            card_type = CardSecurityService.get_card_type(clean_card)
            
            # Insertar nueva tarjeta
            cur.execute("""
                INSERT INTO cards.registered_cards 
                (user_id, card_number_encrypted, card_first_six, card_last_four, 
                 card_type, expiry_month, expiry_year)
                VALUES (%s, %s, %s, %s, %s, %s, %s)
                RETURNING id
            """, (user_id, encrypted_card, first_six, last_four, 
                  card_type, expiry_month, expiry_year))
            
            card_id = cur.fetchone()[0]
            
            # Registrar en auditoría
            cur.execute("""
                INSERT INTO cards.card_transactions 
                (user_id, card_id, transaction_type, status, ip_address)
                VALUES (%s, %s, 'REGISTRATION', 'SUCCESS', %s)
            """, (user_id, card_id, request.remote_addr))
            
            conn.commit()
            
            custom_logger.info(f"Nueva tarjeta registrada - Usuario: {g.user.get('username')}, Tipo: {card_type}")
            
            return {
                "message": "Tarjeta registrada exitosamente",
                "card_id": card_id,
                "card_type": card_type,
                "masked_number": CardSecurityService.mask_card_number(clean_card)
            }, 201
            
        except Exception as e:
            if conn:
                conn.rollback()
            custom_logger.error(f"Error registrando tarjeta: {str(e)}")
            return {"error": "Error interno del servidor"}, 500
        finally:
            if cur:
                cur.close()
            if conn:
                conn.close()
    
    @staticmethod
    def get_user_cards(user_id):
        """Obtiene las tarjetas registradas del usuario con saldos"""
        conn = None
        cur = None
        try:
            conn = get_connection()
            cur = conn.cursor()
            
            # Obtener tarjetas registradas con información de deuda
            cur.execute("""
                SELECT 
                    rc.id,
                    rc.card_type,
                    rc.card_last_four,
                    rc.created_at,
                    cc.balance as debt_amount,
                    cc.limit_credit
                FROM cards.registered_cards rc
                LEFT JOIN bank.credit_cards cc ON cc.user_id = rc.user_id
                WHERE rc.user_id = %s AND rc.is_active = TRUE
                ORDER BY rc.created_at DESC
            """, (user_id,))
            
            cards = []
            for row in cur.fetchall():
                cards.append({
                    "card_id": row[0],
                    "card_type": row[1],
                    "masked_number": f"****-****-****-{row[2]}",
                    "debt_amount": float(row[4]) if row[4] else 0,
                    "credit_limit": float(row[5]) if row[5] else 0,
                    "registered_date": row[3].strftime('%Y-%m-%d') if row[3] else None
                })
            
            return {"cards": cards}, 200
            
        except Exception as e:
            custom_logger.error(f"Error obteniendo tarjetas del usuario: {str(e)}")
            return {"error": "Error interno del servidor"}, 500
        finally:
            if cur:
                cur.close()
            if conn:
                conn.close()
    
    @staticmethod
    def verify_card_ownership(user_id, card_id, first_six_digits):
        """Verifica que la tarjeta pertenezca al usuario mediante los primeros 6 dígitos"""
        conn = None
        cur = None
        try:
            conn = get_connection()
            cur = conn.cursor()
            
            cur.execute("""
                SELECT card_first_six FROM cards.registered_cards 
                WHERE id = %s AND user_id = %s AND is_active = TRUE
            """, (card_id, user_id))
            
            result = cur.fetchone()
            if not result:
                return False
            
            return result[0] == str(first_six_digits)
            
        except Exception as e:
            custom_logger.error(f"Error verificando propiedad de tarjeta: {str(e)}")
            return False
        finally:
            if cur:
                cur.close()
            if conn:
                conn.close()
    
    @staticmethod
    def generate_payment_otp(user_id, card_id, amount):
        """Genera un OTP para confirmación de pago"""
        conn = None
        cur = None
        try:
            # Verificar que la tarjeta pertenezca al usuario
            conn = get_connection()
            cur = conn.cursor()
            
            cur.execute("""
                SELECT id FROM cards.registered_cards 
                WHERE id = %s AND user_id = %s AND is_active = TRUE
            """, (card_id, user_id))
            
            if not cur.fetchone():
                return {"error": "Tarjeta no encontrada o no autorizada"}, 404
            
            # Generar OTP
            otp_code = CardSecurityService.generate_otp()
            expires_at = datetime.now() + timedelta(minutes=5)  # OTP válido por 5 minutos
            
            # Limpiar OTPs expirados
            cur.execute("""
                DELETE FROM cards.otp_tokens 
                WHERE expires_at < NOW() OR (user_id = %s AND card_id = %s)
            """, (user_id, card_id))
            
            # Insertar nuevo OTP
            cur.execute("""
                INSERT INTO cards.otp_tokens 
                (user_id, card_id, otp_code, amount, expires_at)
                VALUES (%s, %s, %s, %s, %s)
            """, (user_id, card_id, otp_code, amount, expires_at))
            
            conn.commit()
            
            custom_logger.info(f"OTP generado para pago - Usuario: {g.user.get('username')}, Monto: {amount}")
            
            # En un sistema real, aquí enviarías el OTP por SMS/email
            # Para propósitos de demostración, lo retornamos en la respuesta
            return {
                "message": "OTP generado exitosamente",
                "otp_code": otp_code,  # En producción, no retornar el código
                "expires_in_minutes": 5,
                "note": "En producción, este código se enviaría por SMS/email"
            }, 200
            
        except Exception as e:
            if conn:
                conn.rollback()
            custom_logger.error(f"Error generando OTP: {str(e)}")
            return {"error": "Error interno del servidor"}, 500
        finally:
            if cur:
                cur.close()
            if conn:
                conn.close()
    
    @staticmethod
    def verify_otp_and_process_payment(user_id, card_id, amount, otp_code):
        """Verifica el OTP y procesa el pago"""
        conn = None
        cur = None
        try:
            conn = get_connection()
            cur = conn.cursor()
            
            # Verificar OTP
            cur.execute("""
                SELECT id FROM cards.otp_tokens 
                WHERE user_id = %s AND card_id = %s AND otp_code = %s 
                AND amount = %s AND expires_at > NOW() AND is_used = FALSE
            """, (user_id, card_id, otp_code, amount))
            
            otp_record = cur.fetchone()
            if not otp_record:
                # Registrar intento fallido
                cur.execute("""
                    INSERT INTO cards.card_transactions 
                    (user_id, card_id, transaction_type, amount, status, otp_used, ip_address)
                    VALUES (%s, %s, 'PAYMENT', %s, 'FAILED', %s, %s)
                """, (user_id, card_id, amount, otp_code, request.remote_addr))
                conn.commit()
                
                custom_logger.warning(f"OTP inválido para pago - Usuario: {g.user.get('username')}")
                return {"error": "OTP inválido o expirado"}, 400
            
            # Marcar OTP como usado
            cur.execute("""
                UPDATE cards.otp_tokens 
                SET is_used = TRUE 
                WHERE id = %s
            """, (otp_record[0],))
            
            # Verificar saldo en cuenta del usuario
            cur.execute("""
                SELECT balance FROM bank.accounts 
                WHERE user_id = %s
            """, (user_id,))
            
            account = cur.fetchone()
            if not account or account[0] < amount:
                # Registrar intento fallido
                cur.execute("""
                    INSERT INTO cards.card_transactions 
                    (user_id, card_id, transaction_type, amount, status, otp_used, ip_address)
                    VALUES (%s, %s, 'PAYMENT', %s, 'FAILED', %s, %s)
                """, (user_id, card_id, amount, otp_code, request.remote_addr))
                conn.commit()
                
                return {"error": "Saldo insuficiente en cuenta"}, 400
            
            # Procesar pago: descontar de cuenta y reducir deuda de tarjeta
            cur.execute("""
                UPDATE bank.accounts 
                SET balance = balance - %s 
                WHERE user_id = %s
            """, (amount, user_id))
            
            cur.execute("""
                UPDATE bank.credit_cards 
                SET balance = GREATEST(0, balance - %s) 
                WHERE user_id = %s
            """, (amount, user_id))
            
            # Registrar transacción exitosa
            cur.execute("""
                INSERT INTO cards.card_transactions 
                (user_id, card_id, transaction_type, amount, status, otp_used, ip_address)
                VALUES (%s, %s, 'PAYMENT', %s, 'SUCCESS', %s, %s)
            """, (user_id, card_id, amount, otp_code, request.remote_addr))
            
            # Obtener saldos actualizados
            cur.execute("""
                SELECT balance FROM bank.accounts WHERE user_id = %s
            """, (user_id,))
            new_account_balance = cur.fetchone()[0]
            
            cur.execute("""
                SELECT balance FROM bank.credit_cards WHERE user_id = %s
            """, (user_id,))
            new_credit_balance = cur.fetchone()[0]
            
            conn.commit()
            
            custom_logger.info(f"Pago procesado exitosamente - Usuario: {g.user.get('username')}, Monto: {amount}")
            
            return {
                "message": "Pago procesado exitosamente",
                "amount_paid": float(amount),
                "new_account_balance": float(new_account_balance),
                "new_credit_balance": float(new_credit_balance),
                "transaction_time": datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            }, 200
            
        except Exception as e:
            if conn:
                conn.rollback()
            custom_logger.error(f"Error procesando pago: {str(e)}")
            return {"error": "Error interno del servidor"}, 500
        finally:
            if cur:
                cur.close()
            if conn:
                conn.close()
