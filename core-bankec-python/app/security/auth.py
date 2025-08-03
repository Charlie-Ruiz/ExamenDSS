"""
Módulo de autenticación y gestión de tokens JWT
"""
import os
import jwt
import bcrypt
import hashlib
import pyotp
import qrcode
import io
import base64
from datetime import datetime, timedelta
from functools import wraps
from flask import request, g
from flask_restx import abort
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Variables de configuración
SECRET_KEY = os.getenv("SECRET_KEY")
TOKEN_EXPIRATION_MINUTES = int(os.getenv("TOKEN_EXPIRATION_MINUTES", 60))

def generate_jwt(payload):
    """Genera un token JWT con expiración"""
    expiration = datetime.utcnow() + timedelta(minutes=TOKEN_EXPIRATION_MINUTES)
    payload.update({"exp": expiration})
    token = jwt.encode(payload, SECRET_KEY, algorithm="HS256")
    # En PyJWT >= 2.0 token es str, sino bytes, por eso forzamos str
    if isinstance(token, bytes):
        token = token.decode('utf-8')
    return token

def verify_jwt(token):
    """Verifica y decodifica un token JWT"""
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
        return payload
    except jwt.ExpiredSignatureError:
        abort(401, "Token expirado")
    except jwt.InvalidTokenError:
        abort(401, "Token inválido")

def hash_password(password):
    """Hashea la contraseña usando bcrypt"""
    try:
        # Generar salt y hashear la contraseña
        salt = bcrypt.gensalt()
        hashed = bcrypt.hashpw(password.encode('utf-8'), salt)
        return hashed.decode('utf-8')
    except:
        # Fallback simple si bcrypt no está disponible
        return hashlib.sha256(password.encode()).hexdigest()

def verify_password(password, hashed_password):
    """Verifica si la contraseña coincide con el hash"""
    try:
        return bcrypt.checkpw(password.encode('utf-8'), hashed_password.encode('utf-8'))
    except:
        # Fallback para contraseñas en texto plano (usuarios existentes)
        # Intentar con hash sha256
        if hashlib.sha256(password.encode()).hexdigest() == hashed_password:
            return True
        # Si no es hash, comparar directamente (usuarios de prueba)
        return password == hashed_password

def token_required(f):
    """Decorador para proteger rutas que requieren autenticación"""
    @wraps(f)
    def decorated(*args, **kwargs):
        auth_header = request.headers.get("Authorization", "")
        if not auth_header.startswith("Bearer "):
            abort(401, "Authorization header missing or invalid")
        token = auth_header.split(" ")[1]
        payload = verify_jwt(token)
        g.user = {
            "id": payload["user_id"],
            "username": payload["username"],
            "role": payload["role"],
            "full_name": payload["full_name"],
            "email": payload["email"]
        }
        return f(*args, **kwargs)
    return decorated

def cashier_required(f):
    """Decorador para proteger rutas que requieren rol de cajero"""
    @wraps(f)
    def decorated(*args, **kwargs):
        # Primero validar que hay token válido
        auth_header = request.headers.get("Authorization", "")
        if not auth_header.startswith("Bearer "):
            abort(401, "Authorization header missing or invalid")
        token = auth_header.split(" ")[1]
        payload = verify_jwt(token)
        
        # Verificar que el rol es cajero
        if payload.get("role") != "cajero":
            abort(403, "Acceso denegado: Solo cajeros pueden realizar esta operación")
        
        g.user = {
            "id": payload["user_id"],
            "username": payload["username"],
            "role": payload["role"],
            "full_name": payload["full_name"],
            "email": payload["email"]
        }
        return f(*args, **kwargs)
    return decorated

# ===== FUNCIONES OTP =====

def generate_otp_secret():
    """Genera un secreto aleatorio para OTP"""
    return pyotp.random_base32()

def generate_qr_code(username, secret, issuer="CoreBankec"):
    """Genera código QR para configurar OTP en apps como Google Authenticator"""
    try:
        # Crear URI para OTP
        totp = pyotp.TOTP(secret)
        provisioning_uri = totp.provisioning_uri(
            name=username,
            issuer_name=issuer
        )
        
        # Generar código QR
        qr = qrcode.QRCode(
            version=1,
            error_correction=qrcode.constants.ERROR_CORRECT_L,
            box_size=10,
            border=4,
        )
        qr.add_data(provisioning_uri)
        qr.make(fit=True)
        
        # Crear imagen
        img = qr.make_image(fill_color="black", back_color="white")
        
        # Convertir a base64 para enviar en JSON
        img_buffer = io.BytesIO()
        img.save(img_buffer, format='PNG')
        img_str = base64.b64encode(img_buffer.getvalue()).decode()
        
        return {
            "qr_code": f"data:image/png;base64,{img_str}",
            "secret": secret,
            "manual_entry_key": secret,
            "provisioning_uri": provisioning_uri
        }
    except Exception as e:
        return None

def verify_otp_token(secret, token):
    """Verifica si el token OTP es válido"""
    try:
        totp = pyotp.TOTP(secret)
        # Asegurar que el token sea string
        token_str = str(token).strip()
        # Verificar con ventana de tolerancia (30 segundos antes y después)
        return totp.verify(token_str, valid_window=1)
    except Exception as e:
        return False

def get_current_otp(secret):
    """Obtiene el token OTP actual (útil para testing)"""
    try:
        totp = pyotp.TOTP(secret)
        return totp.now()
    except:
        return None
