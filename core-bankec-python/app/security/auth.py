"""
Módulo de autenticación y gestión de tokens JWT
"""
import os
import jwt
import bcrypt
import hashlib
from datetime import datetime, timedelta
from functools import wraps
from flask import request, g
from flask_restx import abort

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
