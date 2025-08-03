"""
Módulo de validaciones de seguridad específicas
"""
import re
from .sanitization import sanitize_input
from .password import validate_security_password

def validate_sql_safe(input_string):
    """Validación adicional para prevenir SQL injection"""
    if not input_string:
        return True
    
    # Lista de palabras clave SQL peligrosas
    dangerous_keywords = [
        'SELECT', 'INSERT', 'UPDATE', 'DELETE', 'DROP', 'CREATE', 'ALTER',
        'EXEC', 'EXECUTE', 'UNION', 'SCRIPT', 'DECLARE', 'CAST', 'CONVERT'
    ]
    
    # Verificar palabras clave peligrosas
    upper_input = input_string.upper()
    for keyword in dangerous_keywords:
        if keyword in upper_input:
            return False
    
    # Verificar patrones sospechosos
    suspicious_patterns = [
        r'--',  # Comentarios SQL
        r'/\*.*\*/',  # Comentarios multilínea
        r';\s*$',  # Terminación con punto y coma
        r'\bOR\s+\d+\s*=\s*\d+',  # OR 1=1
        r'\bAND\s+\d+\s*=\s*\d+',  # AND 1=1
        r"'.*'",  # Strings con comillas simples sospechosas
        r'".*"',  # Strings con comillas dobles sospechosas
    ]
    
    for pattern in suspicious_patterns:
        if re.search(pattern, input_string, re.IGNORECASE):
            return False
    
    return True

def validate_ecuadorian_cedula(cedula):
    """Valida cédula ecuatoriana usando algoritmo del dígito verificador"""
    if not cedula:
        return False
    
    # Sanitizar entrada - solo números
    cedula = re.sub(r'[^\d]', '', str(cedula))
    
    if len(cedula) != 10:
        return False
    
    # Validación SQL safe
    if not validate_sql_safe(cedula):
        return False
    
    # Los primeros dos dígitos deben corresponder a una provincia (01-24)
    provincia = int(cedula[:2])
    if provincia < 1 or provincia > 24:
        return False
    
    # El tercer dígito debe ser menor a 6 (para personas naturales)
    if int(cedula[2]) >= 6:
        return False
    
    # Algoritmo del dígito verificador
    coeficientes = [2, 1, 2, 1, 2, 1, 2, 1, 2]
    suma = 0
    
    for i in range(9):
        valor = int(cedula[i]) * coeficientes[i]
        if valor >= 10:
            valor = valor - 9
        suma += valor
    
    digito_verificador = (10 - (suma % 10)) % 10
    return digito_verificador == int(cedula[9])

def validate_phone_number(phone):
    """Valida número celular ecuatoriano (formato: 09XXXXXXXX)"""
    if not phone:
        return False
    
    # Sanitizar entrada - solo números
    phone = re.sub(r'[^\d]', '', str(phone))
    
    # Validación SQL safe
    if not validate_sql_safe(phone):
        return False
    
    # Debe tener 10 dígitos y empezar con 09
    pattern = r'^09\d{8}$'
    return bool(re.match(pattern, phone))

def validate_username(username, personal_info):
    """Valida que el username solo tenga letras y números, sin información personal"""
    if not username:
        return False, "Username es requerido"
    
    # Sanitizar entrada
    username = sanitize_input(str(username), allow_special_chars=False)
    
    # Validación SQL safe
    if not validate_sql_safe(username):
        return False, "Username contiene caracteres no permitidos"
    
    # Solo letras y números
    if not re.match(r'^[a-zA-Z0-9]+$', username):
        return False, "Username solo puede contener letras y números"
    
    # Longitud mínima y máxima
    if len(username) < 4 or len(username) > 20:
        return False, "Username debe tener entre 4 y 20 caracteres"
    
    # No debe contener información personal
    username_lower = username.lower()
    personal_data = [
        sanitize_input(personal_info.get('first_name', ''), allow_special_chars=False).lower(),
        sanitize_input(personal_info.get('last_name', ''), allow_special_chars=False).lower(),
        sanitize_input(personal_info.get('cedula', ''), allow_special_chars=False),
        sanitize_input(personal_info.get('phone', ''), allow_special_chars=False),
        sanitize_input(personal_info.get('email', ''), allow_special_chars=False).lower().split('@')[0]
    ]
    
    for data in personal_data:
        if data and len(data) >= 3:  # Solo verificar si tiene al menos 3 caracteres
            if data in username_lower or username_lower in data:
                return False, "Username no puede contener información personal"
    
    return True, username

def validate_strong_password(password, personal_info):
    """Valida que la contraseña sea robusta y no contenga información personal"""
    if not password:
        return False, "Contraseña es requerida"
    
    # Convertir a string pero NO sanitizar completamente (necesitamos símbolos)
    password = str(password)
    
    # Verificar patrones de inyección específicos pero mantener símbolos válidos
    injection_patterns = [
        r'(\b(SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER|EXEC|EXECUTE|UNION|SCRIPT)\b)',
        r'(--|\/\*|\*\/)',
        r'(\bOR\b.*\b1\s*=\s*1\b)',
        r'(\bAND\b.*\b1\s*=\s*1\b)',
        r'(<script|javascript:|vbscript:)',
    ]
    
    for pattern in injection_patterns:
        if re.search(pattern, password, re.IGNORECASE):
            return False, "Contraseña contiene patrones no permitidos"
    
    # Validar robustez de la contraseña
    is_good_password, error = validate_security_password(password)
    # Retornar el error si la contraseña no es buena
    if(is_good_password == False): return False, error

    # No debe contener información personal
    password_lower = password.lower()
    personal_data = [
        sanitize_input(personal_info.get('first_name', ''), allow_special_chars=False).lower(),
        sanitize_input(personal_info.get('last_name', ''), allow_special_chars=False).lower(),
        sanitize_input(personal_info.get('cedula', ''), allow_special_chars=False),
        sanitize_input(personal_info.get('phone', ''), allow_special_chars=False),
        sanitize_input(personal_info.get('email', ''), allow_special_chars=False).lower().split('@')[0]
    ]
    
    for data in personal_data:
        if data and len(data) >= 3:  # Solo verificar si tiene al menos 3 caracteres
            if data in password_lower:
                return False, "Contraseña no puede contener información personal"
    
    return True, "Contraseña válida"

def validate_email(email):
    """Valida formato de email"""
    if not email:
        return False, "Email es requerido"
    
    # Sanitizar entrada manteniendo @ y puntos
    email = sanitize_input(str(email), allow_special_chars=True)
    
    # Validación SQL safe
    if not validate_sql_safe(email):
        return False, "Email contiene caracteres no permitidos"
    
    # Validación de formato básico
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    if not re.match(pattern, email):
        return False, "Formato de email inválido"
    
    # Longitud máxima
    if len(email) > 254:
        return False, "Email demasiado largo"
    
    return True, email
