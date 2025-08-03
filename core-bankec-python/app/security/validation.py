"""
Módulo de validaciones de seguridad específicas
"""
import re
from .sanitization import sanitize_input
from .password import validate_security_password

# Patrones de seguridad reutilizables
SECURITY_PATTERNS = {
    'sql_keywords': [
        'SELECT', 'INSERT', 'UPDATE', 'DELETE', 'DROP', 'CREATE', 'ALTER',
        'EXEC', 'EXECUTE', 'UNION', 'SCRIPT', 'DECLARE', 'CAST', 'CONVERT'
    ],
    
    'injection_patterns': [
        r'(\b(SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER|EXEC|EXECUTE|UNION|SCRIPT)\b)',
        r'(--|\/\*|\*\/)',  # Comentarios SQL
        r'(\bOR\b.*\b1\s*=\s*1\b)',  # OR 1=1
        r'(\bAND\b.*\b1\s*=\s*1\b)',  # AND 1=1
        r'(<script|javascript:|vbscript:)',  # XSS patterns
    ],
    
    'suspicious_patterns': [
        r'--',  # Comentarios SQL
        r'/\*.*\*/',  # Comentarios multilínea
        r';\s*$',  # Terminación con punto y coma
        r'\bOR\s+\d+\s*=\s*\d+',  # OR 1=1
        r'\bAND\s+\d+\s*=\s*\d+',  # AND 1=1
        r"'.*'",  # Strings con comillas simples sospechosas
        r'".*"',  # Strings con comillas dobles sospechosas
    ],
    
    'password_symbols': r'[!@#$%^&*(),.?":{}|<>_+=\-\[\]\\;]'
}

def check_injection_patterns(input_string, pattern_type='injection_patterns'):
    """Verifica patrones de inyección en una cadena"""
    if not input_string:
        return True
    
    patterns = SECURITY_PATTERNS.get(pattern_type, [])
    for pattern in patterns:
        if re.search(pattern, input_string, re.IGNORECASE):
            return False
    return True

def check_sql_keywords(input_string):
    """Verifica palabras clave SQL peligrosas"""
    if not input_string:
        return True
    
    upper_input = input_string.upper()
    for keyword in SECURITY_PATTERNS['sql_keywords']:
        if keyword in upper_input:
            return False
    return True

def validate_sql_safe(input_string):
    """Validación adicional para prevenir SQL injection"""
    if not input_string:
        return True
    
    # Verificar palabras clave SQL peligrosas
    if not check_sql_keywords(input_string):
        return False
    
    # Verificar patrones sospechosos
    if not check_injection_patterns(input_string, 'suspicious_patterns'):
        return False
    
    return True

def validate_password_security(password, min_length=8):
    """Validación de seguridad común para contraseñas"""
    if not password:
        return False, "Contraseña es requerida"
    
    # Convertir a string pero NO sanitizar completamente (necesitamos símbolos)
    password = str(password)
    
    # Verificar patrones de inyección
    if not check_injection_patterns(password, 'injection_patterns'):
        return False, "Contraseña contiene patrones no permitidos"
    
    # Longitud mínima
    if len(password) < min_length:
        return False, f"Contraseña debe tener al menos {min_length} caracteres"
    
    # Al menos una letra minúscula
    if not re.search(r'[a-z]', password):
        return False, "Contraseña debe contener al menos una letra minúscula"
    
    # Al menos una letra mayúscula
    if not re.search(r'[A-Z]', password):
        return False, "Contraseña debe contener al menos una letra mayúscula"
    
    # Al menos un número
    if not re.search(r'\d', password):
        return False, "Contraseña debe contener al menos un número"
    
    # Al menos un símbolo permitido
    if not re.search(SECURITY_PATTERNS['password_symbols'], password):
        return False, "Contraseña debe contener al menos un símbolo (!@#$%^&*(),.?\":{}|<>_+-=[]\\;)"
    
    return True, "Contraseña válida"

def check_personal_info_in_text(text, personal_info):
    """Verifica si el texto contiene información personal"""
    if not text or not personal_info:
        return False
    
    text_lower = text.lower()
    personal_data = [
        sanitize_input(personal_info.get('first_name', ''), allow_special_chars=False).lower(),
        sanitize_input(personal_info.get('last_name', ''), allow_special_chars=False).lower(),
        sanitize_input(personal_info.get('cedula', ''), allow_special_chars=False),
        sanitize_input(personal_info.get('phone', ''), allow_special_chars=False),
        sanitize_input(personal_info.get('email', ''), allow_special_chars=False).lower().split('@')[0]
    ]
    
    for data in personal_data:
        if data and len(data) >= 3:  # Solo verificar si tiene al menos 3 caracteres
            if data in text_lower or text_lower in data:
                return True
    return False

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
    if check_personal_info_in_text(username, personal_info):
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

def validate_cashier_username(username):
    """Valida username de cajero: solo letras y números"""
    if not username:
        return False, "Username es requerido"
    
    # Sanitizar entrada
    username = sanitize_input(str(username), allow_special_chars=False)
    
    # Validación SQL safe
    if not validate_sql_safe(username):
        return False, "Username contiene caracteres no permitidos"
    
    # Solo letras y números (sin guiones bajos ni otros símbolos)
    if not re.match(r'^[a-zA-Z0-9]+$', username):
        return False, "Username solo puede contener letras y números"
    
    # Longitud mínima y máxima
    if len(username) < 4 or len(username) > 20:
        return False, "Username debe tener entre 4 y 20 caracteres"
    
    return True, username

def validate_cashier_password(password):
    """Valida contraseña de cajero: mínimo 10 caracteres, letras, números y símbolos"""
    # Usar validación de seguridad base con longitud más estricta
    is_valid, message = validate_password_security(password, min_length=10)
    return is_valid, message
