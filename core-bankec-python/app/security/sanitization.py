"""
Módulo de sanitización de inputs para prevenir inyecciones
"""
import re
import html
import unicodedata
import logging
from flask import request

try:
    import bleach
    BLEACH_AVAILABLE = True
except ImportError:
    BLEACH_AVAILABLE = False

def get_client_ip():
    """Obtiene la IP del cliente"""
    # Verificar headers de proxy
    if request.headers.get('X-Forwarded-For'):
        return request.headers.get('X-Forwarded-For').split(',')[0].strip()
    elif request.headers.get('X-Real-IP'):
        return request.headers.get('X-Real-IP')
    else:
        return request.remote_addr

def sanitize_input(input_string, allow_special_chars=False):
    """Sanitiza entrada contra XSS, SQL injection y otras inyecciones"""
    if not input_string:
        return ""
    
    # Convertir a string si no lo es
    input_string = str(input_string).strip()
    
    # Normalizar caracteres Unicode para prevenir bypass
    input_string = unicodedata.normalize('NFKC', input_string)
    
    # Escape HTML para prevenir XSS
    input_string = html.escape(input_string, quote=True)
    
    # Usar bleach para sanitización adicional si está disponible
    if BLEACH_AVAILABLE:
        try:
            # Permitir solo tags seguros si se permiten caracteres especiales
            if allow_special_chars:
                # No permitir ningún tag HTML
                input_string = bleach.clean(input_string, tags=[], strip=True)
            else:
                # Limpiar completamente
                input_string = bleach.clean(input_string, tags=[], attributes={}, strip=True)
        except:
            # Si hay error con bleach, continuar con limpieza manual
            pass
    
    # Lista de patrones peligrosos para SQL injection
    sql_patterns = [
        r'(\b(SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER|EXEC|EXECUTE|UNION|SCRIPT)\b)',
        r'(--|\/\*|\*\/)',  # Comentarios SQL
        r'(\bOR\b.*\b1\s*=\s*1\b)',  # OR 1=1
        r'(\bAND\b.*\b1\s*=\s*1\b)',  # AND 1=1
        r'(;|\|)',  # Separadores de comandos
        r'(\bxp_|\bsp_)',  # Procedimientos almacenados
        r'(\\\$|@@)',  # Variables de sistema
    ]
    
    # Lista de patrones peligrosos para NoSQL injection
    nosql_patterns = [
        r'(\$where|\$ne|\$gt|\$lt|\$regex|\$exists)',  # MongoDB operators
        r'(javascript:|eval\(|function\()',  # JavaScript injection
        r'(\{\s*\$)',  # MongoDB query objects
    ]
    
    # Lista de patrones peligrosos para XSS
    xss_patterns = [
        r'(<script[^>]*>.*?</script>)',  # Script tags
        r'(javascript:|vbscript:|data:)',  # Protocolos peligrosos
        r'(on\w+\s*=)',  # Event handlers
        r'(<iframe|<object|<embed|<applet)',  # Tags peligrosos
        r'(expression\(|url\()',  # CSS injection
    ]
    
    # Combinar todos los patrones
    all_patterns = sql_patterns + nosql_patterns + xss_patterns
    
    # Verificar patrones peligrosos
    for pattern in all_patterns:
        if re.search(pattern, input_string, re.IGNORECASE):
            # Log del intento de inyección
            try:
                client_ip = get_client_ip()
            except:
                client_ip = 'unknown'
            logging.warning(f"Intento de inyección detectado: {pattern}, Input: {input_string[:50]}, IP: {client_ip}")
            # Limpiar el patrón detectado
            input_string = re.sub(pattern, '', input_string, flags=re.IGNORECASE)
    
    # Si no se permiten caracteres especiales, remover solo alfanuméricos, espacios y algunos símbolos básicos
    if not allow_special_chars:
        # Permitir letras, números, espacios, guiones, puntos, @, y algunos símbolos básicos
        input_string = re.sub(r'[^\w\s\-\.@áéíóúñüÁÉÍÓÚÑÜ]', '', input_string)
    
    return input_string.strip()

def validate_and_sanitize_numeric(value, min_val=None, max_val=None):
    """Valida y sanitiza valores numéricos"""
    try:
        # Convertir a float y validar rangos
        numeric_value = float(value)
        
        if min_val is not None and numeric_value < min_val:
            return False, f"Valor debe ser mayor o igual a {min_val}"
        
        if max_val is not None and numeric_value > max_val:
            return False, f"Valor debe ser menor o igual a {max_val}"
        
        return True, numeric_value
    
    except (ValueError, TypeError):
        return False, "Valor numérico inválido"

def validate_and_sanitize_string(value, min_length=1, max_length=255, allow_special=True):
    """Valida y sanitiza strings con longitud"""
    if not value:
        return False, "Campo requerido"
    
    # Sanitizar entrada
    sanitized = sanitize_input(str(value), allow_special_chars=allow_special)
    
    # Validar longitud
    if len(sanitized) < min_length:
        return False, f"Debe tener al menos {min_length} caracteres"
    
    if len(sanitized) > max_length:
        return False, f"No puede exceder {max_length} caracteres"
    
    return True, sanitized
