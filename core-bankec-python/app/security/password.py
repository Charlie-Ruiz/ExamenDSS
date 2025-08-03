import re

def validate_security_password(password: str) ->tuple[bool, list]:
    # 1. Longitud mínima 12
    if len(password) < 12:
        return False, "Debe tener al menos 12 caracteres."

    # 2. Contener minúsculas
    if not re.search(r"[a-z]", password):
        return False, "Debe incluir al menos una letra minúscula (a-z)."

    # 3. Contener mayúsculas
    if not re.search(r"[A-Z]", password):
        return False, "Debe incluir al menos una letra mayúscula (A-Z)."

    # 4. Contener dígitos
    if not re.search(r"\d", password):
        return False, "Debe incluir al menos un número (0-9)."

    # 5. Contener caracteres especiales
    if not re.search(r"[!@#$%^&*(),.?\":{}|<>_\-+=/\\\[\]`~;']", password):
        return False, "Debe incluir al menos un símbolo especial."
    
    return True, []