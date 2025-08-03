#!/usr/bin/env python3
"""
Script de demostración del sistema de logs personalizado
Demuestra todas las funcionalidades del middleware de logging
"""

import requests
import json
import time

BASE_URL = "http://localhost:8000"


def test_logging_middleware():
    """Prueba el middleware de logging con diferentes escenarios"""

    print("=== DEMOSTRACIÓN DEL SISTEMA DE LOGS PERSONALIZADO ===\n")

    # 1. Intento de login exitoso
    print("1. Realizando login exitoso...")
    login_data = {"username": "user1", "password": "pass1"}

    response = requests.post(f"{BASE_URL}/auth/login", json=login_data)
    print(f"   Status: {response.status_code}")

    if response.status_code == 200:
        token = response.json().get("token")
        print(f"   Token obtenido: {token[:20]}...")
    else:
        print("   Error en login")
        return

    time.sleep(1)

    # 2. Intento de login fallido
    print("\n2. Realizando login fallido...")
    bad_login_data = {"username": "user_inexistente", "password": "password_incorrecta"}

    response = requests.post(f"{BASE_URL}/auth/login", json=bad_login_data)
    print(f"   Status: {response.status_code}")

    time.sleep(1)

    # 3. Intento de inyección SQL (será detectado)
    print("\n3. Intentando inyección SQL...")
    injection_data = {
        "username": "admin'; DROP TABLE users; --",
        "password": "cualquier_cosa",
    }

    response = requests.post(f"{BASE_URL}/auth/login", json=injection_data)
    print(f"   Status: {response.status_code}")
    print(f"   Mensaje: {response.json().get('message', 'Bloqueado')}")

    time.sleep(1)

    # 4. Operación bancaria con token válido
    print("\n4. Realizando depósito con token válido...")
    headers = {"Authorization": f"Bearer {token}"}
    deposit_data = {"account_number": "123456", "amount": 100.50}

    response = requests.post(
        f"{BASE_URL}/bank/deposit", json=deposit_data, headers=headers
    )
    print(f"   Status: {response.status_code}")

    time.sleep(1)

    # 5. Intento de operación sin token (no autorizado)
    print("\n5. Intentando operación sin autorización...")

    response = requests.post(f"{BASE_URL}/bank/withdraw", json={"amount": 50})
    print(f"   Status: {response.status_code}")

    time.sleep(1)

    # 6. Acceso a documentación
    print("\n6. Accediendo a documentación Swagger...")

    response = requests.get(f"{BASE_URL}/swagger")
    print(f"   Status: {response.status_code}")

    print("\n=== FIN DE LA DEMOSTRACIÓN ===")
    print(
        "\nTodos estos eventos han sido registrados en el sistema de logs personalizado"
    )
    print("con la siguiente información:")
    print("- Fecha y hora local (AAAA-MM-DD HH:MM:SS.ssss)")
    print("- Tipo de log (INFO, DEBUG, WARNING, ERROR)")
    print("- Dirección IP remota")
    print("- Nombre de usuario")
    print("- Acción realizada / Mensaje")
    print("- Código HTTP de respuesta")
    print("- Tiempo de ejecución en milisegundos")
    print("\nLos logs se almacenan en el esquema 'logs.application_logs' de PostgreSQL")


def show_log_structure():
    """Muestra la estructura de la tabla de logs"""
    print("\n=== ESTRUCTURA DE LA TABLA DE LOGS ===")
    print(
        """
    CREATE TABLE logs.application_logs (
        id SERIAL PRIMARY KEY,
        timestamp TIMESTAMP NOT NULL,           -- AAAA-MM-DD HH:MM:SS.ssss
        log_level VARCHAR(10) NOT NULL,         -- INFO, DEBUG, WARNING, ERROR
        remote_ip INET NOT NULL,                -- Dirección IP remota
        username VARCHAR(255),                  -- Nombre de usuario
        action_message TEXT NOT NULL,           -- Acción realizada/Mensaje
        http_status_code INTEGER,               -- Código HTTP de respuesta
        request_method VARCHAR(10),             -- GET, POST, PUT, DELETE
        request_path TEXT,                      -- Ruta solicitada
        user_agent TEXT,                        -- User Agent del navegador
        execution_time_ms NUMERIC,              -- Tiempo de ejecución en ms
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
    """
    )


if __name__ == "__main__":
    print("Iniciando servidor antes de las pruebas...")
    print("Asegúrate de que el servidor esté corriendo en http://localhost:8000")
    input("Presiona Enter para continuar con las pruebas...")

    show_log_structure()
    test_logging_middleware()
