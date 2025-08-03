"""
Custom Logging Middleware
Implementación de sistema de logs personalizado como middleware
Cumple con los requisitos TCG-02 sin usar librerías adicionales
"""

import os
import time
from datetime import datetime
from flask import request, g
import psycopg2
from functools import wraps


class LogLevel:
    """Constantes para niveles de log"""

    INFO = "INFO"
    DEBUG = "DEBUG"
    WARNING = "WARNING"
    ERROR = "ERROR"


class CustomLogger:
    """Sistema de logging personalizado sin librerías externas"""

    def __init__(self, app=None):
        self.app = app
        if app is not None:
            self.init_app(app)

    def init_app(self, app):
        """Inicializa el logger con la aplicación Flask"""
        self.app = app
        self._init_logs_table()

        # Registrar middleware antes y después de cada request
        app.before_request(self._before_request)
        app.after_request(self._after_request)

    def _init_logs_table(self):
        """Crea la tabla de logs en un esquema separado"""
        conn = None
        cur = None
        try:
            conn = self._get_db_connection()
            cur = conn.cursor()

            # Crear esquema separado para logs
            cur.execute("CREATE SCHEMA IF NOT EXISTS logs AUTHORIZATION postgres;")

            # Crear tabla de logs con todos los campos requeridos
            cur.execute(
                """
            CREATE TABLE IF NOT EXISTS logs.application_logs (
                id SERIAL PRIMARY KEY,
                timestamp TIMESTAMP NOT NULL,
                log_level VARCHAR(10) NOT NULL,
                remote_ip INET NOT NULL,
                username VARCHAR(255),
                action_message TEXT NOT NULL,
                http_status_code INTEGER,
                request_method VARCHAR(10),
                request_path TEXT,
                user_agent TEXT,
                execution_time_ms NUMERIC,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
            """
            )

            # Crear índices para mejorar rendimiento
            cur.execute(
                """
            CREATE INDEX IF NOT EXISTS idx_logs_timestamp 
            ON logs.application_logs(timestamp);
            """
            )

            cur.execute(
                """
            CREATE INDEX IF NOT EXISTS idx_logs_level 
            ON logs.application_logs(log_level);
            """
            )

            cur.execute(
                """
            CREATE INDEX IF NOT EXISTS idx_logs_username 
            ON logs.application_logs(username);
            """
            )

            conn.commit()
            print("Sistema de logs inicializado correctamente")

        except Exception as e:
            print(f"Error inicializando tabla de logs: {e}")
            print("La aplicación continuará sin logging en base de datos")
            if conn:
                conn.rollback()
        finally:
            if cur:
                cur.close()
            if conn:
                conn.close()

    def _get_db_connection(self):
        """Obtiene conexión a la base de datos"""
        DB_HOST = os.environ.get("POSTGRES_HOST", "db")
        DB_PORT = os.environ.get("POSTGRES_PORT", "5432")
        DB_NAME = os.environ.get("POSTGRES_DB", "corebank")
        DB_USER = os.environ.get("POSTGRES_USER", "postgres")
        DB_PASSWORD = os.environ.get("POSTGRES_PASSWORD", "postgres")

        conn = psycopg2.connect(
            host=DB_HOST,
            port=DB_PORT,
            dbname=DB_NAME,
            user=DB_USER,
            password=DB_PASSWORD,
        )
        return conn

    def _get_client_ip(self):
        """Obtiene la IP real del cliente considerando proxies"""
        # Prioridad: X-Forwarded-For, X-Real-IP, remote_addr
        forwarded_for = request.headers.get("X-Forwarded-For")
        if forwarded_for:
            return forwarded_for.split(",")[0].strip()

        real_ip = request.headers.get("X-Real-IP")
        if real_ip:
            return real_ip

        return request.remote_addr or "127.0.0.1"

    def _get_username(self):
        """Obtiene el username del usuario autenticado"""
        if hasattr(g, "user") and g.user:
            return g.user.get("username", "anonymous")
        return "anonymous"

    def _before_request(self):
        """Se ejecuta antes de cada request"""
        g.start_time = time.time()
        g.log_data = {
            "timestamp": datetime.now(),
            "remote_ip": self._get_client_ip(),
            "request_method": request.method,
            "request_path": request.path,
            "user_agent": request.headers.get("User-Agent", "")[:500],  # Limitar tamaño
        }

    def _after_request(self, response):
        """Se ejecuta después de cada request"""
        try:
            # Calcular tiempo de ejecución
            execution_time = (time.time() - g.start_time) * 1000  # en milisegundos

            # Determinar la acción realizada
            action_message = self._build_action_message(
                request.method, request.path, response.status_code
            )

            # Determinar nivel de log basado en status code
            log_level = self._determine_log_level(response.status_code)

            # Registrar el log
            self._write_log(
                log_level=log_level,
                action_message=action_message,
                http_status_code=response.status_code,
                execution_time_ms=execution_time,
            )

        except Exception as e:
            # Error en logging no debe afectar la aplicación
            print(f"Error en logging middleware: {e}")

        return response

    def _build_action_message(self, method, path, status_code):
        """Construye el mensaje de acción basado en la ruta y método"""
        action_map = {
            "POST /auth/login": "Intento de autenticación",
            "POST /auth/register": "Registro de nuevo usuario",
            "POST /bank/deposit": "Depósito en cuenta",
            "POST /bank/withdraw": "Retiro de cuenta",
            "POST /bank/transfer": "Transferencia entre cuentas",
            "POST /bank/credit-payment": "Pago con tarjeta de crédito",
            "POST /bank/pay-credit-balance": "Abono a tarjeta de crédito",
            "GET /swagger": "Acceso a documentación API",
        }

        key = f"{method} {path}"
        base_message = action_map.get(key, f"{method} {path}")

        # Agregar resultado basado en status code
        if status_code >= 200 and status_code < 300:
            return f"{base_message} - Exitoso"
        elif status_code >= 400 and status_code < 500:
            return f"{base_message} - Error de cliente"
        elif status_code >= 500:
            return f"{base_message} - Error de servidor"
        else:
            return f"{base_message} - Código {status_code}"

    def _determine_log_level(self, status_code):
        """Determina el nivel de log basado en el código de respuesta HTTP"""
        if status_code >= 500:
            return LogLevel.ERROR
        elif status_code >= 400:
            return LogLevel.WARNING
        elif status_code >= 200 and status_code < 300:
            return LogLevel.INFO
        else:
            return LogLevel.DEBUG

    def _write_log(
        self, log_level, action_message, http_status_code, execution_time_ms
    ):
        """Escribe el log en la base de datos"""
        try:
            conn = self._get_db_connection()
            cur = conn.cursor()

            # Formato de fecha: AAAA-MM-DD HH:MM:SS.ssss
            timestamp = g.log_data["timestamp"].strftime("%Y-%m-%d %H:%M:%S.%f")

            cur.execute(
                """
                INSERT INTO logs.application_logs 
                (timestamp, log_level, remote_ip, username, action_message, 
                 http_status_code, request_method, request_path, user_agent, execution_time_ms)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            """,
                (
                    timestamp,
                    log_level,
                    g.log_data["remote_ip"],
                    self._get_username(),
                    action_message,
                    http_status_code,
                    g.log_data["request_method"],
                    g.log_data["request_path"],
                    g.log_data["user_agent"],
                    execution_time_ms,
                ),
            )

            conn.commit()

        except Exception as e:
            print(f"Error escribiendo log en base de datos: {e}")
            if conn:
                conn.rollback()
        finally:
            if cur:
                cur.close()
            if conn:
                conn.close()

    def log_custom(self, level, message, username=None):
        """Método para registrar logs personalizados"""
        try:
            conn = self._get_db_connection()
            cur = conn.cursor()

            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")
            remote_ip = (
                self._get_client_ip()
                if hasattr(request, "remote_addr")
                else "127.0.0.1"
            )
            username = username or self._get_username()

            cur.execute(
                """
                INSERT INTO logs.application_logs 
                (timestamp, log_level, remote_ip, username, action_message, 
                 request_method, request_path)
                VALUES (%s, %s, %s, %s, %s, %s, %s)
            """,
                (
                    timestamp,
                    level,
                    remote_ip,
                    username,
                    message,
                    getattr(request, "method", "CUSTOM"),
                    getattr(request, "path", "/custom-log"),
                ),
            )

            conn.commit()

        except Exception as e:
            print(f"Error escribiendo log personalizado: {e}")
            if conn:
                conn.rollback()
        finally:
            if cur:
                cur.close()
            if conn:
                conn.close()

    def info(self, message, username=None):
        """Log nivel INFO"""
        self.log_custom(LogLevel.INFO, message, username)

    def debug(self, message, username=None):
        """Log nivel DEBUG"""
        self.log_custom(LogLevel.DEBUG, message, username)

    def warning(self, message, username=None):
        """Log nivel WARNING"""
        self.log_custom(LogLevel.WARNING, message, username)

    def error(self, message, username=None):
        """Log nivel ERROR"""
        self.log_custom(LogLevel.ERROR, message, username)


# Instancia global del logger personalizado
custom_logger = CustomLogger()
