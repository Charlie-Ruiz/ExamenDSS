from dotenv import load_dotenv
import os
from flask import Flask, request, g
from flask_restx import Api, Resource, fields  # type: ignore
import logging

# Importar módulos locales
from .db import init_db
from .security.auth import token_required
from .services import AuthService, BankService
from .models.swagger_models import create_swagger_models
from .middleware.logging import custom_logger

# Configuración logging estándar (mantener para compatibilidad)
logging.basicConfig(
    filename="app.log",
    level=logging.DEBUG,
    encoding="utf-8",
    filemode="a",
    format="{asctime} - {levelname} - {message}",
    style="{",
    datefmt="%Y-%m-%d %H:%M",
)

load_dotenv()

# Configuración Swagger para Bearer token
authorizations = {
    "Bearer": {
        "type": "apiKey",
        "in": "header",
        "name": "Authorization",
        "description": "Ingresa tu token en formato **Bearer <token>**",
    }
}

app = Flask(__name__)

# Inicializar el middleware de logging personalizado
custom_logger.init_app(app)

api = Api(
    app,
    version="1.0",
    title="Core Bancario API",
    description="API para operaciones bancarias, incluyendo autenticación y operaciones de cuenta.",
    doc="/swagger",
    authorizations=authorizations,
    security="Bearer",
)

# Namespaces
auth_ns = api.namespace("auth", description="Operaciones de autenticación")
bank_ns = api.namespace("bank", description="Operaciones bancarias")
logs_ns = api.namespace("logs", description="Consulta de logs del sistema")

# Crear modelos Swagger
models = create_swagger_models(auth_ns, bank_ns)


# Endpoint login con JWT
@auth_ns.route("/login")
class Login(Resource):
    @auth_ns.expect(models["login_model"], validate=True)
    @auth_ns.doc("login")
    def post(self):
        data = api.payload
        username = data.get("username", "")
        password = data.get("password", "")

        result, status_code = AuthService.login(username, password)

        if status_code != 200:
            api.abort(status_code, result.get("error", "Error desconocido"))

        return result, status_code


# Endpoint de registro de cliente
@auth_ns.route("/register")
class Register(Resource):
    @auth_ns.expect(models["register_model"], validate=True)
    @auth_ns.doc("register")
    def post(self):
        """Registra un nuevo cliente con validaciones de seguridad completas"""
        data = api.payload

        result, status_code = AuthService.register(data)

        if status_code != 201:
            api.abort(status_code, result.get("error", "Error desconocido"))

        return result, status_code


# Endpoints bancarios protegidos por token_required
@bank_ns.route("/deposit")
class Deposit(Resource):
    @bank_ns.expect(models["deposit_model"], validate=True)
    @bank_ns.doc("deposit")
    @token_required
    def post(self):
        data = api.payload
        account_number = data.get("account_number")
        amount = data.get("amount", 0)

        result, status_code = BankService.deposit(account_number, amount)

        if status_code != 200:
            api.abort(status_code, result.get("error", "Error desconocido"))

        return result, status_code


@bank_ns.route("/withdraw")
class Withdraw(Resource):
    @bank_ns.expect(models["withdraw_model"], validate=True)
    @bank_ns.doc("withdraw")
    @token_required
    def post(self):
        """Realiza un retiro de la cuenta del usuario autenticado."""
        data = api.payload
        amount = data.get("amount", 0)

        result, status_code = BankService.withdraw(amount)

        if status_code != 200:
            api.abort(status_code, result.get("error", "Error desconocido"))

        return result, status_code


@bank_ns.route("/transfer")
class Transfer(Resource):
    @bank_ns.expect(models["transfer_model"], validate=True)
    @bank_ns.doc("transfer")
    @token_required
    def post(self):
        """Transfiere fondos desde la cuenta del usuario autenticado a otra cuenta."""
        data = api.payload
        target_username = data.get("target_username")
        amount = data.get("amount", 0)

        result, status_code = BankService.transfer(target_username, amount)

        if status_code != 200:
            api.abort(status_code, result.get("error", "Error desconocido"))

        return result, status_code


@bank_ns.route("/credit-payment")
class CreditPayment(Resource):
    @bank_ns.expect(models["credit_payment_model"], validate=True)
    @bank_ns.doc("credit_payment")
    @token_required
    def post(self):
        """
        Realiza una compra a crédito:
        - Descuenta el monto de la cuenta.
        - Aumenta la deuda de la tarjeta de crédito.
        """
        data = api.payload
        amount = data.get("amount", 0)

        result, status_code = BankService.credit_payment(amount)

        if status_code != 200:
            api.abort(status_code, result.get("error", "Error desconocido"))

        return result, status_code


@bank_ns.route("/pay-credit-balance")
class PayCreditBalance(Resource):
    @bank_ns.expect(models["pay_credit_balance_model"], validate=True)
    @bank_ns.doc("pay_credit_balance")
    @token_required
    def post(self):
        """
        Realiza un abono a la deuda de la tarjeta:
        - Descuenta el monto de la cuenta.
        - Reduce la deuda de la tarjeta de crédito.
        """
        data = api.payload
        amount = data.get("amount", 0)

        result, status_code = BankService.pay_credit_balance(amount)

        if status_code != 200:
            api.abort(status_code, result.get("error", "Error desconocido"))

        return result, status_code


# Endpoint para consultar logs del sistema (solo para administradores)
@logs_ns.route("/view")
class LogsView(Resource):
    @logs_ns.doc("get_logs")
    @token_required
    def get(self):
        """Consulta los logs del sistema - Solo para administradores"""
        # Verificar que el usuario tenga rol de administrador
        if not hasattr(g, "user") or g.user.get("role") != "admin":
            custom_logger.warning(
                f"Acceso no autorizado a logs - Usuario: {g.user.get('username', 'unknown')}"
            )
            return {"error": "No autorizado para consultar logs"}, 403

        try:
            from .db import get_connection

            conn = get_connection()
            cur = conn.cursor()

            # Obtener últimos 50 logs
            cur.execute(
                """
                SELECT timestamp, log_level, remote_ip, username, action_message, 
                       http_status_code, request_method, request_path, execution_time_ms
                FROM logs.application_logs 
                ORDER BY timestamp DESC 
                LIMIT 50
            """
            )

            logs = []
            for row in cur.fetchall():
                logs.append(
                    {
                        "timestamp": (
                            row[0].strftime("%Y-%m-%d %H:%M:%S.%f") if row[0] else None
                        ),
                        "log_level": row[1],
                        "remote_ip": str(row[2]),
                        "username": row[3],
                        "action_message": row[4],
                        "http_status_code": row[5],
                        "request_method": row[6],
                        "request_path": row[7],
                        "execution_time_ms": float(row[8]) if row[8] else None,
                    }
                )

            custom_logger.info(
                f"Consulta de logs realizada por administrador: {g.user.get('username')}"
            )
            return {"logs": logs, "total": len(logs)}, 200

        except Exception as e:
            custom_logger.error(f"Error consultando logs: {str(e)}")
            return {"error": "Error interno del servidor"}, 500
        finally:
            if cur:
                cur.close()
            if conn:
                conn.close()


# Inicializar la base de datos al crear la aplicación
with app.app_context():
    init_db()

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8000, debug=True)
