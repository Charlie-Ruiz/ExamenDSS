from dotenv import load_dotenv
import os
from flask import Flask, request, g
from flask_restx import Api, Resource, fields  # type: ignore
import logging

# Importar módulos locales
from .db import init_db
from .security.auth import token_required, cashier_required
from .services import AuthService, BankService, CardSecurityService
from .services.cashier_service import CashierService
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
cashier_ns = api.namespace("cashier", description="Operaciones de cajeros")
logs_ns = api.namespace("logs", description="Consulta de logs del sistema")
cards_ns = api.namespace(
    "cards", description="Gestión segura de tarjetas de crédito")

# Crear modelos Swagger
models = create_swagger_models(auth_ns, bank_ns, cards_ns)


# Endpoint login con JWT
@auth_ns.route("/login")
class Login(Resource):
    @auth_ns.expect(models["login_model"], validate=True)
    @auth_ns.doc("login",
                 description="Autentica un usuario y genera un token JWT. " +
                 "El token debe ser incluido en las siguientes peticiones " +
                 "en el header Authorization con formato Bearer <token>")
    @auth_ns.response(200, 'Login exitoso')
    @auth_ns.response(401, 'Credenciales inválidas')
    @auth_ns.response(400, 'Datos inválidos')
    def post(self):
        """
        Autentica un usuario con sus credenciales

        Retorna un token JWT si las credenciales son válidas.
        """
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
    @auth_ns.doc("register",
                 description="Registra un nuevo cliente en el sistema bancario con todas las validaciones de seguridad.")
    @auth_ns.response(201, 'Cliente registrado exitosamente')
    @auth_ns.response(400, 'Datos inválidos o no cumplen con las validaciones')
    @auth_ns.response(409, 'Usuario ya existe en el sistema')
    def post(self):
        """
        Registra un nuevo cliente en el sistema

        Crea una nueva cuenta bancaria para el cliente realizando todas las validaciones
        de seguridad necesarias y genera un número de cuenta único.
        """
        data = api.payload

        result, status_code = AuthService.register(data)

        if status_code != 201:
            api.abort(status_code, result.get("error", "Error desconocido"))

        return result, status_code


# Endpoints bancarios protegidos por token_required
@bank_ns.route("/deposit")
class Deposit(Resource):
    @bank_ns.expect(models["deposit_model"], validate=True)
    @bank_ns.doc("deposit",
                 description="Realiza un depósito en una cuenta específica. " +
                 "Solo puede ser realizado por cajeros autorizados.")
    @bank_ns.response(200, 'Depósito exitoso')
    @bank_ns.response(400, 'Datos inválidos')
    @bank_ns.response(403, 'No autorizado')
    @bank_ns.response(404, 'Cuenta no encontrada')
    @cashier_required
    def post(self):
        """
        Realiza un depósito en una cuenta

        Requiere autenticación de cajero y número de cuenta válido.
        """
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
    @bank_ns.doc("withdraw",
                 description="Realiza un retiro de efectivo. Solo puede ser realizado por cajeros autorizados.")
    @bank_ns.response(200, 'Retiro exitoso')
    @bank_ns.response(400, 'Datos inválidos o saldo insuficiente')
    @bank_ns.response(403, 'No autorizado - Solo cajeros pueden realizar retiros')
    @cashier_required
    def post(self):
        """
        Realiza un retiro de efectivo

        Permite a un cajero autorizado realizar un retiro de la cuenta del cliente.
        Verifica el saldo disponible y los límites de retiro diarios.
        """
        data = api.payload
        amount = data.get("amount", 0)

        result, status_code = BankService.withdraw(amount)

        if status_code != 200:
            api.abort(status_code, result.get("error", "Error desconocido"))

        return result, status_code


@bank_ns.route("/transfer")
class Transfer(Resource):
    @bank_ns.expect(models["transfer_model"], validate=True)
    @bank_ns.doc("transfer",
                 description="Transfiere fondos entre cuentas. " +
                 "El monto se debita de la cuenta del usuario autenticado.")
    @bank_ns.response(200, 'Transferencia exitosa')
    @bank_ns.response(400, 'Datos inválidos o saldo insuficiente')
    @bank_ns.response(403, 'No autorizado')
    @bank_ns.response(404, 'Usuario destino no encontrado')
    @token_required
    def post(self):
        """
        Transfiere fondos a otra cuenta

        Realiza una transferencia verificando saldo disponible.
        """
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
    @bank_ns.doc("credit_payment",
                 description="Procesa un pago con tarjeta de crédito verificando límites y saldos disponibles.")
    @bank_ns.response(200, 'Pago procesado exitosamente')
    @bank_ns.response(400, 'Datos inválidos o límite de crédito excedido')
    @bank_ns.response(403, 'No autorizado')
    @bank_ns.response(404, 'Tarjeta no encontrada')
    @token_required
    def post(self):
        """
        Realiza un pago con tarjeta de crédito

        Procesa una transacción con tarjeta de crédito:
        - Verifica el límite de crédito disponible
        - Registra la transacción
        - Actualiza el saldo de la tarjeta
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
                            row[0].strftime(
                                "%Y-%m-%d %H:%M:%S.%f") if row[0] else None
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


# ===== ENDPOINTS DE CAJEROS =====

# Modelos para cajeros
cashier_register_model = cashier_ns.model("CashierRegister", {
    "first_name": fields.String(required=True, description="Nombre del cajero", example="Juan"),
    "last_name": fields.String(required=True, description="Apellido del cajero", example="Pérez"),
    "username": fields.String(required=True, description="Usuario (solo letras y números)", example="jperez2024"),
    "password": fields.String(required=True, description="Contraseña (mín. 10 chars con letras, números y símbolos)", example="MiPass123!@#"),
    "email": fields.String(required=True, description="Correo electrónico", example="jperez@corebankec.com")
})

cashier_login_model = cashier_ns.model("CashierLogin", {
    "username": fields.String(required=True, description="Usuario del cajero", example="jperez2024"),
    "password": fields.String(required=True, description="Contraseña del cajero", example="MiPass123!@#"),
    "otp_token": fields.String(required=True, description="Código OTP de 6 dígitos", example="123456")
})


@cashier_ns.route("/register")
class CashierRegister(Resource):
    @cashier_ns.expect(cashier_register_model, validate=True)
    @cashier_ns.doc("cashier_register")
    def post(self):
        """Registra un nuevo cajero con autenticación OTP"""
        data = api.payload
        result, status_code = CashierService.register_cashier(data)

        if status_code != 201:
            api.abort(status_code, result.get("error", "Error desconocido"))

        return result, status_code


@cashier_ns.route("/login")
class CashierLogin(Resource):
    @cashier_ns.expect(cashier_login_model, validate=True)
    @cashier_ns.doc("cashier_login",
                    description="Autentica un cajero usando autenticación de dos factores (2FA)")
    @cashier_ns.response(200, 'Login exitoso')
    @cashier_ns.response(401, 'Credenciales inválidas')
    @cashier_ns.response(400, 'Datos inválidos o código OTP incorrecto')
    def post(self):
        """
        Autentica un cajero con autenticación de dos factores

        Valida las credenciales del cajero y el código OTP:
        - Verifica usuario y contraseña
        - Valida el código OTP de 6 dígitos
        - Genera un token JWT para operaciones de cajero
        """
        data = api.payload
        username = data.get("username")
        password = data.get("password")
        otp_token = data.get("otp_token")

        result, status_code = CashierService.login_with_otp(
            username, password, otp_token)

        if status_code != 200:
            api.abort(status_code, result.get("error", "Error desconocido"))

        return result, status_code


# Endpoints para gestión segura de tarjetas de crédito
@cards_ns.route('/register')
class RegisterCard(Resource):
    @cards_ns.expect(models['register_card_model'], validate=True)
    @cards_ns.doc('register_card')
    @token_required
    def post(self):
        """Registra una nueva tarjeta de crédito para el usuario"""
        data = api.payload
        card_number = data.get("card_number")
        expiry_month = data.get("expiry_month")
        expiry_year = data.get("expiry_year")

        user_id = g.user["id"]

        result, status_code = CardSecurityService.register_card(
            user_id, card_number, expiry_month, expiry_year
        )

        if status_code != 201:
            api.abort(status_code, result.get("error", "Error desconocido"))

        return result, status_code


@cards_ns.route('/my-cards')
class MyCards(Resource):
    @cards_ns.doc('get_my_cards')
    @token_required
    def get(self):
        """Consulta las tarjetas registradas del usuario con saldos adeudados"""
        user_id = g.user["id"]

        result, status_code = CardSecurityService.get_user_cards(user_id)

        if status_code != 200:
            api.abort(status_code, result.get("error", "Error desconocido"))

        return result, status_code


@cards_ns.route('/request-otp')
class RequestOTP(Resource):
    @cards_ns.expect(models['request_otp_model'], validate=True)
    @cards_ns.doc('request_otp',
                  description="Genera un código OTP para confirmar un pago con tarjeta de crédito")
    @cards_ns.response(200, 'Código OTP generado exitosamente')
    @cards_ns.response(400, 'Datos inválidos')
    @cards_ns.response(403, 'Verificación fallida de tarjeta')
    @cards_ns.response(404, 'Tarjeta no encontrada')
    @token_required
    def post(self):
        """
        Solicita un código OTP para autorizar un pago

        Genera un código temporal para confirmar una transacción:
        - Verifica la propiedad de la tarjeta
        - Valida los primeros 6 dígitos
        - Genera un código OTP con 5 minutos de validez
        """
        data = api.payload
        card_id = data.get("card_id")
        first_six_digits = data.get("first_six_digits")
        amount = data.get("amount")

        user_id = g.user["id"]

        # Verificar propiedad de la tarjeta
        if not CardSecurityService.verify_card_ownership(user_id, card_id, first_six_digits):
            custom_logger.warning(
                f"Intento de acceso no autorizado a tarjeta - Usuario: {g.user.get('username')}")
            api.abort(
                403, "Tarjeta no encontrada o los primeros 6 dígitos no coinciden")

        result, status_code = CardSecurityService.generate_payment_otp(
            user_id, card_id, amount)

        if status_code != 200:
            api.abort(status_code, result.get("error", "Error desconocido"))

        return result, status_code


@cards_ns.route('/confirm-payment')
class ConfirmPayment(Resource):
    @cards_ns.expect(models['confirm_payment_model'], validate=True)
    @cards_ns.doc('confirm_payment',
                  description="Confirma y procesa un pago con tarjeta usando el código OTP")
    @cards_ns.response(200, 'Pago confirmado y procesado exitosamente')
    @cards_ns.response(400, 'Datos inválidos o código OTP incorrecto')
    @cards_ns.response(403, 'No autorizado')
    @cards_ns.response(404, 'Tarjeta no encontrada')
    @cards_ns.response(410, 'Código OTP expirado')
    @token_required
    def post(self):
        """
        Confirma y procesa un pago con tarjeta

        Completa una transacción con tarjeta de crédito:
        - Valida el código OTP proporcionado
        - Verifica que el código no haya expirado
        - Procesa el pago si la validación es exitosa
        - Retorna el comprobante de la transacción
        """
        data = api.payload
        card_id = data.get("card_id")
        amount = data.get("amount")
        otp_code = data.get("otp_code")

        user_id = g.user["id"]

        result, status_code = CardSecurityService.verify_otp_and_process_payment(
            user_id, card_id, amount, otp_code
        )

        if status_code != 200:
            api.abort(status_code, result.get("error", "Error desconocido"))

        return result, status_code


# Inicializar la base de datos al crear la aplicación
with app.app_context():
    init_db()

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8000, debug=True)
