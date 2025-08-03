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

# Configuración logging
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
    'Bearer': {
        'type': 'apiKey',
        'in': 'header',
        'name': 'Authorization',
        'description': "Ingresa tu token en formato **Bearer <token>**"
    }
}

app = Flask(__name__)
api = Api(
    app,
    version='1.0',
    title='Core Bancario API',
    description='API para operaciones bancarias, incluyendo autenticación y operaciones de cuenta.',
    doc='/swagger',
    authorizations=authorizations,
    security='Bearer'
)

# Namespaces
auth_ns = api.namespace('auth', description='Operaciones de autenticación')
bank_ns = api.namespace('bank', description='Operaciones bancarias')

# Crear modelos Swagger
models = create_swagger_models(auth_ns, bank_ns)

# Endpoint login con JWT
@auth_ns.route('/login')
class Login(Resource):
    @auth_ns.expect(models['login_model'], validate=True)
    @auth_ns.doc('login')
    def post(self):
        data = api.payload
        username = data.get("username", "")
        password = data.get("password", "")
        
        result, status_code = AuthService.login(username, password)
        
        if status_code != 200:
            api.abort(status_code, result.get("error", "Error desconocido"))
        
        return result, status_code

# Endpoint de registro de cliente
@auth_ns.route('/change-password')
class Register(Resource):
    @auth_ns.expect(models['change_password'], validate=True)
    @auth_ns.doc('change_password')
    def post(self):
        """Actualizar la contraseña de un cliente ya registrado"""
        data = api.payload
        
        result, status_code = AuthService.update_password(data)
        
        if status_code != 201:
            api.abort(status_code, result.get("error", "Error desconocido"))
        
        return result, status_code

# Endpoint de registro de cliente
@auth_ns.route('/register')
class Register(Resource):
    @auth_ns.expect(models['register_model'], validate=True)
    @auth_ns.doc('register')
    def post(self):
        """Registra un nuevo cliente con validaciones de seguridad completas"""
        data = api.payload
        
        result, status_code = AuthService.register(data)
        
        if status_code != 201:
            api.abort(status_code, result.get("error", "Error desconocido"))
        
        return result, status_code

# Endpoints bancarios protegidos por token_required
@bank_ns.route('/deposit')
class Deposit(Resource):
    @bank_ns.expect(models['deposit_model'], validate=True)
    @bank_ns.doc('deposit')
    @token_required
    def post(self):
        data = api.payload
        account_number = data.get("account_number")
        amount = data.get("amount", 0)
        
        result, status_code = BankService.deposit(account_number, amount)
        
        if status_code != 200:
            api.abort(status_code, result.get("error", "Error desconocido"))
        
        return result, status_code

@bank_ns.route('/withdraw')
class Withdraw(Resource):
    @bank_ns.expect(models['withdraw_model'], validate=True)
    @bank_ns.doc('withdraw')
    @token_required
    def post(self):
        """Realiza un retiro de la cuenta del usuario autenticado."""
        data = api.payload
        amount = data.get("amount", 0)
        
        result, status_code = BankService.withdraw(amount)
        
        if status_code != 200:
            api.abort(status_code, result.get("error", "Error desconocido"))
        
        return result, status_code

@bank_ns.route('/transfer')
class Transfer(Resource):
    @bank_ns.expect(models['transfer_model'], validate=True)
    @bank_ns.doc('transfer')
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

@bank_ns.route('/credit-payment')
class CreditPayment(Resource):
    @bank_ns.expect(models['credit_payment_model'], validate=True)
    @bank_ns.doc('credit_payment')
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

@bank_ns.route('/pay-credit-balance')
class PayCreditBalance(Resource):
    @bank_ns.expect(models['pay_credit_balance_model'], validate=True)
    @bank_ns.doc('pay_credit_balance')
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

# Inicializar la base de datos al crear la aplicación
with app.app_context():
    init_db()

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8000, debug=True)
