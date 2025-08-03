"""
Modelos Swagger para la documentación de la API
"""
from flask_restx import fields

def create_swagger_models(auth_ns, bank_ns):
    """Crea y retorna todos los modelos Swagger"""
    
    login_model = auth_ns.model('Login', {
        'username': fields.String(required=True, description='Nombre de usuario', example='user1'),
        'password': fields.String(required=True, description='Contraseña', example='pass1')
    })

    change_password_model = auth_ns.model('Change_password', {
        'username': fields.String(required=True, description='Nombre de usuario', example='user1'),
        'current_password': fields.String(required=True, description='Contraseña actual', example='pass1'),
        'new_password': fields.String(required=True, description='Contraseña nueva', example='pass1')
    })

    register_model = auth_ns.model('Register', {
        'first_name': fields.String(required=True, description='Nombres', example='Juan Carlos'),
        'last_name': fields.String(required=True, description='Apellidos', example='Pérez García'),
        'address': fields.String(required=True, description='Dirección', example='Av. Principal 123, Quito'),
        'cedula': fields.String(required=True, description='Cédula de identidad', example='1234567890'),
        'phone': fields.String(required=True, description='Número celular', example='0987654321'),
        'username': fields.String(required=True, description='Nombre de usuario (solo letras y números)', example='user123'),
        'password': fields.String(required=True, description='Contraseña (mín. 8 caracteres, números, letras y símbolos)', example='MyPass123!'),
        'email': fields.String(required=True, description='Correo electrónico', example='user@example.com')
    })

    deposit_model = bank_ns.model('Deposit', {
        'account_number': fields.Integer(required=True, description='Número de cuenta', example=123),
        'amount': fields.Float(required=True, description='Monto a depositar', example=100)
    })

    withdraw_model = bank_ns.model('Withdraw', {
        'amount': fields.Float(required=True, description='Monto a retirar', example=100)
    })

    transfer_model = bank_ns.model('Transfer', {
        'target_username': fields.String(required=True, description='Usuario destino', example='user2'),
        'amount': fields.Float(required=True, description='Monto a transferir', example=100)
    })

    credit_payment_model = bank_ns.model('CreditPayment', {
        'amount': fields.Float(required=True, description='Monto de la compra a crédito', example=100)
    })

    pay_credit_balance_model = bank_ns.model('PayCreditBalance', {
        'amount': fields.Float(required=True, description='Monto a abonar a la deuda de la tarjeta', example=50)
    })
    
    return {
        'login_model': login_model,
        'change_password': change_password_model,
        'register_model': register_model,
        'deposit_model': deposit_model,
        'withdraw_model': withdraw_model,
        'transfer_model': transfer_model,
        'credit_payment_model': credit_payment_model,
        'pay_credit_balance_model': pay_credit_balance_model
    }
