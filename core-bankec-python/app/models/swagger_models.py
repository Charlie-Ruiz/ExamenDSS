"""
Modelos Swagger para la documentación de la API
"""
from flask_restx import fields

def create_swagger_models(auth_ns, bank_ns, cards_ns):
    """Crea y retorna todos los modelos Swagger"""
    
    login_model = auth_ns.model('Login', {
        'username': fields.String(required=True, description='Nombre de usuario', example='user1'),
        'password': fields.String(required=True, description='Contraseña', example='pass1')
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

    # Modelos para el sistema de tarjetas seguro
    register_card_model = cards_ns.model('RegisterCard', {
        'card_number': fields.String(required=True, description='Número de tarjeta (16 dígitos)', example='4532015112830366'),
        'expiry_month': fields.Integer(required=True, description='Mes de expiración (1-12)', example=12),
        'expiry_year': fields.Integer(required=True, description='Año de expiración', example=2025)
    })

    verify_card_model = cards_ns.model('VerifyCard', {
        'card_id': fields.Integer(required=True, description='ID de la tarjeta registrada', example=1),
        'first_six_digits': fields.String(required=True, description='Primeros 6 dígitos de la tarjeta', example='453201')
    })

    request_otp_model = cards_ns.model('RequestOTP', {
        'card_id': fields.Integer(required=True, description='ID de la tarjeta registrada', example=1),
        'first_six_digits': fields.String(required=True, description='Primeros 6 dígitos para verificación', example='453201'),
        'amount': fields.Float(required=True, description='Monto a pagar', example=150.50)
    })

    confirm_payment_model = cards_ns.model('ConfirmPayment', {
        'card_id': fields.Integer(required=True, description='ID de la tarjeta registrada', example=1),
        'amount': fields.Float(required=True, description='Monto a pagar', example=150.50),
        'otp_code': fields.String(required=True, description='Código OTP de 6 dígitos', example='123456')
    })

    pay_credit_balance_model = bank_ns.model('PayCreditBalance', {
        'amount': fields.Float(required=True, description='Monto a abonar a la deuda de la tarjeta', example=50)
    })
    
    return {
        'login_model': login_model,
        'register_model': register_model,
        'deposit_model': deposit_model,
        'withdraw_model': withdraw_model,
        'transfer_model': transfer_model,
        'credit_payment_model': credit_payment_model,
        'pay_credit_balance_model': pay_credit_balance_model,
        'register_card_model': register_card_model,
        'verify_card_model': verify_card_model,
        'request_otp_model': request_otp_model,
        'confirm_payment_model': confirm_payment_model
    }
