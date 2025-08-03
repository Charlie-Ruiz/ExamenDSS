"""
Servicio bancario - maneja operaciones financieras
"""
import logging
from flask import g
from ..db import get_connection

class BankService:
    """Servicio para operaciones bancarias"""
    
    @staticmethod
    def deposit(account_number, amount):
        """Procesa un depósito a una cuenta específica"""
        if amount <= 0:
            return {"error": "El monto debe ser mayor a cero"}, 400

        conn = get_connection()
        cur = conn.cursor()
        
        try:
            cur.execute(
                "UPDATE bank.accounts SET balance = balance + %s WHERE id = %s RETURNING balance",
                (amount, account_number)
            )
            result = cur.fetchone()
            if not result:
                conn.rollback()
                return {"error": "Cuenta no encontrada"}, 404
                
            new_balance = float(result[0])
            conn.commit()
            
            return {"message": "Depósito exitoso", "new_balance": new_balance}, 200
            
        except Exception as e:
            conn.rollback()
            logging.error(f"Error en depósito: {str(e)}")
            return {"error": "Error interno del servidor"}, 500
        
        finally:
            cur.close()
            conn.close()
    
    @staticmethod
    def withdraw(amount):
        """Procesa un retiro de la cuenta del usuario autenticado"""
        if amount <= 0:
            return {"error": "El monto debe ser mayor a cero"}, 400
            
        user_id = g.user['id']
        conn = get_connection()
        cur = conn.cursor()
        
        try:
            cur.execute("SELECT balance FROM bank.accounts WHERE user_id = %s", (user_id,))
            row = cur.fetchone()
            if not row:
                return {"error": "Cuenta no encontrada"}, 404
                
            current_balance = float(row[0])
            if current_balance < amount:
                return {"error": "Fondos insuficientes"}, 400
                
            cur.execute("UPDATE bank.accounts SET balance = balance - %s WHERE user_id = %s RETURNING balance", (amount, user_id))
            new_balance = float(cur.fetchone()[0])
            conn.commit()
            
            return {"message": "Retiro exitoso", "new_balance": new_balance}, 200
            
        except Exception as e:
            conn.rollback()
            logging.error(f"Error en retiro: {str(e)}")
            return {"error": "Error interno del servidor"}, 500
        
        finally:
            cur.close()
            conn.close()
    
    @staticmethod
    def transfer(target_username, amount):
        """Transfiere fondos desde la cuenta del usuario autenticado a otra cuenta"""
        if not target_username or amount <= 0:
            return {"error": "Datos inválidos"}, 400
            
        if target_username == g.user['username']:
            return {"error": "No puedes transferir a tu misma cuenta"}, 400
            
        conn = get_connection()
        cur = conn.cursor()
        
        try:
            # Verifica balance del remitente
            cur.execute("SELECT balance FROM bank.accounts WHERE user_id = %s", (g.user['id'],))
            row = cur.fetchone()
            if not row:
                return {"error": "Cuenta del remitente no encontrada"}, 404
                
            sender_balance = float(row[0])
            if sender_balance < amount:
                return {"error": "Fondos insuficientes"}, 400
            
            # Busca cuenta destino
            cur.execute("SELECT id FROM bank.users WHERE username = %s", (target_username,))
            target_user = cur.fetchone()
            if not target_user:
                return {"error": "Usuario destino no encontrado"}, 404
                
            target_user_id = target_user[0]
            
            # Ejecutar transferencia
            cur.execute("UPDATE bank.accounts SET balance = balance - %s WHERE user_id = %s", (amount, g.user['id']))
            cur.execute("UPDATE bank.accounts SET balance = balance + %s WHERE user_id = %s", (amount, target_user_id))
            cur.execute("SELECT balance FROM bank.accounts WHERE user_id = %s", (g.user['id'],))
            new_balance = float(cur.fetchone()[0])
            conn.commit()
            
            return {"message": "Transferencia exitosa", "new_balance": new_balance}, 200
            
        except Exception as e:
            conn.rollback()
            logging.error(f"Error durante la transferencia: {str(e)}")
            return {"error": f"Error durante la transferencia: {str(e)}"}, 500
        
        finally:
            cur.close()
            conn.close()
    
    @staticmethod
    def credit_payment(amount):
        """Realiza una compra a crédito"""
        if amount <= 0:
            return {"error": "El monto debe ser mayor a cero"}, 400
            
        user_id = g.user['id']
        conn = get_connection()
        cur = conn.cursor()
        
        try:
            cur.execute("SELECT balance FROM bank.accounts WHERE user_id = %s", (user_id,))
            row = cur.fetchone()
            if not row:
                return {"error": "Cuenta no encontrada"}, 404
                
            account_balance = float(row[0])
            if account_balance < amount:
                return {"error": "Fondos insuficientes en cuenta"}, 400
            
            cur.execute("UPDATE bank.accounts SET balance = balance - %s WHERE user_id = %s", (amount, user_id))
            cur.execute("UPDATE bank.credit_cards SET balance = balance + %s WHERE user_id = %s", (amount, user_id))
            cur.execute("SELECT balance FROM bank.accounts WHERE user_id = %s", (user_id,))
            new_account_balance = float(cur.fetchone()[0])
            cur.execute("SELECT balance FROM bank.credit_cards WHERE user_id = %s", (user_id,))
            new_credit_balance = float(cur.fetchone()[0])
            conn.commit()
            
            return {
                "message": "Compra a crédito exitosa",
                "account_balance": new_account_balance,
                "credit_card_debt": new_credit_balance
            }, 200
            
        except Exception as e:
            conn.rollback()
            logging.error(f"Error procesando compra a crédito: {str(e)}")
            return {"error": f"Error procesando compra a crédito: {str(e)}"}, 500
        
        finally:
            cur.close()
            conn.close()
    
    @staticmethod
    def pay_credit_balance(amount):
        """Realiza un abono a la deuda de la tarjeta"""
        if amount <= 0:
            return {"error": "El monto debe ser mayor a cero"}, 400
            
        user_id = g.user['id']
        conn = get_connection()
        cur = conn.cursor()
        
        try:
            # Verifica fondos de la cuenta
            cur.execute("SELECT balance FROM bank.accounts WHERE user_id = %s", (user_id,))
            row = cur.fetchone()
            if not row:
                return {"error": "Cuenta no encontrada"}, 404
                
            account_balance = float(row[0])
            if account_balance < amount:
                return {"error": "Fondos insuficientes en cuenta"}, 400
            
            # Obtiene deuda actual de la tarjeta
            cur.execute("SELECT balance FROM bank.credit_cards WHERE user_id = %s", (user_id,))
            row = cur.fetchone()
            if not row:
                return {"error": "Tarjeta de crédito no encontrada"}, 404
                
            credit_debt = float(row[0])
            payment = min(amount, credit_debt)
            
            cur.execute("UPDATE bank.accounts SET balance = balance - %s WHERE user_id = %s", (payment, user_id))
            cur.execute("UPDATE bank.credit_cards SET balance = balance - %s WHERE user_id = %s", (payment, user_id))
            cur.execute("SELECT balance FROM bank.accounts WHERE user_id = %s", (user_id,))
            new_account_balance = float(cur.fetchone()[0])
            cur.execute("SELECT balance FROM bank.credit_cards WHERE user_id = %s", (user_id,))
            new_credit_debt = float(cur.fetchone()[0])
            conn.commit()
            
            return {
                "message": "Pago de deuda exitoso",
                "account_balance": new_account_balance,
                "credit_card_debt": new_credit_debt
            }, 200
            
        except Exception as e:
            conn.rollback()
            logging.error(f"Error procesando el abono: {str(e)}")
            return {"error": f"Error procesando el abono: {str(e)}"}, 500
        
        finally:
            cur.close()
            conn.close()
