# app/db.py
import os
import psycopg2

# Variables de entorno (docker-compose o locales)
DB_HOST = os.environ.get('POSTGRES_HOST', 'db')
DB_PORT = os.environ.get('POSTGRES_PORT', '5432')
DB_NAME = os.environ.get('POSTGRES_DB', 'corebank')
DB_USER = os.environ.get('POSTGRES_USER', 'postgres')
DB_PASSWORD = os.environ.get('POSTGRES_PASSWORD', 'postgres')

def get_connection():
    conn = psycopg2.connect(
        host=DB_HOST,
        port=DB_PORT,
        dbname=DB_NAME,
        user=DB_USER,
        password=DB_PASSWORD
    )
    return conn

def init_db():
    conn = get_connection()
    cur = conn.cursor()
    
    try:
        # Crear esquema bank si no existe
        cur.execute("CREATE SCHEMA IF NOT EXISTS bank AUTHORIZATION postgres;")

        # Crear tabla de usuarios
        cur.execute("""
        CREATE TABLE IF NOT EXISTS bank.users (
            id SERIAL PRIMARY KEY,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            role TEXT NOT NULL,
            full_name TEXT,
            email TEXT
        );
        """)

        # Crear tabla de cuentas
        cur.execute("""
        CREATE TABLE IF NOT EXISTS bank.accounts (
            id SERIAL PRIMARY KEY,
            balance NUMERIC NOT NULL DEFAULT 0,
            user_id INTEGER REFERENCES bank.users(id)
        );
        """)

        # Crear tabla de tarjetas de crédito
        cur.execute("""
        CREATE TABLE IF NOT EXISTS bank.credit_cards (
            id SERIAL PRIMARY KEY,
            limit_credit NUMERIC NOT NULL DEFAULT 5000,
            balance NUMERIC NOT NULL DEFAULT 0,
            user_id INTEGER REFERENCES bank.users(id)
        );
        """)

        # Crear tabla de clientes (información personal separada)
        cur.execute("""
        CREATE TABLE IF NOT EXISTS bank.clients (
            id SERIAL PRIMARY KEY,
            first_name TEXT NOT NULL,
            last_name TEXT NOT NULL,
            address TEXT NOT NULL,
            cedula TEXT UNIQUE NOT NULL,
            phone TEXT NOT NULL,
            registration_ip INET,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            user_id INTEGER REFERENCES bank.users(id)
        );
        """)

        # Crear tabla de cajeros (sin información personal, solo OTP)
        cur.execute("""
        CREATE TABLE IF NOT EXISTS bank.cashiers (
            id SERIAL PRIMARY KEY,
            otp_secret TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            user_id INTEGER REFERENCES bank.users(id)
        );
        """)

        # Crear esquema y tabla de logs personalizado
        cur.execute("CREATE SCHEMA IF NOT EXISTS logs AUTHORIZATION postgres;")
        
        cur.execute("""
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
        """)

        # Crear índices para logs
        cur.execute("""
        CREATE INDEX IF NOT EXISTS idx_logs_timestamp 
        ON logs.application_logs(timestamp);
        """)
        
        cur.execute("""
        CREATE INDEX IF NOT EXISTS idx_logs_level 
        ON logs.application_logs(log_level);
        """)
        
        cur.execute("""
        CREATE INDEX IF NOT EXISTS idx_logs_username 
        ON logs.application_logs(username);
        """)

        conn.commit()

        # Insertar datos de ejemplo si no existen usuarios
        cur.execute("SELECT COUNT(*) FROM bank.users;")
        count = cur.fetchone()[0]
        if count == 0:
            sample_users = [
                ('user1', 'pass1', 'cliente', 'Usuario Uno', 'user1@example.com'),
                ('user2', 'pass2', 'cliente', 'Usuario Dos', 'user2@example.com'),
                ('user3', 'pass3', 'cajero',  'Usuario Tres', 'user3@example.com')
            ]
            for username, password, role, full_name, email in sample_users:
                cur.execute("""
                    INSERT INTO bank.users (username, password, role, full_name, email)
                    VALUES (%s, %s, %s, %s, %s) RETURNING id;
                """, (username, password, role, full_name, email))
                user_id = cur.fetchone()[0]
                # Crear cuenta bancaria con saldo inicial 1000
                cur.execute("""
                    INSERT INTO bank.accounts (balance, user_id)
                    VALUES (%s, %s);
                """, (1000, user_id))
                # Crear tarjeta de crédito
                cur.execute("""
                    INSERT INTO bank.credit_cards (limit_credit, balance, user_id)
                    VALUES (%s, %s, %s);
                """, (5000, 0, user_id))
            conn.commit()

    except Exception as e:
        print(f"Error inicializando la base de datos: {e}")
        conn.rollback()
    finally:
        cur.close()
        conn.close()
    conn.close()
