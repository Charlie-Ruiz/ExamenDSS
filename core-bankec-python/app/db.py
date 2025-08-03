# app/db.py
import os
import psycopg2

# Variables de entorno (docker-compose o locales)
DB_HOST = os.environ.get('POSTGRES_HOST', 'localhost')
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
        # Verificar y crear esquema bank si no existe
        cur.execute("""
            SELECT 1 FROM information_schema.schemata 
            WHERE schema_name = 'bank'
        """)
        
        if not cur.fetchone():
            cur.execute("CREATE SCHEMA bank AUTHORIZATION postgres;")
            print("Esquema 'bank' creado exitosamente")
        else:
            print("Esquema 'bank' ya existe, continuando...")

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

        # Crear tabla de cajeros (sin información personal, solo OTP)
        cur.execute("""
        CREATE TABLE IF NOT EXISTS bank.cashiers (
            id SERIAL PRIMARY KEY,
            otp_secret TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            user_id INTEGER REFERENCES bank.users(id)
        );
        """)

        # El esquema y tabla de logs se crean en el middleware de logging
        # para evitar duplicación y conflictos

        # Crear esquema separado para información sensible de tarjetas
        cur.execute("""
            SELECT 1 FROM information_schema.schemata 
            WHERE schema_name = 'cards'
        """)
        
        if not cur.fetchone():
            cur.execute("CREATE SCHEMA cards AUTHORIZATION postgres;")
            print("Esquema 'cards' creado exitosamente")
        else:
            print("Esquema 'cards' ya existe, continuando...")
        
        # Tabla para números de tarjeta registrados (repositorio separado)
        cur.execute("""
        CREATE TABLE IF NOT EXISTS cards.registered_cards (
            id SERIAL PRIMARY KEY,
            user_id INTEGER REFERENCES bank.users(id),
            card_number_encrypted TEXT NOT NULL,  -- Número completo encriptado
            card_first_six VARCHAR(6) NOT NULL,   -- Primeros 6 dígitos para validación
            card_last_four VARCHAR(4) NOT NULL,   -- Últimos 4 para mostrar enmascarado
            card_type VARCHAR(20),                -- VISA, MASTERCARD, etc.
            expiry_month INTEGER,
            expiry_year INTEGER,
            is_active BOOLEAN DEFAULT TRUE,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
        """)
        
        # Tabla para OTP temporal
        cur.execute("""
        CREATE TABLE IF NOT EXISTS cards.otp_tokens (
            id SERIAL PRIMARY KEY,
            user_id INTEGER REFERENCES bank.users(id),
            card_id INTEGER REFERENCES cards.registered_cards(id),
            otp_code VARCHAR(6) NOT NULL,
            amount NUMERIC NOT NULL,
            expires_at TIMESTAMP NOT NULL,
            is_used BOOLEAN DEFAULT FALSE,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
        """)
        
        # Tabla para auditoría de transacciones con tarjetas
        cur.execute("""
        CREATE TABLE IF NOT EXISTS cards.card_transactions (
            id SERIAL PRIMARY KEY,
            user_id INTEGER REFERENCES bank.users(id),
            card_id INTEGER REFERENCES cards.registered_cards(id),
            transaction_type VARCHAR(20) NOT NULL, -- 'PAYMENT', 'REGISTRATION'
            amount NUMERIC,
            status VARCHAR(20) NOT NULL,           -- 'SUCCESS', 'FAILED', 'PENDING'
            otp_used VARCHAR(6),
            ip_address INET,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
        """)

        # Crear índices para las nuevas tablas
        cur.execute("""
        CREATE INDEX IF NOT EXISTS idx_registered_cards_user 
        ON cards.registered_cards(user_id);
        """)
        
        cur.execute("""
        CREATE INDEX IF NOT EXISTS idx_otp_tokens_user 
        ON cards.otp_tokens(user_id);
        """)
        
        cur.execute("""
        CREATE INDEX IF NOT EXISTS idx_otp_tokens_expires 
        ON cards.otp_tokens(expires_at);
        """)

        # Los índices para logs se crean en el middleware de logging

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
