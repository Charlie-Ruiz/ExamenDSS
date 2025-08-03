# Usar imagen base de Python 3.10-slim
FROM python:3.10-slim

# Establecer el directorio de trabajo
WORKDIR /app

# Instalar dependencias del sistema (gcc, libpq-dev para compilar psycopg2)
RUN apt-get update && apt-get install -y gcc libpq-dev && rm -rf /var/lib/apt/lists/*

# Copiar archivo de requerimientos e instalar dependencias Python
COPY requirements.txt .
RUN pip install --upgrade pip && pip install --no-cache-dir -r requirements.txt

# Copiar el código de la aplicación y archivo de configuración
COPY app/ ./app/
COPY .env .

# Exponer el puerto 8000
EXPOSE 8000

# Ejecutar la aplicación con Gunicorn (4 workers)
CMD ["gunicorn", "-w", "4", "-b", "0.0.0.0:8000", "app.main:app"]