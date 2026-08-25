# Imagen base estable con Python
FROM python:3.12-slim

# Dependencias del sistema: OCR (tesseract + español) y lectura de QR (zbar).
# libglib2.0-0 es requerida por opencv-python-headless.
RUN apt-get update && apt-get install -y --no-install-recommends \
        tesseract-ocr \
        tesseract-ocr-spa \
        libzbar0 \
        libglib2.0-0 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Instala primero las dependencias (mejor caché de capas).
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copia el resto del código.
COPY . .

# Por defecto arranca la API REST (que alimenta la app móvil). No necesita
# token. Railway inyecta la variable PORT.
# Si en el futuro se revive el bot de Discord, crear un servicio con
# Custom Start Command: python bot.py (y su variable DISCORD_TOKEN).
CMD ["sh", "-c", "uvicorn api:app --host 0.0.0.0 --port ${PORT:-8000}"]
