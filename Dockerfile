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

# Arranca el bot. El token se pasa por variable de entorno DISCORD_TOKEN.
CMD ["python", "bot.py"]
