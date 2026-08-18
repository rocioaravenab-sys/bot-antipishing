# 🛡️ Bot Anti-Phishing para Discord

Recibe una **captura de pantalla** (SMS, correo, WhatsApp, etc.), extrae la URL
por **OCR de texto** y por **código QR**, la analiza y responde con un veredicto
de riesgo. Pensado como herramienta **defensiva**: avisa y educa, no ataca.

> ℹ️ Este bot **no** inunda enlaces con datos basura ni realiza contraataques.
> Automatizar el envío masivo de datos a un servidor es un ataque de denegación
> de servicio (ilegal en la mayoría de países, incluso contra un phisher) y
> convertiría al bot en un arma si alguien le pasa una URL legítima. En su lugar,
> el bot detecta, avisa y te permite **reportar** el phishing a las bases de datos
> que sí lo tumban de forma legal.

## ¿Qué hace?

1. Detecta imágenes adjuntas en un mensaje.
2. Lee códigos **QR** (`pyzbar`) y hace **OCR** del texto (`pytesseract`).
3. Extrae las URLs candidatas.
4. Expande acortadores (`bit.ly`, etc.) **de forma segura** (solo peticiones HEAD,
   nunca envía datos) para revelar el destino real.
5. Aplica **heurísticas** (typosquatting, TLDs sospechosos, punycode, IPs,
   lenguaje de estafa…) y consulta **threat intelligence** opcional
   (Google Safe Browsing, URLhaus).
6. Responde con un **embed** 🔴/🟠/🟢 explicando las señales.

## Estructura

```
bot-antipishing/
├── bot.py                 # entrada: cliente de Discord y flujo principal
├── bot_ui.py              # construcción de los embeds de respuesta
├── config.py              # carga de variables de entorno
├── test_local.py          # probar el análisis SIN Discord
├── extractors/
│   ├── image_utils.py     # descarga/preprocesado de imagen
│   ├── ocr.py             # OCR + regex de URLs
│   └── qr.py              # decodificación de QR
└── analysis/
    ├── url_utils.py       # normalización + expansión segura de acortadores
    ├── heuristics.py      # reglas locales de detección
    ├── threat_intel.py    # Safe Browsing / URLhaus (opcionales)
    └── scanner.py         # orquestador + puntuación de riesgo
```

## Instalación

### 1. Dependencias del sistema (OCR + QR)

**macOS (Homebrew):**
```bash
brew install tesseract tesseract-lang zbar
```

**Ubuntu/Debian:**
```bash
sudo apt install tesseract-ocr tesseract-ocr-spa libzbar0
```

### 2. Entorno de Python

```bash
cd bot-antipishing
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

### 3. Configuración

```bash
cp .env.example .env
# edita .env y pega tu DISCORD_TOKEN
```

## Crear el bot en Discord (paso a paso)

1. Entra en <https://discord.com/developers/applications> → **New Application**.
2. Menú **Bot** → **Reset Token** → copia el token en `.env` (`DISCORD_TOKEN=`).
3. En **Bot**, activa **MESSAGE CONTENT INTENT** (imprescindible para leer adjuntos).
4. Menú **OAuth2 → URL Generator**:
   - *Scopes:* `bot`
   - *Bot Permissions:* `Read Messages/View Channels`, `Send Messages`,
     `Embed Links`, `Attach Files`, `Read Message History`.
5. Copia la URL generada, ábrela y añade el bot a tu servidor.

## Ejecutar

```bash
python bot.py
```

Sube una captura al canal y el bot responderá con el análisis.

## Probar sin Discord

```bash
python test_local.py ruta/a/tu/captura.png
```

## Threat intelligence (opcional pero recomendado)

Sin claves, el bot funciona solo con heurísticas. Para máxima precisión añade
en `.env`:

- **Google Safe Browsing** — <https://developers.google.com/safe-browsing>
- **URLhaus (abuse.ch)** — <https://urlhaus.abuse.ch/api/>

## Próximos pasos sugeridos

- Botón **"Reportar a PhishTank/Safe Browsing"** en el embed.
- Comando slash `/analizar <url>` para texto directo.
- Caché de resultados por URL para no repetir consultas.
- Registro de estadísticas (nº de estafas detectadas por servidor).
```
