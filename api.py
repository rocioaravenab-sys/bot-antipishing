"""API REST del motor anti-phishing (para la app móvil).

Reutiliza el mismo pipeline que el bot de Discord. Las imágenes se procesan en
memoria y NO se almacenan.

Arranque local:  uvicorn api:app --reload
Producción:      uvicorn api:app --host 0.0.0.0 --port $PORT
"""
from __future__ import annotations

import logging

from fastapi import FastAPI, File, Header, HTTPException, Request, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

import config
from analysis.rules import ruleset_payload
from analysis.serialize import report_to_dict
from analysis.version import ENGINE_VERSION, RULES_VERSION
from pipeline import analyze_image_bytes, analyze_text
from ratelimit import RateLimiter

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger("antiphishing-api")

app = FastAPI(title="Anti-Phishing API", version="1.0")

# CORS abierto: la app móvil (y opcionalmente la web) consumen esta API.
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

_MAX_IMAGE_BYTES = 15 * 1024 * 1024  # 15 MB

# Rate limiting por X-Install-Id (o IP). Se puede desactivar con RATE_LIMIT=false.
_rl_analyze = RateLimiter(config.RL_ANALYZE_PER_MIN, 60, enabled=config.RATE_LIMIT)
_rl_text = RateLimiter(config.RL_TEXT_PER_MIN, 60, enabled=config.RATE_LIMIT)
_rl_rules = RateLimiter(config.RL_RULES_PER_HOUR, 3600, enabled=config.RATE_LIMIT)


def _check_key(x_api_key: str | None) -> None:
    """Valida el header X-API-Key si hay una clave configurada."""
    if config.API_KEY and x_api_key != config.API_KEY:
        raise HTTPException(status_code=401, detail="API key inválida o ausente.")


@app.get("/health")
def health() -> dict:
    return {"ok": True, "engine_version": ENGINE_VERSION, "rules_version": RULES_VERSION}


@app.get("/rules")
def rules(request: Request) -> dict:
    """Reglas de detección (listas + versión) para el motor offline de la app.

    La app las cachea y las usa cuando no hay conexión; así el chequeo local usa
    exactamente los mismos datos que el servidor. Ver 'analysis/rules.py'.
    """
    _rl_rules.check(request)
    return ruleset_payload()


@app.post("/analyze")
async def analyze(
    request: Request,
    image: UploadFile = File(...),
    x_api_key: str | None = Header(default=None),
) -> dict:
    """Analiza una captura (SMS/correo/mensaje) y devuelve el veredicto."""
    _rl_analyze.check(request)
    _check_key(x_api_key)
    data = await image.read()
    if not data:
        raise HTTPException(status_code=400, detail="Imagen vacía.")
    if len(data) > _MAX_IMAGE_BYTES:
        raise HTTPException(status_code=413, detail="La imagen es demasiado grande.")
    try:
        report = analyze_image_bytes(data)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except Exception:
        log.exception("Error analizando imagen")
        raise HTTPException(status_code=500, detail="Error al analizar la imagen.")
    return report_to_dict(report)


class TextIn(BaseModel):
    texto: str


@app.post("/analyze-text")
def analyze_text_endpoint(
    body: TextIn,
    request: Request,
    x_api_key: str | None = Header(default=None),
) -> dict:
    """Analiza una URL o mensaje en texto plano."""
    _rl_text.check(request)
    _check_key(x_api_key)
    texto = body.texto.strip()
    if not texto:
        raise HTTPException(status_code=400, detail="Texto vacío.")
    report = analyze_text(texto)
    return report_to_dict(report)
