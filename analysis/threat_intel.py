"""Consultas a servicios de threat intelligence (opcionales según API keys).

Todas las funciones fallan de forma segura: si no hay clave o hay error de
red, devuelven None (desconocido) en lugar de romper el análisis.
"""
from __future__ import annotations

import requests

import config


def check_google_safe_browsing(url: str) -> bool | None:
    """True = marcado como malicioso; False = limpio; None = sin datos/clave."""
    if not config.GOOGLE_SAFE_BROWSING_API_KEY:
        return None

    endpoint = (
        "https://safebrowsing.googleapis.com/v4/threatMatches:find"
        f"?key={config.GOOGLE_SAFE_BROWSING_API_KEY}"
    )
    payload = {
        "client": {"clientId": "anti-phishing-bot", "clientVersion": "1.0"},
        "threatInfo": {
            "threatTypes": [
                "MALWARE", "SOCIAL_ENGINEERING",
                "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION",
            ],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}],
        },
    }
    try:
        resp = requests.post(endpoint, json=payload, timeout=config.REQUEST_TIMEOUT)
        resp.raise_for_status()
        data = resp.json()
        return bool(data.get("matches"))
    except requests.RequestException:
        return None


def check_urlhaus(url: str) -> dict | None:
    """Consulta URLhaus (abuse.ch). Devuelve dict con info o None."""
    if not config.URLHAUS_AUTH_KEY:
        return None
    try:
        resp = requests.post(
            "https://urlhaus-api.abuse.ch/v1/url/",
            data={"url": url},
            headers={"Auth-Key": config.URLHAUS_AUTH_KEY},
            timeout=config.REQUEST_TIMEOUT,
        )
        resp.raise_for_status()
        data = resp.json()
        if data.get("query_status") == "ok":
            return {
                "threat": data.get("threat"),
                "status": data.get("url_status"),
                "tags": data.get("tags"),
            }
        return None
    except requests.RequestException:
        return None


def gather(url: str) -> list[str]:
    """Ejecuta todas las fuentes disponibles y devuelve señales legibles."""
    signals: list[str] = []

    gsb = check_google_safe_browsing(url)
    if gsb is True:
        signals.append("⛔ Google Safe Browsing lo marca como malicioso.")

    uh = check_urlhaus(url)
    if uh:
        tags = ", ".join(uh.get("tags") or []) or "sin etiquetas"
        signals.append(f"⛔ Listado en URLhaus (amenaza: {uh.get('threat')}, tags: {tags}).")

    return signals
