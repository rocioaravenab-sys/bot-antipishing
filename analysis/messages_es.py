"""Plantillas de los mensajes/señales que ve la persona usuaria — español.

Centralizadas para que añadir otro idioma sea crear 'messages_<lang>.py' con las
mismas claves. No hay librería i18n: 't(key, **kw)' devuelve la plantilla ya
formateada. El texto es idéntico al que estaba embebido en heuristics.py /
scanner.py (solo cambió de lugar).
"""
from __future__ import annotations

LOCALE = "es"

_M: dict[str, str] = {
    # --- heuristics.analyze_url -------------------------------------------
    "url_shortener": "Usa un acortador de URLs ({domain}) que oculta el destino real.",
    "url_ip": "El enlace apunta a una dirección IP en lugar de un dominio.",
    "url_punycode": "El dominio usa punycode (xn--), técnica común de suplantación visual.",
    "url_bad_tld": "Dominio de nivel superior sospechoso: .{suffix}",
    "url_many_hyphens": "El dominio tiene muchos guiones (patrón común en phishing).",
    "url_long": "Nombre de dominio inusualmente largo.",
    "url_random": "El dominio '{core}' parece generado al azar (patrón típico de phishing).",
    "url_subdomain_brand": "Menciona '{target}' en un subdominio; el dominio real es '{real}'.",
    "url_typosquat": "El dominio '{core}' se parece mucho a '{target}' (posible typosquatting).",
    "url_at": "La URL contiene '@' (puede redirigir a un host distinto al que aparenta).",
    # --- heuristics.analyze_text / scanner ------------------------------
    "scam_language_inline": "Lenguaje típico de estafa detectado: {hits}.",
    "scam_language_msg": "El mensaje usa lenguaje típico de estafa: {hits}.",
    # --- scanner --------------------------------------------------------
    "redirects_to": "Redirige a: {url}",
    "brand_mismatch": "El mensaje dice ser de {brands}, pero el enlace NO lleva a ese sitio.",
    "brand_mismatch_item": "'{display}' (su sitio real es {domain})",
    "reassurance_official": "El enlace lleva al sitio oficial de {who}.",
}


def t(key: str, **kw) -> str:
    """Plantilla formateada. Sin kwargs devuelve la plantilla tal cual."""
    return _M[key].format(**kw) if kw else _M[key]
