"""Carga las reglas de detección desde 'analysis/data/*.json'.

Estos archivos JSON son la **fuente canónica** de las listas que antes estaban
hardcodeadas en 'heuristics.py' y 'url_utils.py'. La API los expone en
'GET /rules' para que el motor offline de la app móvil use exactamente los
mismos datos (ver 'packages/rules' en el monorepo 'agente-anti-spam').

Regla de oro: si cambias una lista, cámbiala aquí (en el JSON), no en el código.
"""
from __future__ import annotations

import hashlib
import json
from functools import lru_cache
from pathlib import Path

DATA_DIR = Path(__file__).resolve().parent / "data"


def _load(name: str) -> dict:
    with (DATA_DIR / name).open(encoding="utf-8") as fh:
        return json.load(fh)


_TLDS_RAW = _load("suspicious_tlds.json")
_SHORTENERS_RAW = _load("shorteners.json")
_SCAM_RAW = _load("scam_keywords.json")
_BRANDS_RAW = _load("brands.json")

# --- Listas simples -------------------------------------------------------------

SUSPICIOUS_TLDS: set[str] = {t.lower() for t in _TLDS_RAW["tlds"]}
SHORTENER_DOMAINS: set[str] = {d.lower() for d in _SHORTENERS_RAW["domains"]}

# --- Idiomas de palabras de estafa -------------------------------------------

SCAM_LANGS: tuple[str, ...] = tuple(k for k in _SCAM_RAW if not k.startswith("_"))


def scam_keywords(langs: tuple[str, ...] | list[str] | None = None) -> list[str]:
    """Palabras/expresiones de estafa para los idiomas pedidos (por defecto, todos)."""
    langs = tuple(langs) if langs else SCAM_LANGS
    out: list[str] = []
    seen: set[str] = set()
    for lang in langs:
        for kw in _SCAM_RAW.get(lang, []):
            k = kw.lower()
            if k not in seen:
                seen.add(k)
                out.append(k)
    return out


# Compat: el comportamiento histórico solo consideraba español.
SCAM_KEYWORDS: list[str] = scam_keywords(("es",))

# --- Marcas / lista blanca ----------------------------------------------------

BRANDS: list[dict] = _BRANDS_RAW["brands"]


def _tokens_for_labels() -> set[str]:
    """Tokens de una sola palabra aptos para comparar contra etiquetas de dominio."""
    toks: set[str] = set()
    for b in BRANDS:
        for name in [b["brand"], *b.get("aliases", [])]:
            n = name.lower().strip()
            if n and " " not in n and "-" not in n and "." not in n:
                toks.add(n)
    return toks


# Compat con 'heuristics.analyze_url': set plano de marcas suplantables.
COMMON_TARGETS: set[str] = _tokens_for_labels()

# Todos los dominios oficiales conocidos (para la lista blanca).
OFFICIAL_DOMAINS: set[str] = {
    d.lower() for b in BRANDS for d in b.get("official_domains", [])
}


def _domain_matches(domain: str, official: str) -> bool:
    """True si 'domain' es el dominio oficial o un subdominio suyo."""
    domain = domain.lower().strip(".")
    official = official.lower().strip(".")
    return domain == official or domain.endswith("." + official)


@lru_cache(maxsize=2048)
def official_brand_for_domain(domain: str) -> dict | None:
    """Devuelve la marca cuyo dominio oficial cubre 'domain', o None."""
    if not domain:
        return None
    for b in BRANDS:
        for official in b.get("official_domains", []):
            if _domain_matches(domain, official):
                return b
    return None


def brands_mentioned_in_text(text: str) -> list[dict]:
    """Marcas (con dominios oficiales) nombradas en el texto del mensaje."""
    low = (text or "").lower()
    hits: list[dict] = []
    for b in BRANDS:
        if not b.get("official_domains"):
            continue  # tokens genéricos no cuentan como "suplantación de marca"
        names = [b["brand"], b.get("display", ""), *b.get("aliases", [])]
        if any(n and n.lower() in low for n in names):
            hits.append(b)
    return hits


# --- Versión de las reglas --------------------------------------------------

def _rules_version() -> str:
    h = hashlib.sha256()
    for name in sorted(("suspicious_tlds.json", "shorteners.json",
                        "scam_keywords.json", "brands.json")):
        h.update((DATA_DIR / name).read_bytes())
    return h.hexdigest()[:12]


RULES_VERSION: str = _rules_version()


def ruleset_payload() -> dict:
    """Payload para 'GET /rules' — consumido por el motor offline de la app."""
    return {
        "version": RULES_VERSION,
        "tlds": sorted(SUSPICIOUS_TLDS),
        "shorteners": sorted(SHORTENER_DOMAINS),
        "brands": BRANDS,
        "scam_keywords": {lang: _SCAM_RAW.get(lang, []) for lang in SCAM_LANGS},
    }
