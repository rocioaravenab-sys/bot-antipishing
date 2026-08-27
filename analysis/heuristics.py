"""Heurísticas locales de detección de phishing (sin llamadas externas)."""
from __future__ import annotations

import re

import tldextract

from .rules import COMMON_TARGETS, SUSPICIOUS_TLDS, scam_keywords
from .url_utils import get_domain, is_shortener, normalize

# COMMON_TARGETS y SUSPICIOUS_TLDS ahora viven en 'analysis/data/*.json'
# (cargados por 'analysis/rules.py'). No los redefinas aquí.

_PUNYCODE_RE = re.compile(r"xn--", re.IGNORECASE)
_IP_RE = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")
_VOWELS = set("aeiou")


def _longest_consonant_run(s: str) -> int:
    """Longitud de la racha más larga de consonantes seguidas."""
    best = run = 0
    for ch in s.lower():
        if ch.isalpha() and ch not in _VOWELS:
            run += 1
            best = max(best, run)
        else:
            run = 0
    return best


def _looks_random(core: str) -> bool:
    """Heurística de "dominio generado al azar" (p. ej. pasasteslntagbc).

    Conservadora para evitar falsos positivos: solo aplica a nombres largos
    (>= 10) con muy pocas vocales o rachas largas de consonantes.
    """
    core = core.lower()
    letters = [c for c in core if c.isalpha()]
    digits = [c for c in core if c.isdigit()]
    if not letters:
        return False
    # Mezcla de letras con varios dígitos: típico de dominios autogenerados
    # (p. ej. oro7x-16, x9k2a1). Las marcas legítimas rara vez usan 2+ dígitos.
    if len(digits) >= 2 and len(letters) >= 2:
        return True
    if len(core) < 10:
        return False
    vowel_ratio = sum(c in _VOWELS for c in letters) / len(letters)
    return vowel_ratio < 0.30 or _longest_consonant_run(core) >= 5


def _levenshtein(a: str, b: str) -> int:
    if a == b:
        return 0
    if not a:
        return len(b)
    if not b:
        return len(a)
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]


def analyze_url(url: str) -> list[str]:
    """Devuelve una lista de señales sospechosas encontradas en la URL."""
    signals: list[str] = []
    url = normalize(url)
    domain = get_domain(url)
    ext = tldextract.extract(url)

    if is_shortener(url):
        signals.append(f"Usa un acortador de URLs ({domain}) que oculta el destino real.")

    if _IP_RE.match(ext.domain or "") or _IP_RE.match(domain):
        signals.append("El enlace apunta a una dirección IP en lugar de un dominio.")

    if _PUNYCODE_RE.search(domain):
        signals.append("El dominio usa punycode (xn--), técnica común de suplantación visual.")

    if ext.suffix.split(".")[-1].lower() in SUSPICIOUS_TLDS:
        signals.append(f"Dominio de nivel superior sospechoso: .{ext.suffix}")

    if domain.count("-") >= 3:
        signals.append("El dominio tiene muchos guiones (patrón común en phishing).")

    if len(domain) > 40:
        signals.append("Nombre de dominio inusualmente largo.")

    core = (ext.domain or "").lower()
    if core and not is_shortener(url) and _looks_random(core):
        signals.append(
            f"El dominio '{core}' parece generado al azar (patrón típico de phishing)."
        )

    # Subdominio que imita una marca: p.ej. paypal.seguro-login.com
    labels = domain.split(".")
    core = (ext.domain or "").lower()
    # No evaluamos typosquatting sobre acortadores conocidos (bit.ly, t.co…),
    # cuyo dominio corto genera falsos positivos (bit≈bcp, etc.).
    check_targets = not is_shortener(url)
    for target in COMMON_TARGETS:
        if target in labels[:-2]:  # aparece como subdominio, no como dominio raíz
            signals.append(
                f"Menciona '{target}' en un subdominio; el dominio real es '{ext.domain}.{ext.suffix}'."
            )
            break
        # Typosquatting: dominio muy parecido pero no igual. Exigimos nombres
        # de longitud razonable y similar para evitar coincidencias espurias.
        if (
            check_targets
            and len(core) >= 4
            and len(target) >= 4
            and abs(len(core) - len(target)) <= 2
            and 0 < _levenshtein(core, target) <= 2
        ):
            signals.append(
                f"El dominio '{core}' se parece mucho a '{target}' (posible typosquatting)."
            )
            break

    if "@" in url:
        signals.append("La URL contiene '@' (puede redirigir a un host distinto al que aparenta).")

    return signals


def scam_keyword_hits(text: str, langs: tuple[str, ...] | None = ("es",)) -> list[str]:
    """Devuelve las palabras/expresiones de estafa encontradas en el texto.

    'langs' selecciona los idiomas del diccionario (ver 'analysis/data/scam_keywords.json').
    Por ahora el default es solo español; la v2.B4 lo ampliará a ('es', 'pt').
    """
    low = text.lower()
    return [kw for kw in scam_keywords(langs) if kw in low]


def analyze_text(text: str) -> list[str]:
    """Detecta lenguaje de estafa en el texto OCR del mensaje."""
    hits = scam_keyword_hits(text)
    if hits:
        return [f"Lenguaje típico de estafa detectado: {', '.join(hits[:5])}."]
    return []
