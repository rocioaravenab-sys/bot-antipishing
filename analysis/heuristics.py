"""Heurísticas locales de detección de phishing (sin llamadas externas)."""
from __future__ import annotations

import ipaddress
import re

import tldextract

from .messages_es import t
from .rules import COMMON_TARGETS, SUSPICIOUS_TLDS, scam_keywords
from .url_utils import get_domain, is_shortener, normalize

# COMMON_TARGETS y SUSPICIOUS_TLDS ahora viven en 'analysis/data/*.json'
# (cargados por 'analysis/rules.py'). No los redefinas aquí.

_PUNYCODE_RE = re.compile(r"xn--", re.IGNORECASE)
_IP_RE = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")
_VOWELS = set("aeiou")

# Peso de cada señal de URL para el scoring (ver analysis/scanner.py:
# MEDIO = score >= 3, ALTO = score >= 6).
#
# Casi todas las señales pesan 2: por sí solas no bastan para "sospechoso".
# Un puñado de señales de ALTA CONFIANZA pesan 3 —una sola ya justifica MEDIO—
# porque en un mensaje de consumo casi nunca aparecen de forma legítima:
#   * enlace a una IP pública en vez de a un dominio
#   * dominio con punycode (xn--), típico de ataques homográficos
#   * TLD de la lista de abuso (.top / .xyz / .monster …)
#   * dominio con letras y dígitos intercalados (x7k2a9q1z4), firma de DGA
DEFAULT_SIGNAL_WEIGHT = 2
HIGH_CONFIDENCE_WEIGHT = 3


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


def _is_private_ip(host: str) -> bool:
    """True si 'host' es una IP no enrutable en internet (LAN, loopback,
    enlace local…). Un enlace a 192.168.x.x / 10.x / 127.0.0.1 es una
    dirección de red local, no infraestructura de phishing: la señal se emite
    igual (sigue siendo raro en un mensaje), pero no cuenta como alta confianza.
    """
    try:
        return not ipaddress.ip_address(host).is_global
    except ValueError:
        return False


def _looks_generated(core: str) -> bool:
    """Firma de nombre generado por máquina (DGA): letras y dígitos
    intercalados, p. ej. 'x7k2a9q1z4'. No marca un año pegado a una palabra
    ('taller2024') ni un prefijo numérico ('24horas'), donde los dígitos van
    en un solo bloque.
    """
    digits = sum(c.isdigit() for c in core)
    letters = sum(c.isalpha() for c in core)
    if digits < 2 or letters < 2:
        return False
    transitions = sum(
        1 for a, b in zip(core, core[1:])
        if a.isalnum() and b.isalnum() and a.isdigit() != b.isdigit()
    )
    return transitions >= 4


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


def _url_signals(url: str) -> list[tuple[str, int]]:
    """(texto de la señal, peso) de cada patrón sospechoso de la URL, en orden.

    Única ruta de detección: 'analyze_url' descarta el peso y 'analyze_url_signals'
    lo conserva para el scoring.
    """
    out: list[tuple[str, int]] = []
    url = normalize(url)
    domain = get_domain(url)
    ext = tldextract.extract(url)

    def add(key: str, weight: int = DEFAULT_SIGNAL_WEIGHT, **kw) -> None:
        out.append((t(key, **kw), weight))

    if is_shortener(url):
        add("url_shortener", domain=domain)

    ip_host = (ext.domain or "") if _IP_RE.match(ext.domain or "") else (
        domain if _IP_RE.match(domain) else "")
    if ip_host:
        # Una IP privada/loopback es red local, no infraestructura de phishing.
        add("url_ip", DEFAULT_SIGNAL_WEIGHT if _is_private_ip(ip_host)
            else HIGH_CONFIDENCE_WEIGHT)

    if _PUNYCODE_RE.search(domain):
        add("url_punycode", HIGH_CONFIDENCE_WEIGHT)

    if ext.suffix.split(".")[-1].lower() in SUSPICIOUS_TLDS:
        add("url_bad_tld", HIGH_CONFIDENCE_WEIGHT, suffix=ext.suffix)

    if domain.count("-") >= 3:
        add("url_many_hyphens")

    if len(domain) > 40:
        add("url_long")

    core = (ext.domain or "").lower()
    if core and not is_shortener(url) and _looks_random(core):
        # Solo es alta confianza si además es letras+dígitos intercalados (DGA);
        # 'chilexpress' o '24horas' disparan _looks_random pero no son phishing.
        add("url_random",
            HIGH_CONFIDENCE_WEIGHT if _looks_generated(core) else DEFAULT_SIGNAL_WEIGHT,
            core=core)

    # Subdominio que imita una marca: p.ej. paypal.seguro-login.com
    labels = domain.split(".")
    # No evaluamos typosquatting sobre acortadores conocidos (bit.ly, t.co…),
    # cuyo dominio corto genera falsos positivos (bit≈bcp, etc.).
    check_targets = not is_shortener(url)
    for target in COMMON_TARGETS:
        if target in labels[:-2]:  # aparece como subdominio, no como dominio raíz
            add("url_subdomain_brand", target=target, real=f"{ext.domain}.{ext.suffix}")
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
            add("url_typosquat", core=core, target=target)
            break

    if "@" in url:
        add("url_at")

    return out


def analyze_url_signals(url: str) -> list[tuple[str, int]]:
    """Señales sospechosas de la URL con su peso para el scoring (ver scanner).

    Casi todas pesan 2; las de alta confianza pesan 3 —una sola ya alcanza MEDIO.
    """
    return _url_signals(url)


def analyze_url(url: str) -> list[str]:
    """Devuelve una lista de señales sospechosas encontradas en la URL."""
    return [sig for sig, _weight in _url_signals(url)]


def scam_keyword_hits(text: str, langs: tuple[str, ...] | None = None) -> list[str]:
    """Devuelve las palabras/expresiones de estafa encontradas en el texto.

    'langs' selecciona los idiomas del diccionario (ver 'analysis/data/scam_keywords.json').
    Por defecto se usan todos los idiomas disponibles (hoy 'es' + 'pt'); las
    expresiones portuguesas son frases largas y no colisionan con el español.
    """
    low = text.lower()
    return [kw for kw in scam_keywords(langs) if kw in low]


def analyze_text(text: str) -> list[str]:
    """Detecta lenguaje de estafa en el texto OCR del mensaje."""
    hits = scam_keyword_hits(text)
    if hits:
        return [t("scam_language_inline", hits=", ".join(hits[:5]))]
    return []
