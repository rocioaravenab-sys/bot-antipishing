"""OCR de texto + extracción de URLs de la imagen."""
from __future__ import annotations

import re

from urllib.parse import urlparse

import pytesseract
import tldextract

from analysis.url_utils import is_shortener, normalize
from .image_utils import bytes_to_cv2, color_pil_for_ocr, preprocess_for_ocr


def get_path(url: str) -> str:
    """Devuelve la ruta de la URL (para detectar acortadores sin código)."""
    return urlparse(normalize(url)).path

# Captura URLs con esquema (https://...) o dominios "desnudos" (ejemplo.com/x).
_URL_RE = re.compile(
    r"(https?://[^\s<>\"']+|(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,24}(?:/[^\s<>\"']*)?)",
    re.IGNORECASE,
)

# Caracteres válidos al final de una URL; el resto se recorta.
_TRAILING = ".,);]}>\"'"


# Varias pasadas de OCR; se unen los resultados para maximizar la recuperación.
# - color + PSM 6/11: recupera enlaces azules y líneas que el modo automático
#   descarta cuando hay varios globos de chat.
# - umbral + PSM 3: refuerza el texto normal y ayuda con dígitos (4 vs A).
_OCR_PASSES = (
    ("color", "--psm 6"),
    ("color", "--psm 11"),
    ("thresh", "--psm 3"),
)


def _ocr_variants(image_bytes: bytes) -> list[str]:
    """Ejecuta todas las pasadas de OCR y devuelve el texto de cada una."""
    img = bytes_to_cv2(image_bytes)
    variants = {"color": color_pil_for_ocr(img), "thresh": preprocess_for_ocr(img)}

    texts: list[str] = []
    for variant, config in _OCR_PASSES:
        try:
            texts.append(
                pytesseract.image_to_string(variants[variant], lang="spa+eng", config=config)
            )
        except pytesseract.TesseractError:
            continue
    return texts


def extract_text(image_bytes: bytes) -> str:
    """OCR multi-pasada (español + inglés). Devuelve el texto de todas unido."""
    return "\n".join(_ocr_variants(image_bytes))


def _join_wrapped_urls(text: str) -> str:
    """Une una URL partida en dos líneas (típico en capturas de móvil).

    En las capturas la URL suele romperse justo tras una '/', p. ej.:
        adicionales: https://bit.ly/
        4vzyzPo?h0sd
    Se añade SOLO el primer token de la siguiente línea no vacía, de modo que
    no se arrastre el texto posterior ("+ Mensaje de texto", etc.).
    """
    lines = text.splitlines()
    out: list[str] = []
    i = 0
    while i < len(lines):
        line = lines[i].rstrip()
        # ¿La línea termina con un fragmento de URL acabado en '/'? Toleramos
        # errores de OCR en el esquema (p. ej. 'nitps://') exigiendo solo que
        # termine en 'dominio.tld/'.
        if re.search(r"[A-Za-z0-9][\w.-]*\.[A-Za-z]{2,10}/\s*$", line):
            j = i + 1
            while j < len(lines) and not lines[j].strip():
                j += 1
            if j < len(lines):
                cont = lines[j].strip().split()[0]
                line += cont
                i = j  # consumimos la línea de continuación
        out.append(line)
        i += 1
    return "\n".join(out)


def _looks_like_real_domain(candidate: str) -> bool:
    """Filtra basura del OCR: exige un TLD real (según la Public Suffix List),
    o bien un host que sea una IP literal — un enlace a IP es señal de phishing
    y debe llegar al análisis, no descartarse aquí."""
    ext = tldextract.extract(candidate)
    if ext.ipv4:
        return True
    if not (ext.domain and ext.suffix):
        return False
    # Descarta acortadores con código ausente o demasiado corto (p. ej.
    # 'bit.ly/' o 'bit.ly/ls'): son ruido de OCR. Los códigos reales son largos.
    if is_shortener(candidate) and len(get_path(candidate).strip("/")) < 4:
        return False
    return True


def find_urls_in_text(text: str) -> list[str]:
    """Extrae URLs candidatas válidas de un bloque de texto."""
    joined = _join_wrapped_urls(text)
    found: set[str] = set()
    for m in _URL_RE.finditer(joined):
        url = m.group(1).rstrip(_TRAILING)
        if _looks_like_real_domain(url):
            found.add(url)
    return sorted(found)


def extract_urls_from_image(image_bytes: bytes) -> tuple[list[str], str]:
    """OCR multi-pasada + extracción de URLs. Devuelve (urls, texto_ocr).

    Las URLs se extraen de cada pasada por separado (para que la unión de
    líneas partidas funcione sin contaminación entre pasadas) y luego se unen.
    """
    texts = _ocr_variants(image_bytes)
    urls: set[str] = set()
    for t in texts:
        # Normalizamos (añadimos esquema) para que 'bit.ly/x' y
        # 'https://bit.ly/x' no cuenten como dos URLs distintas.
        urls.update(normalize(u) for u in find_urls_in_text(t))
    return sorted(urls), "\n".join(texts)
