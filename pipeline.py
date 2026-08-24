"""Flujo de análisis reutilizable por el bot de Discord y por la API REST.

Encapsula el orden de pasos (extracción -> análisis) para que 'bot.py' y
'api.py' compartan exactamente la misma lógica.
"""
from __future__ import annotations

from analysis.scanner import MessageReport, scan_message
from extractors.ocr import extract_urls_from_image, find_urls_in_text
from extractors.qr import extract_qr_urls


def analyze_image_bytes(data: bytes) -> MessageReport:
    """Extrae URLs (QR + OCR) de una imagen y devuelve el veredicto del mensaje."""
    qr_urls = extract_qr_urls(data)
    ocr_urls, ocr_text = extract_urls_from_image(data)
    all_urls = list(dict.fromkeys(qr_urls + ocr_urls))  # únicas, en orden
    return scan_message(all_urls, ocr_text)


def analyze_text(texto: str) -> MessageReport:
    """Analiza una URL o mensaje en texto plano."""
    urls = find_urls_in_text(texto)
    return scan_message(urls, texto)
