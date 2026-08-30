"""Flujo de análisis reutilizable por el bot de Discord y por la API REST.

Encapsula el orden de pasos (extracción -> análisis) para que 'bot.py' y
'api.py' compartan exactamente la misma lógica.
"""
from __future__ import annotations

from analysis.scanner import MessageReport, scan_message
from extractors.ocr import extract_urls_from_image, find_urls_in_text
from extractors.qr import extract_qr_urls


def analyze_image_bytes(data: bytes) -> MessageReport:
    """Extrae URLs (QR + OCR) de una imagen y devuelve el veredicto del mensaje.

    Si la imagen no se puede leer (formato no soportado, p. ej. HEIC de la
    cámara del iPhone) o se lee pero no contiene un mensaje analizable (una foto
    cualquiera, sin enlaces/QR/remitente/texto de estafa), se devuelve un reporte
    marcado con 'no_content' para que la app diga "no detecté un mensaje" en vez
    de un error 400 o un "es seguro" engañoso.
    """
    try:
        qr_urls = extract_qr_urls(data)
        ocr_urls, ocr_text = extract_urls_from_image(data)
    except ValueError:
        # cv2 no pudo decodificar la imagen (formato no soportado / archivo dañado).
        return MessageReport(no_content=True)

    all_urls = list(dict.fromkeys(qr_urls + ocr_urls))  # únicas, en orden
    report = scan_message(all_urls, ocr_text)
    # Ni enlaces, ni QR, ni remitente, ni lenguaje de estafa: la imagen no traía
    # un mensaje/SMS que revisar.
    if not report.urls and not report.phones and not report.scam_signal:
        report.no_content = True
    return report


def analyze_text(texto: str) -> MessageReport:
    """Analiza una URL o mensaje en texto plano."""
    urls = find_urls_in_text(texto)
    return scan_message(urls, texto)
