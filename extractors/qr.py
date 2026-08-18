"""Decodificación de códigos QR presentes en la imagen."""
from __future__ import annotations

from pyzbar.pyzbar import decode

from .image_utils import bytes_to_cv2


def extract_qr_payloads(image_bytes: bytes) -> list[str]:
    """Devuelve el contenido de todos los QR/códigos de barras encontrados."""
    img = bytes_to_cv2(image_bytes)
    results = []
    for code in decode(img):
        try:
            results.append(code.data.decode("utf-8", errors="replace"))
        except Exception:
            continue
    return results


def extract_qr_urls(image_bytes: bytes) -> list[str]:
    """Filtra los payloads de QR que parezcan URLs."""
    payloads = extract_qr_payloads(image_bytes)
    urls = []
    for p in payloads:
        low = p.lower()
        if low.startswith(("http://", "https://")) or "." in p:
            urls.append(p.strip())
    return sorted(set(urls))
