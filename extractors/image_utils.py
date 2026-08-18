"""Utilidades de imagen: descarga y preprocesado para OCR/QR."""
from __future__ import annotations

import io

import cv2
import numpy as np
from PIL import Image


def bytes_to_cv2(data: bytes) -> np.ndarray:
    """Convierte bytes de imagen en una matriz BGR de OpenCV."""
    arr = np.frombuffer(data, dtype=np.uint8)
    img = cv2.imdecode(arr, cv2.IMREAD_COLOR)
    if img is None:
        raise ValueError("No se pudo decodificar la imagen.")
    return img


def cv2_to_pil(img: np.ndarray) -> Image.Image:
    """Convierte una imagen BGR de OpenCV en PIL RGB (para pytesseract)."""
    return Image.fromarray(cv2.cvtColor(img, cv2.COLOR_BGR2RGB))


def color_pil_for_ocr(img: np.ndarray, scale: int = 2) -> Image.Image:
    """Imagen a COLOR escalada, para OCR.

    Mantener el color es clave: los enlaces suelen ir en azul y un umbral en
    escala de grises los borra. Tesseract binariza el color por su cuenta.
    """
    img = cv2.resize(img, None, fx=scale, fy=scale, interpolation=cv2.INTER_CUBIC)
    return Image.fromarray(cv2.cvtColor(img, cv2.COLOR_BGR2RGB))


def preprocess_for_ocr(img: np.ndarray) -> Image.Image:
    """Mejora el contraste/legibilidad antes del OCR.

    Los SMS suelen venir en modo oscuro (texto claro sobre fondo negro),
    así que escalamos, pasamos a gris y umbralizamos de forma adaptativa.
    """
    # Escalar x2 ayuda con texto pequeño de capturas de móvil.
    img = cv2.resize(img, None, fx=2, fy=2, interpolation=cv2.INTER_CUBIC)
    gray = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY)

    # Si el fondo es oscuro (media baja), invertimos para OCR.
    if gray.mean() < 127:
        gray = cv2.bitwise_not(gray)

    gray = cv2.bilateralFilter(gray, 9, 75, 75)
    # Bloque 41/C=20 lee mejor los dígitos en fuentes de móvil (evita 4->A).
    thresh = cv2.adaptiveThreshold(
        gray, 255, cv2.ADAPTIVE_THRESH_GAUSSIAN_C, cv2.THRESH_BINARY, 41, 20
    )
    return Image.fromarray(thresh)
