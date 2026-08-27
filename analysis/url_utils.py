"""Normalización de URLs y expansión SEGURA de acortadores.

Importante: la expansión sigue redirecciones usando SOLO peticiones HEAD.
Nunca se envían datos ni se rellena ningún formulario. Es lectura pasiva
de las cabeceras 'Location' para saber a dónde apunta el enlace.

Cada salto se valida con 'netguard' antes de conectar: si una redirección
apunta a un host no público (rango privado, loopback, metadatos de nube), se
corta la expansión y se marca el destino como no verificable.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from urllib.parse import urlparse

import requests

import config

from . import netguard
from .rules import SHORTENER_DOMAINS  # noqa: F401  (canónico en analysis/data/shorteners.json)

_BLOCKED_MSG = "No se pudo verificar el destino (host no público)."


def normalize(url: str) -> str:
    """Asegura que la URL tenga esquema; recorta espacios."""
    url = url.strip()
    if not url.lower().startswith(("http://", "https://")):
        url = "https://" + url
    return url


def get_domain(url: str) -> str:
    """Devuelve el host (netloc) en minúsculas, sin puerto."""
    netloc = urlparse(normalize(url)).netloc.lower()
    return netloc.split(":")[0]


def is_shortener(url: str) -> bool:
    return get_domain(url) in SHORTENER_DOMAINS


@dataclass
class ExpansionResult:
    original: str
    final_url: str
    chain: list[str] = field(default_factory=list)
    error: str | None = None

    @property
    def was_redirected(self) -> bool:
        return self.final_url != self.original


def _fetch_headers(current: str, headers: dict) -> requests.Response:
    """HEAD al host; si el servidor no acepta HEAD, GET+stream sin leer cuerpo.

    Nunca sigue redirecciones automáticamente: cada salto lo controla
    'expand_url' para poder validarlo con 'netguard'.
    """
    try:
        return requests.head(
            current, allow_redirects=False,
            timeout=config.REQUEST_TIMEOUT, headers=headers,
        )
    except requests.RequestException:
        resp = requests.get(
            current, allow_redirects=False, stream=True,
            timeout=config.REQUEST_TIMEOUT, headers=headers,
        )
        resp.close()  # no descargamos el cuerpo
        return resp


def expand_url(url: str) -> ExpansionResult:
    """Sigue redirecciones con HEAD para revelar el destino real.

    No descarga el cuerpo de la página ni envía datos. Valida cada salto con
    'netguard' antes de conectar.
    """
    url = normalize(url)
    if not config.EXPAND_SHORTENERS:
        return ExpansionResult(original=url, final_url=url)

    chain = [url]
    current = url
    headers = {"User-Agent": config.HTTP_USER_AGENT}
    last_ok = url

    try:
        for _ in range(config.MAX_REDIRECTS):
            try:
                netguard.assert_public_url(current)
            except netguard.BlockedHostError:
                return ExpansionResult(
                    original=url, final_url=last_ok, chain=chain, error=_BLOCKED_MSG,
                )

            resp = _fetch_headers(current, headers)
            last_ok = current
            location = resp.headers.get("Location")
            if resp.status_code in (301, 302, 303, 307, 308) and location:
                current = requests.compat.urljoin(current, location)
                chain.append(current)
                continue
            break
        else:
            return ExpansionResult(
                original=url, final_url=current, chain=chain,
                error="Se alcanzó el máximo de redirecciones.",
            )
        return ExpansionResult(original=url, final_url=current, chain=chain)
    except requests.RequestException as exc:
        return ExpansionResult(
            original=url, final_url=last_ok, chain=chain, error=str(exc)
        )
