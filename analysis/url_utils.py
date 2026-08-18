"""Normalización de URLs y expansión SEGURA de acortadores.

Importante: la expansión sigue redirecciones usando SOLO peticiones HEAD.
Nunca se envían datos ni se rellena ningún formulario. Es lectura pasiva
de las cabeceras 'Location' para saber a dónde apunta el enlace.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from urllib.parse import urlparse

import requests

import config

# Dominios de acortadores más comunes.
SHORTENER_DOMAINS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly",
    "cutt.ly", "rebrand.ly", "shorturl.at", "rb.gy", "bl.ink", "t.ly",
    "acortar.link", "n9.cl", "v.gd", "s.id", "lnkd.in",
}


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


def expand_url(url: str) -> ExpansionResult:
    """Sigue redirecciones con HEAD para revelar el destino real.

    No descarga el cuerpo de la página ni envía datos. Si el servidor no
    responde a HEAD, se hace UN intento con GET+stream y se cierra sin leer
    el contenido.
    """
    url = normalize(url)
    if not config.EXPAND_SHORTENERS:
        return ExpansionResult(original=url, final_url=url)

    chain = [url]
    current = url
    headers = {"User-Agent": config.HTTP_USER_AGENT}

    try:
        for _ in range(config.MAX_REDIRECTS):
            resp = requests.head(
                current,
                allow_redirects=False,
                timeout=config.REQUEST_TIMEOUT,
                headers=headers,
            )
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
        # Fallback: algunos servidores no aceptan HEAD.
        try:
            resp = requests.get(
                url,
                allow_redirects=True,
                stream=True,  # no descargamos el cuerpo
                timeout=config.REQUEST_TIMEOUT,
                headers=headers,
            )
            final = resp.url
            resp.close()
            return ExpansionResult(
                original=url, final_url=final,
                chain=[h.url for h in resp.history] + [final],
            )
        except requests.RequestException:
            return ExpansionResult(
                original=url, final_url=url, chain=chain, error=str(exc)
            )
