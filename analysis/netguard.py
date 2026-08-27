"""Guarda anti-SSRF para las peticiones salientes del motor.

La API está alojada (Railway) y recibe URLs de terceros. Sin esta guarda, un
acortador que redirige a 'http://169.254.169.254/…' o a un rango privado haría
que el servidor pegue a metadatos de la nube o a servicios internos.

Uso: llama a 'assert_public_host(host)' ANTES de cualquier conexión saliente a
un host controlado por el usuario (expansión de acortadores, RDAP, socket TLS).
Falla de forma explícita con 'BlockedHostError'; el llamador debe capturarla y
degradar con elegancia (saltar el paso, añadir una señal neutra), nunca 500.
"""
from __future__ import annotations

import ipaddress
import socket
from urllib.parse import urlparse

# Nombres que nunca deben resolverse hacia afuera.
_BLOCKED_NAMES = {"localhost", "metadata", "metadata.google.internal"}
_BLOCKED_SUFFIXES = (".internal", ".local", ".localhost")
# Endpoints de metadatos de nube (por si el DNS los devuelve como IP literal).
_BLOCKED_IPS = {"169.254.169.254", "100.100.100.200", "fd00:ec2::254"}


class BlockedHostError(Exception):
    """El host resuelve a una dirección no pública (o es un nombre reservado)."""


def _ip_is_public(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    if str(addr) in _BLOCKED_IPS:
        return False
    return not (
        addr.is_private
        or addr.is_loopback
        or addr.is_link_local
        or addr.is_multicast
        or addr.is_reserved
        or addr.is_unspecified
    )


def is_public_host(host: str) -> bool:
    """True si 'host' resuelve exclusivamente a direcciones públicas."""
    if not host:
        return False
    host = host.strip().rstrip(".").lower().strip("[]")  # [::1] -> ::1
    if host in _BLOCKED_NAMES or host.endswith(_BLOCKED_SUFFIXES):
        return False

    # ¿Es ya una IP literal? Entonces se valida directamente.
    try:
        ipaddress.ip_address(host)
    except ValueError:
        pass  # es un nombre de dominio; se resuelve abajo
    else:
        return _ip_is_public(host)

    try:
        infos = socket.getaddrinfo(host, None, proto=socket.IPPROTO_TCP)
    except socket.gaierror:
        return False  # no resuelve -> trátalo como no verificable

    resolved = {info[4][0] for info in infos}
    return bool(resolved) and all(_ip_is_public(ip) for ip in resolved)


def assert_public_host(host: str) -> None:
    """Lanza 'BlockedHostError' si 'host' no es un host público verificable."""
    if not is_public_host(host):
        raise BlockedHostError(f"Host no público o no verificable: {host!r}")


def assert_public_url(url: str) -> None:
    """Igual que 'assert_public_host' pero tomando la URL completa."""
    assert_public_host(urlparse(url).hostname or "")
