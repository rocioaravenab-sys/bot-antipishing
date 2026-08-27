"""Antigüedad del dominio (RDAP) e inspección del certificado TLS.

Un dominio registrado hace días que dice ser un banco es casi siempre phishing.
RDAP es gratis y sin API key. La inspección del certificado abre un socket TLS
al host (handshake nada más, sin enviar datos de aplicación) y lee 'notBefore'
y los nombres del certificado.

Todo es fail-safe: cualquier error de red o de parseo -> None/[] (desconocido),
nunca rompe el análisis. Antes de conectar por TLS se valida el host con
'netguard' (anti-SSRF). El resultado se cachea por dominio (TTL 1 h).
"""
from __future__ import annotations

import socket
import ssl
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone

import requests

import config
from . import netguard

_CACHE_TTL = 3600
_cache: dict[str, tuple[float, list[tuple[str, int]]]] = {}


@dataclass
class DomainAge:
    registered: datetime | None
    days: int | None
    found: bool  # RDAP encontró el dominio


@dataclass
class CertInfo:
    not_before: datetime | None
    days: int | None
    names: list[str] = field(default_factory=list)  # CN + SAN (DNS)
    covers_domain: bool | None = None


# --- RDAP --------------------------------------------------------------------

def _parse_registration(data: dict) -> datetime | None:
    for ev in data.get("events", []):
        if ev.get("eventAction") == "registration" and ev.get("eventDate"):
            try:
                return datetime.fromisoformat(ev["eventDate"].replace("Z", "+00:00"))
            except ValueError:
                return None
    return None


def rdap_lookup(domain: str) -> DomainAge | None:
    if not config.DOMAIN_INTEL or not domain:
        return None
    url = f"{config.RDAP_BASE.rstrip('/')}/domain/{domain}"
    try:
        resp = requests.get(
            url, timeout=config.REQUEST_TIMEOUT,
            headers={"User-Agent": config.HTTP_USER_AGENT},
        )
    except requests.RequestException:
        return None

    if resp.status_code == 404:
        return DomainAge(registered=None, days=None, found=False)
    if not resp.ok:
        return None
    try:
        data = resp.json()
    except ValueError:
        return None

    reg = _parse_registration(data)
    days = None
    if reg is not None:
        days = (datetime.now(timezone.utc) - reg.astimezone(timezone.utc)).days
    return DomainAge(registered=reg, days=days, found=True)


# --- TLS --------------------------------------------------------------------

def _name_matches(pattern: str, host: str) -> bool:
    pattern, host = pattern.lower().strip("."), host.lower().strip(".")
    if pattern == host:
        return True
    if pattern.startswith("*."):
        base = pattern[2:]
        return host.endswith("." + base) and "." not in host[: -len(base) - 1]
    return False


def tls_cert_info(domain: str) -> CertInfo | None:
    if not config.DOMAIN_INTEL or not domain:
        return None
    try:
        netguard.assert_public_host(domain)
    except netguard.BlockedHostError:
        return None

    ctx = ssl.create_default_context()
    try:
        with socket.create_connection((domain, 443), timeout=config.REQUEST_TIMEOUT) as sock:
            with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
    except (OSError, ssl.SSLError, ValueError):
        return None
    if not cert:
        return None

    names: list[str] = []
    for typ, val in cert.get("subjectAltName", []):
        if typ == "DNS":
            names.append(val.lower())
    for rdn in cert.get("subject", []):
        for key, val in rdn:
            if key == "commonName":
                names.append(str(val).lower())
    names = list(dict.fromkeys(names))

    not_before = None
    raw = cert.get("notBefore")
    if raw:
        try:
            not_before = datetime.fromtimestamp(ssl.cert_time_to_seconds(raw), tz=timezone.utc)
        except (ValueError, OverflowError, OSError):
            not_before = None
    days = (datetime.now(timezone.utc) - not_before).days if not_before else None
    covers = any(_name_matches(n, domain) for n in names) if names else None

    return CertInfo(not_before=not_before, days=days, names=names, covers_domain=covers)


# --- Orquestación ----------------------------------------------------------

def _gather_uncached(domain: str) -> list[tuple[str, int]]:
    out: list[tuple[str, int]] = []

    age = rdap_lookup(domain)
    # Nota: NO penalizamos "RDAP no lo encuentra": varios registros (p. ej. NIC
    # Chile / .cl) no exponen RDAP y devolverían 404 para dominios legítimos.
    # RDAP solo aporta cuando SÍ trae fecha de registro reciente.
    if age is not None and age.days is not None:
        if age.days < 7:
            out.append((f"El dominio se registró hace {age.days} día(s): recién creado, "
                        "señal fuerte de phishing.", 5))
        elif age.days < 30:
            out.append((f"El dominio se registró hace {age.days} días (menos de un mes).", 4))
        elif age.days < 90:
            out.append((f"El dominio se registró hace {age.days} días (menos de tres meses).", 2))

    cert = tls_cert_info(domain)
    if cert is not None:
        if cert.days is not None and cert.days < 3:
            out.append((f"El certificado TLS se emitió hace {cert.days} día(s).", 2))
        if cert.covers_domain is False:
            visible = ", ".join(cert.names[:3]) or "ninguno"
            out.append((f"El certificado TLS no corresponde a '{domain}' "
                        f"(está emitido para: {visible}).", 3))

    return out


def gather(domain: str) -> list[tuple[str, int]]:
    """Señales de intel de dominio como (texto, peso). Cacheado por dominio."""
    if not config.DOMAIN_INTEL or not domain:
        return []
    now = time.monotonic()
    hit = _cache.get(domain)
    if hit and now - hit[0] < _CACHE_TTL:
        return hit[1]
    result = _gather_uncached(domain)
    _cache[domain] = (now, result)
    return result
