"""Rate limiting in-process (token bucket) para la API.

No usa Redis: la API corre como instancia única en Railway. Si algún día se
escala a varias réplicas, sustituir el diccionario de buckets por un backend
compartido.

La clave es el header 'X-Install-Id' (un UUID que la app genera una vez y
guarda localmente — aleatorio, no atado a identidad, no es PII). Si falta, se
usa la IP del cliente.
"""
from __future__ import annotations

import time
from dataclasses import dataclass
from threading import Lock

from fastapi import HTTPException, Request

_SWEEP_EVERY = 300
_IDLE_TTL = 3600


@dataclass
class _Bucket:
    capacity: float
    refill_per_sec: float
    tokens: float
    updated: float  # instante (monotonic) de la última recarga

    def take(self, now: float) -> float | None:
        """None si se concede; si no, segundos aproximados hasta el próximo token."""
        self.tokens = min(
            self.capacity, self.tokens + (now - self.updated) * self.refill_per_sec
        )
        self.updated = now
        if self.tokens >= 1.0:
            self.tokens -= 1.0
            return None
        return (1.0 - self.tokens) / self.refill_per_sec


class RateLimiter:
    def __init__(self, capacity: int, per_seconds: float, *, enabled: bool = True):
        self.capacity = capacity
        self.refill = capacity / per_seconds
        self.enabled = enabled
        self._buckets: dict[str, _Bucket] = {}
        self._lock = Lock()
        self._last_sweep = time.monotonic()

    @staticmethod
    def key_for(request: Request) -> str:
        install = (request.headers.get("x-install-id") or "").strip()
        if install:
            return "id:" + install[:64]
        host = request.client.host if request.client else "unknown"
        return "ip:" + host

    def check(self, request: Request) -> None:
        if not self.enabled:
            return
        now = time.monotonic()
        key = self.key_for(request)
        with self._lock:
            self._sweep(now)
            bucket = self._buckets.get(key)
            if bucket is None:
                bucket = _Bucket(self.capacity, self.refill,
                                 tokens=float(self.capacity), updated=now)
                self._buckets[key] = bucket
            wait = bucket.take(now)
        if wait is not None:
            raise HTTPException(
                status_code=429,
                detail="Demasiadas solicitudes. Espera un momento e inténtalo de nuevo.",
                headers={"Retry-After": str(max(1, int(wait + 0.999)))},
            )

    def _sweep(self, now: float) -> None:
        if now - self._last_sweep < _SWEEP_EVERY:
            return
        self._last_sweep = now
        for k in [k for k, b in self._buckets.items() if now - b.updated > _IDLE_TTL]:
            del self._buckets[k]
