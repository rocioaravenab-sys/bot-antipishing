"""Versión del motor y de las reglas (se expone en /health y en cada análisis).

Sirve para: (a) que la app móvil sepa si debe refrescar su snapshot offline de
reglas, (b) trazar qué versión produjo un veredicto, (c) A/B de heurísticas.
"""
from __future__ import annotations

import os
import subprocess
from pathlib import Path

from .rules import RULES_VERSION  # noqa: F401  (re-exportado)

_REPO_ROOT = Path(__file__).resolve().parent.parent


def _git_short_sha() -> str | None:
    # Railway inyecta el SHA del commit desplegado.
    for env in ("RAILWAY_GIT_COMMIT_SHA", "GIT_COMMIT", "SOURCE_COMMIT"):
        val = os.getenv(env, "").strip()
        if val:
            return val[:12]
    try:
        out = subprocess.run(
            ["git", "rev-parse", "--short=12", "HEAD"],
            cwd=_REPO_ROOT, capture_output=True, text=True, timeout=2, check=True,
        )
        return out.stdout.strip() or None
    except (OSError, subprocess.SubprocessError):
        return None


ENGINE_VERSION: str = _git_short_sha() or "dev"
