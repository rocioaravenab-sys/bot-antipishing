"""Configuración común de tests: los tests unitarios NUNCA salen a la red."""
import pytest


@pytest.fixture(autouse=True)
def _no_threat_intel_network(monkeypatch):
    """Neutraliza threat intel (Safe Browsing / URLhaus) en todos los tests.

    Los tests que quieran probar threat intel deben re-parchear explícitamente.
    """
    from analysis import threat_intel

    monkeypatch.setattr(threat_intel, "gather", lambda *a, **k: [])
