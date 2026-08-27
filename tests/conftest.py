"""Configuración común de tests: los tests unitarios NUNCA salen a la red."""
import pytest


@pytest.fixture(autouse=True)
def _no_outbound_network(monkeypatch):
    """Neutraliza las fuentes que salen a la red (threat intel, intel de dominio).

    Los tests que quieran probarlas deben re-parchear explícitamente.
    """
    from analysis import domain_intel, threat_intel

    monkeypatch.setattr(threat_intel, "gather", lambda *a, **k: [])
    monkeypatch.setattr(domain_intel, "gather", lambda *a, **k: [])
