"""A2 — antigüedad de dominio (RDAP) + certificado TLS. Todo con mocks (sin red)."""
from datetime import datetime, timedelta, timezone

import pytest

from analysis import domain_intel
from analysis.domain_intel import CertInfo, DomainAge


@pytest.fixture(autouse=True)
def _no_outbound_network():
    """Anula el stub global de conftest: aquí probamos domain_intel con mocks propios."""
    yield


@pytest.fixture(autouse=True)
def _clear_cache():
    domain_intel._cache.clear()
    yield
    domain_intel._cache.clear()


class _FakeResp:
    def __init__(self, status=200, payload=None):
        self.status_code = status
        self.ok = 200 <= status < 300
        self._payload = payload if payload is not None else {}

    def json(self):
        return self._payload


def _rdap_payload(days_ago: int) -> dict:
    when = (datetime.now(timezone.utc) - timedelta(days=days_ago)).isoformat()
    return {"events": [{"eventAction": "registration", "eventDate": when}]}


# --- rdap_lookup -----------------------------------------------------------

def test_rdap_recent_registration(monkeypatch):
    monkeypatch.setattr(domain_intel.requests, "get", lambda *a, **k: _FakeResp(200, _rdap_payload(3)))
    age = domain_intel.rdap_lookup("nuevo-banco.top")
    assert age.found is True and age.days == 3


def test_rdap_not_found(monkeypatch):
    monkeypatch.setattr(domain_intel.requests, "get", lambda *a, **k: _FakeResp(404))
    age = domain_intel.rdap_lookup("no-existe.top")
    assert age.found is False and age.days is None


def test_rdap_network_error_is_failsafe(monkeypatch):
    def boom(*a, **k):
        raise domain_intel.requests.RequestException("timeout")

    monkeypatch.setattr(domain_intel.requests, "get", boom)
    assert domain_intel.rdap_lookup("algo.cl") is None


def test_rdap_disabled(monkeypatch):
    monkeypatch.setattr(domain_intel.config, "DOMAIN_INTEL", False)
    assert domain_intel.rdap_lookup("algo.cl") is None


# --- _name_matches -------------------------------------------------------

@pytest.mark.parametrize(
    ("pattern", "host", "expected"),
    [
        ("bancoestado.cl", "bancoestado.cl", True),
        ("*.bancoestado.cl", "www.bancoestado.cl", True),
        ("*.bancoestado.cl", "a.b.bancoestado.cl", False),
        ("*.bancoestado.cl", "bancoestado.cl", False),
        ("otrodominio.com", "bancoestado.cl", False),
    ],
)
def test_name_matches(pattern, host, expected):
    assert domain_intel._name_matches(pattern, host) is expected


# --- gather (orquestación) --------------------------------------------

def test_gather_flags_new_domain_and_bad_cert(monkeypatch):
    monkeypatch.setattr(domain_intel, "rdap_lookup",
                        lambda d: DomainAge(registered=None, days=2, found=True))
    monkeypatch.setattr(domain_intel, "tls_cert_info",
                        lambda d: CertInfo(not_before=None, days=0, names=["otra.com"], covers_domain=False))
    sigs = domain_intel.gather("banco-falso.top")
    joined = " ".join(s for s, _ in sigs)
    assert "hace 2 día" in joined
    assert "no corresponde" in joined
    assert sum(w for _, w in sigs) >= 8  # 5 (recién creado) + 3 (cert no coincide)


def test_gather_quiet_for_established_domain(monkeypatch):
    monkeypatch.setattr(domain_intel, "rdap_lookup",
                        lambda d: DomainAge(registered=None, days=900, found=True))
    monkeypatch.setattr(domain_intel, "tls_cert_info",
                        lambda d: CertInfo(not_before=None, days=200, names=["banco.cl"], covers_domain=True))
    assert domain_intel.gather("banco.cl") == []


def test_gather_is_cached(monkeypatch):
    calls = {"n": 0}

    def once(d):
        calls["n"] += 1
        return DomainAge(registered=None, days=1, found=True)

    monkeypatch.setattr(domain_intel, "rdap_lookup", once)
    monkeypatch.setattr(domain_intel, "tls_cert_info", lambda d: None)
    domain_intel.gather("x.top")
    domain_intel.gather("x.top")
    assert calls["n"] == 1


def test_gather_failsafe_returns_empty(monkeypatch):
    monkeypatch.setattr(domain_intel, "rdap_lookup", lambda d: None)
    monkeypatch.setattr(domain_intel, "tls_cert_info", lambda d: None)
    assert domain_intel.gather("cualquier.cosa") == []


def test_gather_does_not_penalize_missing_rdap(monkeypatch):
    # NIC Chile (.cl) no expone RDAP -> 404 no debe penalizar dominios legítimos.
    monkeypatch.setattr(domain_intel, "rdap_lookup",
                        lambda d: DomainAge(registered=None, days=None, found=False))
    monkeypatch.setattr(domain_intel, "tls_cert_info", lambda d: None)
    assert domain_intel.gather("sitio-legitimo.cl") == []
