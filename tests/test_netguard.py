"""Guarda anti-SSRF: clasificación de hosts públicos vs. no verificables."""
import pytest

from analysis import netguard

PRIVATE = [
    "127.0.0.1", "10.0.0.5", "10.255.255.255", "192.168.1.1", "172.16.0.1",
    "172.31.255.255", "169.254.169.254", "169.254.1.1", "100.100.100.200",
    "0.0.0.0", "::1", "[::1]", "fe80::1", "fc00::1",
    "localhost", "foo.internal", "bar.local", "metadata",
    "metadata.google.internal", "", "   ",
]

PUBLIC_IPS = ["8.8.8.8", "1.1.1.1", "93.184.216.34"]


@pytest.mark.parametrize("host", PRIVATE)
def test_rejects_non_public(host):
    assert netguard.is_public_host(host) is False
    with pytest.raises(netguard.BlockedHostError):
        netguard.assert_public_host(host)


@pytest.mark.parametrize("ip", PUBLIC_IPS)
def test_accepts_public_ip_literals(ip):
    assert netguard.is_public_host(ip) is True
    netguard.assert_public_host(ip)  # no lanza


def test_domain_resolving_to_private_is_blocked(monkeypatch):
    """Un nombre que resuelve a 10.x debe rechazarse (aunque 'parezca' normal)."""
    def fake_getaddrinfo(host, *a, **kw):
        return [(None, None, None, "", ("10.1.2.3", 0))]

    monkeypatch.setattr(netguard.socket, "getaddrinfo", fake_getaddrinfo)
    assert netguard.is_public_host("sneaky.example") is False


def test_domain_resolving_to_public_is_allowed(monkeypatch):
    def fake_getaddrinfo(host, *a, **kw):
        return [(None, None, None, "", ("93.184.216.34", 0))]

    monkeypatch.setattr(netguard.socket, "getaddrinfo", fake_getaddrinfo)
    assert netguard.is_public_host("ok.example") is True


def test_unresolvable_is_treated_as_non_verifiable(monkeypatch):
    def boom(*a, **kw):
        raise netguard.socket.gaierror("no such host")

    monkeypatch.setattr(netguard.socket, "getaddrinfo", boom)
    assert netguard.is_public_host("nope.invalid") is False


def test_assert_public_url_extracts_host():
    with pytest.raises(netguard.BlockedHostError):
        netguard.assert_public_url("http://169.254.169.254/latest/meta-data/")
