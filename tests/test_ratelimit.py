"""B2 — rate limiting in-process (token bucket)."""
from types import SimpleNamespace

import pytest
from fastapi import HTTPException

from ratelimit import RateLimiter


class FakeRequest:
    def __init__(self, headers=None, host="9.9.9.9"):
        self.headers = headers or {}
        self.client = SimpleNamespace(host=host)


@pytest.fixture
def clock(monkeypatch):
    t = {"now": 1000.0}
    monkeypatch.setattr("ratelimit.time.monotonic", lambda: t["now"])
    return t


def test_allows_capacity_then_blocks(clock):
    rl = RateLimiter(3, 60)
    req = FakeRequest({"x-install-id": "abc"})
    for _ in range(3):
        rl.check(req)  # ok
    with pytest.raises(HTTPException) as exc:
        rl.check(req)
    assert exc.value.status_code == 429
    assert int(exc.value.headers["Retry-After"]) >= 1


def test_refills_over_time(clock):
    rl = RateLimiter(2, 60)  # 1 token cada 30 s
    req = FakeRequest({"x-install-id": "abc"})
    rl.check(req)
    rl.check(req)
    with pytest.raises(HTTPException):
        rl.check(req)
    clock["now"] += 31  # pasa medio minuto -> 1 token nuevo
    rl.check(req)
    with pytest.raises(HTTPException):
        rl.check(req)


def test_install_ids_are_independent(clock):
    rl = RateLimiter(1, 60)
    rl.check(FakeRequest({"x-install-id": "user-a"}))
    rl.check(FakeRequest({"x-install-id": "user-b"}))  # no afecta a user-a
    with pytest.raises(HTTPException):
        rl.check(FakeRequest({"x-install-id": "user-a"}))


def test_falls_back_to_ip_without_install_id(clock):
    rl = RateLimiter(1, 60)
    rl.check(FakeRequest(host="1.1.1.1"))
    with pytest.raises(HTTPException):
        rl.check(FakeRequest(host="1.1.1.1"))
    rl.check(FakeRequest(host="2.2.2.2"))  # otra IP, bucket propio


def test_disabled_never_limits(clock):
    rl = RateLimiter(1, 60, enabled=False)
    req = FakeRequest({"x-install-id": "abc"})
    for _ in range(50):
        rl.check(req)
