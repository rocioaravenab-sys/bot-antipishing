"""Corre las fixtures canónicas (tests/rules_fixtures.json) por el camino offline.

El mismo archivo se corre en el monorepo (packages/rules/parity.test.ts). Si las
reglas cambian y una implementación deja de coincidir, este test falla.
"""
import json
from pathlib import Path

import pytest

from analysis import heuristics

FIXTURES = json.loads((Path(__file__).parent / "rules_fixtures.json").read_text("utf-8"))["cases"]


def _signals_for(case: dict) -> list[str]:
    if case["kind"] == "url":
        return heuristics.analyze_url(case["input"])
    if case["kind"] == "text":
        return heuristics.scam_keyword_hits(case["input"], langs=("es", "pt"))
    raise AssertionError(f"kind desconocido: {case['kind']}")


@pytest.mark.parametrize("case", FIXTURES, ids=[c["id"] for c in FIXTURES])
def test_offline_fixture(case):
    signals = _signals_for(case)
    joined = " || ".join(signals).lower()

    for needle in case.get("expect_signal_substrings", []):
        assert needle.lower() in joined, f"falta señal {needle!r} en {signals}"

    assert len(signals) >= case.get("min_signals", 0), signals
    if "max_signals" in case:
        assert len(signals) <= case["max_signals"], signals
