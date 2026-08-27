"""B3 — CI gatea el motor contra el corpus etiquetado (tests/corpus/cases.jsonl).

Modo determinista (sin red). Si una regresión baja el recall de ALTO o sube los
falsos positivos en ham por encima del umbral, este test falla. Ver tests/eval.py
para el panel completo (`python tests/eval.py`).
"""
import config
from tests.eval import THRESHOLDS, confusion, load_cases, metrics


def test_engine_meets_thresholds(monkeypatch):
    monkeypatch.setattr(config, "DOMAIN_INTEL", False)

    matrix, _rows = confusion(load_cases())
    m = metrics(matrix)

    assert m["alto_recall"] >= THRESHOLDS["alto_recall"], m
    assert m["ham_false_positive"] <= THRESHOLDS["ham_false_positive"], m
    assert m["accuracy"] >= THRESHOLDS["accuracy"], m


def test_corpus_is_well_formed():
    cases = load_cases()
    assert len(cases) >= 20
    ids = [c["id"] for c in cases]
    assert len(ids) == len(set(ids)), "ids duplicados en el corpus"
    for c in cases:
        assert c["expected_risk"] in {"BAJO", "MEDIO", "ALTO"}
        assert c["kind"] in {"text", "image"}
        assert c.get("input") or c.get("image_path")
