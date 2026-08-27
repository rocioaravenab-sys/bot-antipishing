"""B4 — i18n del motor: idiomas de scam keywords, plantillas, canales por región."""
import pytest

from analysis import heuristics
from analysis.messages_es import t
from analysis.reporting import DEFAULT_REGION, report_channels
from analysis.rules import scam_keywords


def test_scam_keywords_default_includes_pt():
    hits = heuristics.scam_keyword_hits("Sua encomenda esta retida, pague agora a taxa alfandegaria")
    assert "pague agora" in hits
    assert "taxa alfandeg" in hits


def test_spanish_still_detected():
    hits = heuristics.scam_keyword_hits("paquete retenido en aduana, pague ahora")
    assert {"pague ahora", "aduana", "paquete retenido"} <= set(hits)


def test_pt_phrases_do_not_collide_with_plain_spanish():
    # Texto español inocente no debe activar ninguna expresión portuguesa.
    innocent = "Hola, confirmo que llego a las ocho a la reunion de manana"
    pt_only = set(scam_keywords(("pt",)))
    assert not (set(heuristics.scam_keyword_hits(innocent)) & pt_only)


def test_report_channels_fallback():
    assert report_channels(DEFAULT_REGION) == report_channels("region-inexistente")
    assert len(report_channels()) >= 4


def test_message_templates():
    assert t("url_at").startswith("La URL contiene '@'")
    assert t("url_bad_tld", suffix="top") == "Dominio de nivel superior sospechoso: .top"
    with pytest.raises(KeyError):
        t("clave_que_no_existe")
