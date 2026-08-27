"""Carga y forma del ruleset canónico (analysis/data/*.json)."""
from analysis import rules


def test_lists_non_empty():
    assert len(rules.SUSPICIOUS_TLDS) >= 30
    assert "top" in rules.SUSPICIOUS_TLDS
    assert "bit.ly" in rules.SHORTENER_DOMAINS
    assert rules.COMMON_TARGETS  # derivado de brands.json
    assert "bancoestado" in rules.COMMON_TARGETS
    assert "paypal" in rules.COMMON_TARGETS


def test_scam_keywords_langs():
    es = rules.scam_keywords(("es",))
    both = rules.scam_keywords(("es", "pt"))
    assert "aduana" in es
    assert len(both) > len(es)
    assert any("encomenda" in k for k in both)
    # SCAM_KEYWORDS (compat) == solo español
    assert rules.SCAM_KEYWORDS == es


def test_official_domain_lookup():
    assert rules.official_brand_for_domain("bancoestado.cl")["brand"] == "bancoestado"
    assert rules.official_brand_for_domain("www.bancoestado.cl")["brand"] == "bancoestado"
    # subdominio malicioso que EMBEBE el dominio oficial -> no coincide
    assert rules.official_brand_for_domain("bancoestado.cl.evil.com") is None
    assert rules.official_brand_for_domain("bancoestad0.cl") is None
    assert rules.official_brand_for_domain("") is None


def test_brands_mentioned_in_text():
    hits = rules.brands_mentioned_in_text("Estimado cliente de BancoEstado, confirme su clave")
    assert [b["brand"] for b in hits] == ["bancoestado"]
    # token genérico sin dominios oficiales no cuenta como suplantación de marca
    assert rules.brands_mentioned_in_text("hola mundo") == []


def test_rules_version_stable_and_hex():
    v = rules.RULES_VERSION
    assert isinstance(v, str) and len(v) == 12
    assert v == rules._rules_version()  # determinista


def test_ruleset_payload_shape():
    p = rules.ruleset_payload()
    assert set(p) == {"version", "tlds", "shorteners", "brands", "scam_keywords"}
    assert p["version"] == rules.RULES_VERSION
    assert isinstance(p["brands"], list) and p["brands"]
    assert set(p["scam_keywords"]) >= {"es", "pt"}
