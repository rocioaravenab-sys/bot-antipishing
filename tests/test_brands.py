"""A3 — marcas chilenas + lista blanca de dominios oficiales."""
from analysis.scanner import scan_message, scan_url


def test_official_domain_is_verified_and_low_risk():
    r = scan_url("https://www.bancoestado.cl/personas")
    assert r.verified_official is True
    assert r.official_brand == "BancoEstado"
    assert r.risk == "BAJO"


def test_message_to_official_site_is_reassured_not_alarmed():
    report = scan_message(
        ["https://www.bancoestado.cl/"],
        "Estimado cliente de BancoEstado, revise su cartola mensual.",
    )
    assert report.risk == "BAJO"
    assert report.reassurance and "BancoEstado" in report.reassurance
    assert report.brand_signal is None


def test_brand_mentioned_but_link_is_not_official():
    report = scan_message(
        ["https://bancoestado-seguro.top/acceso"],
        "URGENTE BancoEstado: su cuenta sera bloqueada. Ingrese ahora para validar.",
    )
    assert report.brand_signal is not None
    assert "BancoEstado" in report.brand_signal
    assert "bancoestado.cl" in report.brand_signal
    assert report.risk == "ALTO"


def test_strong_scam_language_with_official_link_capped_at_medio():
    # El enlace es real, pero el texto es de estafa -> "raro", no "seguro".
    report = scan_message(
        ["https://www.bancoestado.cl/"],
        "URGENTE: su cuenta fue suspendida. Pague ahora. Ultima oportunidad, confirmar datos.",
    )
    assert report.all_official is True
    assert report.risk == "MEDIO"


def test_typosquat_still_fires():
    report = scan_message(["https://bancoestadk.cl/login"], "acceso")
    sigs = [s for u in report.urls for s in u.signals]
    assert any("typosquatting" in s for s in sigs)
    assert report.urls[0].verified_official is False


def test_generic_token_not_treated_as_brand_impersonation():
    # "banco" es un token genérico (sin dominios oficiales) -> no dispara mismatch.
    report = scan_message(["https://mi-banco-online.top/"], "Su banco le informa")
    assert report.brand_signal is None
