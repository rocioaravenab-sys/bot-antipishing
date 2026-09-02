"""Regresión: el refactor de reglas a JSON no cambia veredictos conocidos.

No usa acortadores para no depender de la red (expand_url).
"""
import pytest

from analysis.scanner import scan_message
from analysis.serialize import report_to_dict


@pytest.mark.parametrize(
    ("urls", "text", "expected_risk"),
    [
        # Estafa de encomienda con dominio típico de phishing.
        (["http://aduana-chile-pago.top/tramite"],
         "Su encomienda esta retenida por aduana. Pague ahora para liberarla.",
         "ALTO"),
        # Typosquatting de un banco, sin lenguaje de estafa: una sola señal (score 2).
        # Nota: la v2.A3 sube esto al detectar el mismatch de marca.
        (["https://bancoestadk.cl/acceso"], "Acceda a su cuenta", "BAJO"),
        # Mensaje limpio, dominio conocido.
        (["https://www.bancoestado.cl/"], "Hola, gracias por tu compra", "BAJO"),
        # Solo texto de estafa, sin URL.
        ([], "URGENTE: multa por exceso de velocidad, pague ahora o habra recargo",
         "ALTO"),
    ],
)
def test_known_verdicts(urls, text, expected_risk):
    report = scan_message(urls, text)
    assert report.risk == expected_risk, (report.risk, report.score)


def test_typosquat_signal_present():
    report = scan_message(["https://bancoestadk.cl/acceso"], "Acceda a su cuenta")
    signals = [s for u in report.urls for s in u.signals]
    assert any("typosquatting" in s for s in signals), signals


@pytest.mark.parametrize(
    "url",
    [
        "http://190.111.22.33/documento.pdf",   # IP pública
        "https://portal-clientes-cl.xyz/form",  # TLD abusado
        "https://x7k2a9q1z4.com/ver",           # dominio DGA (dígitos intercalados)
    ],
)
def test_single_high_confidence_signal_reaches_medio(url):
    # Una sola señal de alta confianza (peso 3) ya cruza el umbral de MEDIO,
    # incluso sin lenguaje de estafa en el texto.
    report = scan_message([url], "Revisa esto")
    assert report.risk == "MEDIO", (report.risk, report.score)


@pytest.mark.parametrize(
    "url",
    [
        "http://192.168.1.20:8080/panel",           # IP de red local (no enrutable)
        "https://muebles-a-medida-santiago.cl/x",   # dominio legítimo con guiones
        "https://www.24horas.cl/deportes",          # medio real, dígitos pero no DGA
    ],
)
def test_single_low_confidence_signal_stays_bajo(url):
    report = scan_message([url], "Revisa esto")
    assert report.risk == "BAJO", (report.risk, report.score)


@pytest.mark.parametrize(
    "text",
    [
        # Promo legítima de tienda desde un número que clasifica como VOIP.
        "+56 44 261 3010: Hola! Tienes 15% de descuento en Kinegun. "
        "Activalo en https://www.kinegun.cl/15black",
        # Aviso de local desde una línea fija, sin lenguaje de estafa.
        "+56 2 2707 0000 Recordatorio: tu pedido esta listo para retiro en tienda.",
    ],
)
def test_sender_line_type_alone_stays_bajo(text):
    # El tipo de línea del remitente es señal de apoyo: no alarma por sí sola.
    report = scan_message([], text)
    assert report.phones and report.phones[0].signals, "esperaba señal de línea"
    assert report.risk == "BAJO", (report.risk, report.score)


def test_voip_sender_plus_one_scam_word_reaches_medio():
    # Combinado con una señal más (aquí, una sola palabra de estafa: scam_score 2)
    # sí cruza a MEDIO. Ni el remitente VOIP (2) ni la palabra sola (2) bastan.
    base = "Tiene una deuda pendiente asociada a su RUT."
    assert scan_message([], base).risk == "BAJO"                       # solo estafa
    assert scan_message([], "+56 44 261 3010").risk == "BAJO"          # solo VOIP
    report = scan_message([], "+56 44 261 3010: " + base)             # ambas
    assert report.risk == "MEDIO", (report.risk, report.score)


def test_high_confidence_signal_weights():
    from analysis.heuristics import analyze_url_signals

    def weight_of(url):
        sigs = analyze_url_signals(url)
        assert len(sigs) == 1, sigs
        return sigs[0][1]

    assert weight_of("http://190.111.22.33/x") == 3           # IP pública
    assert weight_of("http://10.0.0.5/x") == 2                # IP privada (RFC1918)
    assert weight_of("https://evento.monster/registro") == 3  # TLD abusado
    assert weight_of("https://portal-de-pagos-online.com/x") == 2  # guiones


def test_report_dict_carries_versions():
    d = report_to_dict(scan_message([], "hola"))
    assert d["engine_version"]
    assert len(d["rules_version"]) == 12
    assert d["risk"] == "BAJO"
