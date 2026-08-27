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


def test_report_dict_carries_versions():
    d = report_to_dict(scan_message([], "hola"))
    assert d["engine_version"]
    assert len(d["rules_version"]) == 12
    assert d["risk"] == "BAJO"
