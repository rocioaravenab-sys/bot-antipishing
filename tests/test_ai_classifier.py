"""Clasificador IA: redacción, puntaje, integración con el veredicto y fail-safe.

Nunca llama a la API real: el cliente se reemplaza por un doble.
"""
from types import SimpleNamespace

import anthropic
import httpx2
import pytest

import config
from analysis import ai_classifier, scanner
from analysis.ai_classifier import AiVerdict, _AiOutput, redact
from analysis.ai_classifier import classify as real_classify  # conftest parchea el atributo
from analysis.serialize import report_to_dict


def _verdict(is_smishing=True, confidence="alta", tactics=("cambio_de_numero",)):
    return AiVerdict(
        is_smishing=is_smishing,
        confidence=confidence,
        tactics=tactics,
        explanation="Parece un falso familiar pidiendo dinero.",
        model="test-model",
    )


# --- redacción -----------------------------------------------------------

@pytest.mark.parametrize(
    ("text", "hidden", "token"),
    [
        ("Llámame al +56 9 1234 5678 urgente", "1234 5678", "[TELEFONO]"),
        ("mi numero nuevo es 912345678", "912345678", "[TELEFONO]"),
        ("Su RUT 12.345.678-9 tiene deuda", "12.345.678-9", "[RUT]"),
        ("RUT 12345678-K", "12345678-K", "[RUT]"),
        ("escribe a juan.perez@gmail.com", "juan.perez@gmail.com", "[CORREO]"),
    ],
)
def test_redact_hides_personal_data(text, hidden, token):
    out = redact(text)
    assert hidden not in out
    assert token in out


def test_redact_keeps_amounts_codes_and_urls():
    text = "Pague $2.990 con el código 4821 en http://aduana-cl-pagos.top/tramite?id=12345678"
    assert redact(text) == text


# --- puntaje ---------------------------------------------------------------

@pytest.mark.parametrize(
    ("is_smishing", "confidence", "score"),
    [(True, "alta", 4), (True, "media", 2), (True, "baja", 0),
     (False, "alta", 0), (False, "media", 0)],
)
def test_score_mapping(is_smishing, confidence, score):
    assert _verdict(is_smishing, confidence).score == score


# --- integración con el veredicto ------------------------------------------

FALSO_FAMILIAR = "Hola mamá, se me cayó el celu al agua, este es mi número nuevo. Guárdalo"


def test_ai_alone_raises_to_medio(monkeypatch):
    assert scanner.scan_message([], FALSO_FAMILIAR).risk == "BAJO"
    monkeypatch.setattr(ai_classifier, "classify", lambda t: _verdict())
    report = scanner.scan_message([], FALSO_FAMILIAR, use_ai=True)
    assert report.risk == "MEDIO"
    assert report.ai_signal and "falso familiar" in report.ai_signal


def test_ai_plus_other_signal_reaches_alto(monkeypatch):
    monkeypatch.setattr(ai_classifier, "classify", lambda t: _verdict())
    report = scanner.scan_message([], FALSO_FAMILIAR + " y transfiere urgente hoy", use_ai=True)
    assert report.scam_score > 0
    assert report.risk == "ALTO"


def test_ai_never_lowers_a_heuristic_alto(monkeypatch):
    urls = ["http://aduana-chile-pago.top/tramite"]
    text = "Su encomienda esta retenida por aduana. Pague ahora para liberarla."
    monkeypatch.setattr(ai_classifier, "classify", lambda t: _verdict(False, "alta"))
    report = scanner.scan_message(urls, text, use_ai=True)
    assert report.ai_score == 0
    assert report.risk == "ALTO"


def test_official_link_with_confident_ai_caps_at_medio(monkeypatch):
    monkeypatch.setattr(ai_classifier, "classify", lambda t: _verdict())
    report = scanner.scan_message(["https://www.bancoestado.cl/"], "Hola, verifica tu cuenta", use_ai=True)
    assert report.all_official
    assert report.risk == "MEDIO"


def test_ai_unavailable_keeps_engine_unchanged():
    # conftest deja classify -> None: mismo veredicto que antes de la IA.
    report = scanner.scan_message([], FALSO_FAMILIAR, use_ai=True)
    assert report.ai is None and report.ai_score == 0 and report.ai_signal is None


def test_serialize_includes_ai(monkeypatch):
    monkeypatch.setattr(ai_classifier, "classify", lambda t: _verdict())
    d = report_to_dict(scanner.scan_message([], FALSO_FAMILIAR, use_ai=True))
    assert d["ai"]["is_smishing"] is True
    assert d["ai"]["confidence"] == "alta"
    assert d["ai"]["tactics"] == ["cambio_de_numero"]
    assert d["ai"]["score"] == 4
    assert d["ai_signal"]


def test_serialize_ai_none_when_off():
    d = report_to_dict(scanner.scan_message([], FALSO_FAMILIAR))
    assert d["ai"] is None and d["ai_signal"] is None


# --- classify(): llamada a la API, fail-safe y caché -----------------------

class _FakeMessages:
    def __init__(self, result=None, exc=None):
        self.result, self.exc, self.calls = result, exc, []

    def parse(self, **kwargs):
        self.calls.append(kwargs)
        if self.exc:
            raise self.exc
        return self.result


@pytest.fixture
def fake_api(monkeypatch):
    """Activa la IA con una clave falsa y devuelve un instalador de doble."""
    monkeypatch.setattr(config, "ANTHROPIC_API_KEY", "sk-test")
    monkeypatch.setattr(config, "AI_CLASSIFIER", True)
    monkeypatch.setattr(config, "AI_PROVIDER", "anthropic")
    monkeypatch.setattr(config, "AI_MODEL", "claude-haiku-4-5")
    ai_classifier._classify_cached.cache_clear()

    def install(result=None, exc=None):
        messages = _FakeMessages(result, exc)
        monkeypatch.setattr(ai_classifier, "_client", lambda: SimpleNamespace(messages=messages))
        return messages

    yield install
    ai_classifier._classify_cached.cache_clear()


def _ok_response(**over):
    out = _AiOutput(is_smishing=True, confidence="alta",
                    tactics=["pide_dinero", "urgencia", "urgencia"],
                    explanation="  Le piden pagar para liberar un paquete.  ")
    return SimpleNamespace(parsed_output=out, stop_reason="end_turn", **over)


def test_classify_parses_and_redacts(fake_api):
    messages = fake_api(result=_ok_response())
    v = real_classify("Encomienda retenida, llame al +56 9 1234 5678 y pague hoy")
    assert v.is_smishing and v.confidence == "alta"
    assert v.tactics == ("pide_dinero", "urgencia")  # deduplicadas
    assert v.explanation == "Le piden pagar para liberar un paquete."
    sent = messages.calls[0]["messages"][0]["content"]
    assert "1234 5678" not in sent and "[TELEFONO]" in sent
    assert sent.startswith("<mensaje>") and sent.endswith("</mensaje>")
    assert messages.calls[0]["output_format"] is _AiOutput


def test_classify_caches_same_text(fake_api):
    messages = fake_api(result=_ok_response())
    real_classify("mismo SMS masivo")
    real_classify("mismo SMS masivo")
    assert len(messages.calls) == 1


def test_classify_disabled_without_key(fake_api, monkeypatch):
    messages = fake_api(result=_ok_response())
    monkeypatch.setattr(config, "ANTHROPIC_API_KEY", "")
    assert real_classify("Pague ahora") is None
    assert messages.calls == []


def test_classify_skips_empty_text(fake_api):
    messages = fake_api(result=_ok_response())
    assert real_classify("   ") is None
    assert messages.calls == []


def test_classify_api_error_is_fail_safe_and_not_cached(fake_api):
    req = httpx2.Request("POST", "https://api.anthropic.com/v1/messages")
    messages = fake_api(exc=anthropic.APIConnectionError(request=req))
    assert real_classify("Pague ahora") is None
    assert real_classify("Pague ahora") is None
    assert len(messages.calls) == 2  # el error no quedó en caché


def test_classify_unexpected_error_is_fail_safe(fake_api):
    fake_api(exc=RuntimeError("boom"))
    assert real_classify("Pague ahora") is None


def test_classify_incomplete_response_is_ignored(fake_api):
    fake_api(result=SimpleNamespace(parsed_output=None, stop_reason="max_tokens"))
    assert real_classify("Pague ahora") is None


# --- proveedor compatible con OpenAI (Qwen y otros) -------------------------

GOOD_JSON = ('{"is_smishing": true, "confidence": "alta", '
             '"tactics": ["pide_dinero"], "explanation": "Le piden pagar."}')


class _FakeResp:
    def __init__(self, content=GOOD_JSON, status=200):
        self.status_code, self.text, self._content = status, "detalle", content

    def json(self):
        return {"choices": [{"message": {"content": self._content}}]}


@pytest.fixture
def qwen(monkeypatch):
    """Activa el proveedor 'openai' y captura las llamadas a requests.post."""
    monkeypatch.setattr(config, "AI_CLASSIFIER", True)
    monkeypatch.setattr(config, "AI_PROVIDER", "")  # se deduce por AI_BASE_URL
    monkeypatch.setattr(config, "AI_BASE_URL", "https://llm.example/v1/")
    monkeypatch.setattr(config, "AI_API_KEY", "k-test")
    monkeypatch.setattr(config, "AI_MODEL", "qwen-test")
    monkeypatch.setattr(config, "AI_JSON_MODE", True)
    ai_classifier._classify_cached.cache_clear()
    calls = []

    def install(resp=None, exc=None):
        def post(url, **kwargs):
            calls.append((url, kwargs))
            if exc:
                raise exc
            return resp or _FakeResp()
        monkeypatch.setattr(ai_classifier.requests, "post", post)
        return calls

    yield install
    ai_classifier._classify_cached.cache_clear()


def test_qwen_request_shape_and_verdict(qwen):
    calls = qwen()
    v = real_classify("Encomienda retenida, llame al +56 9 1234 5678 y pague hoy")
    assert (v.is_smishing, v.confidence, v.tactics, v.model) == (
        True, "alta", ("pide_dinero",), "qwen-test")
    url, kw = calls[0]
    assert url == "https://llm.example/v1/chat/completions"
    assert kw["headers"]["Authorization"] == "Bearer k-test"
    body = kw["json"]
    assert body["model"] == "qwen-test"
    assert body["response_format"] == {"type": "json_object"}
    system, user = body["messages"]
    assert system["role"] == "system" and '"cambio_de_numero"' in system["content"]
    assert "[TELEFONO]" in user["content"] and "1234 5678" not in user["content"]


def test_qwen_json_mode_can_be_disabled(qwen, monkeypatch):
    monkeypatch.setattr(config, "AI_JSON_MODE", False)
    calls = qwen()
    assert real_classify("Pague ahora") is not None
    assert "response_format" not in calls[0][1]["json"]


def test_qwen_local_server_without_key(qwen, monkeypatch):
    monkeypatch.setattr(config, "AI_API_KEY", "")
    calls = qwen()
    assert real_classify("Pague ahora") is not None
    assert "Authorization" not in calls[0][1]["headers"]


@pytest.mark.parametrize(
    "content",
    [
        "<think>\nveamos {esto} parece estafa\n</think>\n" + GOOD_JSON,
        "```json\n" + GOOD_JSON + "\n```",
        "Claro, aquí está:\n" + GOOD_JSON + "\nEspero que sirva.",
        GOOD_JSON.replace('"alta"', '"Alta"'),
        GOOD_JSON.replace('["pide_dinero"]', '["pide_dinero", "tactica_inventada"]'),
    ],
)
def test_qwen_tolerates_messy_output(qwen, content):
    qwen(_FakeResp(content))
    v = real_classify("Pague ahora")
    assert v.is_smishing and v.confidence == "alta" and v.tactics == ("pide_dinero",)


@pytest.mark.parametrize(
    "content",
    ["no sé", "{no es json}", '{"is_smishing": true}',
     GOOD_JSON.replace('"alta"', '"segurísimo"'), "[1, 2]"],
)
def test_qwen_invalid_output_is_fail_safe(qwen, content):
    qwen(_FakeResp(content))
    assert real_classify("Pague ahora") is None


def test_qwen_quota_exhausted_is_fail_safe_and_not_cached(qwen):
    calls = qwen(_FakeResp(status=429))
    assert real_classify("Pague ahora") is None
    assert real_classify("Pague ahora") is None
    assert len(calls) == 2


def test_qwen_network_error_is_fail_safe(qwen):
    import requests
    qwen(exc=requests.ConnectionError("sin red"))
    assert real_classify("Pague ahora") is None


def test_qwen_disabled_without_model(qwen, monkeypatch):
    monkeypatch.setattr(config, "AI_MODEL", "")
    calls = qwen()
    assert real_classify("Pague ahora") is None
    assert calls == []


# --- consentimiento: sin él, el texto no sale hacia la IA --------------------

def _spy(monkeypatch):
    seen = []
    monkeypatch.setattr(ai_classifier, "classify", lambda t: seen.append(t) or _verdict())
    return seen


def test_no_consent_never_calls_ai(monkeypatch):
    seen = _spy(monkeypatch)
    report = scanner.scan_message([], FALSO_FAMILIAR)
    assert seen == [] and report.ai is None and report.risk == "BAJO"


def test_pipeline_passes_consent(monkeypatch):
    import pipeline
    seen = _spy(monkeypatch)
    assert pipeline.analyze_text(FALSO_FAMILIAR).ai is None
    assert seen == []
    assert pipeline.analyze_text(FALSO_FAMILIAR, ai_consent=True).ai is not None
    assert seen == [FALSO_FAMILIAR]


@pytest.mark.parametrize(
    ("header", "expected"),
    [(None, False), ("", False), ("0", False), ("true", False), ("1", True), (" 1 ", True)],
)
def test_api_consent_header(header, expected):
    import api
    assert api._ai_consent(header) is expected


def test_api_endpoint_only_uses_ai_with_consent_header(monkeypatch):
    import api
    seen = _spy(monkeypatch)
    req = SimpleNamespace(headers={}, client=SimpleNamespace(host="t"))
    monkeypatch.setattr(api._rl_text, "check", lambda r: None)
    body = api.TextIn(texto=FALSO_FAMILIAR)
    out = api.analyze_text_endpoint(body, req, x_api_key=None, x_ai_consent=None)
    assert out["ai"] is None and seen == []
    out = api.analyze_text_endpoint(body, req, x_api_key=None, x_ai_consent="1")
    assert out["ai"]["is_smishing"] is True and len(seen) == 1
