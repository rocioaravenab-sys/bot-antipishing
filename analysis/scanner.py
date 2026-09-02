"""Orquesta extracción + análisis y produce un veredicto por mensaje."""
from __future__ import annotations

from dataclasses import dataclass, field

from . import domain_intel, heuristics, rules, threat_intel
from .messages_es import t
from .phone import PhoneInfo, analyze_phones
from .url_utils import expand_url, get_domain, is_shortener, normalize

# Umbrales de puntuación -> nivel de riesgo.
RISK_LOW = "BAJO"
RISK_MEDIUM = "MEDIO"
RISK_HIGH = "ALTO"

_BLOCKLIST_MARK = "⛔"  # lo ponen las señales de threat intel (lista negra)


@dataclass
class UrlReport:
    url: str
    final_url: str
    signals: list[str] = field(default_factory=list)
    score: int = 0
    expansion_error: str | None = None
    # Lista blanca: el destino final es un dominio oficial conocido.
    verified_official: bool = False
    official_brand: str | None = None

    @property
    def _blocklisted(self) -> bool:
        return any(_BLOCKLIST_MARK in s for s in self.signals)

    @property
    def risk(self) -> str:
        # Un dominio oficial verificado no asusta salvo que esté en lista negra.
        if self.verified_official and not self._blocklisted:
            return RISK_LOW
        if self.score >= 6:
            return RISK_HIGH
        if self.score >= 3:
            return RISK_MEDIUM
        return RISK_LOW


def scan_url(url: str) -> UrlReport:
    """Analiza una URL: expande, aplica heurísticas y threat intel."""
    url = normalize(url)
    report = UrlReport(url=url, final_url=url)

    # 1) Expandir acortadores (HEAD, solo lectura).
    if is_shortener(url):
        exp = expand_url(url)
        report.final_url = exp.final_url
        report.expansion_error = exp.error
        if exp.was_redirected:
            report.signals.append(t("redirects_to", url=exp.final_url))

    # 2) Lista blanca: ¿el destino final es un dominio oficial conocido?
    brand = rules.official_brand_for_domain(get_domain(report.final_url))
    if brand:
        report.verified_official = True
        report.official_brand = brand.get("display") or brand["brand"]

    # 3) Heurísticas sobre la URL original y la final. Cada señal trae su peso:
    #    la mayoría suma 2; las de alta confianza suman 3 (una sola ya es MEDIO).
    #    Ver heuristics.analyze_url_signals.
    seen = set()
    for candidate in (url, report.final_url):
        for sig, weight in heuristics.analyze_url_signals(candidate):
            if sig not in seen:
                seen.add(sig)
                report.signals.append(sig)
                report.score += weight

    # 4) Intel de dominio: antigüedad (RDAP) + certificado TLS.
    #    Se salta si la URL ya es oficial verificada (no aporta y ahorra latencia).
    if not report.verified_official:
        for sig, weight in domain_intel.gather(get_domain(report.final_url)):
            report.signals.append(sig)
            report.score += weight

    # 5) Threat intelligence (si hay claves configuradas).
    for sig in threat_intel.gather(report.final_url):
        report.signals.append(sig)
        report.score += 5  # una coincidencia en listas negras es contundente

    return report


def scan_urls(urls: list[str]) -> list[UrlReport]:
    return [scan_url(u) for u in urls]


def brand_mismatch_signal(ocr_text: str, url_reports: list[UrlReport]) -> str | None:
    """Señal de suplantación: el texto nombra una marca pero ningún enlace del
    mensaje lleva a su sitio oficial.

    Solo se evalúa si el mensaje trae al menos una URL (nombrar una marca sin
    enlace no es, por sí solo, un intento de phishing por enlace).
    """
    if not url_reports:
        return None
    mentioned = rules.brands_mentioned_in_text(ocr_text)
    if not mentioned:
        return None

    final_brands = {
        (rules.official_brand_for_domain(get_domain(u.final_url)) or {}).get("brand")
        for u in url_reports
    }
    problems = [
        t("brand_mismatch_item",
          display=b.get("display") or b["brand"], domain=b["official_domains"][0])
        for b in mentioned
        if b["brand"] not in final_brands
    ]
    if not problems:
        return None
    return t("brand_mismatch", brands=", ".join(problems))


@dataclass
class MessageReport:
    """Veredicto agregado del mensaje: URLs + remitente + texto."""
    urls: list[UrlReport] = field(default_factory=list)
    phones: list[PhoneInfo] = field(default_factory=list)
    scam_signal: str | None = None
    scam_score: int = 0
    brand_signal: str | None = None
    brand_score: int = 0
    # True = la imagen no traía un mensaje/SMS analizable (una foto cualquiera,
    # o un formato que no se pudo leer). La app lo muestra como "no detecté un
    # mensaje" en vez de un "es seguro" engañoso o un error.
    no_content: bool = False

    @property
    def _blocklisted(self) -> bool:
        return any(u._blocklisted for u in self.urls)

    @property
    def all_official(self) -> bool:
        """Todas las URLs del mensaje llevan a un dominio oficial conocido."""
        return bool(self.urls) and all(u.verified_official for u in self.urls)

    @property
    def reassurance(self) -> str | None:
        if not (self.all_official and not self._blocklisted):
            return None
        names = sorted({u.official_brand for u in self.urls if u.official_brand})
        who = names[0] if names else "la entidad"
        return t("reassurance_official", who=who)

    @property
    def score(self) -> int:
        total = self.scam_score + self.brand_score
        total += sum(r.score for r in self.urls)
        total += sum(p.score for p in self.phones)
        return total

    @property
    def risk(self) -> str:
        s = self.score
        raw = RISK_HIGH if s >= 6 else RISK_MEDIUM if s >= 3 else RISK_LOW

        # Guarda de falsos positivos: si TODAS las URLs son oficiales y ninguna
        # está en lista negra, no alarmar. Si además hay lenguaje de estafa
        # fuerte, dejar en MEDIO ("el enlace es real, pero el mensaje es raro").
        if self.all_official and not self._blocklisted:
            if self.scam_score >= 4:
                return RISK_MEDIUM if raw == RISK_HIGH else raw
            return RISK_LOW
        return raw


def scan_message(urls: list[str], ocr_text: str = "") -> MessageReport:
    """Analiza el mensaje completo: URLs + número remitente + texto OCR."""
    hits = heuristics.scam_keyword_hits(ocr_text)
    # Cada palabra de estafa suma; con 3+ ya alcanza por sí sola nivel ALTO.
    scam_score = min(len(hits), 3) * 2
    scam_signal = (
        t("scam_language_msg", hits=", ".join(hits[:5])) if hits else None
    )

    url_reports = scan_urls(urls)
    brand_signal = brand_mismatch_signal(ocr_text, url_reports)

    return MessageReport(
        urls=url_reports,
        phones=analyze_phones(ocr_text),
        scam_signal=scam_signal,
        scam_score=scam_score,
        brand_signal=brand_signal,
        brand_score=4 if brand_signal else 0,
    )
