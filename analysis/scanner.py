"""Orquesta extracción + análisis y produce un veredicto por mensaje."""
from __future__ import annotations

from dataclasses import dataclass, field

from . import heuristics, threat_intel
from .phone import PhoneInfo, analyze_phones
from .url_utils import expand_url, is_shortener, normalize

# Umbrales de puntuación -> nivel de riesgo.
RISK_LOW = "BAJO"
RISK_MEDIUM = "MEDIO"
RISK_HIGH = "ALTO"


@dataclass
class UrlReport:
    url: str
    final_url: str
    signals: list[str] = field(default_factory=list)
    score: int = 0
    expansion_error: str | None = None

    @property
    def risk(self) -> str:
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
            report.signals.append(f"Redirige a: {exp.final_url}")

    # 2) Heurísticas sobre la URL original y la final.
    seen = set()
    for candidate in (url, report.final_url):
        for sig in heuristics.analyze_url(candidate):
            if sig not in seen:
                seen.add(sig)
                report.signals.append(sig)
                report.score += 2

    # 3) Threat intelligence (si hay claves configuradas).
    for sig in threat_intel.gather(report.final_url):
        report.signals.append(sig)
        report.score += 5  # una coincidencia en listas negras es contundente

    return report


def scan_urls(urls: list[str]) -> list[UrlReport]:
    return [scan_url(u) for u in urls]


@dataclass
class MessageReport:
    """Veredicto agregado del mensaje: URLs + remitente + texto."""
    urls: list[UrlReport] = field(default_factory=list)
    phones: list[PhoneInfo] = field(default_factory=list)
    scam_signal: str | None = None
    scam_score: int = 0

    @property
    def score(self) -> int:
        total = self.scam_score
        total += sum(r.score for r in self.urls)
        total += sum(p.score for p in self.phones)
        return total

    @property
    def risk(self) -> str:
        s = self.score
        if s >= 6:
            return RISK_HIGH
        if s >= 3:
            return RISK_MEDIUM
        return RISK_LOW


def scan_message(urls: list[str], ocr_text: str = "") -> MessageReport:
    """Analiza el mensaje completo: URLs + número remitente + texto OCR."""
    hits = heuristics.scam_keyword_hits(ocr_text)
    # Cada palabra de estafa suma; con 3+ ya alcanza por sí sola nivel ALTO.
    scam_score = min(len(hits), 3) * 2
    scam_signal = (
        f"El mensaje usa lenguaje típico de estafa: {', '.join(hits[:5])}."
        if hits else None
    )

    return MessageReport(
        urls=scan_urls(urls),
        phones=analyze_phones(ocr_text),
        scam_signal=scam_signal,
        scam_score=scam_score,
    )
