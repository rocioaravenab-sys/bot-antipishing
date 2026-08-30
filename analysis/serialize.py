"""Serialización de MessageReport a un dict JSON para la API REST."""
from __future__ import annotations

from typing import TYPE_CHECKING

from analysis.reporting import build_complaint_text, report_channels
from analysis.version import ENGINE_VERSION, RULES_VERSION

if TYPE_CHECKING:
    from analysis.scanner import MessageReport


def report_to_dict(report: "MessageReport") -> dict:
    """Aplana MessageReport/UrlReport/PhoneInfo a un dict serializable."""
    return {
        "engine_version": ENGINE_VERSION,
        "rules_version": RULES_VERSION,
        "risk": report.risk,
        "score": report.score,
        "no_content": report.no_content,
        "scam_signal": report.scam_signal,
        "brand_signal": report.brand_signal,
        "reassurance": report.reassurance,
        "urls": [
            {
                "url": u.url,
                "final_url": u.final_url,
                "risk": u.risk,
                "score": u.score,
                "signals": u.signals,
                "verified_official": u.verified_official,
                "official_brand": u.official_brand,
            }
            for u in report.urls
        ],
        "phones": [
            {
                "e164": p.e164,
                "valid": p.valid,
                "region": p.region,
                "zone": p.zone,
                "carrier": p.carrier,
                "line_type": p.line_type,
                "signals": p.signals,
            }
            for p in report.phones
        ],
        "report": {
            "complaint_text": build_complaint_text(report),
            "channels": [list(c) for c in report_channels()],
        },
    }
