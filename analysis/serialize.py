"""Serialización de MessageReport a un dict JSON para la API REST."""
from __future__ import annotations

from typing import TYPE_CHECKING

from analysis.reporting import REPORT_CHANNELS_CL, build_complaint_text

if TYPE_CHECKING:
    from analysis.scanner import MessageReport


def report_to_dict(report: "MessageReport") -> dict:
    """Aplana MessageReport/UrlReport/PhoneInfo a un dict serializable."""
    return {
        "risk": report.risk,
        "score": report.score,
        "scam_signal": report.scam_signal,
        "urls": [
            {
                "url": u.url,
                "final_url": u.final_url,
                "risk": u.risk,
                "score": u.score,
                "signals": u.signals,
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
            "channels": [list(c) for c in REPORT_CHANNELS_CL],
        },
    }
