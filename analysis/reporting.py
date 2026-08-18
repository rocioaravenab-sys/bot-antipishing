"""Reporte de smishing con HUMANO EN EL BUCLE.

Este módulo NO envía denuncias automáticamente a ninguna autoridad: hacerlo
sería una acción externa irreversible y abriría la puerta al "report-bombing"
(denunciar en masa números arbitrarios). En su lugar:

  1. Guarda la evidencia en un log local (JSONL), sin salir a internet.
  2. Genera un texto de denuncia listo para que la PERSONA lo envíe ella misma
     por los canales oficiales.
"""
from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .scanner import MessageReport

DEFAULT_LOG = Path(__file__).resolve().parent.parent / "reportes.jsonl"

# Canales oficiales (Chile). Portales principales; el usuario completa la denuncia.
REPORT_CHANNELS_CL = [
    ("SUBTEL — reclamos de telecomunicaciones", "https://www.subtel.gob.cl"),
    ("SERNAC — estafas/consumo", "https://www.sernac.cl"),
    ("PDI Cibercrimen — denuncia de fraude", "https://www.pdichile.cl"),
    ("Tu operador móvil", "Reenvía el SMS a tu operador para bloquear el número"),
]


def log_evidence(report: "MessageReport", path: Path = DEFAULT_LOG) -> dict:
    """Añade un registro de evidencia al log local. Devuelve el registro."""
    record = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "risk": report.risk,
        "score": report.score,
        "phones": [
            {"e164": p.e164, "line_type": p.line_type, "zone": p.zone, "valid": p.valid}
            for p in report.phones
        ],
        "urls": [
            {"url": r.url, "final_url": r.final_url} for r in report.urls
        ],
        "scam_signal": report.scam_signal,
    }
    with path.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(record, ensure_ascii=False) + "\n")
    return record


def build_complaint_text(report: "MessageReport") -> str:
    """Texto de denuncia listo para copiar/pegar en un canal oficial."""
    fecha = datetime.now().strftime("%Y-%m-%d %H:%M")
    lines = [
        "DENUNCIA DE MENSAJE FRAUDULENTO (SMISHING)",
        f"Fecha del reporte: {fecha}",
        "",
    ]
    for p in report.phones:
        lines.append(f"Número remitente: {p.e164} (tipo de línea: {p.line_type}, zona: {p.zone})")
    for r in report.urls:
        lines.append(f"Enlace del mensaje: {r.url}")
        if r.final_url != r.url:
            lines.append(f"Destino real del enlace: {r.final_url}")
    lines += [
        "",
        "Motivo: mensaje que suplanta a una entidad para inducir un pago/entrega",
        "de datos mediante urgencia. Indicadores automáticos detectados:",
    ]
    signals: list[str] = []
    if report.scam_signal:
        signals.append(report.scam_signal)
    for p in report.phones:
        signals.extend(p.signals)
    for r in report.urls:
        signals.extend(r.signals)
    lines += [f"  - {s}" for s in signals]
    lines += ["", f"Nivel de riesgo estimado: {report.risk} (score {report.score})."]
    return "\n".join(lines)
