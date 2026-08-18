"""Prueba local sin Discord: analiza una imagen desde la línea de comandos.

Uso:
    python test_local.py ruta/a/captura.png
"""
from __future__ import annotations

import sys

from analysis.scanner import scan_message
from extractors.ocr import extract_urls_from_image
from extractors.qr import extract_qr_urls


def main() -> None:
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    if len(args) != 1:
        print("Uso: python test_local.py <imagen> [--reporte]")
        raise SystemExit(1)

    with open(args[0], "rb") as fh:
        data = fh.read()

    qr_urls = extract_qr_urls(data)
    ocr_urls, ocr_text = extract_urls_from_image(data)

    print("=== Texto OCR ===")
    print(ocr_text.strip() or "(vacío)")
    print("\n=== URLs por QR ===", qr_urls or "(ninguna)")
    print("=== URLs por OCR ===", ocr_urls or "(ninguna)")

    urls = list(dict.fromkeys(qr_urls + ocr_urls))
    report = scan_message(urls, ocr_text)

    print("\n=== Remitente (teléfono) ===")
    if not report.phones:
        print("(no se detectó número)")
    for ph in report.phones:
        print(f"{ph.e164} · {'válido' if ph.valid else 'NO válido'} · "
              f"zona: {ph.zone} · tipo: {ph.line_type} · operador: {ph.carrier}")
        for s in ph.signals:
            print("  -", s)

    print("\n=== Análisis de URLs ===")
    for r in report.urls:
        print(f"\nURL: {r.url}")
        if r.final_url != r.url:
            print(f"Destino: {r.final_url}")
        for s in r.signals:
            print("  -", s)

    if report.scam_signal:
        print("\n=== Texto ===\n  -", report.scam_signal)

    print(f"\n=== VEREDICTO: {report.risk} (score total {report.score}) ===")

    # Con --reporte: guarda evidencia local y muestra la denuncia pre-rellenada.
    if "--reporte" in sys.argv:
        from analysis.reporting import (
            REPORT_CHANNELS_CL,
            build_complaint_text,
            log_evidence,
        )

        rec = log_evidence(report)
        print("\n=== Evidencia guardada en reportes.jsonl ===")
        print(f"  {rec['timestamp']} · riesgo {rec['risk']}")
        print("\n=== Denuncia lista para enviar (cópiala) ===")
        print(build_complaint_text(report))
        print("\n=== Canales oficiales (envíala tú) ===")
        for nombre, url in REPORT_CHANNELS_CL:
            print(f"  • {nombre}: {url}")


if __name__ == "__main__":
    main()
