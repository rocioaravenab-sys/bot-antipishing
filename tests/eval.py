"""Panel de precisión/recall del motor sobre un corpus etiquetado.

Uso:
    python tests/eval.py                # determinista (sin red): heurísticas + marcas + texto
    python tests/eval.py --live         # además consulta RDAP/TLS/threat intel
    python tests/eval.py --html         # escribe tests/eval-report.html
    python tests/eval.py --ai           # además usa el clasificador IA (requiere
                                        # configurarla en .env; gasta cuota: 1 llamada/caso)

Corpus: tests/corpus/cases.jsonl  ({id, kind, input|image_path, lang, expected_risk, notes,
requires_ai?}).
Los casos actuales son SINTÉTICOS y realistas para Chile; reemplázalos/añade casos
reales anonimizados del taller para que las métricas sirvan de verdad.

Sale con código != 0 si no se cumplen los umbrales (ver THRESHOLDS) — así CI
detecta regresiones (tests/test_eval_thresholds.py).
"""
from __future__ import annotations

import argparse
import html
import json
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))  # ejecutable como script

import config  # noqa: E402
from pipeline import analyze_image_bytes, analyze_text  # noqa: E402

CORPUS = Path(__file__).parent / "corpus" / "cases.jsonl"
HTML_OUT = Path(__file__).parent / "eval-report.html"
CLASSES = ["BAJO", "MEDIO", "ALTO"]

# Umbrales mínimos aceptables (modo determinista, corpus actual). Se gatea solo
# sobre lo que más importa: detectar el phishing (recall ALTO) y no asustar sin
# motivo (falsos positivos en ham). El recall de MEDIO NO se gatea: tras subir a
# 3 el peso de las señales de alta confianza (IP pública, punycode, TLD abusado,
# dominio DGA) el hueco se cerró casi del todo; lo que queda —una sola señal de
# baja confianza, p. ej. "muchos guiones"— se deja a propósito en BAJO para no
# marcar dominios legítimos con guiones (ver casos ham del corpus).
THRESHOLDS = {
    "alto_recall": 0.85,      # de los phishing reales, cuántos detecta como ALTO
    "ham_false_positive": 0.15,  # de los BAJO reales, cuántos sube de nivel (crying wolf)
    "accuracy": 0.75,
}


def load_cases(include_ai: bool = False) -> list[dict]:
    """Casos del corpus. Los marcados 'requires_ai' (fraudes sin enlace ni
    palabras clave, que solo un LLM detecta) se incluyen únicamente con --ai,
    para que la línea base determinista y el gate de CI no cambien."""
    cases = []
    for line in CORPUS.read_text("utf-8").splitlines():
        line = line.strip()
        if line and not line.startswith("//"):
            case = json.loads(line)
            if include_ai or not case.get("requires_ai"):
                cases.append(case)
    return cases


# Con --ai: pausa entre casos y reintentos, para no chocar con el límite por
# minuto de los planes gratuitos (el clasificador es fail-safe: ante un 429
# devuelve "sin IA", lo que falsearía la medición).
AI_PACE_SECONDS = 6
AI_RETRIES = 4
AI_RETRY_WAIT = 20
ai_unanswered: list[str] = []


def _analyze(case: dict, ai_on: bool = False):
    # El corpus es propio (sintético/anonimizado): con --ai se da el consentimiento.
    if case["kind"] == "image":
        return analyze_image_bytes(
            (CORPUS.parent / case["image_path"]).read_bytes(), ai_consent=ai_on)
    return analyze_text(case["input"], ai_consent=ai_on)


def predict(case: dict, ai_on: bool = False) -> str:
    report = _analyze(case, ai_on)
    if ai_on:
        for _ in range(AI_RETRIES):
            if report.ai is not None:
                break
            time.sleep(AI_RETRY_WAIT)
            report = _analyze(case, ai_on)
        if report.ai is None:
            ai_unanswered.append(case["id"])
        time.sleep(AI_PACE_SECONDS)
    return report.risk


def confusion(cases: list[dict], ai_on: bool = False) -> tuple[dict, list[dict]]:
    matrix = {a: {p: 0 for p in CLASSES} for a in CLASSES}
    rows = []
    for c in cases:
        exp = c["expected_risk"]
        got = predict(c, ai_on)
        matrix[exp][got] += 1
        rows.append({"id": c["id"], "expected": exp, "got": got, "ok": exp == got})
    return matrix, rows


def metrics(matrix: dict) -> dict:
    total = sum(matrix[a][p] for a in CLASSES for p in CLASSES)
    correct = sum(matrix[a][a] for a in CLASSES)
    per_class = {}
    for cls in CLASSES:
        tp = matrix[cls][cls]
        fp = sum(matrix[a][cls] for a in CLASSES if a != cls)
        fn = sum(matrix[cls][p] for p in CLASSES if p != cls)
        prec = tp / (tp + fp) if tp + fp else 0.0
        rec = tp / (tp + fn) if tp + fn else 0.0
        f1 = 2 * prec * rec / (prec + rec) if prec + rec else 0.0
        per_class[cls] = {"precision": prec, "recall": rec, "f1": f1,
                          "support": sum(matrix[cls].values())}
    bajo_total = sum(matrix["BAJO"].values())
    ham_fp = (bajo_total - matrix["BAJO"]["BAJO"]) / bajo_total if bajo_total else 0.0
    return {
        "accuracy": correct / total if total else 0.0,
        "per_class": per_class,
        "alto_recall": per_class["ALTO"]["recall"],
        "ham_false_positive": ham_fp,
        "total": total,
    }


def _bar(v: float, n: int = 20) -> str:
    return "█" * round(v * n) + "·" * (n - round(v * n))


def print_report(matrix: dict, m: dict, rows: list[dict], passed: bool) -> None:
    print("\n=== Matriz de confusión (fila = esperado, columna = predicho) ===")
    print(f"{'':8}" + "".join(f"{p:>8}" for p in CLASSES))
    for a in CLASSES:
        print(f"{a:8}" + "".join(f"{matrix[a][p]:>8}" for p in CLASSES))

    print("\n=== Por clase ===")
    print(f"{'clase':8}{'prec':>8}{'recall':>8}{'f1':>8}{'n':>6}")
    for cls in CLASSES:
        pc = m["per_class"][cls]
        print(f"{cls:8}{pc['precision']:>8.2f}{pc['recall']:>8.2f}{pc['f1']:>8.2f}{pc['support']:>6}")

    print("\n=== Métricas clave ===")
    print(f"  accuracy             {m['accuracy']:.2f}  {_bar(m['accuracy'])}  (mín {THRESHOLDS['accuracy']})")
    print(f"  recall ALTO          {m['alto_recall']:.2f}  {_bar(m['alto_recall'])}  (mín {THRESHOLDS['alto_recall']})")
    print(f"  falsos positivos ham {m['ham_false_positive']:.2f}  {_bar(m['ham_false_positive'])}  (máx {THRESHOLDS['ham_false_positive']})")
    print(f"  recall MEDIO         {m['per_class']['MEDIO']['recall']:.2f}  {_bar(m['per_class']['MEDIO']['recall'])}  (informativo, no se gatea)")

    miss = [r for r in rows if not r["ok"]]
    if miss:
        print(f"\n=== Fallos ({len(miss)}) ===")
        for r in miss:
            print(f"  {r['id']:40} esperado {r['expected']:6} -> {r['got']}")

    print("\n" + ("✅ UMBRALES OK" if passed else "❌ UMBRALES NO CUMPLIDOS"))


def write_html(matrix: dict, m: dict, rows: list[dict], passed: bool) -> None:
    def cell(v):
        return f"<td>{v}</td>"
    mrows = "".join(
        "<tr><th>" + a + "</th>" + "".join(cell(matrix[a][p]) for p in CLASSES) + "</tr>"
        for a in CLASSES
    )
    prows = "".join(
        f"<tr><th>{c}</th><td>{m['per_class'][c]['precision']:.2f}</td>"
        f"<td>{m['per_class'][c]['recall']:.2f}</td><td>{m['per_class'][c]['f1']:.2f}</td>"
        f"<td>{m['per_class'][c]['support']}</td></tr>"
        for c in CLASSES
    )
    miss = "".join(
        f"<li><code>{html.escape(r['id'])}</code>: esperado <b>{r['expected']}</b>, obtenido <b>{r['got']}</b></li>"
        for r in rows if not r["ok"]
    ) or "<li>ninguno</li>"
    status = "OK" if passed else "NO CUMPLIDO"
    doc = f"""<!doctype html><meta charset=utf-8>
<title>Eval motor anti-phishing</title>
<style>
 body{{font-family:system-ui,sans-serif;max-width:720px;margin:2rem auto;padding:0 1rem;color:#111}}
 table{{border-collapse:collapse;margin:1rem 0}} td,th{{border:1px solid #ccc;padding:.4rem .7rem;text-align:center}}
 .k{{font-size:1.1rem}} .ok{{color:#16a34a}} .bad{{color:#dc2626}}
</style>
<h1>Evaluación del motor anti-phishing</h1>
<p>Corpus: {m['total']} casos · estado umbrales:
   <b class="{ 'ok' if passed else 'bad' }">{status}</b></p>
<h2>Matriz de confusión</h2>
<table><tr><th></th>{"".join(f"<th>{p}</th>" for p in CLASSES)}</tr>{mrows}</table>
<h2>Por clase</h2>
<table><tr><th>clase</th><th>precisión</th><th>recall</th><th>F1</th><th>n</th></tr>{prows}</table>
<h2 class=k>Métricas clave</h2>
<ul>
 <li>Accuracy: <b>{m['accuracy']:.2f}</b></li>
 <li>Recall ALTO (phishing detectado): <b>{m['alto_recall']:.2f}</b> (mín {THRESHOLDS['alto_recall']})</li>
 <li>Falsos positivos en ham: <b>{m['ham_false_positive']:.2f}</b> (máx {THRESHOLDS['ham_false_positive']})</li>
</ul>
<h2>Casos fallados</h2><ul>{miss}</ul>
"""
    HTML_OUT.write_text(doc, "utf-8")
    print(f"\nHTML -> {HTML_OUT}")


def run(live: bool, want_html: bool, ai: bool = False) -> bool:
    if not live:
        config.DOMAIN_INTEL = False  # determinista: sin RDAP/TLS
    config.AI_CLASSIFIER = ai  # la IA solo se mide si se pide explícitamente
    ai_on = False
    if ai:
        from analysis import ai_classifier
        ai_on = ai_classifier.enabled()
        if ai_on:
            print(f"IA: {ai_classifier.provider()} · {config.AI_MODEL}")
        else:
            print("⚠️  --ai sin IA configurada en .env: se evalúa sin IA.")

    cases = load_cases(include_ai=ai_on)
    matrix, rows = confusion(cases, ai_on)
    m = metrics(matrix)
    passed = (
        m["alto_recall"] >= THRESHOLDS["alto_recall"]
        and m["ham_false_positive"] <= THRESHOLDS["ham_false_positive"]
        and m["accuracy"] >= THRESHOLDS["accuracy"]
    )
    print_report(matrix, m, rows, passed)
    if ai_unanswered:
        print(f"⚠️  La IA no respondió en {len(ai_unanswered)} caso(s) "
              f"(evaluados sin IA): {', '.join(ai_unanswered)}")
    if want_html:
        write_html(matrix, m, rows, passed)
    return passed


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--live", action="store_true", help="consulta RDAP/TLS/threat intel")
    ap.add_argument("--html", action="store_true", help="escribe tests/eval-report.html")
    ap.add_argument("--ai", action="store_true", help="usa el clasificador IA (Qwen/Claude)")
    args = ap.parse_args()
    sys.exit(0 if run(args.live, args.html, args.ai) else 1)


if __name__ == "__main__":
    main()
