"""
report_service.py - Security score calculation and HTML report export.
"""
from __future__ import annotations
from datetime import datetime, timezone
from typing import Any, Dict, List

SEVERITY_WEIGHTS = {"critical": 25, "high": 15, "medium": 7, "low": 2, "info": 0}
SEVERITY_COLORS = {
    "critical": "#ef4444",
    "high": "#f97316",
    "medium": "#eab308",
    "low": "#3b82f6",
    "info": "#6b7280",
}
SEVERITY_NAMES_ES = {
    "critical": "CRÍTICO",
    "high": "ALTO",
    "medium": "MEDIO",
    "low": "BAJO",
    "info": "INFO",
}


def calculate_score(findings: List[Dict[str, Any]]) -> int:
    """
    Calculate a security score from 0 (worst) to 100 (best).
    Each finding deducts weighted points. Score is floored at 0.
    """
    penalty = sum(SEVERITY_WEIGHTS.get(f.get("severity", "info"), 0) for f in findings)
    score = max(0, 100 - penalty)
    return score


def build_summary(findings: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Build a statistics summary dict from a findings list."""
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    categories: Dict[str, int] = {}
    for f in findings:
        sev = f.get("severity", "info")
        counts[sev] = counts.get(sev, 0) + 1
        cat = f.get("category", "general")
        categories[cat] = categories.get(cat, 0) + 1

    score = calculate_score(findings)
    grade = _score_to_grade(score)
    return {
        "total": len(findings),
        "counts": counts,
        "categories": categories,
        "score": score,
        "grade": grade,
        "grade_color": _grade_color(grade),
    }


def _score_to_grade(score: int) -> str:
    if score >= 90:
        return "A"
    if score >= 75:
        return "B"
    if score >= 60:
        return "C"
    if score >= 40:
        return "D"
    return "F"


def _grade_color(grade: str) -> str:
    return {"A": "#22c55e", "B": "#84cc16", "C": "#eab308", "D": "#f97316", "F": "#ef4444"}.get(grade, "#6b7280")


def generate_html_report(
    filename: str,
    file_type: str,
    findings: List[Dict[str, Any]],
    summary: Dict[str, Any],
) -> str:
    """Generate a self-contained standalone HTML report string."""
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    findings_html = ""
    for f in findings:
        sev = f.get("severity", "info")
        color = SEVERITY_COLORS.get(sev, "#6b7280")
        sev_name = SEVERITY_NAMES_ES.get(sev, sev.upper())
        ln = f"Línea {f['line_number']}" if f.get("line_number") else ""
        lc = f"<code>{_esc(f['line_content'])}</code>" if f.get("line_content") else ""
        findings_html += f"""
        <div class="finding" style="border-left:4px solid {color}; margin:12px 0; padding:12px 16px; background:#1e2235; border-radius:6px;">
          <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:6px;">
            <strong style="color:#e2e8f0;">{_esc(f.get('title',''))}</strong>
            <span style="background:{color};color:#000;padding:2px 10px;border-radius:12px;font-size:12px;font-weight:700;">{sev_name}</span>
          </div>
          <p style="color:#94a3b8;margin:4px 0;">{_esc(f.get('description',''))}</p>
          {"<p style='color:#64748b;font-size:12px;margin:4px 0;'>" + ln + " " + lc + "</p>" if ln or lc else ""}
          <p style="color:#00d4ff;margin:6px 0 0;font-size:13px;">💡 {_esc(f.get('recommendation',''))}</p>
        </div>"""

    score = summary.get("score", 0)
    grade = summary.get("grade", "F")
    grade_color = summary.get("grade_color", "#ef4444")
    counts = summary.get("counts", {})

    return f"""<!DOCTYPE html>
<html lang="es">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Reporte de Seguridad — {_esc(filename)}</title>
<style>
  body{{font-family:'Segoe UI',system-ui,sans-serif;background:#0a0e1a;color:#e2e8f0;margin:0;padding:24px;}}
  h1{{color:#00d4ff;}} h2{{color:#7dd3fc;border-bottom:1px solid #1e3a5f;padding-bottom:8px;}}
  .grid{{display:grid;grid-template-columns:repeat(auto-fit,minmax(140px,1fr));gap:12px;margin:16px 0;}}
  .stat{{background:#0d1117;border:1px solid #1e293b;border-radius:8px;padding:16px;text-align:center;}}
  .stat .val{{font-size:2rem;font-weight:700;}} .stat .lbl{{font-size:12px;color:#64748b;}}
  code{{background:#0d1117;padding:2px 6px;border-radius:4px;font-size:12px;color:#f59e0b;}}
  .badge{{display:inline-block;padding:2px 8px;border-radius:10px;font-size:11px;font-weight:600;}}
</style>
</head>
<body>
<h1>🔒 Analizador de Seguridad de Contenedores</h1>
<p style="color:#64748b;">Reporte generado: {now}</p>
<h2>Archivo: {_esc(filename)} <span class="badge" style="background:#1e3a5f;color:#7dd3fc;">{file_type.upper()}</span></h2>

<div class="grid">
  <div class="stat"><div class="val" style="color:{grade_color}">{grade}</div><div class="lbl">Grado de Seguridad</div></div>
  <div class="stat"><div class="val" style="color:{grade_color}">{score}</div><div class="lbl">Puntuación / 100</div></div>
  <div class="stat"><div class="val" style="color:#ef4444">{counts.get('critical',0)}</div><div class="lbl">Crítico</div></div>
  <div class="stat"><div class="val" style="color:#f97316">{counts.get('high',0)}</div><div class="lbl">Alto</div></div>
  <div class="stat"><div class="val" style="color:#eab308">{counts.get('medium',0)}</div><div class="lbl">Medio</div></div>
  <div class="stat"><div class="val" style="color:#3b82f6">{counts.get('low',0)}</div><div class="lbl">Bajo</div></div>
</div>

<h2>Hallazgos ({summary.get('total',0)} en total)</h2>
{findings_html if findings_html else '<p style="color:#22c55e;">✅ No se detectaron problemas.</p>'}
<hr style="border-color:#1e293b;margin-top:32px;">
<p style="color:#334155;font-size:12px;">Generado por el Analizador de Seguridad de Contenedores · Sólo análisis estático — no se ejecutaron contenedores.</p>
</body>
</html>"""


def _esc(text: str) -> str:
    """HTML-escape a string."""
    return (
        str(text)
        .replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
    )
