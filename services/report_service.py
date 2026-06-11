"""
report_service.py - Score calculation and report export helpers.
"""
from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any, Dict, List

from services.sanitization_service import sanitize_findings

SEVERITY_WEIGHTS = {"critical": 25, "high": 15, "medium": 7, "low": 2, "info": 0}
SEVERITY_COLORS = {
    "critical": "#dc2626",
    "high": "#ea580c",
    "medium": "#ca8a04",
    "low": "#2563eb",
    "info": "#64748b",
}
SEVERITY_NAMES_ES = {
    "critical": "CRITICO",
    "high": "ALTO",
    "medium": "MEDIO",
    "low": "BAJO",
    "info": "INFO",
}

STANDARD_MAP = {
    "DOCKERFILE_001": ["CIS Docker 4.1", "OWASP Docker: Least Privilege"],
    "DOCKERFILE_002": ["CIS Docker 5.4"],
    "DOCKERFILE_003": ["CIS Docker 4.10", "OWASP Secrets Management"],
    "DOCKERFILE_004": ["CIS Docker 4.10", "OWASP Secrets Management"],
    "DOCKERFILE_005": ["CIS Docker 4.3", "SLSA Supply Chain"],
    "DOCKERFILE_007": ["CIS Docker 4.8"],
    "DOCKERFILE_009": ["SLSA Supply Chain", "OWASP Docker: Trusted Images"],
    "DOCKERFILE_010": ["CIS Docker 4.10", "OWASP Secrets Management"],
    "DOCKERFILE_011": ["CIS Docker 4.1"],
    "COMPOSE_001": ["CIS Docker 5.4"],
    "COMPOSE_002": ["CIS Docker 5.9"],
    "COMPOSE_003": ["CIS Docker 5.15"],
    "COMPOSE_006": ["CIS Docker 5.31"],
    "COMPOSE_009": ["OWASP Secrets Management"],
    "COMPOSE_010": ["CIS Docker 5.3"],
    "KUBERNETES_001": ["NSA/CISA Kubernetes: RBAC", "Kubernetes Least Privilege"],
    "KUBERNETES_002": ["NSA/CISA Kubernetes: RBAC"],
    "KUBERNETES_004": ["Pod Security Standards: Restricted"],
    "KUBERNETES_005": ["Pod Security Standards: Restricted"],
    "KUBERNETES_007": ["Pod Security Standards: Restricted"],
    "KUBERNETES_008": ["Pod Security Standards: Restricted"],
    "KUBERNETES_009": ["Pod Security Standards: Restricted"],
    "KUBERNETES_011": ["Pod Security Standards: Restricted"],
    "KUBERNETES_012": ["NSA/CISA Kubernetes Hardening"],
    "KUBERNETES_014": ["Kubernetes Resource Management"],
    "ENV_001": ["OWASP Secrets Management"],
    "ENV_002": ["OWASP Secrets Management"],
}


def calculate_score(findings: List[Dict[str, Any]]) -> int:
    """Calculate a security score from 0 (worst) to 100 (best)."""
    penalty = sum(SEVERITY_WEIGHTS.get(f.get("severity", "info"), 0) for f in findings)
    return max(0, 100 - penalty)


def enrich_findings(findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Add standards metadata to findings."""
    enriched = []
    for finding in sanitize_findings(findings):
        rule_id = finding.get("rule_id", "")
        finding["standards"] = STANDARD_MAP.get(rule_id, [])
        enriched.append(finding)
    return enriched


def build_summary(findings: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Build a statistics summary dict from a findings list."""
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    categories: Dict[str, int] = {}
    standards: Dict[str, int] = {}

    for finding in findings:
        sev = finding.get("severity", "info")
        counts[sev] = counts.get(sev, 0) + 1
        cat = finding.get("category", "general")
        categories[cat] = categories.get(cat, 0) + 1
        for standard in finding.get("standards", []):
            standards[standard] = standards.get(standard, 0) + 1

    score = calculate_score(findings)
    grade = _score_to_grade(score)
    penalty = 100 - score
    return {
        "total": len(findings),
        "counts": counts,
        "categories": categories,
        "standards": standards,
        "score": score,
        "grade": grade,
        "grade_color": _grade_color(grade),
        "risk_level": _risk_level(grade),
        "score_explanation": (
            f"Penalizacion total: {penalty} puntos "
            f"(critico={counts.get('critical', 0)}, alto={counts.get('high', 0)}, "
            f"medio={counts.get('medium', 0)}, bajo={counts.get('low', 0)})."
        ),
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


def _risk_level(grade: str) -> str:
    return {"A": "Bajo", "B": "Controlado", "C": "Moderado", "D": "Alto", "F": "Critico"}.get(grade, "Desconocido")


def _grade_color(grade: str) -> str:
    return {"A": "#16a34a", "B": "#65a30d", "C": "#ca8a04", "D": "#ea580c", "F": "#dc2626"}.get(grade, "#64748b")


def generate_json_report(
    filename: str,
    file_type: str,
    findings: List[Dict[str, Any]],
    summary: Dict[str, Any],
) -> str:
    """Generate a machine-readable JSON report."""
    payload = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "filename": filename,
        "file_type": file_type,
        "summary": summary,
        "findings": enrich_findings(findings),
    }
    return json.dumps(payload, indent=2, ensure_ascii=False)


def generate_sarif_report(
    filename: str,
    file_type: str,
    findings: List[Dict[str, Any]],
    summary: Dict[str, Any],
) -> str:
    """Generate a minimal SARIF 2.1.0 report for CI systems."""
    enriched = enrich_findings(findings)
    rules = {}
    results = []

    for finding in enriched:
        rule_id = finding.get("rule_id", "ASC_UNKNOWN")
        rules.setdefault(rule_id, {
            "id": rule_id,
            "name": finding.get("title", rule_id),
            "shortDescription": {"text": finding.get("title", "")},
            "help": {"text": finding.get("recommendation", "")},
            "properties": {
                "severity": finding.get("severity", "info"),
                "category": finding.get("category", "general"),
                "standards": finding.get("standards", []),
            },
        })
        region = {}
        if finding.get("line_number"):
            region["startLine"] = finding["line_number"]
        results.append({
            "ruleId": rule_id,
            "level": _sarif_level(finding.get("severity", "info")),
            "message": {"text": finding.get("description", "")},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": filename},
                    "region": region,
                }
            }],
        })

    payload = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "Container Security Analyzer",
                    "informationUri": "https://github.com/alonso190201/proyecto-si784-2026-i-u1-analizador_de_seguridad_de_contenedores",
                    "rules": list(rules.values()),
                }
            },
            "properties": {"score": summary.get("score"), "grade": summary.get("grade"), "file_type": file_type},
            "results": results,
        }],
    }
    return json.dumps(payload, indent=2, ensure_ascii=False)


def _sarif_level(severity: str) -> str:
    if severity in ("critical", "high"):
        return "error"
    if severity == "medium":
        return "warning"
    return "note"


def generate_html_report(
    filename: str,
    file_type: str,
    findings: List[Dict[str, Any]],
    summary: Dict[str, Any],
) -> str:
    """Generate a self-contained standalone HTML report string."""
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    enriched = enrich_findings(findings)
    findings_html = ""

    for finding in enriched:
        sev = finding.get("severity", "info")
        color = SEVERITY_COLORS.get(sev, "#64748b")
        sev_name = SEVERITY_NAMES_ES.get(sev, sev.upper())
        line = f"Linea {finding['line_number']}" if finding.get("line_number") else ""
        code = f"<code>{_esc(finding['line_content'])}</code>" if finding.get("line_content") else ""
        standards = ", ".join(finding.get("standards", []))
        standards_html = f"<p class='standards'>{_esc(standards)}</p>" if standards else ""
        findings_html += f"""
        <article class="finding" style="border-left-color:{color};">
          <div class="finding-head">
            <strong>{_esc(finding.get('title', ''))}</strong>
            <span style="background:{color};">{sev_name}</span>
          </div>
          <p>{_esc(finding.get('description', ''))}</p>
          {"<p class='line'>" + line + " " + code + "</p>" if line or code else ""}
          {standards_html}
          <p class="recommendation">Recomendacion: {_esc(finding.get('recommendation', ''))}</p>
        </article>"""

    counts = summary.get("counts", {})
    score = summary.get("score", 0)
    grade = summary.get("grade", "F")
    grade_color = summary.get("grade_color", "#dc2626")

    return f"""<!DOCTYPE html>
<html lang="es">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Reporte de Seguridad - {_esc(filename)}</title>
<style>
  body{{font-family:Inter,Segoe UI,system-ui,sans-serif;background:#f6f7fb;color:#111827;margin:0;padding:32px;}}
  main{{max-width:1040px;margin:auto;}}
  h1{{margin:0 0 4px;font-size:30px;}} h2{{margin-top:28px;border-bottom:1px solid #d8dee9;padding-bottom:8px;}}
  .muted{{color:#64748b;}} .grid{{display:grid;grid-template-columns:repeat(auto-fit,minmax(140px,1fr));gap:12px;margin:18px 0;}}
  .stat{{background:white;border:1px solid #e5e7eb;border-radius:8px;padding:16px;}} .val{{font-size:30px;font-weight:800;}}
  .finding{{background:white;border:1px solid #e5e7eb;border-left:5px solid;border-radius:8px;margin:12px 0;padding:14px 16px;}}
  .finding-head{{display:flex;justify-content:space-between;gap:12px;align-items:center;}}
  .finding-head span{{color:white;padding:3px 10px;border-radius:999px;font-size:12px;font-weight:800;}}
  code{{background:#f1f5f9;color:#92400e;padding:2px 6px;border-radius:4px;}} .line,.standards{{font-size:12px;color:#64748b;}}
  .recommendation{{color:#075985;font-weight:600;}}
</style>
</head>
<body>
<main>
<h1>Analizador de Seguridad de Contenedores</h1>
<p class="muted">Reporte generado: {now}</p>
<h2>{_esc(filename)} <span class="muted">({file_type.upper()})</span></h2>
<div class="grid">
  <div class="stat"><div class="val" style="color:{grade_color}">{grade}</div><div class="muted">Grado</div></div>
  <div class="stat"><div class="val" style="color:{grade_color}">{score}</div><div class="muted">Puntaje / 100</div></div>
  <div class="stat"><div class="val" style="color:#dc2626">{counts.get('critical', 0)}</div><div class="muted">Criticos</div></div>
  <div class="stat"><div class="val" style="color:#ea580c">{counts.get('high', 0)}</div><div class="muted">Altos</div></div>
  <div class="stat"><div class="val" style="color:#ca8a04">{counts.get('medium', 0)}</div><div class="muted">Medios</div></div>
</div>
<p class="muted">{_esc(summary.get('score_explanation', ''))}</p>
<h2>Hallazgos ({summary.get('total', 0)})</h2>
{findings_html if findings_html else '<p style="color:#16a34a;">No se detectaron problemas.</p>'}
<p class="muted" style="margin-top:32px;font-size:12px;">Analisis estatico: no se ejecutaron contenedores.</p>
</main>
</body>
</html>"""


def _esc(text: Any) -> str:
    """HTML-escape a value."""
    return (
        str(text)
        .replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
    )
