"""
routes/api.py - REST API endpoints for file analysis and reporting.
"""
from __future__ import annotations
import re
import uuid
from flask import Blueprint, request, jsonify, Response

from services.file_service import allowed_file, detect_file_type, read_file_content
from services.report_service import (
    build_summary,
    enrich_findings,
    generate_html_report,
    generate_json_report,
    generate_sarif_report,
)
from services.sanitization_service import sanitize_result
from services import history_service

from analyzers.dockerfile_analyzer import DockerfileAnalyzer
from analyzers.compose_analyzer import ComposeAnalyzer
from analyzers.kubernetes_analyzer import KubernetesAnalyzer
from analyzers.env_analyzer import EnvAnalyzer

api_bp = Blueprint("api", __name__, url_prefix="/api")

# Map file type to analyzer class
ANALYZERS = {
    "dockerfile": DockerfileAnalyzer,
    "compose": ComposeAnalyzer,
    "kubernetes": KubernetesAnalyzer,
    "env": EnvAnalyzer,
}


@api_bp.route("/analyze", methods=["POST"])
def analyze():
    """
    Accept one or more uploaded files, analyze each, and return a JSON
    array of analysis results.
    """
    if "files" not in request.files:
        return jsonify({"error": "No files provided."}), 400

    uploaded = request.files.getlist("files")
    if not uploaded:
        return jsonify({"error": "Empty file list."}), 400

    results = []
    for file in uploaded:
        filename = file.filename or "unnamed"

        # Validate extension
        if not allowed_file(filename):
            results.append({
                "filename": filename,
                "error": f"Tipo de archivo no soportado: '{filename}'. "
                         "Tipos aceptados: Dockerfile, docker-compose.yml, *.yaml, .env, *.cfg, *.conf",
            })
            continue

        # Read content
        content, read_error = read_file_content(file)
        if read_error:
            results.append({"filename": filename, "error": read_error})
            continue

        # Detect type
        file_type = detect_file_type(filename, content)
        if file_type == "unknown":
            file_type = _guess_from_content(content)

        # Pick analyzer
        analyzer_cls = ANALYZERS.get(file_type)
        if not analyzer_cls:
            results.append({
                "filename": filename,
                "file_type": file_type,
                "error": "No se pudo determinar el tipo de archivo. Asegúrate de que sea un Dockerfile, "
                         "docker-compose, Kubernetes YAML, o archivo .env.",
            })
            continue

        # Run analysis
        analyzer = analyzer_cls()
        raw_findings = analyzer.analyze(content, filename=filename)
        findings_dicts = enrich_findings([f.to_dict() for f in raw_findings])
        summary = build_summary(findings_dicts)

        result_id = str(uuid.uuid4())
        
        result = {
            "id": result_id,
            "filename": filename,
            "file_type": file_type,
            "findings": findings_dicts,
            "summary": summary,
            "lines_analyzed": len(content.splitlines()),
        }
        result = sanitize_result(result)
        results.append(result)

        # Store sanitized result in local JSON history. No database is required.
        history_service.add_entry(result)

    return jsonify(results), 200


@api_bp.route("/history", methods=["GET"])
def history():
    """Return the persistent analysis history summary (newest first)."""
    return jsonify(history_service.get_history_summary()), 200

@api_bp.route("/history/<entry_id>", methods=["GET"])
def history_detail(entry_id):
    """Return a full analysis entry by its ID."""
    entry = history_service.get_entry_by_id(entry_id)
    if not entry:
        return jsonify({"error": "Análisis no encontrado"}), 404
    return jsonify(entry), 200


@api_bp.route("/history", methods=["DELETE"])
def clear_history():
    """Clear the persistent analysis history."""
    history_service.clear_history()
    return jsonify({"message": "Historial borrado."}), 200


@api_bp.route("/export", methods=["POST"])
def export_report():
    """
    Accept a JSON analysis result and return a standalone HTML report
    as a downloadable file.
    """
    data = request.get_json(silent=True)
    if not data:
        return jsonify({"error": "No JSON body provided."}), 400

    filename = data.get("filename", "unknown")
    file_type = data.get("file_type", "unknown")
    findings = enrich_findings(data.get("findings", []))
    summary = data.get("summary") or build_summary(findings)
    export_format = str(data.get("format", "html")).lower()

    if export_format == "json":
        body = generate_json_report(filename, file_type, findings, summary)
        mimetype = "application/json"
        extension = "json"
    elif export_format == "sarif":
        body = generate_sarif_report(filename, file_type, findings, summary)
        mimetype = "application/sarif+json"
        extension = "sarif"
    else:
        body = generate_html_report(filename, file_type, findings, summary)
        mimetype = "text/html"
        extension = "html"

    safe_name = filename.replace("/", "_").replace("\\", "_")
    return Response(
        body,
        mimetype=mimetype,
        headers={"Content-Disposition": f'attachment; filename="reporte_{safe_name}.{extension}"'},
    )


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _guess_from_content(content: str) -> str:
    """Fallback type detection based on content keywords."""
    if content.lstrip().startswith("FROM "):
        return "dockerfile"
    lc = content.lower()
    if "apiversion:" in lc and "kind:" in lc:
        return "kubernetes"
    if "services:" in lc and ("image:" in lc or "build:" in lc):
        return "compose"
    if re.search(r"^\w+=", content, re.MULTILINE):
        return "env"
    return "unknown"
