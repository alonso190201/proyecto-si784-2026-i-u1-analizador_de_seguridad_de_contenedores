"""
scan.py - Command-line scanner for local files and repositories.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Dict, List

from analyzers.compose_analyzer import ComposeAnalyzer
from analyzers.dockerfile_analyzer import DockerfileAnalyzer
from analyzers.env_analyzer import EnvAnalyzer
from analyzers.kubernetes_analyzer import KubernetesAnalyzer
from analyzers.base_analyzer import SEVERITY_ORDER
from services.file_service import allowed_file, detect_file_type
from services.report_service import (
    build_summary,
    enrich_findings,
    generate_json_report,
    generate_sarif_report,
)

ANALYZERS = {
    "dockerfile": DockerfileAnalyzer,
    "compose": ComposeAnalyzer,
    "kubernetes": KubernetesAnalyzer,
    "env": EnvAnalyzer,
}

SKIP_DIRS = {".git", ".venv", "venv", "node_modules", "__pycache__", ".python_packages"}


def main() -> int:
    parser = argparse.ArgumentParser(description="Static security scanner for container configuration files.")
    parser.add_argument("path", nargs="?", default=".", help="File or directory to scan.")
    parser.add_argument("--format", choices=("text", "json", "sarif"), default="text", help="Output format.")
    parser.add_argument("--output", "-o", help="Write report to a file.")
    parser.add_argument(
        "--fail-on",
        choices=("critical", "high", "medium", "low", "info"),
        default=None,
        help="Exit with code 1 when a finding at this severity or higher exists.",
    )
    args = parser.parse_args()

    results = scan_path(Path(args.path))
    all_findings = [finding for result in results for finding in result.get("findings", [])]
    summary = build_summary(all_findings)

    if args.format == "json":
        output = json.dumps({"summary": summary, "results": results}, indent=2, ensure_ascii=False)
    elif args.format == "sarif":
        output = generate_sarif_report(str(Path(args.path)), "repository", all_findings, summary)
    else:
        output = render_text(results, summary)

    if args.output:
        Path(args.output).write_text(output, encoding="utf-8")
    else:
        print(output)

    if args.fail_on and exceeds_threshold(all_findings, args.fail_on):
        return 1
    return 0


def scan_path(path: Path) -> List[Dict]:
    files = [path] if path.is_file() else list(iter_candidate_files(path))
    results = []
    for file_path in files:
        if not allowed_file(file_path.name):
            continue
        try:
            content = file_path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            content = file_path.read_text(encoding="latin-1", errors="replace")
        file_type = detect_file_type(file_path.name, content)
        analyzer_cls = ANALYZERS.get(file_type)
        if not analyzer_cls:
            continue

        findings = enrich_findings([finding.to_dict() for finding in analyzer_cls().analyze(content, filename=file_path.name)])
        results.append({
            "filename": str(file_path),
            "file_type": file_type,
            "summary": build_summary(findings),
            "findings": findings,
            "lines_analyzed": len(content.splitlines()),
        })
    return results


def iter_candidate_files(root: Path):
    for file_path in root.rglob("*"):
        if not file_path.is_file():
            continue
        if any(part in SKIP_DIRS for part in file_path.parts):
            continue
        yield file_path


def render_text(results: List[Dict], summary: Dict) -> str:
    lines = [
        "Container Security Analyzer",
        f"Score: {summary.get('score')}/100 - Grade {summary.get('grade')} ({summary.get('risk_level')})",
        summary.get("score_explanation", ""),
        "",
    ]
    for result in results:
        lines.append(f"{result['filename']} [{result['file_type']}] - {result['summary']['total']} findings")
        for finding in result["findings"]:
            standards = ", ".join(finding.get("standards", []))
            suffix = f" [{standards}]" if standards else ""
            location = f":{finding['line_number']}" if finding.get("line_number") else ""
            lines.append(f"  {finding['severity'].upper()} {finding['rule_id']}{location} {finding['title']}{suffix}")
        lines.append("")
    return "\n".join(lines).rstrip()


def exceeds_threshold(findings: List[Dict], threshold: str) -> bool:
    min_order = SEVERITY_ORDER.get(threshold, 0)
    return any(SEVERITY_ORDER.get(finding.get("severity", "info"), 0) >= min_order for finding in findings)


if __name__ == "__main__":
    sys.exit(main())
