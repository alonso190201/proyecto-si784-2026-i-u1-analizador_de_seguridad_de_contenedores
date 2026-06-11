"""
sanitization_service.py - Redaction helpers for sensitive analysis output.
"""
from __future__ import annotations

import copy
import re
from typing import Any, Dict, List

SENSITIVE_WORDS = (
    "password",
    "passwd",
    "pwd",
    "secret",
    "token",
    "api_key",
    "apikey",
    "access_key",
    "private_key",
    "ssh_key",
    "database_url",
    "db_pass",
    "connection_string",
    "bearer",
    "jwt",
)

SENSITIVE_ASSIGNMENT_RE = re.compile(
    r"(?i)\b([A-Z0-9_.-]*"
    r"password|passwd|pwd|secret|token|api[_-]?key|apikey|aws_access_key|"
    r"aws_secret|aws_session_token|private[_-]?key|ssh[_-]?key|database[_-]?url|"
    r"db[_-]?pass|connection[_-]?string|auth[_-]?token|bearer[_-]?token|jwt"
    r"[A-Z0-9_.-]*)(\s*[:=]\s*)(['\"]?)([^'\"\s,;]+)"
)

URL_CREDENTIAL_RE = re.compile(r"(?i)([a-z][a-z0-9+.-]*://[^:/\s]+:)([^@\s]+)(@)")
LONG_SECRET_RE = re.compile(
    r"\b("
    r"AKIA[0-9A-Z]{16}|ASIA[0-9A-Z]{16}|ghp_[A-Za-z0-9_]{20,}|"
    r"sk_live_[0-9A-Za-z]{16,}|xox[baprs]-[0-9A-Za-z-]{20,}|"
    r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"
    r")\b"
)


def redact_text(value: Any) -> str:
    """Return a string with credential-like values masked."""
    text = "" if value is None else str(value)
    text = SENSITIVE_ASSIGNMENT_RE.sub(lambda m: f"{m.group(1)}{m.group(2)}{m.group(3)}********", text)
    text = URL_CREDENTIAL_RE.sub(r"\1********\3", text)
    text = LONG_SECRET_RE.sub("********", text)
    return text


def sanitize_finding(finding: Dict[str, Any]) -> Dict[str, Any]:
    """Redact sensitive fields in a finding without mutating the original."""
    clean = copy.deepcopy(finding)
    for field in ("title", "description", "recommendation", "line_content"):
        if field in clean:
            clean[field] = redact_text(clean[field])
    return clean


def sanitize_findings(findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Redact a list of findings."""
    return [sanitize_finding(finding) for finding in findings]


def sanitize_result(result: Dict[str, Any], keep_findings: bool = True) -> Dict[str, Any]:
    """Redact an analysis result and optionally drop full findings."""
    clean = copy.deepcopy(result)
    clean["filename"] = redact_text(clean.get("filename", ""))
    if keep_findings:
        clean["findings"] = sanitize_findings(clean.get("findings", []))
    else:
        clean.pop("findings", None)
    return clean


def has_sensitive_keyword(text: Any) -> bool:
    """Return True if a string contains a sensitive-looking key name."""
    normalized = str(text or "").lower().replace("-", "_")
    return any(word in normalized for word in SENSITIVE_WORDS)
