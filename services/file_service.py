"""
file_service.py - File validation, type detection and safe reading.
"""
from __future__ import annotations
import os
import re
from typing import Optional, Tuple
from werkzeug.datastructures import FileStorage
import yaml

ALLOWED_EXTENSIONS = {
    "dockerfile", "yml", "yaml", "env", "txt", "cfg", "conf", "json", "toml",
}

# Max file size: 2 MB
MAX_FILE_SIZE = 2 * 1024 * 1024


def allowed_file(filename: str) -> bool:
    """Return True if the filename has an allowed extension."""
    name = filename.lower()
    # Dockerfile has no extension
    if name == "dockerfile" or name.startswith("dockerfile."):
        return True
    # .env files
    if name.startswith(".env") or name == ".env":
        return True
    ext = name.rsplit(".", 1)[-1] if "." in name else ""
    return ext in ALLOWED_EXTENSIONS


def detect_file_type(filename: str, content: str) -> str:
    """
    Detect the semantic type of the uploaded file.
    Returns one of: 'dockerfile', 'compose', 'kubernetes', 'env', 'unknown'
    """
    name = filename.lower()

    # Explicit name matches
    if name == "dockerfile" or re.match(r"dockerfile(\.\w+)?$", name):
        return "dockerfile"
    if re.match(r"docker-compose[\w.-]*\.(yml|yaml)$", name):
        return "compose"
    if name.startswith(".env") or name == ".env":
        return "env"

    # Content-based detection for YAML files
    if name.endswith((".yml", ".yaml")):
        return _detect_yaml_type(content)

    return "unknown"


def _detect_yaml_type(content: str) -> str:
    """Inspect YAML content to distinguish compose from kubernetes."""
    try:
        docs = [doc for doc in yaml.safe_load_all(content) if doc]
    except yaml.YAMLError:
        return "unknown"

    if not docs:
        return "unknown"

    data = docs[0]
    if not isinstance(data, dict):
        return "unknown"

    # docker-compose has a 'services' top-level key
    if "services" in data and isinstance(data["services"], dict):
        return "compose"

    # Kubernetes has 'apiVersion' and 'kind'
    if any(isinstance(doc, dict) and "apiVersion" in doc and "kind" in doc for doc in docs):
        return "kubernetes"

    return "unknown"


def read_file_content(file: FileStorage) -> Tuple[Optional[str], Optional[str]]:
    """
    Safely read a FileStorage object.
    Returns (content, error_message). On success error_message is None.
    """
    try:
        raw = file.read()
        if len(raw) > MAX_FILE_SIZE:
            return None, f"File exceeds maximum allowed size of {MAX_FILE_SIZE // 1024} KB."
        # Try UTF-8, fall back to latin-1
        try:
            return raw.decode("utf-8"), None
        except UnicodeDecodeError:
            return raw.decode("latin-1", errors="replace"), None
    except Exception as exc:
        return None, f"Failed to read file: {exc}"
