"""
auth_service.py - Optional API token protection for production deployments.
"""
from __future__ import annotations

import hmac
from functools import wraps
from typing import Callable

from flask import current_app, jsonify, request


def require_api_token(view: Callable) -> Callable:
    """Require a bearer token only when APP_AUTH_TOKEN is configured."""
    @wraps(view)
    def wrapped(*args, **kwargs):
        expected = current_app.config.get("APP_AUTH_TOKEN")
        if not expected:
            return view(*args, **kwargs)

        provided = request.headers.get("X-API-Token", "")
        auth_header = request.headers.get("Authorization", "")
        if auth_header.lower().startswith("bearer "):
            provided = auth_header[7:].strip()

        if not provided or not hmac.compare_digest(provided, expected):
            return jsonify({"error": "No autorizado. Token de API requerido."}), 401

        return view(*args, **kwargs)

    return wrapped
