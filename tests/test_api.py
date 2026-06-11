from io import BytesIO
from pathlib import Path
from uuid import uuid4

from app import create_app


def make_app():
    history_file = Path(f".test_history_{uuid4().hex}.json").resolve()
    app = create_app("default")
    app.config.update(
        TESTING=True,
        HISTORY_FILE=str(history_file),
        APP_AUTH_TOKEN="",
        STORE_FULL_HISTORY=True,
    )
    return app, history_file


def cleanup(path):
    if path.exists():
        path.unlink()


def test_analyze_redacts_secrets_and_history_keeps_sanitized_findings():
    app, history_file = make_app()
    try:
        client = app.test_client()
        data = {
            "files": (BytesIO(b"SECRET_KEY=very-secret-value\n"), ".env"),
        }

        response = client.post("/api/analyze", data=data, content_type="multipart/form-data")

        assert response.status_code == 200
        result = response.get_json()[0]
        assert result["findings"][0]["line_content"] == "SECRET_KEY=********"
        assert "very-secret-value" not in str(result)

        history = client.get("/api/history").get_json()
        detail = client.get(f"/api/history/{history[0]['id']}").get_json()
        assert detail["findings"][0]["line_content"] == "SECRET_KEY=********"
        assert "very-secret-value" not in str(detail)
    finally:
        cleanup(history_file)


def test_export_json_and_sarif():
    app, history_file = make_app()
    try:
        client = app.test_client()
        payload = {
            "filename": "Dockerfile",
            "file_type": "dockerfile",
            "format": "json",
            "findings": [{
                "rule_id": "DOCKERFILE_011",
                "severity": "high",
                "title": "Falta USER",
                "description": "Corre como root",
                "recommendation": "Define USER app",
                "line_number": 0,
                "line_content": "",
                "category": "privilege",
            }],
        }

        response = client.post("/api/export", json=payload)
        assert response.status_code == 200
        assert response.content_type.startswith("application/json")

        payload["format"] = "sarif"
        response = client.post("/api/export", json=payload)
        assert response.status_code == 200
        assert response.get_json()["version"] == "2.1.0"
    finally:
        cleanup(history_file)

