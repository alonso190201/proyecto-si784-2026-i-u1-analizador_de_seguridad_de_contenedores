"""
env_analyzer.py - Security rule engine for .env and environment files.
Detects exposed secrets, API keys, passwords, and tokens.
"""
from __future__ import annotations
import re
from typing import List
from .base_analyzer import BaseAnalyzer, Finding, CRITICAL, HIGH, MEDIUM, LOW

# Patterns for key names that indicate sensitive data
SENSITIVE_KEY_PATTERNS = [
    (re.compile(r"(?i)(password|passwd|pwd)"), CRITICAL, "contraseña"),
    (re.compile(r"(?i)(secret[_-]?key|secret)"), CRITICAL, "secreto"),
    (re.compile(r"(?i)(api[_-]?key|apikey)"), CRITICAL, "clave API"),
    (re.compile(r"(?i)(token|auth[_-]?token|access[_-]?token|jwt|bearer)"), CRITICAL, "token"),
    (re.compile(r"(?i)(aws_access_key|aws_secret|aws_session_token)"), CRITICAL, "credencial AWS"),
    (re.compile(r"(?i)(private[_-]?key|rsa|pem)"), CRITICAL, "clave privada"),
    (re.compile(r"(?i)(database[_-]?url|db[_-]?url|connection[_-]?string)"), HIGH, "URL de base de datos"),
    (re.compile(r"(?i)(db[_-]?pass|database[_-]?pass)"), CRITICAL, "contraseña de BD"),
    (re.compile(r"(?i)(smtp[_-]?pass|mail[_-]?pass|email[_-]?pass)"), HIGH, "contraseña de correo"),
    (re.compile(r"(?i)(github[_-]?token|gh[_-]?token|gitlab[_-]?token)"), HIGH, "token de git"),
    (re.compile(r"(?i)(stripe[_-]?(key|secret)|paypal[_-]?secret)"), CRITICAL, "secreto de pago"),
    (re.compile(r"(?i)(slack[_-]?token|discord[_-]?token|telegram[_-]?token)"), MEDIUM, "token de mensajería"),
    (re.compile(r"(?i)(encryption[_-]?key|cipher[_-]?key)"), HIGH, "clave de encriptación"),
    (re.compile(r"(?i)(client[_-]?secret|oauth[_-]?secret)"), HIGH, "secreto OAuth"),
]

# Patterns for values that look like secrets (regardless of key name)
SECRET_VALUE_PATTERNS = [
    (re.compile(r"[A-Za-z0-9/+]{40,}={0,2}$"), "Valor en Base64"),
    (re.compile(r"[0-9a-fA-F]{32,64}$"), "Secreto hexadecimal"),
    (re.compile(r"(?i)^(AKIA|ASIA|AROA)[A-Z0-9]{16}"), "Clave de acceso AWS"),
    (re.compile(r"(?i)^sk_live_[0-9a-z]+"), "Clave secreta Stripe Live"),
    (re.compile(r"(?i)^ghp_[A-Za-z0-9]+"), "Token de GitHub"),
    (re.compile(r"(?i)^xox[baprs]-[0-9A-Za-z-]+"), "Token de Slack"),
    (re.compile(r"(?i)eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"), "Token JWT"),
]

# Value patterns indicating it's NOT an actual secret (placeholder/template)
PLACEHOLDER_PATTERNS = re.compile(
    r"(?i)^(your[_-]|<[^>]+>|changeme|placeholder|example|todo|xxx|none|null|false|true|\d{1,5})$"
)


class EnvAnalyzer(BaseAnalyzer):
    """Analyzes .env files and environment variable configurations for secrets."""

    file_type = "env"

    def analyze(self, content: str, filename: str = "") -> List[Finding]:
        findings: List[Finding] = []
        lines = self.get_lines(content)

        for idx, line in enumerate(lines, start=1):
            stripped = line.strip()
            # Skip comments and empty lines
            if not stripped or stripped.startswith("#"):
                continue

            # Parse KEY=VALUE
            if "=" not in stripped:
                continue

            key, _, value = stripped.partition("=")
            key = key.strip()
            value = value.strip().strip('"').strip("'")

            if not value or PLACEHOLDER_PATTERNS.match(value):
                continue

            # Check key name against sensitive patterns
            for pattern, severity, secret_type in SENSITIVE_KEY_PATTERNS:
                if pattern.search(key):
                    findings.append(self._make_finding(
                        "001", severity,
                        f"{secret_type.capitalize()} expuesto: {key}",
                        f"La variable de entorno '{key}' parece contener un/una {secret_type}. "
                        "Subir archivos .env con credenciales reales al control de versiones es un "
                        "riesgo crítico de seguridad.",
                        "Agrega el archivo .env a .gitignore inmediatamente. Usa un administrador "
                        "de secretos (Azure Key Vault, AWS Secrets Manager) en lugar de un .env en la nube.",
                        line_number=idx,
                        line_content=f"{key}={'*' * min(len(value), 8)}",
                        category="secrets",
                    ))
                    break

            # Check value patterns (even if key name is non-obvious)
            else:
                for val_pattern, val_type in SECRET_VALUE_PATTERNS:
                    if val_pattern.search(value):
                        findings.append(self._make_finding(
                            "002", HIGH,
                            f"Valor sospechoso de secreto para clave: {key}",
                            f"El valor de '{key}' coincide con un formato de secreto conocido ({val_type}). "
                            "Incluso si el nombre de la clave parece inocuo, este valor no debe almacenarse en texto plano.",
                            "Rota la credencial inmediatamente si es real. Almacena secretos en un administrador de secretos.",
                            line_number=idx,
                            line_content=f"{key}={'*' * min(len(value), 8)}",
                            category="secrets",
                        ))
                        break

        # Check if the .env file itself has a dangerous name
        if filename.lower() in (".env.production", ".env.prod", ".env.staging"):
            findings.append(self._make_finding(
                "003", HIGH,
                f"Archivo de entorno de producción detectado: {filename}",
                f"El archivo '{filename}' parece ser un archivo de entorno de producción. "
                "Los secretos de producción NUNCA deben estar en archivos susceptibles a control de versiones.",
                "Usa variables de entorno de CI/CD o un servicio de secretos para credenciales de producción.",
                category="secrets",
            ))

        # Check for DEBUG=True in what looks like a production file
        debug_match = re.search(r"(?i)^DEBUG\s*=\s*(true|1|yes|on)", content, re.MULTILINE)
        if debug_match and "prod" in filename.lower():
            findings.append(self._make_finding(
                "004", HIGH,
                "Modo DEBUG activado en archivo .env de producción",
                "Tener DEBUG=True en un entorno de producción expone trazas de código, "
                "rutas internas y mensajes detallados de error.",
                "Establece DEBUG=False para todos los entornos de producción.",
                line_content="DEBUG=True", category="configuration",
            ))

        return findings
