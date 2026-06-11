"""
dockerfile_analyzer.py - Security rule engine for Dockerfiles.
Detects insecure patterns, secrets, bad practices, and misconfigurations.
"""
from __future__ import annotations

import re
from typing import List

from .base_analyzer import BaseAnalyzer, Finding, CRITICAL, HIGH, MEDIUM, LOW, INFO


class DockerfileAnalyzer(BaseAnalyzer):
    """Analyzes Dockerfile content for security issues."""

    file_type = "dockerfile"

    # Patterns that indicate hardcoded secrets in ENV / ARG instructions
    SECRET_PATTERNS = [
        r"(?i)(password|passwd|pwd)\s*=\s*\S+",
        r"(?i)(secret|token|api[_-]?key|apikey)\s*=\s*\S+",
        r"(?i)(aws_access_key|aws_secret)\s*=\s*\S+",
        r"(?i)(private[_-]?key|ssh[_-]?key)\s*=\s*\S+",
        r"(?i)(database[_-]?url|db[_-]?pass)\s*=\s*\S+",
        r"(?i)(auth[_-]?token|bearer[_-]?token)\s*=\s*\S+",
    ]

    # Images that are considered unofficial / risky
    UNOFFICIAL_IMAGE_PATTERNS = [
        r"^FROM\s+(?!([a-z0-9]+\.)?docker\.io/library/|alpine|ubuntu|debian|centos|python|node|golang|nginx|redis|postgres|mysql|mongo|openjdk|amazoncorretto|gcr\.io/|mcr\.microsoft\.com/|public\.ecr\.aws/)",
    ]

    def analyze(self, content: str, filename: str = "") -> List[Finding]:
        findings: List[Finding] = []
        lines = self._logical_lines(content)

        has_healthcheck = False
        has_user_instruction = False
        uses_root = False

        for idx, line in lines:
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue

            # --- USER root ---
            if re.match(r"^USER\s+root\b", stripped, re.IGNORECASE):
                uses_root = True
                has_user_instruction = True
                findings.append(self._make_finding(
                    "001", CRITICAL,
                    "El contenedor se ejecuta como root",
                    "La instrucción USER configura explícitamente el contenedor para ejecutarse como root, "
                    "otorgando privilegios completos dentro del contenedor. Si es vulnerado, un atacante "
                    "obtendría acceso a nivel de root en el host.",
                    "Agrega 'RUN groupadd -r appuser && useradd -r -g appuser appuser' y "
                    "establece 'USER appuser' antes de la instrucción CMD/ENTRYPOINT.",
                    line_number=idx, line_content=stripped, category="privilege",
                ))

            # --- USER instruction found (non-root) ---
            elif re.match(r"^USER\s+", stripped, re.IGNORECASE):
                has_user_instruction = True

            # --- EXPOSE 22 (SSH) ---
            if re.match(r"^EXPOSE\s+22\b", stripped, re.IGNORECASE):
                findings.append(self._make_finding(
                    "002", HIGH,
                    "Puerto SSH 22 expuesto",
                    "Exponer el puerto 22 (SSH) dentro de un contenedor Docker es un riesgo de seguridad significativo. "
                    "Los contenedores no deberían correr servicios SSH; usa 'docker exec' para depuración en su lugar.",
                    "Elimina la directiva 'EXPOSE 22'. Administra los contenedores mediante herramientas "
                    "de orquestación o 'docker exec' en lugar de SSH.",
                    line_number=idx, line_content=stripped, category="network",
                ))

            # --- Hardcoded secrets in ENV ---
            if re.match(r"^ENV\s+", stripped, re.IGNORECASE):
                for pattern in self.SECRET_PATTERNS:
                    if re.search(pattern, stripped):
                        findings.append(self._make_finding(
                            "003", CRITICAL,
                            "Secreto en código duro en la instrucción ENV",
                            f"Parece haber datos sensibles directamente en código duro en una instrucción ENV: "
                            f"'{stripped[:80]}'. Los secretos integrados en las capas de la imagen son visibles "
                            "mediante 'docker inspect' y en el historial de la imagen.",
                            "Usa los secretos de Docker BuildKit ('--mount=type=secret'), variables de entorno "
                            "en tiempo de ejecución o un gestor de secretos (Azure Key Vault, HashiCorp Vault).",
                            line_number=idx, line_content=stripped, category="secrets",
                        ))
                        break

            # --- Hardcoded secrets in ARG ---
            if re.match(r"^ARG\s+", stripped, re.IGNORECASE):
                for pattern in self.SECRET_PATTERNS:
                    if re.search(pattern, stripped):
                        findings.append(self._make_finding(
                            "004", HIGH,
                            "Valor ARG sensible detectado",
                            "Las instrucciones ARG con valores predeterminados que contienen secretos se "
                            "integran en el caché de construcción de la imagen y pueden ser extraídas de capas intermedias.",
                            "Nunca pases secretos a través de ARG. Usa montajes de secretos de BuildKit o inyecta "
                            "los secretos en tiempo de ejecución mediante variables de entorno o montajes.",
                            line_number=idx, line_content=stripped, category="secrets",
                        ))
                        break

            # --- Use of 'latest' tag ---
            if re.match(r"^FROM\s+", stripped, re.IGNORECASE):
                image = self._extract_from_image(stripped)
                if image and (image.endswith(":latest") or (
                    ":" not in image.split("/")[-1] and "@" not in image
                )):
                    findings.append(self._make_finding(
                        "005", MEDIUM,
                        "La imagen usa 'latest' o un tag no fijado",
                        "Usar el tag 'latest' o no usar ningún tag hace que las construcciones sean no deterministas. "
                        "Una actualización futura de la imagen podría introducir vulnerabilidades o cambios que rompan el código.",
                        "Fija tu imagen base a un digest específico o tag de versión, por ejemplo, "
                        "'FROM python:3.12.3-slim-bookworm@sha256:<digest>'.",
                        line_number=idx, line_content=stripped, category="image",
                    ))

            # --- Sudo usage ---
            if re.search(r"\bsudo\b", stripped, re.IGNORECASE) and re.match(r"^RUN\b", stripped, re.IGNORECASE):
                findings.append(self._make_finding(
                    "006", MEDIUM,
                    "Uso innecesario de sudo",
                    "Usar 'sudo' dentro de una instrucción RUN sugiere que el contenedor puede estar operando "
                    "con privilegios elevados o que la estructura de la imagen está mal diseñada.",
                    "Diseña tu imagen para que las operaciones requeridas no necesiten sudo. "
                    "Ejecuta instalaciones de paquetes como root durante el build y cambia a un USER no-root al final.",
                    line_number=idx, line_content=stripped, category="privilege",
                ))

            # --- Insecure permissions (chmod 777) ---
            if re.search(r"chmod\s+[-R\s]*777", stripped, re.IGNORECASE):
                findings.append(self._make_finding(
                    "007", HIGH,
                    "Permisos de archivo inseguros (chmod 777)",
                    "Establecer permisos en 777 otorga acceso completo de lectura/escritura/ejecución a todos los usuarios. "
                    "Dentro de un contenedor esto puede permitir escalada de privilegios si se combina con otras fallas.",
                    "Usa los permisos mínimos requeridos. Prefiere 750 o 755 para directorios y 640 o 644 para archivos.",
                    line_number=idx, line_content=stripped, category="filesystem",
                ))

            # --- HEALTHCHECK present ---
            if re.match(r"^HEALTHCHECK\b", stripped, re.IGNORECASE):
                has_healthcheck = True

            # --- ADD instead of COPY (potential remote URL risk) ---
            if re.match(r"^ADD\s+https?://", stripped, re.IGNORECASE):
                findings.append(self._make_finding(
                    "008", MEDIUM,
                    "ADD con una URL remota es inseguro",
                    "Usar ADD con una URL HTTP(S) descarga recursos en tiempo de compilación sin verificación "
                    "de integridad, permitiendo ataques de cadena de suministro vía secuestro de URL.",
                    "Usa 'RUN curl -fsSL <url> | sha256sum --check' con un checksum predefinido, "
                    "o usa 'COPY' con artefactos descargados y verificados previamente.",
                    line_number=idx, line_content=stripped, category="supply-chain",
                ))

            # --- curl | bash / wget | bash (supply chain) ---
            if re.search(r"(curl|wget).+\|\s*(bash|sh|python)", stripped, re.IGNORECASE):
                findings.append(self._make_finding(
                    "009", HIGH,
                    "Redirección de script remoto a shell",
                    "Descargar y ejecutar scripts directamente desde internet en una instrucción RUN es "
                    "un vector común de ataque de cadena de suministro. El contenido remoto podría cambiar.",
                    "Descarga el script, verifica su checksum y luego ejecútalo. "
                    "Es mejor incluir la dependencia directamente en el repositorio de código.",
                    line_number=idx, line_content=stripped, category="supply-chain",
                ))

            # --- Package manager upgrade in builds ---
            if re.match(r"^RUN\b", stripped, re.IGNORECASE) and re.search(
                r"\b(apt-get|apt|apk|yum|dnf)\s+.*\bupgrade\b", stripped, re.IGNORECASE
            ):
                findings.append(self._make_finding(
                    "013", MEDIUM,
                    "Actualizacion completa de paquetes durante el build",
                    "Ejecutar upgrades generales hace que la imagen sea menos reproducible y puede introducir cambios no controlados.",
                    "Usa una imagen base actualizada y fija versiones de paquetes cuando el build requiera instalarlos.",
                    line_number=idx, line_content=stripped, category="supply-chain",
                ))

            # --- Package cache not removed ---
            if re.match(r"^RUN\b", stripped, re.IGNORECASE) and re.search(
                r"\bapt-get\s+install\b", stripped, re.IGNORECASE
            ) and "/var/lib/apt/lists" not in stripped:
                findings.append(self._make_finding(
                    "014", LOW,
                    "Cache de paquetes APT no limpiada",
                    "Mantener el cache de APT aumenta el tamano de la imagen y puede dejar metadatos innecesarios.",
                    "Agrega 'rm -rf /var/lib/apt/lists/*' en la misma instruccion RUN.",
                    line_number=idx, line_content=stripped, category="image",
                ))

            # --- Secrets via RUN commands ---
            for pattern in self.SECRET_PATTERNS:
                if re.match(r"^RUN\b", stripped, re.IGNORECASE) and re.search(pattern, stripped):
                    findings.append(self._make_finding(
                        "010", CRITICAL,
                        "Secreto incrustado en la instrucción RUN",
                        "Las credenciales pasadas directamente a comandos RUN se almacenan en el historial "
                        "de la capa de la imagen y pueden recuperarse con 'docker history --no-trunc'.",
                        "Usa montajes de secretos de BuildKit: '--mount=type=secret,id=mysecret' para inyectar "
                        "secretos en tiempo de construcción sin incrustarlos en las capas de la imagen.",
                        line_number=idx, line_content=stripped, category="secrets",
                    ))
                    break

        # --- Post-loop checks ---

        # No USER instruction — runs as root by default
        if not has_user_instruction:
            findings.append(self._make_finding(
                "011", HIGH,
                "Falta instrucción USER — usa root por defecto",
                "Cuando no se especifica una instrucción USER, Docker por defecto ejecuta el contenedor "
                "como root (UID 0), otorgando privilegios elevados innecesarios.",
                "Agrega un usuario dedicado que no sea root con 'RUN useradd -r -s /bin/false appuser' "
                "y establece 'USER appuser' antes del CMD/ENTRYPOINT.",
                category="privilege",
            ))

        # Missing HEALTHCHECK
        if not has_healthcheck:
            findings.append(self._make_finding(
                "012", LOW,
                "Falta instrucción HEALTHCHECK",
                "Sin un HEALTHCHECK, los orquestadores como Kubernetes no pueden determinar si el "
                "contenedor está realmente saludable y sirviendo tráfico correctamente.",
                "Agrega una instrucción HEALTHCHECK, ej: "
                "'HEALTHCHECK --interval=30s --timeout=5s CMD curl -f http://localhost:8080/health || exit 1'",
                category="availability",
            ))

        return findings

    @staticmethod
    def _extract_from_image(line: str) -> str:
        """Return the image token from a FROM instruction, ignoring AS aliases."""
        parts = line.split()
        if len(parts) < 2:
            return ""
        return parts[1]

    @staticmethod
    def _logical_lines(content: str) -> List[tuple[int, str]]:
        """Join Dockerfile lines continued with a backslash, preserving start line."""
        logical: List[tuple[int, str]] = []
        buffer = ""
        start_line = 1

        for idx, raw in enumerate(content.splitlines(), start=1):
            line = raw.rstrip()
            if not buffer:
                start_line = idx
            if line.endswith("\\"):
                buffer += line[:-1] + " "
                continue
            buffer += line
            logical.append((start_line, buffer))
            buffer = ""

        if buffer:
            logical.append((start_line, buffer))
        return logical
