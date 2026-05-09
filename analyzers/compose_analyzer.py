"""
compose_analyzer.py - Security rule engine for docker-compose files.
"""
from __future__ import annotations
import re
from typing import Any, Dict, List
import yaml
from .base_analyzer import BaseAnalyzer, Finding, CRITICAL, HIGH, MEDIUM, LOW

SENSITIVE_VOLUME_PATHS = [
    "/etc", "/var/run/docker.sock", "/proc", "/sys", "/dev", "/root", "/boot",
]

DANGEROUS_PORTS = {
    "22": "SSH", "23": "Telnet", "3389": "RDP", "445": "SMB",
    "139": "NetBIOS", "2375": "Docker daemon (no autenticado)",
}

SECRET_KEY_PATTERNS = re.compile(
    r"(?i)^(password|passwd|pwd|secret|token|api[_-]?key|apikey|"
    r"auth[_-]?token|private[_-]?key|aws_access|aws_secret|db[_-]?pass)\s*=\s*\S+"
)


class ComposeAnalyzer(BaseAnalyzer):
    file_type = "compose"

    def analyze(self, content: str, filename: str = "") -> List[Finding]:
        findings: List[Finding] = []
        try:
            data: Dict[str, Any] = yaml.safe_load(content) or {}
        except yaml.YAMLError as exc:
            findings.append(self._make_finding(
                "PARSE_ERROR", CRITICAL, "Error de análisis YAML",
                f"No se pudo procesar el archivo docker-compose: {exc}",
                "Corrige los errores de sintaxis YAML antes de realizar el análisis.", category="general",
            ))
            return findings

        services = data.get("services", {})
        if not services:
            return findings

        for svc_name, svc_cfg in services.items():
            if not isinstance(svc_cfg, dict):
                continue
            n = svc_name

            # privileged
            if svc_cfg.get("privileged") is True:
                findings.append(self._make_finding(
                    "001", CRITICAL, f"[{n}] Contenedor privilegiado",
                    "Establecer privileged:true elimina el aislamiento del contenedor y otorga acceso al kernel del host.",
                    "Elimina privileged:true. Usa capacidades cap_add mínimas requeridas en su lugar.",
                    category="privilege",
                ))

            # network_mode host
            if svc_cfg.get("network_mode") == "host":
                findings.append(self._make_finding(
                    "002", CRITICAL, f"[{n}] Modo de red del host",
                    "El modo network_mode:host omite el aislamiento de red de Docker.",
                    "Define redes de Docker dedicadas y expón solo los puertos necesarios.",
                    category="network",
                ))

            # pid host
            if svc_cfg.get("pid") == "host":
                findings.append(self._make_finding(
                    "003", CRITICAL, f"[{n}] Namespace de procesos del host compartido",
                    "pid:host permite al contenedor ver todos los procesos del host.",
                    "Elimina pid:host para mantener los espacios de nombres de los procesos aislados.",
                    category="privilege",
                ))

            # dangerous ports
            for port_entry in svc_cfg.get("ports", []):
                port_str = str(port_entry)
                for dp, label in DANGEROUS_PORTS.items():
                    if re.search(rf"(?:^|:){dp}(?:$|:|\s)", port_str):
                        findings.append(self._make_finding(
                            "004", HIGH, f"[{n}] Puerto peligroso {dp} ({label}) expuesto",
                            f"El puerto {dp} ({label}) está mapeado al host.",
                            f"Restrínjalo a 127.0.0.1:{dp}:{dp} o elimine el mapeo.",
                            line_content=port_str, category="network",
                        ))
                # bound to all interfaces
                if re.match(r"^\d+:", port_str) or re.match(r"^0\.0\.0\.0:", port_str):
                    findings.append(self._make_finding(
                        "005", MEDIUM, f"[{n}] Puerto vinculado a todas las interfaces",
                        f"El mapeo del puerto '{port_str}' es accesible desde cualquier interfaz de red.",
                        "Restrínjalo a 127.0.0.1:<host>:<contenedor> para servicios internos.",
                        line_content=port_str, category="network",
                    ))

            # sensitive volumes
            for vol in svc_cfg.get("volumes", []):
                vol_str = str(vol)
                host_path = vol_str.split(":")[0]
                for sp in SENSITIVE_VOLUME_PATHS:
                    if host_path == sp or host_path.startswith(sp + "/"):
                        sev = CRITICAL if "docker.sock" in vol_str else HIGH
                        findings.append(self._make_finding(
                            "006", sev, f"[{n}] Ruta sensible del host montada: {host_path}",
                            f"Montar '{host_path}' otorga al contenedor acceso a recursos críticos del host."
                            + (" El montaje del socket Docker = control total del demonio Docker." if "docker.sock" in vol_str else ""),
                            "Usa volúmenes con nombre de Docker o configuraciones/secretos de Docker en su lugar.",
                            line_content=vol_str, category="filesystem",
                        ))
                        break

            # resource limits
            deploy = svc_cfg.get("deploy", {}) or {}
            limits = (deploy.get("resources", {}) or {}).get("limits", {}) or {}
            if not (limits.get("memory") or svc_cfg.get("mem_limit")):
                findings.append(self._make_finding(
                    "007", MEDIUM, f"[{n}] Sin límite de memoria",
                    "Sin límites de memoria, el contenedor puede agotar la memoria del host (DoS).",
                    "Configura deploy.resources.limits.memory (ej. '512m').",
                    category="resources",
                ))
            if not (limits.get("cpus") or svc_cfg.get("cpu_quota")):
                findings.append(self._make_finding(
                    "008", LOW, f"[{n}] Sin límite de CPU",
                    "Sin límites de CPU, el contenedor puede monopolizar todos los núcleos.",
                    "Configura deploy.resources.limits.cpus (ej. '0.5').",
                    category="resources",
                ))

            # env secrets
            env_entries = svc_cfg.get("environment", [])
            if isinstance(env_entries, dict):
                env_entries = [f"{k}={v}" for k, v in env_entries.items()]
            for entry in env_entries:
                if SECRET_KEY_PATTERNS.match(str(entry)):
                    findings.append(self._make_finding(
                        "009", HIGH, f"[{n}] Secreto incrustado en environment",
                        f"Un valor sensible aparece codificado en el entorno: '{str(entry)[:60]}'",
                        "Usa el bloque secrets de Docker o un archivo .env excluido del control de versiones.",
                        line_content=str(entry), category="secrets",
                    ))

            # dangerous capabilities
            dangerous_caps = {"SYS_ADMIN", "NET_ADMIN", "SYS_PTRACE", "SYS_MODULE", "ALL"}
            for cap in svc_cfg.get("cap_add", []):
                if str(cap).upper() in dangerous_caps:
                    findings.append(self._make_finding(
                        "010", HIGH, f"[{n}] Capacidad peligrosa: {cap}",
                        f"La capacidad '{cap}' otorga privilegios elevados a nivel del kernel.",
                        "Usa cap_drop:[ALL] y añade solo las capacidades mínimas necesarias.",
                        line_content=str(cap), category="privilege",
                    ))

            # user root
            user = str(svc_cfg.get("user", ""))
            if user in ("root", "0", "0:0"):
                findings.append(self._make_finding(
                    "011", HIGH, f"[{n}] Servicio ejecutándose como root",
                    "Ejecutar explícitamente como root maximiza el impacto si hay un escape del contenedor.",
                    "Configura user: a un UID que no sea root, ej: '1001:1001'.",
                    category="privilege",
                ))

            # unpinned image
            image = str(svc_cfg.get("image", ""))
            if image and (image.endswith(":latest") or (
                ":" not in image.split("/")[-1] and "@" not in image
            )):
                findings.append(self._make_finding(
                    "012", MEDIUM, f"[{n}] Etiqueta de imagen sin fijar",
                    f"La imagen '{image}' no tiene una versión fija.",
                    "Fija a una versión específica, ej: 'nginx:1.27.0-alpine'.",
                    line_content=image, category="image",
                ))

        return findings
