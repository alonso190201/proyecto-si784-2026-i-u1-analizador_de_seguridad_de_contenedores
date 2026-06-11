"""
kubernetes_analyzer.py - Security rule engine for Kubernetes manifests.
"""
from __future__ import annotations
import re
from typing import Any, Dict, List
import yaml
from .base_analyzer import BaseAnalyzer, Finding, CRITICAL, HIGH, MEDIUM, LOW


class KubernetesAnalyzer(BaseAnalyzer):
    file_type = "kubernetes"

    def analyze(self, content: str, filename: str = "") -> List[Finding]:
        findings: List[Finding] = []
        docs = []
        try:
            docs = list(yaml.safe_load_all(content))
        except yaml.YAMLError as exc:
            findings.append(self._make_finding(
                "PARSE_ERROR", CRITICAL, "Error de análisis YAML",
                f"No se pudo analizar el manifiesto de Kubernetes: {exc}",
                "Corrige los errores de sintaxis YAML.", category="general",
            ))
            return findings

        for doc in docs:
            if not isinstance(doc, dict):
                continue
            kind = doc.get("kind", "Unknown")
            name = doc.get("metadata", {}).get("name", "unnamed") if doc.get("metadata") else "unnamed"
            ref = f"{kind}/{name}"
            self._analyze_doc(findings, doc, ref)

        return findings

    def _analyze_doc(self, findings: List[Finding], doc: dict, ref: str):
        kind = doc.get("kind", "")
        spec = doc.get("spec", {}) or {}

        # ClusterRoleBinding / RoleBinding — cluster-admin
        if kind in ("ClusterRoleBinding", "RoleBinding"):
            role_ref = doc.get("roleRef", {}) or {}
            if role_ref.get("name") == "cluster-admin":
                findings.append(self._make_finding(
                    "001", CRITICAL, f"[{ref}] Permiso RBAC cluster-admin",
                    "Vincular usuarios al ClusterRole cluster-admin otorga acceso sin restricciones "
                    "a todos los recursos de Kubernetes en todos los namespaces.",
                    "Sigue el principio de mínimo privilegio: crea Roles limitados con los permisos exactos.",
                    category="rbac",
                ))

        # ClusterRole / Role — wildcard permissions
        if kind in ("ClusterRole", "Role"):
            for rule in doc.get("rules", []) or []:
                if isinstance(rule, dict):
                    if "*" in (rule.get("verbs") or []) or "*" in (rule.get("resources") or []):
                        findings.append(self._make_finding(
                            "002", HIGH, f"[{ref}] Permisos RBAC comodín (*)",
                            "Usar '*' en los verbos o recursos de RBAC otorga permisos excesivamente amplios.",
                            "Enumera verbos específicos (get, list, watch) y recursos en lugar de usar '*'.",
                            category="rbac",
                        ))
                        break

        # Secret stored as plain ConfigMap value
        if kind == "ConfigMap":
            data = doc.get("data", {}) or {}
            secret_re = re.compile(
                r"(?i)(password|secret|token|api[_-]?key|apikey|private[_-]?key)", re.I
            )
            for key, val in data.items():
                if secret_re.search(key) and val:
                    findings.append(self._make_finding(
                        "003", HIGH, f"[{ref}] Secreto en ConfigMap clave '{key}'",
                        "Los ConfigMaps no están diseñados para datos sensibles — se guardan sin cifrar "
                        "y son accesibles para cualquier pod con acceso RBAC.",
                        "Mueve los valores sensibles a Kubernetes Secrets o a un gestor externo "
                        "(Azure Key Vault, HashiCorp Vault).",
                        category="secrets",
                    ))

        if kind == "Service":
            svc_type = spec.get("type", "ClusterIP")
            if svc_type in ("NodePort", "LoadBalancer"):
                findings.append(self._make_finding(
                    "018", MEDIUM, f"[{ref}] Servicio expuesto como {svc_type}",
                    f"El tipo {svc_type} puede exponer la aplicacion fuera del cluster.",
                    "Usa ClusterIP por defecto y publica trafico mediante Ingress/Gateway con controles de acceso.",
                    category="network",
                ))

        # Pod / Deployment / DaemonSet / StatefulSet / Job / CronJob
        pod_specs = self._extract_pod_specs(doc)
        for pod_spec in pod_specs:
            self._check_pod_spec(findings, ref, pod_spec)

    def _extract_pod_specs(self, doc: dict) -> List[dict]:
        """Extract podSpec(s) from various Kubernetes resource types."""
        kind = doc.get("kind", "")
        specs = []
        spec = doc.get("spec", {}) or {}

        if kind == "Pod":
            specs.append(spec)
        elif kind in ("Deployment", "ReplicaSet", "DaemonSet", "StatefulSet"):
            template = spec.get("template", {}) or {}
            pod_spec = template.get("spec", {}) or {}
            if pod_spec:
                specs.append(pod_spec)
        elif kind == "Job":
            template = spec.get("template", {}) or {}
            pod_spec = template.get("spec", {}) or {}
            if pod_spec:
                specs.append(pod_spec)
        elif kind == "CronJob":
            job_template = spec.get("jobTemplate", {}) or {}
            job_spec = job_template.get("spec", {}) or {}
            template = job_spec.get("template", {}) or {}
            pod_spec = template.get("spec", {}) or {}
            if pod_spec:
                specs.append(pod_spec)

        return specs

    def _check_pod_spec(self, findings: List[Finding], ref: str, pod_spec: dict):
        pod_ctx = pod_spec.get("securityContext", {}) or {}

        if pod_spec.get("automountServiceAccountToken") is not False:
            findings.append(self._make_finding(
                "019", MEDIUM, f"[{ref}] Token de ServiceAccount montado automaticamente",
                "Montar automaticamente el token de ServiceAccount aumenta el impacto de una intrusion en el pod.",
                "Configura automountServiceAccountToken:false si la carga no necesita llamar al API de Kubernetes.",
                category="rbac",
            ))

        pod_seccomp = (pod_ctx.get("seccompProfile", {}) or {}).get("type")
        if pod_seccomp not in ("RuntimeDefault", "Localhost"):
            findings.append(self._make_finding(
                "020", MEDIUM, f"[{ref}] Falta perfil seccomp seguro",
                "Sin seccomp RuntimeDefault o Localhost, el contenedor queda con una superficie mayor de syscalls.",
                "Configura securityContext.seccompProfile.type: RuntimeDefault.",
                category="privilege",
            ))

        # hostNetwork
        if pod_spec.get("hostNetwork") is True:
            findings.append(self._make_finding(
                "004", CRITICAL, f"[{ref}] hostNetwork activado",
                "hostNetwork comparte el espacio de red del host, omitiendo políticas de red "
                "y exponiendo los servicios del host al contenedor.",
                "Elimina hostNetwork:true. Usa servicios ClusterIP.",
                category="network",
            ))

        # hostPID
        if pod_spec.get("hostPID") is True:
            findings.append(self._make_finding(
                "005", CRITICAL, f"[{ref}] hostPID activado",
                "hostPID comparte el namespace de procesos del host, permitiendo al contenedor ver "
                "los procesos del host — una brecha grave de aislamiento.",
                "Elimina hostPID:true.",
                category="privilege",
            ))

        # hostIPC
        if pod_spec.get("hostIPC") is True:
            findings.append(self._make_finding(
                "006", HIGH, f"[{ref}] hostIPC activado",
                "hostIPC comparte el namespace IPC del host, permitiendo comunicación entre procesos.",
                "Elimina hostIPC:true.",
                category="privilege",
            ))

        # hostPath volumes
        for vol in pod_spec.get("volumes", []) or []:
            if isinstance(vol, dict) and "hostPath" in vol:
                hp = vol.get("hostPath", {}).get("path", "")
                findings.append(self._make_finding(
                    "007", HIGH, f"[{ref}] hostPath volumen: {hp}",
                    f"El volumen hostPath '{hp}' omite el aislamiento de almacenamiento "
                    "y puede exponer información sensible del host.",
                    "Usa PersistentVolumeClaims respaldados por almacenamiento gestionado.",
                    line_content=hp, category="filesystem",
                ))

        # Container-level checks
        for container in (pod_spec.get("containers", []) or []) + (pod_spec.get("initContainers", []) or []):
            if not isinstance(container, dict):
                continue
            cname = container.get("name", "unnamed-container")
            ctx = container.get("securityContext", {}) or {}

            # privileged
            if ctx.get("privileged") is True:
                findings.append(self._make_finding(
                    "008", CRITICAL, f"[{ref}] Contenedor '{cname}' es privilegiado",
                    "privileged:true elimina todo el aislamiento del contenedor.",
                    "Elimina privileged:true. Usa capabilities específicos.",
                    category="privilege",
                ))

            # runAsRoot
            run_as_user = ctx.get("runAsUser")
            run_as_non_root = ctx.get("runAsNonRoot")
            if run_as_user == 0:
                findings.append(self._make_finding(
                    "009", HIGH, f"[{ref}] Contenedor '{cname}' ejecuta como root (UID 0)",
                    "runAsUser:0 fuerza la ejecución como root.",
                    "Establece runAsUser a un UID mayor que cero y usa runAsNonRoot:true.",
                    category="privilege",
                ))
            elif run_as_non_root is False:
                findings.append(self._make_finding(
                    "010", HIGH, f"[{ref}] Contenedor '{cname}' permite ejecución root",
                    "runAsNonRoot:false permite explícitamente procesos root.",
                    "Configura runAsNonRoot:true.",
                    category="privilege",
                ))

            # allowPrivilegeEscalation
            if ctx.get("allowPrivilegeEscalation") is True:
                findings.append(self._make_finding(
                    "011", HIGH, f"[{ref}] Contenedor '{cname}' permite escalada de privilegios",
                    "allowPrivilegeEscalation:true permite a los procesos obtener más privilegios que su proceso padre.",
                    "Configura allowPrivilegeEscalation:false.",
                    category="privilege",
                ))

            # No read-only root filesystem
            if ctx.get("readOnlyRootFilesystem") is not True:
                findings.append(self._make_finding(
                    "012", MEDIUM, f"[{ref}] Contenedor '{cname}' tiene sistema de archivos root escribible",
                    "Un rootfs escribible permite a los atacantes modificar binarios o guardar código malicioso.",
                    "Usa readOnlyRootFilesystem:true y monta volúmenes solo en donde se requiere.",
                    category="filesystem",
                ))

            # Unpinned image
            image = container.get("image", "")
            if image and (image.endswith(":latest") or (
                ":" not in image.split("/")[-1] and "@" not in image
            )):
                findings.append(self._make_finding(
                    "013", MEDIUM, f"[{ref}] Contenedor '{cname}' usa imagen sin fijar",
                    f"La imagen '{image}' no tiene versión fija, haciendo el despliegue no determinista.",
                    "Fija a un digest específico, ej: 'nginx:1.27.0-alpine@sha256:<digest>'.",
                    line_content=image, category="image",
                ))

            # No resource limits
            resources = container.get("resources", {}) or {}
            limits = resources.get("limits", {}) or {}
            if not limits.get("memory"):
                findings.append(self._make_finding(
                    "014", MEDIUM, f"[{ref}] Contenedor '{cname}' no tiene límite de memoria",
                    "Sin límite de memoria, puede agotar los recursos del nodo.",
                    "Define resources.limits.memory.",
                    category="resources",
                ))
            if not limits.get("cpu"):
                findings.append(self._make_finding(
                    "015", LOW, f"[{ref}] Contenedor '{cname}' no tiene límite de CPU",
                    "Sin límite de CPU, puede monopolizar los ciclos del procesador.",
                    "Define resources.limits.cpu.",
                    category="resources",
                ))

            # Dangerous capabilities
            caps = ctx.get("capabilities", {}) or {}
            dangerous = {"SYS_ADMIN", "NET_ADMIN", "SYS_PTRACE", "SYS_MODULE", "ALL"}
            for cap in caps.get("add", []) or []:
                if str(cap).upper() in dangerous:
                    findings.append(self._make_finding(
                        "016", HIGH, f"[{ref}] Contenedor '{cname}' tiene capacidad peligrosa: {cap}",
                        f"La capacidad '{cap}' da privilegios elevados.",
                        "Elimina todas las capacidades y añade solo las necesarias.",
                        line_content=str(cap), category="privilege",
                    ))

            dropped = {str(cap).upper() for cap in caps.get("drop", []) or []}
            if "ALL" not in dropped:
                findings.append(self._make_finding(
                    "021", LOW, f"[{ref}] Contenedor '{cname}' no elimina capacidades Linux",
                    "Las capacidades por defecto amplian la superficie de ataque si la aplicacion es comprometida.",
                    "Configura securityContext.capabilities.drop: ['ALL'] y agrega solo las necesarias.",
                    category="privilege",
                ))

            # Env secrets
            for env_var in container.get("env", []) or []:
                if not isinstance(env_var, dict):
                    continue
                key = env_var.get("name", "")
                val = env_var.get("value", "")
                secret_re = re.compile(
                    r"(?i)(password|secret|token|api[_-]?key|apikey|private[_-]?key|aws)", re.I
                )
                if secret_re.search(key) and val and not str(val).startswith("$("):
                    findings.append(self._make_finding(
                        "017", HIGH, f"[{ref}] Contenedor '{cname}' tiene secreto incrustado en env: {key}",
                        f"La variable '{key}' parece contener un secreto.",
                        "Usa Kubernetes Secrets con valueFrom.secretKeyRef en su lugar.",
                        line_content=f"{key}={str(val)[:30]}", category="secrets",
                    ))

        return findings
