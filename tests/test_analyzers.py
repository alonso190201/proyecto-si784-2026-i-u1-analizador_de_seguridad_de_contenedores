from analyzers.compose_analyzer import ComposeAnalyzer
from analyzers.dockerfile_analyzer import DockerfileAnalyzer
from analyzers.env_analyzer import EnvAnalyzer
from analyzers.kubernetes_analyzer import KubernetesAnalyzer
from services.report_service import build_summary, enrich_findings


def ids(findings):
    return {finding.rule_id for finding in findings}


def test_dockerfile_detects_multiline_supply_chain_and_unpinned_stage():
    content = """
FROM python AS builder
RUN apt-get update && apt-get install -y curl \\
    && curl https://example.com/install.sh | bash
ENV API_TOKEN=real-token-value
"""
    findings = DockerfileAnalyzer().analyze(content)
    rule_ids = ids(findings)

    assert "DOCKERFILE_005" in rule_ids
    assert "DOCKERFILE_009" in rule_ids
    assert "DOCKERFILE_003" in rule_ids


def test_compose_detects_privilege_and_hardening_gaps():
    content = """
services:
  web:
    image: nginx
    privileged: true
    ports:
      - "0.0.0.0:22:22"
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock
    environment:
      - DB_PASSWORD=supersecret
"""
    findings = ComposeAnalyzer().analyze(content)
    rule_ids = ids(findings)

    assert "COMPOSE_001" in rule_ids
    assert "COMPOSE_006" in rule_ids
    assert "COMPOSE_009" in rule_ids
    assert "COMPOSE_013" in rule_ids
    assert "COMPOSE_014" in rule_ids


def test_kubernetes_detects_pod_security_gaps():
    content = """
apiVersion: apps/v1
kind: Deployment
metadata:
  name: demo
spec:
  template:
    spec:
      containers:
        - name: app
          image: nginx
          securityContext:
            runAsUser: 0
            allowPrivilegeEscalation: true
"""
    findings = KubernetesAnalyzer().analyze(content)
    rule_ids = ids(findings)

    assert "KUBERNETES_009" in rule_ids
    assert "KUBERNETES_011" in rule_ids
    assert "KUBERNETES_019" in rule_ids
    assert "KUBERNETES_020" in rule_ids


def test_env_masks_sensitive_line_content_after_enrichment():
    content = "SECRET_KEY=my-production-secret\nDEBUG=True\n"
    findings = [finding.to_dict() for finding in EnvAnalyzer().analyze(content, filename=".env.prod")]
    enriched = enrich_findings(findings)

    assert enriched[0]["line_content"] == "SECRET_KEY=********"
    assert build_summary(enriched)["counts"]["critical"] >= 1
