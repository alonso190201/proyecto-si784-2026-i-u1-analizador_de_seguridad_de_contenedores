"""
base_analyzer.py - Abstract base class for all file analyzers.
Defines the Finding data structure and the common interface.
"""
from __future__ import annotations

import re
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import List


# ---------------------------------------------------------------------------
# Severity constants
# ---------------------------------------------------------------------------

CRITICAL = "critical"
HIGH = "high"
MEDIUM = "medium"
LOW = "low"
INFO = "info"

SEVERITY_ORDER = {CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1, INFO: 0}


@dataclass
class Finding:
    """Represents a single security finding detected in an analyzed file."""

    rule_id: str
    severity: str          # critical | high | medium | low | info
    title: str
    description: str
    recommendation: str
    line_number: int = 0
    line_content: str = ""
    category: str = "general"

    def to_dict(self) -> dict:
        """Serialize to JSON-compatible dict."""
        return {
            "rule_id": self.rule_id,
            "severity": self.severity,
            "title": self.title,
            "description": self.description,
            "recommendation": self.recommendation,
            "line_number": self.line_number,
            "line_content": self.line_content,
            "category": self.category,
        }


class BaseAnalyzer(ABC):
    """
    Abstract base class for container config analyzers.
    Subclasses must implement the `analyze` method.
    """

    file_type: str = "unknown"

    # ------------------------------------------------------------------
    # Public interface
    # ------------------------------------------------------------------

    @abstractmethod
    def analyze(self, content: str, filename: str = "") -> List[Finding]:
        """
        Analyze *content* (raw file text) and return a list of Findings.
        Subclasses implement the actual rule engine here.
        """

    # ------------------------------------------------------------------
    # Shared helpers available to all subclasses
    # ------------------------------------------------------------------

    @staticmethod
    def get_lines(content: str) -> List[str]:
        """Split content into a list of (1-indexed) lines."""
        return content.splitlines()

    @staticmethod
    def search_line(pattern: str, line: str, flags: int = re.IGNORECASE) -> bool:
        """Return True if *pattern* matches anywhere in *line*."""
        return bool(re.search(pattern, line, flags))

    @staticmethod
    def find_in_content(
        pattern: str, content: str, flags: int = re.IGNORECASE
    ) -> List[re.Match]:
        """Return all matches of *pattern* in the full *content*."""
        return list(re.finditer(pattern, content, flags))

    def _make_finding(
        self,
        rule_id: str,
        severity: str,
        title: str,
        description: str,
        recommendation: str,
        line_number: int = 0,
        line_content: str = "",
        category: str = "general",
    ) -> Finding:
        """Convenience factory that prefixes rule_id with file_type."""
        prefixed_id = f"{self.file_type.upper()}_{rule_id}"
        return Finding(
            rule_id=prefixed_id,
            severity=severity,
            title=title,
            description=description,
            recommendation=recommendation,
            line_number=line_number,
            line_content=line_content.strip(),
            category=category,
        )
