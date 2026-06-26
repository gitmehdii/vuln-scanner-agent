"""
Core data models.
"""

from dataclasses import dataclass, field
from typing import Optional
from enum import Enum


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class FindingType(str, Enum):
    DEPENDENCY = "dependency"   # CVE in a package
    SAST = "sast"               # static analysis finding
    DOCKER = "docker"           # CVE in docker layer
    LLM = "llm"                 # AI-discovered vulnerability (code)
    WEB = "web"                 # web application security finding


@dataclass
class Finding:
    id: str                          # CVE-2024-XXXX or semgrep rule id
    title: str
    description: str
    severity: str                    # CRITICAL / HIGH / MEDIUM / LOW / INFO
    finding_type: FindingType
    file_path: Optional[str] = None  # relevant for SAST
    line: Optional[int] = None       # relevant for SAST
    package: Optional[str] = None    # relevant for dep/docker
    version: Optional[str] = None    # affected version
    fixed_version: Optional[str] = None
    cvss_score: Optional[float] = None
    source: str = ""                 # osv / semgrep / trivy
    llm_context: Optional[str] = None  # LLM-generated triage note
    exploitable: Optional[bool] = None  # None=unknown, True=confirmed, False=not reachable


@dataclass
class ScanResult:
    findings: list[Finding]
    duration: float
    repo_url: Optional[str] = None
    image: Optional[str] = None
    findings_by_severity: dict = field(default_factory=dict)

    def __post_init__(self):
        from collections import Counter
        self.findings_by_severity = Counter(f.severity for f in self.findings)
