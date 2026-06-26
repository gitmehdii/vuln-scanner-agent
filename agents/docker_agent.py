"""
DockerAgent — scans Docker images for CVEs via Trivy CLI.
Trivy must be installed: https://aquasecurity.github.io/trivy/
"""

import json
import subprocess

from core.models import Finding, FindingType
from core.logger import get_logger

logger = get_logger(__name__)

SEVERITY_MAP = {
    "CRITICAL": "CRITICAL",
    "HIGH": "HIGH",
    "MEDIUM": "MEDIUM",
    "LOW": "LOW",
    "UNKNOWN": "INFO",
}


class DockerAgent:
    async def run(self, image: str) -> list[Finding]:
        logger.info("DockerAgent starting", image=image)

        if not self._trivy_available():
            logger.warning("DockerAgent: trivy not found. Install: https://aquasecurity.github.io/trivy/")
            return []

        findings = self._run_trivy(image)
        logger.info("DockerAgent done", findings=len(findings))
        return findings

    def _trivy_available(self) -> bool:
        try:
            result = subprocess.run(["trivy", "--version"], capture_output=True, timeout=5)
            return result.returncode == 0
        except (FileNotFoundError, subprocess.TimeoutExpired):
            return False

    def _run_trivy(self, image: str) -> list[Finding]:
        try:
            result = subprocess.run(
                [
                    "trivy", "image",
                    "--format", "json",
                    "--quiet",
                    "--severity", "LOW,MEDIUM,HIGH,CRITICAL",
                    image,
                ],
                capture_output=True,
                text=True,
                timeout=300,  # pulling images can be slow
            )

            if result.returncode != 0:
                logger.error("DockerAgent: trivy failed", stderr=result.stderr[:300])
                return []

            data = json.loads(result.stdout or "{}")
            return self._parse_results(data, image)

        except subprocess.TimeoutExpired:
            logger.error("DockerAgent: trivy timed out (image pull too slow?)", image=image)
            return []
        except json.JSONDecodeError as e:
            logger.warning("DockerAgent: failed to parse trivy output", error=str(e))
            return []

    def _parse_results(self, data: dict, image: str) -> list[Finding]:
        findings = []
        for result in data.get("Results", []):
            target = result.get("Target", image)
            for vuln in result.get("Vulnerabilities") or []:
                severity = SEVERITY_MAP.get(vuln.get("Severity", "UNKNOWN"), "INFO")
                findings.append(Finding(
                    id=vuln.get("VulnerabilityID", "UNKNOWN"),
                    title=vuln.get("Title") or vuln.get("VulnerabilityID", ""),
                    description=vuln.get("Description", "")[:500],
                    severity=severity,
                    finding_type=FindingType.DOCKER,
                    package=vuln.get("PkgName"),
                    version=vuln.get("InstalledVersion"),
                    fixed_version=vuln.get("FixedVersion"),
                    cvss_score=self._extract_cvss(vuln),
                    source="trivy",
                    file_path=target,
                ))
        return findings

    def _extract_cvss(self, vuln: dict) -> float | None:
        scores = vuln.get("CVSS", {})
        for source in ("nvd", "redhat"):
            if source in scores:
                v3 = scores[source].get("V3Score")
                if v3:
                    return float(v3)
        return None
