"""
SASTAgent — static analysis via Semgrep CLI.
Semgrep must be installed: pip install semgrep
"""

import json
import subprocess
import sys
from pathlib import Path

from core.models import Finding, FindingType
from core.logger import get_logger

logger = get_logger(__name__)

# Dossier de règles — Semgrep charge tous les .yaml présents (Python, JS/TS, Java, PHP, Go, Ruby, C#)
RULES_DIR = Path(__file__).parent.parent / "rules"

SEVERITY_MAP = {
    "ERROR": "HIGH",
    "WARNING": "MEDIUM",
    "INFO": "LOW",
}


def _semgrep_bin() -> str:
    """Retourne le binaire semgrep du venv courant si dispo, sinon PATH."""
    venv_bin = Path(sys.executable).parent / "semgrep"
    if venv_bin.exists():
        return str(venv_bin)
    return "semgrep"


class SASTAgent:
    async def run(self, repo_path: Path) -> list[Finding]:
        logger.info("SASTAgent starting", path=str(repo_path))

        semgrep = _semgrep_bin()
        if not self._semgrep_available(semgrep):
            logger.warning("SASTAgent: semgrep not found, skipping. Install with: pip install semgrep")
            return []

        findings = self._run_semgrep(repo_path, semgrep)

        # Deduplicate by (rule_id, file, line)
        seen = set()
        deduped = []
        for f in findings:
            key = (f.id, f.file_path, f.line)
            if key not in seen:
                seen.add(key)
                deduped.append(f)

        logger.info("SASTAgent done", findings=len(deduped))
        return deduped

    def _semgrep_available(self, semgrep: str) -> bool:
        try:
            result = subprocess.run([semgrep, "--version"], capture_output=True, timeout=5)
            return result.returncode == 0
        except (FileNotFoundError, subprocess.TimeoutExpired):
            return False

    def _run_semgrep(self, repo_path: Path, semgrep: str) -> list[Finding]:
        try:
            result = subprocess.run(
                [
                    semgrep,
                    "--config", str(RULES_DIR),
                    "--json",
                    "--quiet",
                    "--no-git-ignore",
                    str(repo_path),
                ],
                capture_output=True,
                text=True,
                timeout=300,
            )

            if result.returncode not in (0, 1):  # 1 = findings found
                logger.warning("SASTAgent: semgrep returned unexpected exit code",
                               code=result.returncode, stderr=result.stderr[:200])
                # Still try to parse partial output on non-zero exit
                if not result.stdout:
                    return []

            data = json.loads(result.stdout or "{}")
            findings = self._parse_results(data, repo_path)
            logger.info("SASTAgent: semgrep run done", findings=len(findings))
            return findings

        except subprocess.TimeoutExpired as e:
            logger.warning("SASTAgent: semgrep timed out after 300s — returning partial results")
            # Semgrep may have written partial JSON to stdout before timeout
            partial_stdout = getattr(e, "output", None) or ""
            if isinstance(partial_stdout, bytes):
                partial_stdout = partial_stdout.decode(errors="ignore")
            try:
                data = json.loads(partial_stdout or "{}")
                return self._parse_results(data, repo_path)
            except (json.JSONDecodeError, Exception):
                return []
        except json.JSONDecodeError as e:
            logger.warning("SASTAgent: failed to parse semgrep output", error=str(e))
            return []

    def _parse_results(self, data: dict, repo_path: Path) -> list[Finding]:
        findings = []
        for result in data.get("results", []):
            rule_id = result.get("check_id", "unknown")
            extra = result.get("extra", {})
            severity_raw = extra.get("severity", "WARNING").upper()
            severity = SEVERITY_MAP.get(severity_raw, "MEDIUM")

            file_path = result.get("path", "")
            try:
                rel_path = str(Path(file_path).relative_to(repo_path))
            except ValueError:
                rel_path = file_path

            findings.append(Finding(
                id=rule_id,
                title=extra.get("message", rule_id)[:120],
                description=extra.get("message", "")[:500],
                severity=severity,
                finding_type=FindingType.SAST,
                file_path=rel_path,
                line=result.get("start", {}).get("line"),
                source="semgrep",
            ))

        return findings
