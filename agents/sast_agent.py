"""
SASTAgent — static analysis via Semgrep CLI.
Semgrep must be installed: pip install semgrep

Rule sources (combined in a single run):
  1. rules/  — custom rules (55 rules, 7 languages, always used, works offline)
  2. Semgrep community packs — downloaded on first use, cached in ~/.semgrep/
       - p/owasp-top-ten  (always)
       - p/secrets        (always)
       - p/python / p/javascript / p/java / p/php / p/go / p/ruby / p/c-sharp
         (auto-enabled based on detected languages)

Set SEMGREP_COMMUNITY=false to disable community rules (offline / CI use).
"""

import json
import os
import subprocess
import sys
from pathlib import Path

from core.models import Finding, FindingType
from core.logger import get_logger

logger = get_logger(__name__)

RULES_DIR = Path(__file__).parent.parent / "rules"

SEVERITY_MAP = {
    "CRITICAL": "CRITICAL",
    "ERROR":    "HIGH",
    "WARNING":  "MEDIUM",
    "INFO":     "LOW",
}

# Community packs always included when community rules are enabled
ALWAYS_PACKS = ["p/owasp-top-ten", "p/secrets"]

# Language extension → community pack
LANGUAGE_PACKS: dict[str, str] = {
    ".py":   "p/python",
    ".js":   "p/javascript",
    ".ts":   "p/javascript",
    ".jsx":  "p/javascript",
    ".tsx":  "p/javascript",
    ".java": "p/java",
    ".php":  "p/php",
    ".go":   "p/go",
    ".rb":   "p/ruby",
    ".cs":   "p/c-sharp",
}

SKIP_DIRS = {"node_modules", ".git", "__pycache__", "venv", ".venv", "dist", "build", "vendor"}


def _semgrep_bin() -> str:
    venv_bin = Path(sys.executable).parent / "semgrep"
    if venv_bin.exists():
        return str(venv_bin)
    return "semgrep"


def _detect_languages(repo_path: Path) -> set[str]:
    """Return set of file extensions present in the repo (skipping vendor dirs)."""
    extensions: set[str] = set()
    for f in repo_path.rglob("*"):
        if not f.is_file():
            continue
        if any(skip in f.parts for skip in SKIP_DIRS):
            continue
        if f.suffix in LANGUAGE_PACKS:
            extensions.add(f.suffix)
    return extensions


def _community_configs(repo_path: Path) -> list[str]:
    """Return list of --config values for community packs, based on detected languages."""
    if os.getenv("SEMGREP_COMMUNITY", "true").lower() in ("false", "0", "no"):
        return []
    langs = _detect_languages(repo_path)
    packs = list(ALWAYS_PACKS)
    seen_packs: set[str] = set(packs)
    for ext in langs:
        pack = LANGUAGE_PACKS.get(ext)
        if pack and pack not in seen_packs:
            packs.append(pack)
            seen_packs.add(pack)
    return packs


def _is_community_rule(rule_id: str) -> bool:
    """True if the rule comes from a Semgrep community pack (not our custom rules/)."""
    community_prefixes = (
        "python.", "javascript.", "typescript.", "java.", "php.",
        "go.", "ruby.", "csharp.", "generic.", "secrets.",
        "trailofbits.", "semgrep.", "owasp.",
    )
    return any(rule_id.startswith(p) for p in community_prefixes)


class SASTAgent:
    async def run(self, repo_path: Path) -> list[Finding]:
        logger.info("SASTAgent starting", path=str(repo_path))

        semgrep = _semgrep_bin()
        if not self._semgrep_available(semgrep):
            logger.warning("SASTAgent: semgrep not found, skipping. Install with: pip install semgrep")
            return []

        community_packs = _community_configs(repo_path)
        if community_packs:
            logger.info("SASTAgent: community packs enabled", packs=len(community_packs))

        findings = self._run_semgrep(repo_path, semgrep, community_packs)

        # Deduplicate by (rule_id, file, line)
        seen: set[tuple] = set()
        deduped: list[Finding] = []
        for f in findings:
            key = (f.id, f.file_path, f.line)
            if key not in seen:
                seen.add(key)
                deduped.append(f)

        custom_count = sum(1 for f in deduped if f.source == "semgrep-custom")
        community_count = sum(1 for f in deduped if f.source == "semgrep-community")
        logger.info("SASTAgent done",
                    findings=len(deduped),
                    custom=custom_count,
                    community=community_count)
        return deduped

    def _semgrep_available(self, semgrep: str) -> bool:
        try:
            result = subprocess.run([semgrep, "--version"], capture_output=True, timeout=5)
            return result.returncode == 0
        except (FileNotFoundError, subprocess.TimeoutExpired):
            return False

    def _run_semgrep(
        self,
        repo_path: Path,
        semgrep: str,
        community_packs: list[str],
    ) -> list[Finding]:
        cmd = [semgrep, "--config", str(RULES_DIR)]
        for pack in community_packs:
            cmd += ["--config", pack]
        cmd += ["--json", "--quiet", "--no-git-ignore", str(repo_path)]

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=300,
            )

            if result.returncode not in (0, 1):
                # Community rules may fail with auth errors or network issues.
                # Retry with custom rules only before giving up.
                if community_packs and result.returncode == 2:
                    logger.warning(
                        "SASTAgent: community rules failed (network/auth?), retrying with custom rules only",
                        stderr=result.stderr[:300],
                    )
                    return self._run_semgrep(repo_path, semgrep, [])
                logger.warning("SASTAgent: semgrep returned unexpected exit code",
                               code=result.returncode, stderr=result.stderr[:200])
                if not result.stdout:
                    return []

            data = json.loads(result.stdout or "{}")
            findings = self._parse_results(data, repo_path)
            return findings

        except subprocess.TimeoutExpired as e:
            logger.warning("SASTAgent: semgrep timed out after 300s — returning partial results")
            partial_stdout = getattr(e, "output", None) or ""
            if isinstance(partial_stdout, bytes):
                partial_stdout = partial_stdout.decode(errors="ignore")
            try:
                data = json.loads(partial_stdout or "{}")
                return self._parse_results(data, repo_path)
            except Exception:
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

            source = "semgrep-community" if _is_community_rule(rule_id) else "semgrep-custom"

            # Community rules often have richer metadata
            metadata = extra.get("metadata", {})
            raw_cwe = metadata.get("cwe", [])
            if isinstance(raw_cwe, str):
                raw_cwe = [raw_cwe]
            # Keep only well-formed CWE entries (e.g. "CWE-78" or "CWE-78: ...")
            cwe = [c for c in raw_cwe if c and re.match(r"CWE-\d+", c)]

            message = extra.get("message", "")
            # Prepend CWE so it survives the description length cap
            if cwe:
                cwe_str = ", ".join(c.split(":")[0] for c in cwe)  # keep "CWE-78" only
                description = f"[{cwe_str}] {message}"
            else:
                description = message

            findings.append(Finding(
                id=rule_id,
                title=message[:120],
                description=description[:500],
                severity=severity,
                finding_type=FindingType.SAST,
                file_path=rel_path,
                line=result.get("start", {}).get("line"),
                source=source,
            ))

        return findings
