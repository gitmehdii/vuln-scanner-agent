"""
ReportAgent — generates a structured markdown vulnerability report.
"""

from collections import Counter, defaultdict
from datetime import datetime, timezone
from typing import Optional

from core.models import Finding, FindingType
from core.logger import get_logger

logger = get_logger(__name__)

SEVERITY_EMOJI = {
    "CRITICAL": "🔴",
    "HIGH": "🟠",
    "MEDIUM": "🟡",
    "LOW": "🔵",
    "INFO": "⚪",
}

SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}


class ReportAgent:
    async def run(
        self,
        findings: list[Finding],
        repo_url: Optional[str],
        image: Optional[str],
        duration: float,
    ) -> str:
        logger.info("ReportAgent generating report", findings=len(findings))

        counts = Counter(f.severity for f in findings)
        now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

        lines = []

        # Header
        lines.append("# Vulnerability Scan Report")
        lines.append(f"\n**Date:** {now}  ")
        if repo_url:
            lines.append(f"**Repo:** {repo_url}  ")
        if image:
            lines.append(f"**Image:** `{image}`  ")
        lines.append(f"**Duration:** {duration:.1f}s  ")
        lines.append(f"**Total findings:** {len(findings)}\n")

        # Summary table
        lines.append("## Summary\n")
        lines.append("| Severity | Count |")
        lines.append("|----------|-------|")
        for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
            if counts.get(sev, 0) > 0:
                emoji = SEVERITY_EMOJI.get(sev, "")
                lines.append(f"| {emoji} {sev} | {counts[sev]} |")
        lines.append("")

        # Group findings by type
        by_type = {
            FindingType.DEPENDENCY: [],
            FindingType.SAST: [],
            FindingType.DOCKER: [],
            FindingType.LLM: [],
            FindingType.WEB: [],
        }
        for f in findings:
            by_type[f.finding_type].append(f)

        section_titles = {
            FindingType.DEPENDENCY: "Dependency Vulnerabilities (OSV + LLM gap analysis)",
            FindingType.SAST: "Static Analysis Findings (Semgrep)",
            FindingType.DOCKER: "Docker Image Vulnerabilities (Trivy)",
            FindingType.LLM: "AI Code Review — CVE patterns & logic flaws (DeepSeek)",
            FindingType.WEB: "Web Application Security",
        }

        for ftype, title in section_titles.items():
            section_findings = by_type[ftype]
            if not section_findings:
                continue

            lines.append(f"## {title}\n")

            if ftype == FindingType.DEPENDENCY:
                self._render_dep_section(lines, section_findings)
            elif ftype == FindingType.LLM:
                self._render_llm_section(lines, section_findings)
            elif ftype == FindingType.WEB:
                self._render_web_section(lines, section_findings)
            else:
                self._render_generic_section(lines, section_findings)

        if not findings:
            lines.append("## No findings\n")
            lines.append("No vulnerabilities detected. 🎉\n")

        report = "\n".join(lines)
        logger.info("ReportAgent done", chars=len(report))
        return report

    def _render_dep_section(self, lines: list[str], findings: list[Finding]) -> None:
        """Group dep findings by (package, version) — one block per package."""
        groups: dict[tuple, list[Finding]] = defaultdict(list)
        for f in findings:
            groups[(f.package or "", f.version or "")].append(f)

        # Sort groups by worst severity first
        def group_worst(item):
            _, fs = item
            return min(SEVERITY_ORDER.get(f.severity, 99) for f in fs)

        for (pkg, ver), group in sorted(groups.items(), key=group_worst):
            worst = min(group, key=lambda f: SEVERITY_ORDER.get(f.severity, 99))
            emoji = SEVERITY_EMOJI.get(worst.severity, "")
            lines.append(f"### {emoji} `{pkg}` @ `{ver}`\n")

            # Fixed version: take the first one found across CVEs
            fixed = next((f.fixed_version for f in group if f.fixed_version), None)
            if fixed:
                lines.append(f"**Fix:** upgrade to `{fixed}`  ")

            lines.append("")
            lines.append("| CVE | Severity | CVSS | Exploitable? | Analyse |")
            lines.append("|-----|----------|------|-------------|---------|")
            for f in sorted(group, key=lambda f: SEVERITY_ORDER.get(f.severity, 99)):
                sev_em = SEVERITY_EMOJI.get(f.severity, "")
                cvss = f"{f.cvss_score:.1f}" if f.cvss_score else "—"
                cve_link = f"[{f.id}](https://osv.dev/vulnerability/{f.id})"
                if f.exploitable is True:
                    expl = "⚠️ Yes"
                elif f.exploitable is False:
                    expl = "✅ No"
                else:
                    source_badge = {
                        "osv-llm-gap": "🤖 LLM+OSV",
                        "llm-gap":     "🤖 LLM only",
                    }.get(f.source or "", "—")
                    expl = source_badge
                analyse = (f.llm_context or f.description or f.title or "").replace("|", "\\|").replace("\n", " ")
                lines.append(f"| {cve_link} | {sev_em} {f.severity} | {cvss} | {expl} | {analyse} |")

            lines.append("\n---\n")

    def _render_generic_section(self, lines: list[str], findings: list[Finding]) -> None:
        """One block per finding — used for SAST and Docker sections."""
        for f in findings:
            emoji = SEVERITY_EMOJI.get(f.severity, "")
            lines.append(f"### {emoji} {f.id}")

            lines.append(f"**Severity:** {f.severity}  ")
            if f.package:
                ver = f.version or "unknown"
                lines.append(f"**Package:** `{f.package}` @ `{ver}`  ")
            if f.fixed_version:
                lines.append(f"**Fix:** upgrade to `{f.fixed_version}`  ")
            if f.cvss_score:
                lines.append(f"**CVSS:** {f.cvss_score}  ")
            if f.file_path:
                loc = f.file_path
                if f.line:
                    loc += f":{f.line}"
                lines.append(f"**Location:** `{loc}`  ")

            lines.append(f"\n{f.description}\n")

            if f.llm_context:
                lines.append(f"> **Analyst note:** {f.llm_context}\n")

            lines.append("---\n")

    def _render_llm_section(self, lines: list[str], findings: list[Finding]) -> None:
        """LLM findings — one block per finding, sorted by severity, with attack scenario."""
        CATEGORY_LABEL = {
            "idor":            "IDOR",
            "auth":            "Auth bypass",
            "mass_assignment": "Mass assignment",
            "logic":           "Business logic",
            "injection":       "Injection",
            "secrets":         "Hardcoded secret",
            "race":            "Race condition",
            "upload":          "Insecure upload",
            "session":         "Session management",
            "disclosure":      "Info disclosure",
            "deserialization": "Deserialization",
            "cmdi":            "Command injection",
            "ssrf":            "SSRF",
            "traversal":       "Path traversal",
            "sqli":            "SQL injection",
            "xxe":             "XXE",
            "jwt":             "JWT/auth",
            "config":          "Insecure config",
            "other":           "Other",
        }

        sorted_findings = sorted(
            findings, key=lambda f: SEVERITY_ORDER.get(f.severity, 99)
        )

        for f in sorted_findings:
            emoji = SEVERITY_EMOJI.get(f.severity, "")
            lines.append(f"### {emoji} {f.title}")
            lines.append(f"**Severity:** {f.severity}  ")

            # Extract category from ID (llm-<category>-...)
            parts = f.id.split("-")
            category_key = parts[1] if len(parts) > 1 else "other"
            category_label = CATEGORY_LABEL.get(category_key, category_key.replace("_", " ").title())
            lines.append(f"**Category:** {category_label}  ")

            if f.file_path and f.file_path != "cross-file":
                loc = f.file_path
                if f.line:
                    loc += f":{f.line}"
                lines.append(f"**Location:** `{loc}`  ")
            elif f.file_path == "cross-file":
                lines.append("**Scope:** cross-file vulnerability  ")

            lines.append("")

            # Split description and attack scenario (joined with \n\n**Attack scenario:**)
            desc = f.description or ""
            if "\n\n**Attack scenario:**" in desc:
                body, scenario = desc.split("\n\n**Attack scenario:**", 1)
                lines.append(body.strip())
                lines.append(f"\n> **Attack scenario:** {scenario.strip()}")
            else:
                lines.append(desc.strip())

            lines.append("\n---\n")

    def _render_web_section(self, lines: list[str], findings: list[Finding]) -> None:
        """Web findings grouped by source (headers, nuclei, llm-web) — URL rendered as clickable link."""
        for f in sorted(findings, key=lambda f: SEVERITY_ORDER.get(f.severity, 99)):
            emoji = SEVERITY_EMOJI.get(f.severity, "")
            lines.append(f"### {emoji} {f.title}")
            lines.append(f"**Severity:** {f.severity}  ")
            lines.append(f"**Source:** `{f.source}`  ")
            if f.file_path:
                if f.file_path.startswith("http"):
                    lines.append(f"**URL:** [{f.file_path}]({f.file_path})  ")
                else:
                    lines.append(f"**Location:** `{f.file_path}`  ")
            lines.append(f"\n{f.description}\n")
            lines.append("---\n")
