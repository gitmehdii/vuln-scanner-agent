"""
CVEGapAgent — uses the LLM's CVE training knowledge to find vulnerabilities
that OSV.dev hasn't returned for the installed packages.

Flow:
  1. Receive packages + existing OSV findings
  2. Ask LLM (in batches of 25 packages): "what CVEs do you know that aren't here?"
  3. Cross-validate every LLM-reported CVE against the real OSV API
  4. Return only confirmed CVEs (OSV data) or LLM-only findings with lower confidence
"""

import asyncio
import json
import os
import re
from pathlib import Path
from typing import Optional

import httpx

from core.models import Finding, FindingType
from core.logger import get_logger
from core.llm import llm_call

logger = get_logger(__name__)

BATCH_SIZE = 25  # packages per LLM call
OSV_VULN_URL = "https://api.osv.dev/v1/vulns/{id}"

GAP_PROMPT = """You are a security expert with CVE knowledge up to mid-2025.

I scanned these {ecosystem} packages with OSV.dev and got the CVEs listed.
Find any CRITICAL or HIGH CVEs for these packages that are NOT already in my list.

Packages (name==version):
{packages}

CVE IDs already found by OSV (do NOT repeat):
{known_cves}

Rules:
- Only report CVEs you are CERTAIN about (no guesses, no hallucinations)
- Only CRITICAL and HIGH severity
- Include the exact package name and version range affected
- If unsure about the CVE ID, skip it

Return ONLY a JSON array, nothing else. Each object:
{{
  "cve_id": "CVE-2024-XXXXX or GHSA-xxxx-xxxx-xxxx",
  "package": "exact-package-name",
  "severity": "CRITICAL" or "HIGH",
  "description": "one sentence — what is vulnerable and how",
  "fixed_version": "1.2.3 or null"
}}

Return [] if you have nothing to add."""


class CVEGapAgent:
    def __init__(self):
        self.api_key = os.getenv("OPENROUTER_API_KEY") or os.getenv("OPENAI_API_KEY")

    async def run(
        self,
        packages: list[dict],
        existing_findings: list[Finding],
    ) -> list[Finding]:
        if not self.api_key:
            logger.warning("CVEGapAgent: no API key, skipping.")
            return []

        if not packages:
            return []

        # Group packages by ecosystem
        by_eco: dict[str, list[dict]] = {}
        for p in packages:
            by_eco.setdefault(p["ecosystem"], []).append(p)

        # Build set of already-known CVE IDs to pass to LLM
        known_ids = {f.id for f in existing_findings if f.finding_type == FindingType.DEPENDENCY}

        all_findings: list[Finding] = []
        for ecosystem, eco_packages in by_eco.items():
            findings = await self._query_ecosystem(ecosystem, eco_packages, known_ids)
            all_findings.extend(findings)

        # Deduplicate against existing
        new_ids = {f.id for f in all_findings}
        truly_new = [f for f in all_findings if f.id not in known_ids]

        logger.info("CVEGapAgent done",
                    llm_reported=len(all_findings),
                    new_after_dedup=len(truly_new))
        return truly_new

    async def _query_ecosystem(
        self,
        ecosystem: str,
        packages: list[dict],
        known_ids: set[str],
    ) -> list[Finding]:
        findings = []

        for i in range(0, len(packages), BATCH_SIZE):
            batch = packages[i:i + BATCH_SIZE]
            pkg_list = "\n".join(f"{p['name']}=={p['version']}" for p in batch)
            known_sample = "\n".join(sorted(known_ids)[:60])  # cap to avoid huge prompts

            prompt = GAP_PROMPT.format(
                ecosystem=ecosystem,
                packages=pkg_list,
                known_cves=known_sample or "(none yet)",
            )

            try:
                raw = await llm_call(prompt, reasoning=False, max_tokens=800, temperature=0.0)
                candidates = self._parse_llm_response(raw)

                if not candidates:
                    continue

                logger.info("CVEGapAgent: LLM reported candidates",
                            ecosystem=ecosystem, count=len(candidates))

                # Cross-validate each candidate against OSV
                validated = await self._validate_candidates(candidates, batch)
                findings.extend(validated)

            except Exception as e:
                logger.warning("CVEGapAgent: LLM call failed", error=str(e))

        return findings

    def _parse_llm_response(self, raw: str) -> list[dict]:
        try:
            start = raw.find("[")
            end = raw.rfind("]") + 1
            if start == -1 or end == 0:
                return []
            data = json.loads(raw[start:end])
            if not isinstance(data, list):
                return []

            valid = []
            for item in data:
                if not isinstance(item, dict):
                    continue
                cve_id = str(item.get("cve_id", "")).strip()
                # Must look like a real CVE or GHSA ID
                if not re.match(r"^(CVE-\d{4}-\d{4,}|GHSA-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4})$",
                                cve_id, re.IGNORECASE):
                    logger.debug("CVEGapAgent: skipping invalid ID", id=cve_id)
                    continue
                valid.append(item)
            return valid
        except json.JSONDecodeError:
            return []

    async def _validate_candidates(
        self,
        candidates: list[dict],
        packages: list[dict],
    ) -> list[Finding]:
        """Fetch each candidate from OSV to confirm it exists and get real data."""
        pkg_by_name = {p["name"].lower(): p for p in packages}
        sem = asyncio.Semaphore(10)

        async def fetch_and_build(candidate: dict) -> Optional[Finding]:
            cve_id = candidate["cve_id"]
            async with sem:
                try:
                    async with httpx.AsyncClient(timeout=10) as c:
                        r = await c.get(OSV_VULN_URL.format(id=cve_id))
                        if r.status_code == 200:
                            return self._finding_from_osv(r.json(), candidate, pkg_by_name)
                        elif r.status_code == 404:
                            # CVE not in OSV — include as LLM-only finding with low confidence
                            return self._finding_from_llm_only(candidate, pkg_by_name)
                except Exception:
                    pass
            return None

        results = await asyncio.gather(*[fetch_and_build(c) for c in candidates])
        confirmed = [f for f in results if f is not None]

        osv_confirmed = sum(1 for f in confirmed if f.source == "osv-llm-gap")
        llm_only = sum(1 for f in confirmed if f.source == "llm-gap")
        logger.info("CVEGapAgent: validation done",
                    confirmed_osv=osv_confirmed, llm_only=llm_only)
        return confirmed

    def _finding_from_osv(
        self,
        vuln: dict,
        candidate: dict,
        pkg_by_name: dict,
    ) -> Optional[Finding]:
        """Build a Finding from OSV-confirmed data (LLM found the gap, OSV provides the details)."""
        pkg_name = candidate.get("package", "")
        pkg = pkg_by_name.get(pkg_name.lower())
        if not pkg:
            return None

        db = vuln.get("database_specific", {})
        sev_str = str(db.get("severity", candidate.get("severity", "HIGH"))).upper()
        if sev_str not in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
            sev_str = "HIGH"

        # Only keep HIGH/CRITICAL — we asked the LLM for those
        if sev_str not in ("CRITICAL", "HIGH"):
            return None

        fixed = self._extract_fixed(vuln)
        description = (
            f"[Found by LLM gap analysis — confirmed in OSV] "
            f"{vuln.get('details') or vuln.get('summary') or candidate.get('description', '')}".strip()
        )[:600]

        return Finding(
            id=vuln.get("id", candidate["cve_id"]),
            title=vuln.get("summary", candidate["cve_id"])[:120],
            description=description,
            severity=sev_str,
            finding_type=FindingType.DEPENDENCY,
            package=pkg["name"],
            version=pkg["version"],
            fixed_version=fixed,
            source="osv-llm-gap",
            llm_context="Discovered by LLM knowledge gap analysis — not returned by OSV batch query for this version.",
        )

    def _finding_from_llm_only(
        self,
        candidate: dict,
        pkg_by_name: dict,
    ) -> Optional[Finding]:
        """Build a Finding for CVEs the LLM knows about but that aren't in OSV.dev."""
        pkg_name = candidate.get("package", "")
        pkg = pkg_by_name.get(pkg_name.lower())
        if not pkg:
            return None

        sev_str = str(candidate.get("severity", "HIGH")).upper()
        if sev_str not in ("CRITICAL", "HIGH"):
            return None

        return Finding(
            id=candidate["cve_id"],
            title=f"{candidate['cve_id']} — {pkg['name']}",
            description=(
                f"[LLM knowledge only — not yet in OSV.dev] "
                f"{candidate.get('description', '')}".strip()
            )[:500],
            severity=sev_str,
            finding_type=FindingType.DEPENDENCY,
            package=pkg["name"],
            version=pkg["version"],
            fixed_version=candidate.get("fixed_version"),
            source="llm-gap",
            llm_context="Reported by LLM but not found in OSV.dev — verify manually before acting on this.",
        )

    def _extract_fixed(self, vuln: dict) -> Optional[str]:
        for affected in vuln.get("affected", []):
            for r in affected.get("ranges", []):
                for event in r.get("events", []):
                    if "fixed" in event:
                        return event["fixed"]
        return None
