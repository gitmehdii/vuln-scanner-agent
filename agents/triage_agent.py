"""
TriageAgent — deduplicates findings, sorts by severity, optionally adds LLM context.
"""

import asyncio
import dataclasses
import os
import re
from collections import defaultdict

from core.models import Finding, FindingType
from core.logger import get_logger
from core.llm import llm_call

logger = get_logger(__name__)

SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}

# Only enrich CRITICAL and HIGH with LLM to limit cost
LLM_ENRICH_SEVERITIES = {"CRITICAL", "HIGH"}

LLM_PROMPT = """You are a security analyst. Given this vulnerability finding, write a 2-sentence triage note:
1. Why it's dangerous in practice (not just the CVE description)
2. The most important remediation step

Finding:
ID: {id}
Title: {title}
Description: {description}
Package: {package} {version}
Severity: {severity}

Respond in plain text, no markdown."""


class TriageAgent:
    def __init__(self, use_llm: bool = True):
        self.use_llm = use_llm
        self.api_key = os.getenv("OPENROUTER_API_KEY") or os.getenv("OPENAI_API_KEY")

    async def run(self, findings: list[Finding]) -> list[Finding]:
        logger.info("TriageAgent starting", total=len(findings))

        # Deduplicate by (id, package, file_path)
        seen = set()
        deduped = []
        for f in findings:
            key = (f.id, f.package or "", f.file_path or "")
            if key not in seen:
                seen.add(key)
                deduped.append(f)

        # Merge web findings with the same title across multiple pages
        deduped = self._dedup_web(deduped)

        logger.info("TriageAgent: after dedup", count=len(deduped))

        # Sort by severity
        deduped.sort(key=lambda f: SEVERITY_ORDER.get(f.severity, 99))

        # LLM enrichment on CRITICAL + HIGH only (skip findings already produced by LLMScanAgent)
        if self.use_llm and self.api_key:
            high_prio = [f for f in deduped if f.severity in LLM_ENRICH_SEVERITIES and f.source != "llm"]
            to_enrich = high_prio[:50]
            logger.info("TriageAgent: LLM enriching", count=len(to_enrich))
            sem = asyncio.Semaphore(8)

            async def enrich_one(finding):
                async with sem:
                    finding.llm_context = await self._enrich(finding)

            await asyncio.gather(*[enrich_one(f) for f in to_enrich])
        elif self.use_llm and not self.api_key:
            logger.warning("TriageAgent: no API key found, skipping LLM enrichment. Set OPENROUTER_API_KEY or OPENAI_API_KEY.")

        logger.info("TriageAgent done", findings=len(deduped))
        return deduped

    def _dedup_web(self, findings: list[Finding]) -> list[Finding]:
        """Merge WEB findings with the same title found across multiple pages."""
        web = [f for f in findings if f.finding_type == FindingType.WEB]
        rest = [f for f in findings if f.finding_type != FindingType.WEB]

        groups: dict[str, list[Finding]] = defaultdict(list)
        for f in web:
            key = re.sub(r"[^a-z0-9]", "", f.title.lower())[:60]
            groups[key].append(f)

        merged = []
        for group in groups.values():
            if len(group) == 1:
                merged.append(group[0])
                continue
            best = min(group, key=lambda f: SEVERITY_ORDER.get(f.severity, 99))
            urls = list(dict.fromkeys(f.file_path for f in group if f.file_path))
            if len(urls) > 1:
                url_list = "\n".join(f"- {u}" for u in urls)
                desc = best.description + f"\n\n**Affected on {len(urls)} page(s):**\n{url_list}"
            else:
                desc = best.description
            copy = dataclasses.replace(best, description=desc)
            merged.append(copy)
            logger.info("TriageAgent: merged web findings", title=best.title, count=len(group))

        return rest + merged

    async def _enrich(self, finding: Finding) -> str:
        try:
            prompt = LLM_PROMPT.format(
                id=finding.id,
                title=finding.title,
                description=finding.description[:300],
                package=finding.package or "N/A",
                version=finding.version or "N/A",
                severity=finding.severity,
            )
            return await llm_call(prompt, reasoning=False, max_tokens=120, temperature=0.2)
        except Exception as e:
            logger.warning("TriageAgent: LLM enrichment failed", id=finding.id, error=str(e))
            return ""
