"""
Orchestrator — runs all agents in sequence and aggregates results.
"""

import asyncio
import time
from pathlib import Path
from typing import Optional

from agents.dep_agent import DepAgent
from agents.sast_agent import SASTAgent
from agents.docker_agent import DockerAgent
from agents.llm_scan_agent import LLMScanAgent
from agents.cve_gap_agent import CVEGapAgent
from agents.exploitability_agent import ExploitabilityAgent
from agents.git_history_agent import GitHistoryAgent
from agents.web_agent import WebAgent
from agents.llm_web_agent import LLMWebAgent
from agents.pentest.recon_agent import ReconAgent
from agents.pentest.pentest_agent import PentestAgent
from agents.triage_agent import TriageAgent
from agents.report_agent import ReportAgent
from core.models import ScanResult, Finding
from core.github import clone_repo, create_issue
from core.logger import get_logger

logger = get_logger(__name__)


class Orchestrator:
    def __init__(
        self,
        repo_url: Optional[str],
        image: Optional[str],
        url: Optional[str] = None,
        output_path: str = "report.md",
        create_issue: bool = False,
        use_llm: bool = True,
        pentest: bool = False,
        local_repo_path: Optional[Path] = None,
    ):
        self.repo_url = repo_url
        self.image = image
        self.url = url
        self.output_path = output_path
        self.create_issue = create_issue
        self.use_llm = use_llm
        self.pentest = pentest
        self.local_repo_path = local_repo_path  # skip download when set

    async def run(self) -> ScanResult:
        start = time.time()
        all_findings: list[Finding] = []
        repo_path: Optional[Path] = None

        logger.info("Starting scan", repo=self.repo_url, image=self.image, url=self.url)

        # --- Resolve repo path (download or use local) ---
        if self.local_repo_path:
            repo_path = self.local_repo_path
            logger.info("Using local repo", path=str(repo_path))
        elif self.repo_url:
            repo_path = await clone_repo(self.repo_url)
            logger.info("Repo cloned", path=str(repo_path))

        # --- Run repo agents if we have a local path ---
        if repo_path:
            # Phase 1: DepAgent + SASTAgent + GitHistoryAgent in parallel
            dep_agent = DepAgent()
            dep_findings, sast_findings, git_findings = await asyncio.gather(
                dep_agent.run(repo_path),
                SASTAgent().run(repo_path),
                GitHistoryAgent().run(repo_path),
            )
            all_findings.extend(dep_findings)
            all_findings.extend(sast_findings)
            all_findings.extend(git_findings)

            # Phase 2: LLM agents — inject package context from DepAgent
            if self.use_llm:
                known_cve_ids = {f.id for f in dep_findings}

                # LLMScanAgent: CVE-aware source code review
                llm_scan = LLMScanAgent()
                llm_scan.packages = dep_agent.packages
                llm_scan.known_cve_ids = known_cve_ids

                # CVEGapAgent: asks LLM what CVEs it knows beyond OSV
                cve_gap = CVEGapAgent()

                llm_results = await asyncio.gather(
                    llm_scan.run(repo_path),
                    cve_gap.run(dep_agent.packages, dep_findings),
                )
                all_findings.extend(llm_results[0])  # llm code scan
                all_findings.extend(llm_results[1])  # cve gap

        # --- Docker scan if image provided ---
        if self.image:
            docker_findings = await DockerAgent().run(self.image)
            all_findings.extend(docker_findings)

        # --- Web scan if URL provided ---
        if self.url:
            web_tasks = [asyncio.create_task(WebAgent().run(self.url))]
            if self.use_llm:
                web_tasks.append(asyncio.create_task(LLMWebAgent().run(self.url)))
            web_results = await asyncio.gather(*web_tasks)
            all_findings.extend(web_results[0])
            if self.use_llm:
                all_findings.extend(web_results[1])

            # --- Pentest mode: autonomous ReAct agent with DeepSeek R1 ---
            if self.pentest:
                logger.info("Pentest mode: starting recon + autonomous agent")
                recon = await ReconAgent().run(self.url)
                pentest_findings = await PentestAgent(self.url, recon).run()
                all_findings.extend(pentest_findings)

        # --- Exploitability assessment (LLM checks if each CVE is reachable in the code) ---
        if self.use_llm and repo_path:
            all_findings = await ExploitabilityAgent(use_llm=True).run(all_findings, repo_path)

        # --- Triage ---
        triage_agent = TriageAgent(use_llm=self.use_llm)
        triaged = await triage_agent.run(all_findings)

        # --- Report ---
        report_agent = ReportAgent()
        report_md = await report_agent.run(
            findings=triaged,
            repo_url=self.repo_url,
            image=self.image,
            duration=time.time() - start,
        )

        Path(self.output_path).write_text(report_md)
        logger.info("Report written", path=self.output_path)

        # --- GitHub Issue ---
        if self.create_issue and self.repo_url:
            critical = [f for f in triaged if f.severity in ("CRITICAL", "HIGH")]
            if critical:
                await create_issue(self.repo_url, report_md)
                logger.info("GitHub issue created")

        result = ScanResult(
            findings=triaged,
            duration=time.time() - start,
            repo_url=self.repo_url,
            image=self.image,
        )

        self._last_findings = triaged  # expose for benchmark access

        self._print_summary(result)
        return result

    def _print_summary(self, result: ScanResult):
        from collections import Counter
        from core.llm import cost_tracker
        counts = Counter(f.severity for f in result.findings)
        print(f"\n{'='*50}")
        print(f"Scan completed in {result.duration:.1f}s")
        print(f"  CRITICAL : {counts.get('CRITICAL', 0)}")
        print(f"  HIGH     : {counts.get('HIGH', 0)}")
        print(f"  MEDIUM   : {counts.get('MEDIUM', 0)}")
        print(f"  LOW      : {counts.get('LOW', 0)}")
        if cost_tracker.calls > 0:
            print(f"  LLM Cost : {cost_tracker.summary()}")
        print(f"  Report   : {self.output_path}")
        print(f"{'='*50}\n")
