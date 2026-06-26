"""
LLMScanAgent — finds vulnerabilities in custom application code that have no CVE.

Why this is unique:
  - Semgrep/Bandit match patterns without understanding data flow or business logic
  - OSV only covers known vulnerabilities in third-party libraries
  - This agent reads the actual application logic and finds:
      * IDOR — object fetched by ID with no ownership check
      * Auth bypass — endpoint accessible without login/role check
      * Mass assignment — model created directly from request data
      * Business logic flaws — payment step skipped, coupon applied N times
      * Hardcoded secrets and insecure defaults
      * Second-order injection — stored XSS via admin panel, stored SQLi
      * Race conditions — non-atomic read-modify-write on sensitive data

Architecture: two-pass analysis
  Pass 1 — App understanding: read routing, settings, auth files → build a security model
  Pass 2 — Per-file analysis: each file analyzed with the app context from Pass 1
  Pass 3 — Synthesis: final cross-file call to find vulnerabilities that span files
"""

import asyncio
import json
import os
import re
from pathlib import Path

from core.models import Finding, FindingType
from core.logger import get_logger
from core.llm import llm_call

logger = get_logger(__name__)

SKIP_DIRS = {
    "venv", ".venv", "node_modules", ".git", "__pycache__",
    "migrations", "test", "tests", "fixtures", "dist", "build",
    "vendor", "static", "media", "public", "assets",
}
MAX_FILE_CHARS = 35_000
MAX_FILES = 30
CONCURRENCY = 4

# Files that define the security model of an app — read first for context
CONTEXT_FILE_PATTERNS = [
    # Routing / entry points
    r"urls\.py$", r"routes\.(js|ts|py|rb)$", r"router\.(js|ts)$",
    r"app\.(py|js|ts|rb)$", r"server\.(js|ts)$", r"index\.(js|ts)$",
    # Auth and middleware
    r"auth\.(py|js|ts|rb)$", r"authentication\.(py|js|ts)$",
    r"middleware\.(py|js|ts|rb)$", r"permissions\.(py|js|ts)$",
    r"decorators\.py$",
    # Configuration
    r"settings\.(py|js|ts)$", r"config\.(py|js|ts|rb)$",
    r"\.env$", r"\.env\.example$",
]

# File priority score — higher = analyzed first
def _file_priority(path: Path) -> int:
    name = path.name.lower()
    stem = path.stem.lower()
    parts = {p.lower() for p in path.parts}

    # Skip test/vendor dirs entirely
    if parts & SKIP_DIRS:
        return -1

    score = 0
    if stem in ("views", "view", "controller", "controllers", "handlers", "handler"):
        score += 100
    if stem in ("auth", "authentication", "login", "middleware", "permissions", "decorators"):
        score += 90
    if stem in ("settings", "config", "configuration"):
        score += 80
    if stem in ("models", "model", "schema", "schemas"):
        score += 60
    if stem in ("urls", "routes", "router", "routing"):
        score += 70
    if stem in ("api", "endpoints", "resources"):
        score += 85
    if stem in ("utils", "helpers", "lib"):
        score += 20
    return score


APP_CONTEXT_PROMPT = """You are a security architect reviewing a web application.

Read these key files (routing, config, auth, models) and produce a concise security map.

Files:
{files_content}

Respond with a JSON object (no prose):
{{
  "framework": "Django / Flask / Express / Rails / etc.",
  "auth_mechanism": "session / JWT / OAuth / none — describe briefly",
  "auth_decorators": ["@login_required", "authenticate", "..."],
  "public_routes": ["list of routes/endpoints with NO auth required"],
  "admin_routes": ["list of routes/endpoints that require elevated privilege"],
  "data_models": ["User", "Order", "Payment", "..."],
  "security_concerns": ["any obvious misconfigs spotted — DEBUG=True, CORS=*, weak SECRET_KEY, etc."]
}}"""


FILE_AUDIT_PROMPT = """You are an expert penetration tester doing a manual code review.

## Application security model
{app_context}

## Task
Find security vulnerabilities in the file below. Focus on vulnerabilities with NO CVE —
meaning bugs in this application's own logic, not library version issues.

Priority issues to look for:
1. **IDOR** — resource fetched by user-supplied ID without verifying ownership
   Example: `Order.objects.get(id=request.GET['id'])` — no check that order.user == request.user
2. **Missing auth check** — endpoint not protected, especially if the app context says it should be
   Example: admin action with no role check, despite admin_routes list above
3. **Mass assignment** — model created/updated directly from request data
   Example: `User(**request.json())` — lets attacker set is_admin=True
4. **Business logic flaw** — workflow can be subverted
   Example: payment endpoint called without completing checkout, negative quantities
5. **Second-order injection** — user input stored then rendered unsafely elsewhere
   Example: username stored raw, displayed in admin panel without escaping
6. **Race condition** — non-atomic read-then-write on sensitive state (balance, inventory)
7. **Hardcoded secrets** — API keys, passwords, tokens in source
8. **Insecure file handling** — upload without type check, path traversal via filename
9. **Broken session management** — token not invalidated on logout, predictable token
10. **Information disclosure** — stack traces exposed, verbose errors reveal internals

File: {filename}
```
{code}
```

Return ONLY a JSON array. Return [] if no issues found. No prose.
Each object:
{{
  "title": "max 80 chars — specific and actionable",
  "severity": "CRITICAL" | "HIGH" | "MEDIUM" | "LOW",
  "category": "idor" | "auth" | "mass_assignment" | "logic" | "injection" | "secrets" | "race" | "upload" | "session" | "disclosure" | "other",
  "description": "3-4 sentences: what is wrong, how an attacker exploits it, what the impact is",
  "line": integer or null,
  "exploit_scenario": "one sentence: concrete attack — e.g. 'Attacker sends GET /orders/42 logged in as user B and retrieves user A's order details'"
}}"""


SYNTHESIS_PROMPT = """You are a lead security engineer reviewing a penetration test report.

## Application security model
{app_context}

## Individual file findings
{findings_summary}

Identify cross-file vulnerabilities — issues that only become apparent when combining
information from multiple files. Examples:
- An endpoint has no auth check, AND the routing file shows it is mounted at /api/admin
- A function in utils.py disables CSRF, AND views.py uses it on a payment endpoint
- Auth middleware is present, BUT settings.py has a bypass flag enabled

Return ONLY a JSON array of NEW findings not already in the individual list. Return [] if none.
Same schema as before (title, severity, category, description, line=null, exploit_scenario)."""


class LLMScanAgent:
    def __init__(self):
        self.api_key = os.getenv("OPENROUTER_API_KEY") or os.getenv("OPENAI_API_KEY")
        # Injected by orchestrator after DepAgent runs (used for context only)
        self.packages: list[dict] = []
        self.known_cve_ids: set[str] = set()

    async def run(self, repo_path: Path) -> list[Finding]:
        if not self.api_key:
            logger.warning("LLMScanAgent: no API key, skipping. Set OPENROUTER_API_KEY or OPENAI_API_KEY.")
            return []

        # Pass 1: understand the app structure
        app_context = await self._build_app_context(repo_path)
        logger.info("LLMScanAgent: app context built", framework=app_context.get("framework", "unknown"))

        # Pass 2: per-file analysis with context
        files = self._collect_files(repo_path)
        logger.info("LLMScanAgent: analyzing files", count=len(files))

        sem = asyncio.Semaphore(CONCURRENCY)
        app_context_str = json.dumps(app_context, indent=2)

        async def analyze(f: Path) -> list[Finding]:
            async with sem:
                return await self._analyze_file(f, repo_path, app_context_str)

        per_file_results = await asyncio.gather(*[analyze(f) for f in files], return_exceptions=True)

        findings: list[Finding] = []
        file_findings_summary: list[str] = []
        for i, result in enumerate(per_file_results):
            if isinstance(result, list) and result:
                findings.extend(result)
                rel = str(files[i].relative_to(repo_path))
                titles = [f.title for f in result]
                file_findings_summary.append(f"### {rel}\n" + "\n".join(f"- {t}" for t in titles))

        # Pass 3: cross-file synthesis (only if we have enough findings to cross-reference)
        if file_findings_summary and len(files) > 3:
            synthesis = await self._synthesize(app_context_str, "\n\n".join(file_findings_summary))
            findings.extend(synthesis)

        logger.info("LLMScanAgent done",
                    files_analyzed=len(files),
                    findings=len(findings))
        return findings

    async def _build_app_context(self, repo_path: Path) -> dict:
        """Read routing, settings, and auth files to understand the security model."""
        context_files: list[tuple[str, str]] = []

        for f in sorted(repo_path.rglob("*")):
            if not f.is_file():
                continue
            if any(skip in f.parts for skip in SKIP_DIRS):
                continue
            if f.suffix not in (".py", ".js", ".ts", ".rb", ".go", ".java", ".php", ".env"):
                continue
            for pattern in CONTEXT_FILE_PATTERNS:
                if re.search(pattern, f.name, re.IGNORECASE):
                    try:
                        content = f.read_text(errors="ignore")[:8000]
                        rel = str(f.relative_to(repo_path))
                        context_files.append((rel, content))
                    except OSError:
                        pass
                    break
            if len(context_files) >= 5:
                break

        if not context_files:
            return {"framework": "unknown", "auth_decorators": [], "public_routes": [], "security_concerns": []}

        files_block = "\n\n".join(
            f"--- {name} ---\n```\n{content}\n```"
            for name, content in context_files
        )

        try:
            raw = await llm_call(
                APP_CONTEXT_PROMPT.format(files_content=files_block),
                reasoning=False,
                max_tokens=600,
                temperature=0.0,
            )
            start = raw.find("{")
            end = raw.rfind("}") + 1
            if start != -1 and end > start:
                return json.loads(raw[start:end])
        except Exception as e:
            logger.warning("LLMScanAgent: context build failed", error=str(e))

        return {"framework": "unknown", "auth_decorators": [], "public_routes": [], "security_concerns": []}

    def _collect_files(self, repo_path: Path) -> list[Path]:
        scored: list[tuple[int, Path]] = []
        for ext in (".py", ".js", ".ts", ".go", ".java", ".rb", ".php"):
            for f in repo_path.rglob(f"*{ext}"):
                score = _file_priority(f)
                if score < 0:
                    continue
                scored.append((score, f))

        # Highest score first, then alphabetically for ties
        scored.sort(key=lambda x: (-x[0], str(x[1])))
        return [f for _, f in scored[:MAX_FILES]]

    async def _analyze_file(self, fpath: Path, repo_path: Path, app_context_str: str) -> list[Finding]:
        try:
            rel_path = str(fpath.relative_to(repo_path))
            code = fpath.read_text(errors="ignore")[:MAX_FILE_CHARS]

            prompt = FILE_AUDIT_PROMPT.format(
                app_context=app_context_str,
                filename=rel_path,
                code=code,
            )

            content = await llm_call(prompt, reasoning=False, max_tokens=1500, temperature=0.0)
            file_findings = self._parse_findings(content, rel_path)
            if file_findings:
                logger.info("LLMScanAgent: vulnerabilities found",
                            file=rel_path, count=len(file_findings))
            return file_findings

        except Exception as e:
            logger.warning("LLMScanAgent: analysis failed", file=str(fpath), error=str(e))
            return []

    async def _synthesize(self, app_context_str: str, findings_summary: str) -> list[Finding]:
        try:
            prompt = SYNTHESIS_PROMPT.format(
                app_context=app_context_str,
                findings_summary=findings_summary,
            )
            content = await llm_call(prompt, reasoning=False, max_tokens=800, temperature=0.0)
            cross_findings = self._parse_findings(content, "cross-file")
            if cross_findings:
                logger.info("LLMScanAgent: cross-file findings", count=len(cross_findings))
            return cross_findings
        except Exception as e:
            logger.warning("LLMScanAgent: synthesis failed", error=str(e))
            return []

    def _parse_findings(self, content: str, rel_path: str) -> list[Finding]:
        findings = []
        try:
            start = content.find("[")
            end = content.rfind("]") + 1
            if start == -1 or end == 0:
                return []
            data = json.loads(content[start:end])
            if not isinstance(data, list):
                return []

            for i, item in enumerate(data):
                if not isinstance(item, dict):
                    continue

                title = str(item.get("title", "Unknown vulnerability"))[:120]
                severity = str(item.get("severity", "MEDIUM")).upper()
                if severity not in {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"}:
                    severity = "MEDIUM"

                description = str(item.get("description", ""))
                exploit = str(item.get("exploit_scenario", ""))
                category = str(item.get("category", "other"))
                line = item.get("line")

                # Combine description + exploit scenario into one block
                full_desc = description
                if exploit:
                    full_desc += f"\n\n**Attack scenario:** {exploit}"

                slug = rel_path.replace("/", "-").replace(".", "-")
                finding_id = f"llm-{category}-{slug}-{i}"

                findings.append(Finding(
                    id=finding_id,
                    title=title,
                    description=full_desc[:1200],
                    severity=severity,
                    finding_type=FindingType.LLM,
                    file_path=rel_path,
                    line=int(line) if isinstance(line, (int, float)) else None,
                    source="llm-code",
                ))

        except json.JSONDecodeError:
            logger.warning("LLMScanAgent: invalid JSON", file=rel_path, preview=content[:200])

        return findings
