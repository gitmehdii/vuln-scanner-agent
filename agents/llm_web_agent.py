"""
LLMWebAgent — crawls a web application and uses DeepSeek to find vulnerabilities
that automated scanners miss: IDOR, auth bypasses, business logic flaws.
"""

import asyncio
import json
import os
import re
from urllib.parse import urljoin, urlparse

import httpx

from core.models import Finding, FindingType
from core.logger import get_logger

logger = get_logger(__name__)

MAX_PAGES = 15
CONCURRENCY = 3

LLM_WEB_PROMPT = """You are an expert penetration tester analyzing HTTP responses from a live web application.
Review the response below and identify security vulnerabilities that automated scanners miss.

Focus on:
- Authentication/authorization issues (unprotected routes, missing role checks, JWT weaknesses)
- IDOR — user-controlled params (id=, user_id=, account=, order=) without ownership validation
- Business logic flaws (price tampering, step skipping in multi-step flows)
- Information disclosure (emails, API keys, internal paths, stack traces, comments in HTML/JS)
- Open redirects (?next=, ?url=, ?redirect=, ?return= parameters)
- Dangerous JS patterns (eval(), document.write() with user input, innerHTML assignment)
- Exposed admin/debug endpoints (/admin, /debug, /api/internal, /.env, /config)
- CSRF vulnerabilities (forms without tokens)
- Insecure cookies (missing HttpOnly, Secure, or SameSite flags)
- Sensitive data in URL query strings (tokens, passwords)

URL: {url}
Status: {status}
Response headers:
{headers}

Response body (truncated to 3000 chars):
```
{body}
```

Return ONLY a valid JSON array. Return [] if no issues found. No prose before or after.
Each object: {{"title": str (max 80 chars), "severity": "CRITICAL"|"HIGH"|"MEDIUM"|"LOW", "description": str (2-3 sentences explaining why exploitable), "category": str}}"""


class LLMWebAgent:
    def __init__(self):
        self.api_key = os.getenv("OPENROUTER_API_KEY") or os.getenv("OPENAI_API_KEY")

    async def run(self, url: str) -> list[Finding]:
        if not self.api_key:
            logger.warning("LLMWebAgent: no API key, skipping")
            return []

        pages = await self._crawl(url)
        logger.info("LLMWebAgent starting", pages=len(pages))

        sem = asyncio.Semaphore(CONCURRENCY)

        async def analyze_with_sem(page: dict) -> list[Finding]:
            async with sem:
                return await self._analyze_page(page)

        results = await asyncio.gather(
            *[analyze_with_sem(p) for p in pages],
            return_exceptions=True,
        )

        findings = []
        for r in results:
            if isinstance(r, list):
                findings.extend(r)

        logger.info("LLMWebAgent done", findings=len(findings))
        return findings

    async def _crawl(self, base_url: str) -> list[dict]:
        """BFS crawl — stays on same domain, collects up to MAX_PAGES pages.
        Falls back to verify=False if the site has an SSL certificate issue."""
        pages = []
        visited: set[str] = set()
        queue = [base_url]
        parsed_base = urlparse(base_url)
        ssl_verify = True

        client_kwargs = dict(
            timeout=15,
            follow_redirects=True,
            headers={"User-Agent": "Mozilla/5.0 (compatible; vuln-scanner/1.0)"},
        )

        async with httpx.AsyncClient(**client_kwargs, verify=ssl_verify) as client:
            while queue and len(pages) < MAX_PAGES:
                url = queue.pop(0)
                if url in visited:
                    continue
                visited.add(url)

                try:
                    resp = await client.get(url)
                except Exception as e:
                    err = str(e)
                    if ssl_verify and ("SSL" in err or "certificate" in err.lower() or "CERTIFICATE" in err):
                        logger.warning("LLMWebAgent: SSL error, switching to verify=False", url=url)
                        ssl_verify = False
                        # restart client without SSL verification
                        await client.aclose()
                        client = httpx.AsyncClient(**client_kwargs, verify=False)
                        try:
                            resp = await client.get(url)
                        except Exception as e2:
                            logger.warning("LLMWebAgent: fetch failed", url=url,
                                           error=f"{type(e2).__name__}: {e2}")
                            continue
                    else:
                        logger.warning("LLMWebAgent: fetch failed", url=url,
                                       error=f"{type(e).__name__}: {e}")
                        continue

                body = resp.text
                pages.append({
                    "url": url,
                    "status": resp.status_code,
                    "headers": dict(resp.headers),
                    "body": body,
                })

                for link in re.findall(r'href=["\']([^"\'#?][^"\']*)["\']', body):
                    abs_link = urljoin(url, link).split("?")[0].split("#")[0]
                    parsed = urlparse(abs_link)
                    if parsed.netloc == parsed_base.netloc and abs_link not in visited:
                        queue.append(abs_link)

        logger.info("LLMWebAgent: crawl done", pages=len(pages))
        return pages

    async def _analyze_page(self, page: dict) -> list[Finding]:
        try:
            headers_str = "\n".join(f"{k}: {v}" for k, v in list(page["headers"].items())[:20])
            prompt = LLM_WEB_PROMPT.format(
                url=page["url"],
                status=page["status"],
                headers=headers_str,
                body=page["body"][:3000],
            )

            if os.getenv("OPENROUTER_API_KEY"):
                api_url = "https://openrouter.ai/api/v1/chat/completions"
                key = os.getenv("OPENROUTER_API_KEY")
                model = "deepseek/deepseek-chat"
            else:
                api_url = "https://api.openai.com/v1/chat/completions"
                key = os.getenv("OPENAI_API_KEY")
                model = "gpt-4o-mini"

            async with httpx.AsyncClient(timeout=60) as client:
                resp = await client.post(
                    api_url,
                    headers={"Authorization": f"Bearer {key}"},
                    json={
                        "model": model,
                        "messages": [{"role": "user", "content": prompt}],
                        "max_tokens": 800,
                        "temperature": 0.1,
                    },
                )
                resp.raise_for_status()
                content = resp.json()["choices"][0]["message"]["content"].strip()

            page_findings = self._parse_findings(content, page["url"])
            logger.info("LLMWebAgent: page done", url=page["url"], findings=len(page_findings))
            return page_findings

        except Exception as e:
            logger.warning("LLMWebAgent: analysis failed", url=page["url"], error=str(e))
            return []

    def _parse_findings(self, content: str, url: str) -> list[Finding]:
        findings = []
        try:
            start = content.find("[")
            end = content.rfind("]") + 1
            if start == -1 or end == 0:
                return []
            data = json.loads(content[start:end])
            if not isinstance(data, list):
                return []

            url_slug = re.sub(r"[^a-zA-Z0-9]", "-", url)[:50]
            for i, item in enumerate(data):
                if not isinstance(item, dict):
                    continue
                title = str(item.get("title", "Unknown vulnerability"))[:120]
                severity = str(item.get("severity", "MEDIUM")).upper()
                if severity not in {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"}:
                    severity = "MEDIUM"
                description = str(item.get("description", ""))[:1000]
                findings.append(Finding(
                    id=f"llm-web-{url_slug}-{i}",
                    title=title,
                    description=description,
                    severity=severity,
                    finding_type=FindingType.WEB,
                    file_path=url,
                    source="llm-web",
                ))

        except json.JSONDecodeError:
            logger.warning("LLMWebAgent: invalid JSON", url=url, preview=content[:200])

        return findings
