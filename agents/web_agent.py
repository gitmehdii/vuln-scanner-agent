"""
WebAgent — analyzes a live web application for security misconfigurations.
Checks: HTTP security headers, HTTPS, and runs nuclei if available.
"""

import json
import shutil
import subprocess
import tempfile
from pathlib import Path
from urllib.parse import urlparse

import httpx

from core.models import Finding, FindingType
from core.logger import get_logger

logger = get_logger(__name__)

# header → (description, severity)
SECURITY_HEADERS = {
    "strict-transport-security": (
        "HSTS header missing — browsers may connect over HTTP, enabling protocol downgrade attacks.",
        "HIGH",
    ),
    "content-security-policy": (
        "Content-Security-Policy missing — no restriction on script/resource sources, increases XSS impact.",
        "MEDIUM",
    ),
    "x-frame-options": (
        "X-Frame-Options missing — page can be embedded in iframes, enabling clickjacking attacks.",
        "MEDIUM",
    ),
    "x-content-type-options": (
        "X-Content-Type-Options missing — browsers may MIME-sniff responses, enabling content injection.",
        "LOW",
    ),
    "referrer-policy": (
        "Referrer-Policy missing — sensitive URLs may be leaked to third-party sites via the Referer header.",
        "LOW",
    ),
    "permissions-policy": (
        "Permissions-Policy missing — browser features (camera, geolocation, etc.) are unrestricted.",
        "LOW",
    ),
}

INFO_LEAKING_HEADERS = [
    "server", "x-powered-by", "x-aspnet-version", "x-aspnetmvc-version",
    "x-generator", "x-drupal-cache", "x-wp-nonce",
]


class WebAgent:
    async def run(self, url: str) -> list[Finding]:
        logger.info("WebAgent starting", url=url)
        findings = []

        resp, ssl_findings = await self._fetch(url)
        findings.extend(ssl_findings)
        if resp is not None:
            findings.extend(self._check_headers(resp, url))

        findings.extend(self._check_ssl(url, has_ssl_error=bool(ssl_findings)))
        findings.extend(self._run_nuclei(url))

        logger.info("WebAgent done", findings=len(findings))
        return findings

    async def _fetch(self, url: str) -> tuple:
        """Try with SSL verification; on failure report the SSL issue and retry without."""
        try:
            async with httpx.AsyncClient(timeout=15, follow_redirects=True) as client:
                return await client.get(url), []
        except Exception as e:
            err = str(e)
            if "SSL" in err or "certificate" in err.lower() or "CERTIFICATE" in err:
                finding = Finding(
                    id="web-ssl-cert-error",
                    title="SSL/TLS certificate error",
                    description=(
                        f"SSL handshake failed: {err}. "
                        "The certificate may be expired, self-signed, or misconfigured — "
                        "browsers will show a security warning and some will refuse to connect."
                    ),
                    severity="HIGH",
                    finding_type=FindingType.WEB,
                    file_path=url,
                    source="web-ssl",
                )
                logger.warning("WebAgent: SSL error, retrying without verification", url=url)
                try:
                    async with httpx.AsyncClient(timeout=15, follow_redirects=True, verify=False) as client:
                        return await client.get(url), [finding]
                except Exception as e2:
                    logger.warning("WebAgent: request failed even without SSL verify",
                                   error=f"{type(e2).__name__}: {e2}")
                    return None, [finding]
            logger.warning("WebAgent: HTTP request failed", url=url, error=f"{type(e).__name__}: {e}")
            return None, []

    def _check_headers(self, resp: httpx.Response, url: str) -> list[Finding]:
        findings = []
        headers_lower = {k.lower(): v for k, v in resp.headers.items()}

        for header, (msg, severity) in SECURITY_HEADERS.items():
            if header not in headers_lower:
                findings.append(Finding(
                    id=f"web-header-missing-{header}",
                    title=f"Missing security header: {header}",
                    description=msg,
                    severity=severity,
                    finding_type=FindingType.WEB,
                    file_path=url,
                    source="web-headers",
                ))

        for header in INFO_LEAKING_HEADERS:
            if header in headers_lower:
                value = headers_lower[header]
                findings.append(Finding(
                    id=f"web-header-leak-{header}",
                    title=f"Technology disclosure via {header} header",
                    description=(
                        f"Server returns `{header}: {value}`. "
                        "Exposing the technology stack helps attackers target known CVEs for that version."
                    ),
                    severity="LOW",
                    finding_type=FindingType.WEB,
                    file_path=url,
                    source="web-headers",
                ))

        return findings

    def _check_ssl(self, url: str, has_ssl_error: bool = False) -> list[Finding]:
        parsed = urlparse(url)
        if parsed.scheme != "https" and not has_ssl_error:
            return [Finding(
                id="web-no-https",
                title="Site does not use HTTPS",
                description=(
                    "The target is served over plain HTTP. All traffic is cleartext, "
                    "enabling passive eavesdropping and active MITM attacks."
                ),
                severity="HIGH",
                finding_type=FindingType.WEB,
                file_path=url,
                source="web-ssl",
            )]
        return []

    def _run_nuclei(self, url: str) -> list[Finding]:
        nuclei = shutil.which("nuclei")
        if not nuclei:
            logger.info("WebAgent: nuclei not found, skipping. Install: https://nuclei.projectdiscovery.io")
            return []

        findings = []
        try:
            with tempfile.NamedTemporaryFile(suffix=".jsonl", delete=False) as tmp:
                tmp_path = tmp.name

            result = subprocess.run(
                [
                    nuclei, "-u", url,
                    "-json-export", tmp_path,
                    "-tags", "cves,misconfigs,exposures,takeovers",
                    "-silent",
                    "-no-color",
                ],
                capture_output=True,
                text=True,
                timeout=180,
            )

            with open(tmp_path) as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        item = json.loads(line)
                        findings.append(self._nuclei_to_finding(item, url))
                    except json.JSONDecodeError:
                        pass

        except subprocess.TimeoutExpired:
            logger.warning("WebAgent: nuclei timed out")
        except Exception as e:
            logger.warning("WebAgent: nuclei failed", error=str(e))
        finally:
            Path(tmp_path).unlink(missing_ok=True)

        logger.info("WebAgent: nuclei done", findings=len(findings))
        return findings

    def _nuclei_to_finding(self, item: dict, base_url: str) -> Finding:
        info = item.get("info", {})
        severity_raw = info.get("severity", "info").upper()
        severity = severity_raw if severity_raw in {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"} else "MEDIUM"
        description = info.get("description") or info.get("name", "No description")

        return Finding(
            id=f"nuclei-{item.get('template-id', 'unknown')}",
            title=info.get("name", item.get("template-id", "Unknown")),
            description=description[:1000],
            severity=severity,
            finding_type=FindingType.WEB,
            file_path=item.get("matched-at", base_url),
            source="nuclei",
        )
