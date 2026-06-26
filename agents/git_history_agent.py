"""
GitHistoryAgent — scans git commit history for accidentally committed secrets.

Why git history and not just current files:
  A secret committed once is readable forever via `git log -p`, even after deletion.
  Anyone who clones the repo can retrieve it. This is the #1 cause of credential leaks.

What we scan:
  - API keys (OpenAI, AWS, GitHub, Stripe, Twilio, Slack, etc.)
  - Private keys and certificates
  - Passwords and tokens in config/env files
  - Database connection strings with credentials
  - Generic high-entropy strings that look like secrets

We do NOT re-scan the current working tree (DepAgent covers that).
We scan the diff of each recent commit, so we catch secrets that were later deleted.
"""

import re
import subprocess
import asyncio
from pathlib import Path
from typing import Optional

from core.models import Finding, FindingType
from core.logger import get_logger

logger = get_logger(__name__)

MAX_COMMITS = 200       # how far back to look
MAX_DIFF_BYTES = 80_000  # max diff size per commit to avoid huge blobs

# Patterns: (name, regex, severity)
# Each pattern matched in a git diff line triggers a finding
SECRET_PATTERNS: list[tuple[str, re.Pattern, str]] = [
    # Cloud providers
    ("AWS Access Key",          re.compile(r"AKIA[0-9A-Z]{16}"),                            "CRITICAL"),
    ("AWS Secret Key",          re.compile(r"aws_secret_access_key\s*=\s*['\"]?[A-Za-z0-9+/]{40}"), "CRITICAL"),
    ("GCP Service Account",     re.compile(r'"type"\s*:\s*"service_account"'),               "CRITICAL"),

    # OpenAI / LLM
    ("OpenAI API Key",          re.compile(r"sk-[A-Za-z0-9]{32,}"),                         "CRITICAL"),
    ("OpenRouter API Key",      re.compile(r"sk-or-v1-[A-Za-z0-9]{40,}"),                   "CRITICAL"),
    ("Anthropic API Key",       re.compile(r"sk-ant-[A-Za-z0-9\-]{32,}"),                   "CRITICAL"),

    # Source control / CI
    ("GitHub Token",            re.compile(r"gh[ps]_[A-Za-z0-9]{36,}"),                     "CRITICAL"),
    ("GitHub OAuth",            re.compile(r"github_token\s*=\s*['\"]?[A-Za-z0-9_\-]{35,}"), "HIGH"),
    ("GitLab Token",            re.compile(r"glpat-[A-Za-z0-9\-_]{20,}"),                   "CRITICAL"),

    # Payment
    ("Stripe Secret Key",       re.compile(r"sk_live_[A-Za-z0-9]{24,}"),                    "CRITICAL"),
    ("Stripe Test Key",         re.compile(r"sk_test_[A-Za-z0-9]{24,}"),                    "HIGH"),

    # Comms
    ("Slack Bot Token",         re.compile(r"xoxb-[0-9]{11,}-[0-9]{11,}-[A-Za-z0-9]{24}"), "HIGH"),
    ("Slack Webhook",           re.compile(r"hooks\.slack\.com/services/T[A-Za-z0-9]+/B[A-Za-z0-9]+"), "HIGH"),
    ("Twilio Auth Token",       re.compile(r"SK[a-z0-9]{32}"),                              "HIGH"),
    ("SendGrid API Key",        re.compile(r"SG\.[A-Za-z0-9\-_]{22}\.[A-Za-z0-9\-_]{43}"), "HIGH"),

    # Private keys
    ("RSA Private Key",         re.compile(r"-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----"), "CRITICAL"),
    ("PEM Certificate",         re.compile(r"-----BEGIN CERTIFICATE-----"),                  "MEDIUM"),

    # Database URLs with embedded credentials
    ("DB connection string",    re.compile(r"(mysql|postgres|mongodb|redis|amqp)://[^:]+:[^@]+@"), "CRITICAL"),

    # Generic password assignments
    ("Hardcoded password",      re.compile(
        r'(?i)(password|passwd|pwd|secret|token|api_key|apikey|auth_key)\s*=\s*["\'][^"\']{8,}["\']'
    ), "HIGH"),

    # .env file content patterns
    ("Env file secret",         re.compile(
        r'(?i)^[+\-]\s*(OPENAI|ANTHROPIC|AWS|GCP|GITHUB|STRIPE|TWILIO|SLACK|DATABASE)_?(KEY|TOKEN|SECRET|PASSWORD|URL)\s*=\s*.{8,}'
    ), "HIGH"),
]

# Lines to skip — common false positives
SKIP_PATTERNS = [
    re.compile(r'(?i)(example|placeholder|changeme|your[_-]?key|insert[_-]?here|xxx+|yyy+|zzz+|<[^>]+>|\*{4,})'),
    re.compile(r'(?i)(test|demo|fake|dummy|sample|mock|fixture)'),
    re.compile(r'^\+\+\+|^---|^index |^diff |^@@ '),  # git diff headers
]

SKIP_EXTENSIONS = {
    ".lock", ".sum", ".mod", ".min.js", ".map",
    ".png", ".jpg", ".jpeg", ".gif", ".ico", ".svg",
    ".ttf", ".woff", ".woff2", ".eot",
    ".pdf", ".zip", ".tar", ".gz",
}


def _is_git_repo(path: Path) -> bool:
    return (path / ".git").exists()


def _get_commits(repo_path: Path) -> list[tuple[str, str, str]]:
    """Return list of (hash, date, subject) for recent commits."""
    try:
        result = subprocess.run(
            ["git", "log", "--format=%H|%ai|%s",
             f"--max-count={MAX_COMMITS}", "--all"],
            cwd=repo_path,
            capture_output=True, text=True, timeout=30,
        )
        commits = []
        for line in result.stdout.strip().splitlines():
            parts = line.split("|", 2)
            if len(parts) == 3:
                commits.append((parts[0], parts[1][:10], parts[2]))
        return commits
    except Exception:
        return []


def _get_diff(repo_path: Path, commit_hash: str) -> str:
    """Return the diff introduced by a specific commit."""
    try:
        result = subprocess.run(
            ["git", "show", "--format=", "--diff-filter=A",  # only added lines
             commit_hash],
            cwd=repo_path,
            capture_output=True, text=True, timeout=15,
        )
        return result.stdout[:MAX_DIFF_BYTES]
    except Exception:
        return ""


def _should_skip_line(line: str) -> bool:
    if not line.startswith("+"):
        return True  # only care about added lines
    for pattern in SKIP_PATTERNS:
        if pattern.search(line):
            return True
    return False


def _scan_diff(diff: str, commit_hash: str, commit_date: str, commit_msg: str) -> list[Finding]:
    """Scan a git diff for secret patterns. Returns one Finding per secret found."""
    findings = []
    seen: set[str] = set()  # dedup within same commit

    current_file = ""
    for line in diff.splitlines():
        # Track current file
        if line.startswith("+++ b/"):
            current_file = line[6:]
            ext = "." + current_file.rsplit(".", 1)[-1] if "." in current_file else ""
            if ext in SKIP_EXTENSIONS:
                current_file = "__skip__"
            continue

        if current_file == "__skip__":
            continue

        if not line.startswith("+") or line.startswith("+++"):
            continue

        if _should_skip_line(line):
            continue

        for name, pattern, severity in SECRET_PATTERNS:
            m = pattern.search(line)
            if not m:
                continue

            matched = m.group(0)
            dedup_key = f"{commit_hash[:8]}:{name}:{matched[:20]}"
            if dedup_key in seen:
                continue
            seen.add(dedup_key)

            # Redact the actual secret value in the report
            safe_line = line[:m.start() + 6] + "***REDACTED***" + line[m.end():]

            findings.append(Finding(
                id=f"git-secret-{commit_hash[:8]}-{len(findings)}",
                title=f"{name} found in git history",
                description=(
                    f"A `{name}` was committed on {commit_date} and may still be "
                    f"accessible in the repository history even if later deleted.\n\n"
                    f"**Commit:** `{commit_hash[:12]}` — {commit_msg[:80]}\n"
                    f"**File:** `{current_file}`\n"
                    f"**Line:** `{safe_line.strip()}`\n\n"
                    f"**Why it matters:** Anyone who clones this repo can retrieve "
                    f"this secret with `git log -p`. Rotate it immediately."
                ),
                severity=severity,
                finding_type=FindingType.LLM,
                file_path=f"git:{commit_hash[:8]}:{current_file}",
                source="git-history",
            ))

    return findings


class GitHistoryAgent:
    async def run(self, repo_path: Path) -> list[Finding]:
        if not _is_git_repo(repo_path):
            logger.info("GitHistoryAgent: not a git repo, skipping")
            return []

        commits = _get_commits(repo_path)
        if not commits:
            logger.info("GitHistoryAgent: no commits found")
            return []

        logger.info("GitHistoryAgent starting", commits=len(commits))

        # Run in thread pool to avoid blocking the event loop on subprocess calls
        loop = asyncio.get_event_loop()
        all_findings: list[Finding] = []

        for commit_hash, commit_date, commit_msg in commits:
            diff = await loop.run_in_executor(
                None, _get_diff, repo_path, commit_hash
            )
            if not diff:
                continue
            findings = _scan_diff(diff, commit_hash, commit_date, commit_msg)
            all_findings.extend(findings)

        # Deduplicate across commits — same secret type + same file is one finding
        seen_sigs: set[str] = set()
        deduped: list[Finding] = []
        for f in all_findings:
            # Extract name from title ("X found in git history")
            sig = f.title + ":" + (f.file_path or "").split(":", 2)[-1]
            if sig not in seen_sigs:
                seen_sigs.add(sig)
                deduped.append(f)

        logger.info("GitHistoryAgent done",
                    raw=len(all_findings),
                    after_dedup=len(deduped))
        return deduped
