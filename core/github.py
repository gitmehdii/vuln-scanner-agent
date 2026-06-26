"""
GitHub utilities — clone repos and create issues.
"""

import os
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Optional

import httpx

from core.logger import get_logger

logger = get_logger(__name__)


async def clone_repo(repo_url: str) -> Path:
    """Download a GitHub repo as a ZIP and extract it. Falls back to git clone."""
    tmp_dir = Path(tempfile.mkdtemp(prefix="vuln-scanner-"))

    if "github.com" in repo_url:
        try:
            return await _download_zip(repo_url, tmp_dir)
        except Exception as e:
            logger.warning("clone_repo: ZIP download failed, trying git clone", error=str(e))
            shutil.rmtree(tmp_dir, ignore_errors=True)
            tmp_dir = Path(tempfile.mkdtemp(prefix="vuln-scanner-"))

    return await _git_clone(repo_url, tmp_dir)


async def _download_zip(repo_url: str, tmp_dir: Path) -> Path:
    """Download repo ZIP via GitHub API — no git, no auth needed for public repos."""
    import zipfile
    import io

    # Normalize URL: strip .git suffix
    repo_url = repo_url.rstrip("/").removesuffix(".git")
    parts = repo_url.split("github.com/")[-1].split("/")
    owner, repo = parts[0], parts[1]

    token = os.getenv("GITHUB_TOKEN")
    headers = {"Accept": "application/vnd.github+json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"

    zip_url = f"https://api.github.com/repos/{owner}/{repo}/zipball"
    logger.info("Downloading repo ZIP", url=zip_url)

    async with httpx.AsyncClient(timeout=120, follow_redirects=True) as client:
        resp = await client.get(zip_url, headers=headers)
        resp.raise_for_status()
        data = resp.content

    with zipfile.ZipFile(io.BytesIO(data)) as zf:
        zf.extractall(tmp_dir)

    # GitHub ZIP contains a single top-level dir like owner-repo-sha/
    extracted = list(tmp_dir.iterdir())
    if len(extracted) == 1 and extracted[0].is_dir():
        repo_dir = extracted[0]
    else:
        repo_dir = tmp_dir

    logger.info("Repo downloaded", path=str(repo_dir))
    return repo_dir


async def _git_clone(repo_url: str, tmp_dir: Path) -> Path:
    """Fallback: shallow git clone."""
    token = os.getenv("GITHUB_TOKEN")
    clone_url = repo_url
    if token and "github.com" in repo_url:
        clone_url = repo_url.replace("https://", f"https://{token}@")

    try:
        result = subprocess.run(
            [
                "git",
                "-c", "credential.helper=",
                "-c", "url.https://github.com/.insteadOf=git@github.com:",
                "-c", "url.https://.insteadOf=git://",
                "clone", "--depth", "1", clone_url, str(tmp_dir),
            ],
            capture_output=True,
            text=True,
            timeout=120,
            env={**os.environ, "GIT_TERMINAL_PROMPT": "0", "GIT_ASKPASS": ""},
        )
        if result.returncode != 0:
            # Scrub token from stderr before logging/raising
            safe_err = result.stderr.replace(token, "***") if token else result.stderr
            raise RuntimeError(f"git clone failed: {safe_err}")
        logger.info("Repo cloned via git", url=repo_url, path=str(tmp_dir))
        return tmp_dir
    except subprocess.TimeoutExpired:
        shutil.rmtree(tmp_dir, ignore_errors=True)
        raise RuntimeError(f"git clone timed out for {repo_url}")


async def create_issue(repo_url: str, report_md: str) -> Optional[str]:
    """Create a GitHub issue with the scan report. Requires GITHUB_TOKEN env var."""
    token = os.getenv("GITHUB_TOKEN")
    if not token:
        logger.warning("create_issue: GITHUB_TOKEN not set, skipping")
        return None

    # Extract owner/repo from URL
    # Handles: https://github.com/owner/repo or https://github.com/owner/repo.git
    parts = repo_url.rstrip("/").rstrip(".git").split("/")
    if len(parts) < 2:
        logger.error("create_issue: cannot parse repo URL", url=repo_url)
        return None

    owner, repo = parts[-2], parts[-1]
    api_url = f"https://api.github.com/repos/{owner}/{repo}/issues"

    # Truncate report to fit GitHub issue body limit (65536 chars)
    body = report_md[:65000]
    if len(report_md) > 65000:
        body += "\n\n_Report truncated — run locally for full output._"

    try:
        async with httpx.AsyncClient(timeout=15) as client:
            resp = await client.post(
                api_url,
                headers={
                    "Authorization": f"Bearer {token}",
                    "Accept": "application/vnd.github+json",
                },
                json={
                    "title": "Security scan findings — vuln-scanner-agent",
                    "body": body,
                    "labels": ["security"],
                },
            )
            resp.raise_for_status()
            issue_url = resp.json().get("html_url", "")
            logger.info("GitHub issue created", url=issue_url)
            return issue_url

    except Exception as e:
        logger.error("create_issue: failed", error=str(e))
        return None
