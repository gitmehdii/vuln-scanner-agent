"""Tests for TriageAgent — deduplication and web merging."""

import pytest
from agents.triage_agent import TriageAgent
from core.models import Finding, FindingType


def web(title: str, url: str, severity: str = "MEDIUM", source: str = "llm-web") -> Finding:
    return Finding(
        id=f"test-{hash(url) % 9999:04d}",
        title=title,
        description=f"Detected on {url}",
        severity=severity,
        finding_type=FindingType.WEB,
        file_path=url,
        source=source,
    )


def sast(title: str, file: str = "app.py") -> Finding:
    return Finding(
        id=f"sast-{hash(title) % 9999:04d}",
        title=title,
        description="SAST finding",
        severity="HIGH",
        finding_type=FindingType.SAST,
        file_path=file,
        source="semgrep",
    )


@pytest.fixture
def agent():
    return TriageAgent(use_llm=False)


# ── _dedup_web ─────────────────────────────────────────────────────────────────

def test_dedup_web_merges_same_title(agent):
    findings = [
        web("Missing CSRF tokens in forms", "https://example.com/login"),
        web("Missing CSRF tokens in forms", "https://example.com/signup"),
        web("Missing CSRF tokens in forms", "https://example.com/contact"),
    ]
    result = agent._dedup_web(findings)
    assert len(result) == 1
    assert "3 page(s)" in result[0].description
    assert "login" in result[0].description
    assert "signup" in result[0].description


def test_dedup_web_keeps_distinct_titles(agent):
    findings = [
        web("Missing CSRF tokens", "https://example.com/login"),
        web("XSS in search form", "https://example.com/search"),
        web("Open redirect via content param", "https://example.com/home"),
    ]
    result = agent._dedup_web(findings)
    assert len(result) == 3


def test_dedup_web_picks_highest_severity(agent):
    findings = [
        web("Missing CSRF tokens", "https://example.com/login", severity="LOW"),
        web("Missing CSRF tokens", "https://example.com/admin", severity="HIGH"),
        web("Missing CSRF tokens", "https://example.com/api", severity="MEDIUM"),
    ]
    result = agent._dedup_web(findings)
    assert len(result) == 1
    assert result[0].severity == "HIGH"


def test_dedup_web_single_finding_unchanged(agent):
    findings = [web("XSS in search", "https://example.com/search", severity="HIGH")]
    result = agent._dedup_web(findings)
    assert len(result) == 1
    assert result[0].severity == "HIGH"
    assert result[0].title == "XSS in search"


def test_dedup_web_deduplicates_same_url(agent):
    findings = [
        web("Missing CSRF tokens", "https://example.com/login"),
        web("Missing CSRF tokens", "https://example.com/login"),  # exact duplicate URL
    ]
    result = agent._dedup_web(findings)
    assert len(result) == 1
    # Same URL should not appear twice in the list
    assert result[0].description.count("https://example.com/login") == 1


def test_dedup_web_does_not_touch_non_web(agent):
    findings = [
        sast("SQL injection", "app.py"),
        sast("SQL injection", "db.py"),  # same title, different file — should NOT merge
    ]
    result = agent._dedup_web(findings)
    assert len(result) == 2


def test_dedup_web_mixed_types(agent):
    findings = [
        web("Missing CSRF tokens", "https://example.com/login"),
        web("Missing CSRF tokens", "https://example.com/signup"),
        sast("Hardcoded password", "config.py"),
    ]
    result = agent._dedup_web(findings)
    web_results = [f for f in result if f.finding_type == FindingType.WEB]
    sast_results = [f for f in result if f.finding_type == FindingType.SAST]
    assert len(web_results) == 1
    assert len(sast_results) == 1


def test_dedup_web_title_normalization(agent):
    """Titles that differ only in punctuation/case should be merged."""
    findings = [
        web("Missing CSRF Tokens in Forms", "https://example.com/login"),
        web("missing csrf tokens in forms", "https://example.com/signup"),
    ]
    result = agent._dedup_web(findings)
    assert len(result) == 1


# ── run() dedup ────────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_run_deduplicates_by_id(agent):
    f = web("XSS", "https://example.com/search")
    result = await agent.run([f, f])  # exact duplicate
    assert len(result) == 1


@pytest.mark.asyncio
async def test_run_sorts_by_severity(agent):
    findings = [
        web("Low finding", "https://example.com/a", severity="LOW"),
        web("Critical finding", "https://example.com/b", severity="CRITICAL"),
        web("Medium finding", "https://example.com/c", severity="MEDIUM"),
    ]
    result = await agent.run(findings)
    severities = [f.severity for f in result]
    assert severities == sorted(severities, key=lambda s: {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}.get(s, 9))
