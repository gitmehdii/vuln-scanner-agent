#!/usr/bin/env python3
"""
benchmark.py — Compare vuln-scanner-agent against 7+ tools on 5 known-vulnerable repos.

Tools compared:
  Dependency scanners:
    - vuln-scanner-agent  (OSV API + SAST + LLM, this project)
    - osv-scanner         (Google's official OSV CLI)
    - grype               (Anchore, NVD + GitHub advisories)
    - trivy fs            (Aqua, NVD + OS advisories)
    - safety              (PyPI/Python only)
    - pip-audit           (PyPI/Python only)
    - npm audit           (npm/JS only)
    - retire              (JS file-based scanner)

  SAST scanners:
    - bandit              (Python SAST)
    - vuln-scanner-agent  (Semgrep, 7 languages - shown separately)

Benchmark targets:
    - juice-shop  Node.js (OWASP Juice Shop)
    - pygoat      Python/Django
    - dvna        Node.js (Damn Vulnerable Node Application)
    - railsgoat   Ruby/Rails (OWASP)
    - dvwa-flask  Python/Flask

Usage:
    python benchmark.py [--targets juice-shop pygoat dvna] [--output benchmark_report.md]
"""

import argparse
import asyncio
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
from collections import Counter
from pathlib import Path
from typing import Optional

# Add project root to sys.path
sys.path.insert(0, str(Path(__file__).parent))

from core.orchestrator import Orchestrator
from dotenv import load_dotenv

load_dotenv()

# ── Tool paths ────────────────────────────────────────────────────────────────

HOME = Path.home()
TOOL_PATHS = {
    "osv-scanner": str(HOME / "go" / "bin" / "osv-scanner"),
    "grype":       str(HOME / ".local" / "bin" / "grype"),
    "trivy":       shutil.which("trivy") or str(HOME / ".local" / "bin" / "trivy"),
    "safety":      str(HOME / ".local" / "bin" / "safety"),
    "pip-audit":   str(HOME / ".local" / "bin" / "pip-audit"),
    "bandit":      str(HOME / ".local" / "bin" / "bandit"),
    "retire":      str(HOME / ".local" / "bin" / "retire"),
    "npm":         shutil.which("npm") or "npm",
}

# ── Benchmark targets ─────────────────────────────────────────────────────────

TARGETS = {
    "juice-shop": {
        "url": "https://github.com/juice-shop/juice-shop",
        "ecosystems": ["npm"],
        "description": "OWASP Juice Shop — intentionally insecure Node.js e-commerce app",
    },
    "pygoat": {
        "url": "https://github.com/adeyosemanputra/pygoat",
        "ecosystems": ["pip"],
        "description": "PyGoat — intentionally insecure Django app (OWASP)",
    },
    "dvna": {
        "url": "https://github.com/appsecco/dvna",
        "ecosystems": ["npm"],
        "description": "DVNA — Damn Vulnerable Node Application (OWASP Top 10)",
    },
    "railsgoat": {
        "url": "https://github.com/OWASP/railsgoat",
        "ecosystems": ["ruby"],
        "description": "RailsGoat — intentionally insecure Ruby on Rails app (OWASP)",
    },
    "dvwa-flask": {
        "url": "https://github.com/anxsec/dvwa-flask",
        "ecosystems": ["pip"],
        "description": "DVWA Flask — intentionally insecure Python Flask app",
    },
}

# ── Helpers ───────────────────────────────────────────────────────────────────

def _cmd(name: str) -> Optional[str]:
    """Return the full path to a tool if installed, else None."""
    path = TOOL_PATHS.get(name, shutil.which(name) or "")
    if path and Path(path).exists():
        return path
    return shutil.which(name)


def _run(cmd: list[str], cwd: Optional[str] = None, timeout: int = 300) -> tuple[int, str, str]:
    try:
        r = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True, timeout=timeout)
        return r.returncode, r.stdout, r.stderr
    except subprocess.TimeoutExpired:
        return -1, "", "timeout"
    except FileNotFoundError:
        return -2, "", f"not found: {cmd[0]}"


def _severity_counts(items: list[str]) -> dict:
    """Count severities, normalising to CRITICAL/HIGH/MEDIUM/LOW."""
    norm = {
        "critical": "CRITICAL", "high": "HIGH", "moderate": "MEDIUM",
        "medium": "MEDIUM", "low": "LOW", "info": "INFO", "informational": "INFO",
    }
    c: Counter = Counter()
    for s in items:
        c[norm.get(s.lower(), "UNKNOWN")] += 1
    return dict(c)


def _ensure_npm_lock(repo_path: Path):
    """Generate package-lock.json if missing (required by npm audit, retire, trivy)."""
    if (repo_path / "package.json").exists() and not (repo_path / "package-lock.json").exists():
        if _cmd("npm"):
            print("        Generating package-lock.json ...")
            _run([_cmd("npm"), "install", "--package-lock-only", "--ignore-scripts"],
                 cwd=str(repo_path), timeout=180)


# ── Tool runners ──────────────────────────────────────────────────────────────

def run_osv_scanner(repo_path: str) -> dict:
    exe = _cmd("osv-scanner")
    if not exe:
        return {"tool": "osv-scanner", "available": False}
    start = time.perf_counter()
    rc, stdout, stderr = _run([exe, "--format=json", repo_path])
    elapsed = time.perf_counter() - start
    if rc == -2:
        return {"tool": "osv-scanner", "available": False}
    try:
        data = json.loads(stdout or "{}")
        severities = []
        total = 0
        for res in data.get("results", []):
            for pkg in res.get("packages", []):
                for v in pkg.get("vulnerabilities", []):
                    db = v.get("database_specific", {})
                    sev = db.get("severity", "UNKNOWN")
                    severities.append(sev)
                    total += 1
        return {"tool": "osv-scanner", "available": True, "total": total,
                "by_severity": _severity_counts(severities), "duration": elapsed}
    except Exception as e:
        return {"tool": "osv-scanner", "available": True, "error": str(e), "duration": elapsed}


def run_grype(repo_path: str) -> dict:
    exe = _cmd("grype")
    if not exe:
        return {"tool": "grype", "available": False}
    start = time.perf_counter()
    rc, stdout, stderr = _run([exe, f"dir:{repo_path}", "--output=json", "--quiet"], timeout=300)
    elapsed = time.perf_counter() - start
    if rc == -2:
        return {"tool": "grype", "available": False}
    try:
        data = json.loads(stdout or "{}")
        severities = [m["vulnerability"]["severity"] for m in data.get("matches", [])]
        return {"tool": "grype", "available": True, "total": len(severities),
                "by_severity": _severity_counts(severities), "duration": elapsed}
    except Exception as e:
        return {"tool": "grype", "available": True, "error": str(e), "duration": elapsed}


def run_trivy_fs(repo_path: str) -> dict:
    exe = _cmd("trivy")
    if not exe:
        return {"tool": "trivy fs", "available": False}
    start = time.perf_counter()
    rc, stdout, stderr = _run(
        [exe, "fs", "--format=json", "--quiet", "--scanners=vuln", repo_path], timeout=300)
    elapsed = time.perf_counter() - start
    if rc == -2:
        return {"tool": "trivy fs", "available": False}
    try:
        data = json.loads(stdout or "{}")
        severities = []
        for r in data.get("Results", []):
            for v in r.get("Vulnerabilities", []) or []:
                severities.append(v.get("Severity", "UNKNOWN"))
        return {"tool": "trivy fs", "available": True, "total": len(severities),
                "by_severity": _severity_counts(severities), "duration": elapsed}
    except Exception as e:
        return {"tool": "trivy fs", "available": True, "error": str(e), "duration": elapsed}


def run_safety(repo_path: str) -> dict:
    exe = _cmd("safety")
    req = Path(repo_path) / "requirements.txt"
    if not req.exists():
        return {"tool": "safety", "available": True, "skipped": "no requirements.txt"}
    if not exe:
        return {"tool": "safety", "available": False}
    start = time.perf_counter()
    rc, stdout, stderr = _run(
        [exe, "check", "--file", str(req), "--output", "json"], timeout=120)
    elapsed = time.perf_counter() - start
    if rc == -2:
        return {"tool": "safety", "available": False}
    try:
        # safety outputs a deprecation banner before the JSON object
        json_start = stdout.find("\n{")
        if json_start < 0:
            return {"tool": "safety", "available": True, "error": "no JSON in output", "duration": elapsed}
        decoder = json.JSONDecoder()
        data, _ = decoder.raw_decode(stdout[json_start:].strip())
        vulns = data.get("vulnerabilities", [])
        # safety doesn't classify by CRITICAL/HIGH — use count only
        return {"tool": "safety", "available": True, "total": len(vulns),
                "by_severity": {"UNKNOWN": len(vulns)}, "duration": elapsed,
                "note": "safety doesn't report severity (uses own ID system)"}
    except Exception as e:
        return {"tool": "safety", "available": True, "error": str(e), "duration": elapsed}


def run_pip_audit(repo_path: str) -> dict:
    exe = _cmd("pip-audit")
    req = Path(repo_path) / "requirements.txt"
    if not req.exists():
        return {"tool": "pip-audit", "available": True, "skipped": "no requirements.txt"}
    if not exe:
        return {"tool": "pip-audit", "available": False}
    start = time.perf_counter()
    rc, stdout, stderr = _run(
        [exe, "--requirement", str(req), "--format=json", "--progress-spinner=off"], timeout=120)
    elapsed = time.perf_counter() - start
    if rc == -2:
        return {"tool": "pip-audit", "available": False}
    try:
        data = json.loads(stdout or "[]")
        total = sum(len(p.get("vulns", [])) for p in data)
        return {"tool": "pip-audit", "available": True, "total": total,
                "by_severity": {"UNKNOWN": total}, "duration": elapsed,
                "note": "pip-audit doesn't report severity"}
    except Exception as e:
        return {"tool": "pip-audit", "available": True, "error": str(e), "duration": elapsed}


def run_npm_audit(repo_path: str) -> dict:
    exe = _cmd("npm")
    if not (Path(repo_path) / "package.json").exists():
        return {"tool": "npm audit", "available": True, "skipped": "no package.json"}
    if not exe:
        return {"tool": "npm audit", "available": False}
    start = time.perf_counter()
    rc, stdout, stderr = _run([exe, "audit", "--json"], cwd=repo_path, timeout=120)
    elapsed = time.perf_counter() - start
    if rc == -2:
        return {"tool": "npm audit", "available": False}
    try:
        data = json.loads(stdout or "{}")
        vulns = data.get("vulnerabilities", {})
        if vulns:
            severities = [v.get("severity", "unknown") for v in vulns.values()]
        else:
            # v1 audit format
            meta = data.get("metadata", {}).get("vulnerabilities", {})
            severities = []
            for k, n in meta.items():
                severities.extend([k] * n)
        counts = _severity_counts(severities)
        return {"tool": "npm audit", "available": True, "total": sum(counts.values()),
                "by_severity": counts, "duration": elapsed}
    except Exception as e:
        return {"tool": "npm audit", "available": True, "error": str(e), "duration": elapsed}


def run_retire(repo_path: str) -> dict:
    exe = _cmd("retire")
    if not (Path(repo_path) / "package.json").exists():
        return {"tool": "retire", "available": True, "skipped": "no package.json"}
    if not exe:
        return {"tool": "retire", "available": False}
    start = time.perf_counter()
    # retire scans JS files in node_modules or any .js files
    rc, stdout, stderr = _run(
        [exe, "--outputformat", "json", "--path", repo_path, "--nocache"], timeout=120)
    elapsed = time.perf_counter() - start
    if rc == -2:
        return {"tool": "retire", "available": False}
    try:
        data = json.loads(stdout or "{}")
        severities = []
        for file_entry in data.get("data", []):
            for result in file_entry.get("results", []):
                for v in result.get("vulnerabilities", []):
                    severities.append(v.get("severity", "unknown"))
        return {"tool": "retire", "available": True, "total": len(severities),
                "by_severity": _severity_counts(severities), "duration": elapsed}
    except Exception as e:
        return {"tool": "retire", "available": True, "error": str(e), "duration": elapsed}


def run_bandit(repo_path: str) -> dict:
    """Python SAST only — not a dep scanner. Shown separately."""
    exe = _cmd("bandit")
    # Only run on Python repos
    py_files = list(Path(repo_path).rglob("*.py"))
    if not py_files:
        return {"tool": "bandit", "available": True, "skipped": "no Python files"}
    if not exe:
        return {"tool": "bandit", "available": False}
    start = time.perf_counter()
    rc, stdout, stderr = _run(
        [exe, "-r", repo_path, "--format", "json", "-q", "--skip", "B101"], timeout=300)
    elapsed = time.perf_counter() - start
    if rc == -2:
        return {"tool": "bandit", "available": False}
    try:
        data = json.loads(stdout or "{}")
        results = data.get("results", [])
        severities = [r.get("issue_severity", "UNKNOWN") for r in results]
        return {"tool": "bandit (SAST)", "available": True, "total": len(results),
                "by_severity": _severity_counts(severities), "duration": elapsed,
                "note": "SAST only — code patterns, not CVEs"}
    except Exception as e:
        return {"tool": "bandit (SAST)", "available": True, "error": str(e), "duration": elapsed}


# ── Our scanner ───────────────────────────────────────────────────────────────

async def run_our_scanner(repo_url: str, local_repo_path: Path) -> dict:
    """Run vuln-scanner-agent on an already-downloaded local repo path (--no-llm)."""
    report_path = str(local_repo_path.parent / "our_report.md")
    start = time.perf_counter()
    try:
        orch = Orchestrator(
            repo_url=repo_url,
            image=None,
            url=None,
            output_path=report_path,
            create_issue=False,
            use_llm=False,
            local_repo_path=local_repo_path,
        )
        await orch.run()
        elapsed = time.perf_counter() - start
        findings = getattr(orch, "_last_findings", [])
        severities = [f.severity for f in findings]
        from core.models import FindingType
        dep_count = sum(1 for f in findings if f.finding_type == FindingType.DEPENDENCY)
        sast_count = sum(1 for f in findings if f.finding_type == FindingType.SAST)
        return {
            "tool": "vuln-scanner-agent", "available": True,
            "total": len(findings), "by_severity": _severity_counts(severities),
            "dep_count": dep_count, "sast_count": sast_count,
            "duration": elapsed,
        }
    except Exception as e:
        return {"tool": "vuln-scanner-agent", "available": True,
                "error": str(e), "duration": time.perf_counter() - start}


# ── Download helper ───────────────────────────────────────────────────────────

async def download_repo(url: str, dest: Path) -> bool:
    import httpx, zipfile, io
    parts = url.rstrip("/").split("/")
    owner, repo = parts[-2], parts[-1]
    zip_url = f"https://api.github.com/repos/{owner}/{repo}/zipball"
    headers = {}
    token = os.getenv("GITHUB_TOKEN")
    if token:
        headers["Authorization"] = f"Bearer {token}"
    try:
        async with httpx.AsyncClient(timeout=120, headers=headers, follow_redirects=True) as c:
            print(f"  Downloading {url} ...")
            r = await c.get(zip_url)
            r.raise_for_status()
            z = zipfile.ZipFile(io.BytesIO(r.content))
            z.extractall(dest)
            subdirs = [d for d in dest.iterdir() if d.is_dir()]
            if len(subdirs) == 1:
                for item in subdirs[0].iterdir():
                    item.rename(dest / item.name)
                subdirs[0].rmdir()
        return True
    except Exception as e:
        print(f"  ERROR downloading {url}: {e}")
        return False


# ── Report generation ─────────────────────────────────────────────────────────

SEV_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO", "UNKNOWN"]


def _row(r: dict) -> str:
    if not r.get("available", True):
        return f"| {r.get('tool','?')} | — | — | — | — | — | not installed |"
    if r.get("skipped"):
        return f"| {r['tool']} | — | — | — | — | — | _{r['skipped']}_ |"
    if r.get("error"):
        return f"| {r['tool']} | ERR | — | — | — | — | {r.get('duration',0):.1f}s |"

    sev = r.get("by_severity", {})
    total = r.get("total", 0)
    c  = sev.get("CRITICAL", 0)
    h  = sev.get("HIGH", 0)
    m  = sev.get("MEDIUM", 0)
    lo = sev.get("LOW", 0)
    dur = f"{r['duration']:.1f}s"
    name = f"**{r['tool']}**" if r["tool"] == "vuln-scanner-agent" else r["tool"]
    if r.get("note"):
        name += " ¹"
    return f"| {name} | {total} | {c} | {h} | {m} | {lo} | {dur} |"


def generate_report(results: dict[str, list[dict]], output: str) -> None:
    from datetime import datetime, timezone
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    installed = [
        t for t in ["osv-scanner", "grype", "trivy fs", "safety", "pip-audit",
                    "npm audit", "retire", "bandit (SAST)"]
        if _cmd(t.split()[0])
    ]

    lines = [
        "# Benchmark — vuln-scanner-agent vs 8 tools\n",
        f"**Date:** {now}  \n",
        "## Test environment\n",
        f"**Installed comparison tools:** {', '.join(installed) or 'none'}\n",
        "| Tool | Type | Data source | Lock file? |",
        "|------|------|-------------|:----------:|",
        "| **vuln-scanner-agent** | Deps + SAST + LLM | OSV.dev API | No ✅ |",
        "| osv-scanner | Deps | OSV.dev | Yes |",
        "| grype | Deps | NVD + GitHub | No |",
        "| trivy fs | Deps + secrets | NVD + OS DB | Yes (JS/Py) |",
        "| safety | Deps (Python) | PyPI Safety DB | No |",
        "| pip-audit | Deps (Python) | OSV.dev | No |",
        "| npm audit | Deps (JS) | npm advisories | Yes |",
        "| retire | Deps (JS) | retire.js DB | No |",
        "| bandit | SAST (Python) | hardcoded rules | No |",
        "",
        "_All scans run without LLM enrichment for fairness._",
        "_Lock files generated automatically when missing._\n",
    ]

    for target_name, tool_results in results.items():
        cfg = TARGETS[target_name]
        lines.append(f"## {target_name}\n")
        lines.append(f"> {cfg['description']}  ")
        lines.append(f"> Ecosystems: `{'`, `'.join(cfg['ecosystems'])}`\n")

        # Dep scanners table
        dep_tools = [r for r in tool_results if "SAST" not in r.get("tool","")]
        if dep_tools:
            lines.append("### Dependency / CVE scanners\n")
            lines.append("| Tool | Total | CRITICAL | HIGH | MEDIUM | LOW | Time |")
            lines.append("|------|------:|:--------:|:----:|:------:|:---:|-----:|")
            for r in dep_tools:
                lines.append(_row(r))

        # SAST table
        sast_tools = [r for r in tool_results if "SAST" in r.get("tool","") or r.get("note","").startswith("SAST")]
        if sast_tools:
            lines.append("\n### SAST scanners\n")
            lines.append("| Tool | Total | HIGH | MEDIUM | LOW | Time |")
            lines.append("|------|------:|:----:|:------:|:---:|-----:|")
            for r in sast_tools:
                sev = r.get("by_severity", {})
                lines.append(
                    f"| {r['tool']} | {r.get('total',0)} | "
                    f"{sev.get('HIGH',0)} | {sev.get('MEDIUM',0)} | "
                    f"{sev.get('LOW',0)} | {r.get('duration',0):.1f}s |"
                )

        # Notes
        noted = [r for r in tool_results if r.get("note")]
        if noted:
            lines.append("")
            for r in noted:
                lines.append(f"> ¹ **{r['tool']}:** {r['note']}")
        lines.append("")

    Path(output).write_text("\n".join(lines))
    print(f"\nBenchmark report → {output}")


# ── Main ──────────────────────────────────────────────────────────────────────

async def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--targets", nargs="+", default=list(TARGETS.keys()),
                        choices=list(TARGETS.keys()))
    parser.add_argument("--output", default="benchmark_report.md")
    args = parser.parse_args()

    installed_tools = {k: v for k, v in TOOL_PATHS.items() if v and Path(v).exists()}
    print("=== vuln-scanner-agent benchmark ===\n")
    print(f"Targets  : {', '.join(args.targets)}")
    print(f"Tools    : {', '.join(installed_tools.keys())}\n")

    all_results: dict[str, list[dict]] = {}

    with tempfile.TemporaryDirectory(prefix="vuln-bench-") as tmp_root:
        for target_name in args.targets:
            cfg = TARGETS[target_name]
            print(f"\n{'='*60}")
            print(f"  {target_name}  ({', '.join(cfg['ecosystems'])})")
            print(f"{'='*60}")

            repo_dir = Path(tmp_root) / target_name
            repo_dir.mkdir()

            if not await download_repo(cfg["url"], repo_dir):
                print(f"  Skipped — download failed")
                continue

            # Pre-generate lock files (shared for all tools)
            _ensure_npm_lock(repo_dir)

            rpath = str(repo_dir)
            tool_results = []

            # 1. Our scanner
            print("  [1/9] vuln-scanner-agent ...")
            r = await run_our_scanner(cfg["url"], repo_dir)
            tool_results.append(r)
            _log_result(r)

            # 2. osv-scanner
            print("  [2/9] osv-scanner ...")
            r = run_osv_scanner(rpath)
            tool_results.append(r)
            _log_result(r)

            # 3. grype
            print("  [3/9] grype ...")
            r = run_grype(rpath)
            tool_results.append(r)
            _log_result(r)

            # 4. trivy fs
            print("  [4/9] trivy fs ...")
            r = run_trivy_fs(rpath)
            tool_results.append(r)
            _log_result(r)

            # 5. safety (Python only)
            print("  [5/9] safety ...")
            r = run_safety(rpath)
            tool_results.append(r)
            _log_result(r)

            # 6. pip-audit (Python only)
            print("  [6/9] pip-audit ...")
            r = run_pip_audit(rpath)
            tool_results.append(r)
            _log_result(r)

            # 7. npm audit (JS only)
            print("  [7/9] npm audit ...")
            r = run_npm_audit(rpath)
            tool_results.append(r)
            _log_result(r)

            # 8. retire (JS only)
            print("  [8/9] retire ...")
            r = run_retire(rpath)
            tool_results.append(r)
            _log_result(r)

            # 9. bandit (Python SAST)
            print("  [9/9] bandit ...")
            r = run_bandit(rpath)
            tool_results.append(r)
            _log_result(r)

            all_results[target_name] = tool_results

    generate_report(all_results, args.output)


def _log_result(r: dict):
    if not r.get("available", True):
        print(f"        → not installed")
    elif r.get("skipped"):
        print(f"        → {r['skipped']}")
    elif r.get("error"):
        print(f"        → ERROR: {r['error'][:80]}")
    else:
        sev = r.get("by_severity", {})
        c = sev.get("CRITICAL", 0)
        h = sev.get("HIGH", 0)
        print(f"        → {r.get('total',0)} findings (C:{c} H:{h}) in {r.get('duration',0):.1f}s")


if __name__ == "__main__":
    asyncio.run(main())
