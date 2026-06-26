"""
DepAgent — scans dependency manifests and queries OSV.dev for known CVEs.

Supports: requirements.txt, package.json, Pipfile, pyproject.toml, go.mod
"""

import asyncio
import json
import re
from pathlib import Path
from typing import Optional

import httpx

from core.models import Finding, FindingType
from core.logger import get_logger

logger = get_logger(__name__)

OSV_BATCH_URL = "https://api.osv.dev/v1/querybatch"
OSV_VULN_URL = "https://api.osv.dev/v1/vulns/{id}"
OSV_FETCH_CONCURRENCY = 20

# Map manifest filename → ecosystem name for OSV
# Lock files take priority over manifest files (resolved versions are more accurate)
MANIFEST_ECOSYSTEMS = {
    "requirements.txt": "PyPI",
    "Pipfile": "PyPI",
    "pyproject.toml": "PyPI",
    "package.json": "npm",
    "go.mod": "Go",
    "Gemfile": "RubyGems",
    "Cargo.toml": "crates.io",
}

# Lock files provide resolved, pinned versions — prefer over manifests
LOCK_ECOSYSTEMS = {
    "package-lock.json": "npm",
    "yarn.lock": "npm",
    "Pipfile.lock": "PyPI",
    "poetry.lock": "PyPI",
    "pnpm-lock.yaml": "npm",
    "Gemfile.lock": "RubyGems",
}


class DepAgent:
    def __init__(self):
        # Exposed after run() for CVEGapAgent and LLMScanAgent to consume
        self.packages: list[dict] = []

    async def run(self, repo_path: Path) -> list[Finding]:
        logger.info("DepAgent starting", path=str(repo_path))
        self.packages = self._extract_packages(repo_path)

        if not self.packages:
            logger.info("DepAgent: no manifests found")
            return []

        logger.info("DepAgent: querying OSV", count=len(self.packages))
        findings = await self._query_osv(self.packages)
        logger.info("DepAgent done", findings=len(findings))
        return findings

    def _extract_packages(self, repo_path: Path) -> list[dict]:
        """Walk the repo and extract (name, version, ecosystem) tuples.

        Lock files take precedence over manifests for a given directory —
        they contain resolved, pinned versions instead of version ranges.
        """
        packages = []
        seen_dirs_ecosystems: set[tuple[str, str]] = set()

        # 1. Lock files first (higher accuracy)
        for lock_file, ecosystem in LOCK_ECOSYSTEMS.items():
            for path in repo_path.rglob(lock_file):
                dir_eco = (str(path.parent), ecosystem)
                seen_dirs_ecosystems.add(dir_eco)
                pkgs = self._parse_lock(path, ecosystem)
                packages.extend(pkgs)
                if pkgs:
                    logger.info("DepAgent: parsed lock file", file=path.name, packages=len(pkgs))

        # 2. Manifest files — skip if a lock file already covered this dir + ecosystem
        for manifest, ecosystem in MANIFEST_ECOSYSTEMS.items():
            for path in repo_path.rglob(manifest):
                dir_eco = (str(path.parent), ecosystem)
                if dir_eco in seen_dirs_ecosystems:
                    continue  # lock file takes precedence
                pkgs = self._parse_manifest(path, ecosystem)
                packages.extend(pkgs)
        return packages

    def _parse_manifest(self, path: Path, ecosystem: str) -> list[dict]:
        packages = []
        try:
            content = path.read_text(errors="ignore")

            if ecosystem == "PyPI" and path.name == "requirements.txt":
                for line in content.splitlines():
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    # Handle: package==1.0.0, package>=1.0.0, package~=1.0.0
                    match = re.match(r"^([a-zA-Z0-9_\-\.]+)[=~><!]+([^\s,;]+)", line)
                    if match:
                        packages.append({
                            "name": match.group(1),
                            "version": match.group(2),
                            "ecosystem": ecosystem,
                        })

            elif ecosystem == "npm" and path.name == "package.json":
                data = json.loads(content)
                for section in ("dependencies", "devDependencies"):
                    for name, version in data.get(section, {}).items():
                        clean_version = re.sub(r"[^0-9\.]", "", version)
                        if clean_version:
                            packages.append({
                                "name": name,
                                "version": clean_version,
                                "ecosystem": ecosystem,
                            })

            elif ecosystem == "Go" and path.name == "go.mod":
                for line in content.splitlines():
                    line = line.strip()
                    if line.startswith("//") or line.startswith("module") or line.startswith("go "):
                        continue
                    # Both inline `require pkg v1.2.3` and block entries `pkg v1.2.3`
                    line = re.sub(r"^require\s+", "", line)
                    match = re.match(r"^([a-zA-Z0-9_\-\./]+)\s+v([^\s]+)", line)
                    if match:
                        packages.append({
                            "name": match.group(1),
                            "version": match.group(2),
                            "ecosystem": ecosystem,
                        })

            elif ecosystem == "crates.io" and path.name == "Cargo.toml":
                in_deps = False
                for line in content.splitlines():
                    stripped = line.strip()
                    if stripped in ("[dependencies]", "[dev-dependencies]", "[build-dependencies]"):
                        in_deps = True
                        continue
                    if stripped.startswith("[") and "dependencies" not in stripped:
                        in_deps = False
                    if not in_deps or not stripped or stripped.startswith("#"):
                        continue
                    if "=" not in stripped:
                        continue
                    name = stripped.split("=")[0].strip()
                    val = stripped.split("=", 1)[1].strip()
                    # { version = "1.0", features = [...] } format
                    ver_match = re.search(r'version\s*=\s*["\']([^"\']+)["\']', val)
                    if ver_match:
                        version = re.sub(r"[^0-9\.]", "", ver_match.group(1))
                    else:
                        version = re.sub(r"[^0-9\.]", "", val.strip('"').strip("'"))
                    if name and version:
                        packages.append({"name": name, "version": version, "ecosystem": ecosystem})

            elif ecosystem == "RubyGems" and path.name == "Gemfile":
                # gem 'rails', '~> 4.2.6'  or  gem 'sqlite3'
                for line in content.splitlines():
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    m = re.match(r"""gem\s+['"]([^'"]+)['"]\s*,?\s*['"]([~><=!^0-9][^'"]*)?['"]?""", line)
                    if m:
                        name = m.group(1)
                        version = re.sub(r"[^0-9\.]", "", m.group(2) or "").strip(".")
                        if name and version:
                            packages.append({"name": name, "version": version, "ecosystem": ecosystem})

            elif ecosystem == "PyPI" and path.name == "pyproject.toml":
                import tomllib
                data = tomllib.loads(content)
                # PEP 517 / PEP 621: [project] dependencies
                for dep in data.get("project", {}).get("dependencies", []):
                    m = re.match(r"^([a-zA-Z0-9_\-\.]+)\s*[>=<!~^]+\s*([^\s,;]+)", dep)
                    if m:
                        packages.append({
                            "name": m.group(1),
                            "version": re.sub(r"[^0-9\.]", "", m.group(2)),
                            "ecosystem": ecosystem,
                        })
                # Poetry: [tool.poetry.dependencies]
                for name, constraint in (
                    data.get("tool", {}).get("poetry", {}).get("dependencies", {}).items()
                ):
                    if name.lower() == "python":
                        continue
                    if isinstance(constraint, str):
                        version = re.sub(r"[^0-9\.]", "", constraint)
                    elif isinstance(constraint, dict):
                        version = re.sub(r"[^0-9\.]", "", constraint.get("version", ""))
                    else:
                        continue
                    if version:
                        packages.append({"name": name, "version": version, "ecosystem": ecosystem})

        except Exception as e:
            logger.warning("DepAgent: failed to parse manifest", path=str(path), error=str(e))

        return packages

    def _parse_lock(self, path: Path, ecosystem: str) -> list[dict]:
        """Parse lock files for pinned/resolved package versions."""
        packages = []
        try:
            content = path.read_text(errors="ignore")

            if path.name == "package-lock.json":
                data = json.loads(content)
                # v2/v3 format: packages["node_modules/foo"].version
                pkgs_dict = data.get("packages", {})
                for pkg_path, info in pkgs_dict.items():
                    if not pkg_path or pkg_path == "":
                        continue
                    name = pkg_path.removeprefix("node_modules/")
                    # Handle scoped packages: node_modules/@scope/name
                    if "/" in name and name.startswith("@"):
                        pass  # keep as-is: @scope/name
                    version = info.get("version", "")
                    if name and version:
                        packages.append({"name": name, "version": version, "ecosystem": ecosystem})

                # v1 fallback: dependencies.foo.version
                if not packages:
                    for name, info in data.get("dependencies", {}).items():
                        version = info.get("version", "")
                        if name and version:
                            packages.append({"name": name, "version": version, "ecosystem": ecosystem})

            elif path.name == "yarn.lock":
                # yarn.lock: "package@version:\n  version \"x.y.z\""
                current_names: list[str] = []
                for line in content.splitlines():
                    line = line.strip()
                    if line.startswith('"') or (line and not line.startswith(" ") and line.endswith(":")):
                        # Parse package header: "name@version, name@version:"
                        header = line.strip('"').rstrip(":")
                        current_names = []
                        for part in header.split(", "):
                            m = re.match(r'^(@?[^@]+)@', part)
                            if m:
                                current_names.append(m.group(1))
                    elif line.startswith("version") and current_names:
                        m = re.match(r'version\s+"([^"]+)"', line)
                        if m:
                            ver = m.group(1)
                            for name in current_names:
                                packages.append({"name": name, "version": ver, "ecosystem": ecosystem})
                        current_names = []

            elif path.name == "Pipfile.lock":
                data = json.loads(content)
                for section in ("default", "develop"):
                    for name, info in data.get(section, {}).items():
                        version = info.get("version", "").lstrip("=")
                        if name and version:
                            packages.append({"name": name, "version": version, "ecosystem": ecosystem})

            elif path.name == "poetry.lock":
                # Simple TOML-like parsing for poetry.lock
                name = version = ""
                for line in content.splitlines():
                    line = line.strip()
                    if line == "[[package]]":
                        if name and version:
                            packages.append({"name": name, "version": version, "ecosystem": ecosystem})
                        name = version = ""
                    elif line.startswith("name = "):
                        name = line.split("=", 1)[1].strip().strip('"')
                    elif line.startswith("version = "):
                        version = line.split("=", 1)[1].strip().strip('"')
                if name and version:
                    packages.append({"name": name, "version": version, "ecosystem": ecosystem})

            elif path.name == "Gemfile.lock":
                # Gemfile.lock format:
                #   GEM
                #     specs:
                #       rails (4.2.7)         ← top-level (4-space indent)
                #         actionview (4.2.7)  ← dependency (6+ spaces, skip)
                in_specs = False
                for line in content.splitlines():
                    stripped = line.strip()
                    if stripped == "specs:":
                        in_specs = True
                        continue
                    # A non-indented non-empty line signals a new section
                    if stripped and not line.startswith(" ") and in_specs:
                        in_specs = False
                    if not in_specs:
                        continue
                    # Top-level gems have exactly 4-space indent
                    m = re.match(r"^    ([a-zA-Z0-9_\-\.]+) \(([^)!<>~^ ,]+)\)$", line)
                    if m:
                        packages.append({"name": m.group(1), "version": m.group(2), "ecosystem": ecosystem})

            elif path.name == "pnpm-lock.yaml":
                # pnpm-lock.yaml: packages:\n  /foo@x.y.z:\n    resolution: ...
                for line in content.splitlines():
                    m = re.match(r"^\s+/(@?[^@\s]+)@([^\s:]+):", line)
                    if m:
                        packages.append({"name": m.group(1), "version": m.group(2), "ecosystem": ecosystem})

        except Exception as e:
            logger.warning("DepAgent: failed to parse lock file", path=str(path), error=str(e))

        # Deduplicate by (name, version)
        seen = set()
        deduped = []
        for p in packages:
            key = (p["name"], p["version"])
            if key not in seen:
                seen.add(key)
                deduped.append(p)
        return deduped

    async def _query_osv(self, packages: list[dict]) -> list[Finding]:
        """Batch query OSV.dev to get CVE IDs, then fetch full details in parallel.

        The querybatch API returns only stubs (id + modified). Full details
        (severity, description, fixed_version) require a separate /vulns/{id} call.
        """
        findings = []
        BATCH_SIZE = 1000

        for i in range(0, len(packages), BATCH_SIZE):
            batch = packages[i:i + BATCH_SIZE]
            queries = [
                {"version": p["version"], "package": {"name": p["name"], "ecosystem": p["ecosystem"]}}
                for p in batch
            ]

            try:
                async with httpx.AsyncClient(timeout=30) as client:
                    resp = await client.post(OSV_BATCH_URL, json={"queries": queries})
                    resp.raise_for_status()
                    data = resp.json()

                # Collect (pkg, vuln_id) pairs — batch returns stubs only
                vuln_refs: list[tuple[dict, str]] = []
                for pkg, result in zip(batch, data.get("results", [])):
                    for stub in result.get("vulns", []):
                        vuln_refs.append((pkg, stub["id"]))

                if not vuln_refs:
                    continue

                logger.info("DepAgent: fetching full vuln details", count=len(vuln_refs))
                unique_ids = list(dict.fromkeys(vid for _, vid in vuln_refs))
                full_vulns = await self._fetch_vulns_parallel(unique_ids)
                vuln_by_id = {v["id"]: v for v in full_vulns if v}

                for pkg, vid in vuln_refs:
                    vuln = vuln_by_id.get(vid)
                    if not vuln:
                        continue
                    findings.append(Finding(
                        id=vuln.get("id", "UNKNOWN"),
                        title=vuln.get("summary", vuln.get("id", ""))[:120],
                        description=(vuln.get("details") or vuln.get("summary") or "")[:500],
                        severity=self._extract_severity(vuln),
                        finding_type=FindingType.DEPENDENCY,
                        package=pkg["name"],
                        version=pkg["version"],
                        fixed_version=self._extract_fixed(vuln),
                        cvss_score=self._extract_cvss(vuln),
                        source="osv",
                    ))

            except Exception as e:
                logger.error("DepAgent: OSV query failed", error=str(e))

        return findings

    async def _fetch_vulns_parallel(self, vuln_ids: list[str]) -> list[Optional[dict]]:
        """Fetch full vulnerability details in parallel with concurrency cap."""
        sem = asyncio.Semaphore(OSV_FETCH_CONCURRENCY)

        async def fetch_one(vid: str) -> Optional[dict]:
            async with sem:
                try:
                    async with httpx.AsyncClient(timeout=15) as c:
                        r = await c.get(OSV_VULN_URL.format(id=vid))
                        if r.status_code == 200:
                            return r.json()
                except Exception as e:
                    logger.warning("DepAgent: failed to fetch vuln", id=vid, error=str(e))
            return None

        return list(await asyncio.gather(*[fetch_one(vid) for vid in vuln_ids]))

    def _extract_severity(self, vuln: dict) -> str:
        # database_specific.severity is the most reliable plain-text label (GHSA, PyPI, npm)
        db = vuln.get("database_specific", {})
        sev = str(db.get("severity", "")).upper()
        if sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
            return sev

        # Fallback: derive from CVSS numeric base score
        cvss = self._extract_cvss(vuln)
        if cvss is not None:
            if cvss >= 9.0:
                return "CRITICAL"
            if cvss >= 7.0:
                return "HIGH"
            if cvss >= 4.0:
                return "MEDIUM"
            return "LOW"

        return "MEDIUM"

    def _extract_cvss(self, vuln: dict) -> Optional[float]:
        # Some databases store a numeric score in database_specific
        db = vuln.get("database_specific", {})
        for key in ("cvss_score", "cvss_v3_score", "base_score", "score"):
            val = db.get(key)
            if val is not None:
                try:
                    f = float(val)
                    if 0.0 <= f <= 10.0:
                        return f
                except (ValueError, TypeError):
                    pass

        # severity[] contains CVSS vector strings (not parseable without the cvss lib)
        # but occasionally contains a plain numeric score
        for sev in vuln.get("severity", []):
            try:
                f = float(sev.get("score", ""))
                if 0.0 <= f <= 10.0:
                    return f
            except (ValueError, TypeError):
                pass

        return None

    def _extract_fixed(self, vuln: dict) -> Optional[str]:
        for affected in vuln.get("affected", []):
            for r in affected.get("ranges", []):
                for event in r.get("events", []):
                    if "fixed" in event:
                        return event["fixed"]
        return None
