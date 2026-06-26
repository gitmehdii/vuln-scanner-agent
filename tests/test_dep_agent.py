"""Tests for DepAgent manifest parsers and OSV severity extraction."""

import pytest
from pathlib import Path
from agents.dep_agent import DepAgent


@pytest.fixture
def agent():
    return DepAgent()


# ── Severity extraction ───────────────────────────────────────────────────────

def test_severity_from_database_specific(agent):
    vuln = {"database_specific": {"severity": "CRITICAL"}, "severity": []}
    assert agent._extract_severity(vuln) == "CRITICAL"


def test_severity_lowercase_normalised(agent):
    vuln = {"database_specific": {"severity": "high"}, "severity": []}
    assert agent._extract_severity(vuln) == "HIGH"


def test_severity_fallback_cvss_score(agent):
    # No database_specific label; numeric score in database_specific
    vuln = {"database_specific": {"cvss_score": 9.5}, "severity": []}
    assert agent._extract_severity(vuln) == "CRITICAL"


def test_severity_fallback_cvss_7(agent):
    vuln = {"database_specific": {"cvss_score": 7.2}, "severity": []}
    assert agent._extract_severity(vuln) == "HIGH"


def test_severity_fallback_cvss_5(agent):
    vuln = {"database_specific": {"cvss_score": 5.0}, "severity": []}
    assert agent._extract_severity(vuln) == "MEDIUM"


def test_severity_fallback_default_medium(agent):
    # CVSS vector string must NOT be parsed as float — should fall to MEDIUM
    vuln = {
        "database_specific": {},
        "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}],
    }
    assert agent._extract_severity(vuln) == "MEDIUM"


# ── CVSS extraction ───────────────────────────────────────────────────────────

def test_cvss_from_database_specific(agent):
    vuln = {"database_specific": {"cvss_score": 8.1}, "severity": []}
    assert agent._extract_cvss(vuln) == 8.1


def test_cvss_vector_string_not_parsed(agent):
    # CVSS vector string should not be returned as a float
    vuln = {
        "database_specific": {},
        "severity": [{"score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}],
    }
    assert agent._extract_cvss(vuln) is None


def test_cvss_none_when_missing(agent):
    vuln = {"database_specific": {}, "severity": []}
    assert agent._extract_cvss(vuln) is None


# ── requirements.txt ──────────────────────────────────────────────────────────

def test_requirements_pinned(agent, tmp_path):
    (tmp_path / "requirements.txt").write_text("requests==2.28.0\n")
    pkgs = agent._parse_manifest(tmp_path / "requirements.txt", "PyPI")
    assert pkgs == [{"name": "requests", "version": "2.28.0", "ecosystem": "PyPI"}]


def test_requirements_operators(agent, tmp_path):
    content = "flask>=2.0.0\ndjango~=4.2.0\nnumpy!=1.0.0,>=1.21\n"
    (tmp_path / "requirements.txt").write_text(content)
    pkgs = agent._parse_manifest(tmp_path / "requirements.txt", "PyPI")
    names = [p["name"] for p in pkgs]
    assert "flask" in names
    assert "django" in names


def test_requirements_skips_comments(agent, tmp_path):
    content = "# this is a comment\nrequests==2.28.0\n"
    (tmp_path / "requirements.txt").write_text(content)
    pkgs = agent._parse_manifest(tmp_path / "requirements.txt", "PyPI")
    assert len(pkgs) == 1


def test_requirements_skips_blank_lines(agent, tmp_path):
    content = "\nrequests==2.28.0\n\nflask==2.0.0\n"
    (tmp_path / "requirements.txt").write_text(content)
    pkgs = agent._parse_manifest(tmp_path / "requirements.txt", "PyPI")
    assert len(pkgs) == 2


# ── package.json ──────────────────────────────────────────────────────────────

def test_package_json_dependencies(agent, tmp_path):
    content = '{"dependencies": {"express": "^4.18.0", "lodash": "~4.17.21"}}'
    (tmp_path / "package.json").write_text(content)
    pkgs = agent._parse_manifest(tmp_path / "package.json", "npm")
    assert len(pkgs) == 2
    express = next(p for p in pkgs if p["name"] == "express")
    assert express["version"] == "4.18.0"


def test_package_json_dev_dependencies(agent, tmp_path):
    content = '{"dependencies": {"express": "4.18.0"}, "devDependencies": {"jest": "29.0.0"}}'
    (tmp_path / "package.json").write_text(content)
    pkgs = agent._parse_manifest(tmp_path / "package.json", "npm")
    names = [p["name"] for p in pkgs]
    assert "express" in names
    assert "jest" in names


def test_package_json_strips_semver_prefix(agent, tmp_path):
    content = '{"dependencies": {"react": "^18.2.0"}}'
    (tmp_path / "package.json").write_text(content)
    pkgs = agent._parse_manifest(tmp_path / "package.json", "npm")
    assert pkgs[0]["version"] == "18.2.0"


# ── go.mod ────────────────────────────────────────────────────────────────────

def test_go_mod_block_require(agent, tmp_path):
    content = (
        "module example.com/app\n"
        "go 1.21\n"
        "require (\n"
        "\tgithub.com/gin-gonic/gin v1.9.1\n"
        "\tgithub.com/gorilla/mux v1.8.0\n"
        ")\n"
    )
    (tmp_path / "go.mod").write_text(content)
    pkgs = agent._parse_manifest(tmp_path / "go.mod", "Go")
    assert len(pkgs) == 2
    gin = next(p for p in pkgs if "gin" in p["name"])
    assert gin["version"] == "1.9.1"
    assert gin["ecosystem"] == "Go"


def test_go_mod_inline_require(agent, tmp_path):
    content = "module example.com/app\ngo 1.21\nrequire github.com/sirupsen/logrus v1.9.3\n"
    (tmp_path / "go.mod").write_text(content)
    pkgs = agent._parse_manifest(tmp_path / "go.mod", "Go")
    assert len(pkgs) == 1
    assert pkgs[0]["version"] == "1.9.3"


def test_go_mod_skips_module_and_go_lines(agent, tmp_path):
    content = "module example.com/app\ngo 1.21\nrequire golang.org/x/crypto v0.13.0\n"
    (tmp_path / "go.mod").write_text(content)
    pkgs = agent._parse_manifest(tmp_path / "go.mod", "Go")
    # should only have the require line, not the module or go directive
    assert all("example.com" not in p["name"] for p in pkgs)
    assert len(pkgs) == 1


# ── Cargo.toml ────────────────────────────────────────────────────────────────

def test_cargo_toml_simple_version(agent, tmp_path):
    content = "[dependencies]\nserde = \"1.0.188\"\n"
    (tmp_path / "Cargo.toml").write_text(content)
    pkgs = agent._parse_manifest(tmp_path / "Cargo.toml", "crates.io")
    assert len(pkgs) == 1
    assert pkgs[0]["name"] == "serde"
    assert pkgs[0]["version"] == "1.0.188"


def test_cargo_toml_inline_table(agent, tmp_path):
    content = '[dependencies]\ntokio = { version = "1.28.0", features = ["full"] }\n'
    (tmp_path / "Cargo.toml").write_text(content)
    pkgs = agent._parse_manifest(tmp_path / "Cargo.toml", "crates.io")
    assert len(pkgs) == 1
    assert pkgs[0]["name"] == "tokio"
    assert pkgs[0]["version"] == "1.28.0"


def test_cargo_toml_dev_dependencies(agent, tmp_path):
    content = "[dependencies]\nserde = \"1.0\"\n[dev-dependencies]\npretty_assertions = \"1.4.0\"\n"
    (tmp_path / "Cargo.toml").write_text(content)
    pkgs = agent._parse_manifest(tmp_path / "Cargo.toml", "crates.io")
    names = [p["name"] for p in pkgs]
    assert "serde" in names
    assert "pretty_assertions" in names


def test_cargo_toml_stops_at_other_section(agent, tmp_path):
    content = "[dependencies]\nserde = \"1.0\"\n[profile.release]\nopt-level = 3\n"
    (tmp_path / "Cargo.toml").write_text(content)
    pkgs = agent._parse_manifest(tmp_path / "Cargo.toml", "crates.io")
    assert len(pkgs) == 1


# ── pyproject.toml ────────────────────────────────────────────────────────────

def test_pyproject_pep621(agent, tmp_path):
    content = (
        "[project]\n"
        "name = \"myapp\"\n"
        'dependencies = [\n'
        '    "requests>=2.28.0",\n'
        '    "fastapi>=0.100.0",\n'
        "]\n"
    )
    (tmp_path / "pyproject.toml").write_text(content)
    pkgs = agent._parse_manifest(tmp_path / "pyproject.toml", "PyPI")
    names = [p["name"] for p in pkgs]
    assert "requests" in names
    assert "fastapi" in names


def test_pyproject_poetry(agent, tmp_path):
    content = (
        "[tool.poetry.dependencies]\n"
        'python = "^3.11"\n'
        'django = "^4.2.0"\n'
        'celery = { version = "5.3.0", extras = ["redis"] }\n'
    )
    (tmp_path / "pyproject.toml").write_text(content)
    pkgs = agent._parse_manifest(tmp_path / "pyproject.toml", "PyPI")
    names = [p["name"] for p in pkgs]
    assert "python" not in names  # should be skipped
    assert "django" in names
    assert "celery" in names


def test_pyproject_empty_deps(agent, tmp_path):
    content = "[project]\nname = \"myapp\"\n"
    (tmp_path / "pyproject.toml").write_text(content)
    pkgs = agent._parse_manifest(tmp_path / "pyproject.toml", "PyPI")
    assert pkgs == []
