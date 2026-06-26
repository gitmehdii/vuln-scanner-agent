# vuln-scanner-agent

A multi-agent vulnerability scanner for GitHub repositories, Docker images, and web applications. Combines CVE detection, static analysis, LLM-powered code review, and exploitability assessment in a single CLI.

## Features

- **Dependency CVEs**: scans lock files against OSV.dev (npm, pip, Ruby, Go, Rust, Java, PHP)
- **SAST**: custom rules (55 rules, 7 languages) + Semgrep community packs auto-selected by detected language (`p/owasp-top-ten`, `p/secrets`, `p/python`, `p/javascript`, ...)
- **Docker image scanning**: Trivy-backed layer analysis
- **LLM code review**: 3-pass analysis (app understanding -> file-by-file -> cross-file synthesis). Finds IDOR, auth bypass, mass assignment, hardcoded secrets, business logic flaws
- **CVE gap analysis**: LLM-discovered CVEs validated against OSV API before inclusion
- **Exploitability assessment**: for each HIGH/CRITICAL CVE, checks whether the vulnerable code path is reachable with user input
- **Git history scan**: detects secrets committed and later deleted (AWS keys, OpenAI, GitHub tokens, Stripe, DB URLs)
- **Web scanning**: HTTP headers, SSL/TLS, nuclei integration
- **Autonomous pentest**: DeepSeek R1 ReAct loop with web_request/run_command/execute_python tools
- **GitHub issue creation**: post findings directly to your repo

## Architecture

```
scan.py
└── Orchestrator
    ├── Phase 1 (parallel)
    │   ├── DepAgent         → OSV.dev batch API
    │   ├── SASTAgent        → Semgrep CLI (rules/)
    │   └── GitHistoryAgent  → git log -p (200 commits)
    ├── Phase 2 - LLM (parallel, skipped with --no-llm)
    │   ├── LLMScanAgent     → DeepSeek V3, 3-pass file analysis
    │   ├── CVEGapAgent      → LLM + OSV cross-validation
    │   └── ExploitabilityAgent → per-package reachability analysis
    ├── DockerAgent          → Trivy (if --image)
    ├── WebAgent             → headers + SSL + nuclei (if --url)
    ├── TriageAgent          → dedup + sort + LLM enrich (CRITICAL/HIGH)
    └── ReportAgent          → markdown report
```

## Agents

| Agent | Role | Tool |
|-------|------|------|
| `DepAgent` | Scans lock files for known CVEs | OSV.dev API |
| `SASTAgent` | Static analysis — custom rules + Semgrep community packs | Semgrep |
| `GitHistoryAgent` | Finds secrets deleted from git history | git |
| `LLMScanAgent` | Deep code review (IDOR, auth bypass, logic flaws) | DeepSeek V3 |
| `CVEGapAgent` | Discovers CVEs beyond OSV, validates each one | DeepSeek V3 + OSV |
| `ExploitabilityAgent` | Checks if vulnerable code paths are reachable | DeepSeek V3 |
| `DockerAgent` | Scans Docker image layers | Trivy |
| `WebAgent` | HTTP headers, SSL, nuclei | nuclei |
| `LLMWebAgent` | BFS crawl + LLM analysis per page | DeepSeek V3 |
| `TriageAgent` | Dedup, sort, LLM enrichment of CRITICAL/HIGH | DeepSeek V3 |
| `ReportAgent` | Generates structured markdown report | n/a |
| `PentestAgent` | Autonomous ReAct pentest loop | DeepSeek R1 |

## Benchmark

Tested against 8 tools on 4 intentionally vulnerable apps (no LLM, for fairness):

| Tool | pygoat (pip) | juice-shop (npm) |
|------|:---:|:---:|
| **vuln-scanner-agent** | **223** | **106** |
| osv-scanner | 167 | 65 |
| grype | 135 | 62 |
| trivy fs | 135 | 67 |
| npm audit | n/a | 45 |
| bandit (SAST) | 65 | n/a |

_No LLM enrichment, for fairness. Semgrep community packs included._

SAST breakdown for vuln-scanner-agent: pygoat 36 findings (11 custom + 25 community), juice-shop 75 findings (58 custom + 17 community).

With LLM enabled on pygoat: **264+ findings**, including findings in custom code (IDOR, auth bypass, hardcoded secrets) that no other tool detects.

## Installation

```bash
pip install -r requirements.txt
```

External tools (optional, extend coverage):
- [Semgrep](https://semgrep.dev/docs/getting-started/): required for SAST
- [Trivy](https://aquasecurity.github.io/trivy/latest/getting-started/installation/): required for `--image`
- [nuclei](https://nuclei.projectdiscovery.io/nuclei/get-started/): optional, enhances `--url`

## Configuration

```bash
cp .env.example .env
```

Three options for the LLM backend (priority order):

### Option 1 - Local model (Ollama, LM Studio, llama.cpp, vLLM)

Any server that exposes an OpenAI-compatible `/v1` API works. No API key needed.

```bash
# Ollama
OPENAI_BASE_URL=http://localhost:11434/v1
LOCAL_MODEL=qwen2.5:14b

# Optional: separate model for reasoning tasks (PentestAgent)
# Defaults to LOCAL_MODEL if not set
LOCAL_REASONING_MODEL=deepseek-r1:8b
```

Recommended models by task:
- Analysis (fast): `qwen2.5:14b`, `mistral:7b`, `llama3.2:3b`
- Reasoning (pentest): `deepseek-r1:8b`, `qwen2.5:14b`

### Option 2 - OpenRouter (DeepSeek V3/R1)

```bash
OPENROUTER_API_KEY=sk-or-v1-...
```

### Option 3 - OpenAI

```bash
OPENAI_API_KEY=sk-...
```

### Other variables

| Variable | Description |
|----------|-------------|
| `SEMGREP_COMMUNITY` | Set to `false` to disable community rule packs (offline/CI use) |
| `GITHUB_TOKEN` | Required for `--issue` (creates a GitHub issue with findings) |

## Usage

```bash
# Scan a GitHub repo (with full LLM analysis)
python scan.py --repo https://github.com/user/repo

# Scan a Docker image
python scan.py --image nginx:1.14.0

# Scan a web app
python scan.py --url https://example.com

# Combine targets
python scan.py --repo https://github.com/user/repo --image myapp:latest --url https://myapp.com

# Skip LLM (faster, no API key needed)
python scan.py --repo https://github.com/user/repo --no-llm

# Create a GitHub issue with findings
python scan.py --repo https://github.com/user/repo --issue

# Autonomous pentest mode (DeepSeek R1 ReAct loop)
python scan.py --url https://target.com --pentest

# Custom output path
python scan.py --repo https://github.com/user/repo --output my-report.md
```

## Output

Generates a `report.md` with:
- Dependency CVEs table with severity, CVSS vector, and **Exploitable?** column
- SAST findings with file/line references
- LLM findings with attack scenario descriptions
- Docker CVE breakdown by layer
- Web findings (headers, SSL, nuclei)
- Git history secrets (with commit hash)
- Cost summary (tokens used + USD cost per LLM call)

## Scan results (examples)

| Target | Findings | CRITICAL | HIGH | Time | LLM cost |
|--------|:--------:|:--------:|:----:|-----:|:--------:|
| `nginx:1.14.0` | 280 | 39 | 107 | 106s | n/a |
| `juice-shop` (repo) | 71 | 0 | 12 | 13s | n/a |
| `pygoat` (repo, LLM) | 264 | 26 | 74 | ~60s | $0.02 |
| `demo.testfire.net` (web) | 37 | 0 | 9 | 75s | $0.001 |

## Lock file support

| Ecosystem | Lock files detected |
|-----------|-------------------|
| npm | `package-lock.json`, `yarn.lock`, `pnpm-lock.yaml` |
| pip | `Pipfile.lock`, `poetry.lock`, `requirements.txt` |
| Ruby | `Gemfile.lock` |
| Go | `go.sum` |
| Rust | `Cargo.lock` |
| Java | `pom.xml` |
| PHP | `composer.lock` |

## Cost

LLM calls use DeepSeek V3 (analysis) and DeepSeek R1 (reasoning) via OpenRouter. Typical costs:
- Repo scan with LLM: **$0.01-$0.05** depending on codebase size
- Web scan with LLM: **< $0.01**
- `--no-llm`: **$0.00**

## Roadmap

- [ ] Nightly cron on own GitHub repos + webhook on push/PR
- [ ] Datadog APM integration (ddtrace + custom metrics)
- [ ] Telegram alerts on CRITICAL findings
- [ ] CVSS numeric score calculation from OSV vectors
- [ ] Semgrep rules for Kotlin, Swift, Rust
