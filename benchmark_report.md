# Benchmark — vuln-scanner-agent vs 8 tools

**Date:** 2026-06-25 13:59 UTC  

## Test environment

**Installed comparison tools:** osv-scanner, grype, trivy fs, safety, pip-audit, npm audit, retire, bandit (SAST)

| Tool | Type | Data source | Lock file? |
|------|------|-------------|:----------:|
| **vuln-scanner-agent** | Deps + SAST + LLM | OSV.dev API | No ✅ |
| osv-scanner | Deps | OSV.dev | Yes |
| grype | Deps | NVD + GitHub | No |
| trivy fs | Deps + secrets | NVD + OS DB | Yes (JS/Py) |
| safety | Deps (Python) | PyPI Safety DB | No |
| pip-audit | Deps (Python) | OSV.dev | No |
| npm audit | Deps (JS) | npm advisories | Yes |
| retire | Deps (JS) | retire.js DB | No |
| bandit | SAST (Python) | hardcoded rules | No |

_All scans run without LLM enrichment for fairness._
_Lock files generated automatically when missing._

## juice-shop

> OWASP Juice Shop — intentionally insecure Node.js e-commerce app  
> Ecosystems: `npm`

### Dependency / CVE scanners

| Tool | Total | CRITICAL | HIGH | MEDIUM | LOW | Time |
|------|------:|:--------:|:----:|:------:|:---:|-----:|
| **vuln-scanner-agent** | 54 | 3 | 25 | 24 | 2 | 6.2s |
| osv-scanner | 65 | 5 | 33 | 24 | 3 | 8.2s |
| grype | 62 | 5 | 32 | 23 | 2 | 2.6s |
| trivy fs | 67 | 5 | 35 | 23 | 4 | 0.2s |
| safety | — | — | — | — | — | _no requirements.txt_ |
| pip-audit | — | — | — | — | — | _no requirements.txt_ |
| npm audit | 45 | 5 | 22 | 15 | 3 | 2.2s |
| retire | 0 | 0 | 0 | 0 | 0 | 0.6s |

### SAST scanners

| Tool | Total | HIGH | MEDIUM | LOW | Time |
|------|------:|:----:|:------:|:---:|-----:|
| bandit (SAST) | 0 | 0 | 0 | 0 | 0.2s |

> ¹ **bandit (SAST):** SAST only — code patterns, not CVEs

## pygoat

> PyGoat — intentionally insecure Django app (OWASP)  
> Ecosystems: `pip`

### Dependency / CVE scanners

| Tool | Total | CRITICAL | HIGH | MEDIUM | LOW | Time |
|------|------:|:--------:|:----:|:------:|:---:|-----:|
| **vuln-scanner-agent** | 192 | 9 | 40 | 128 | 15 | 3.6s |
| osv-scanner | 167 | 7 | 34 | 44 | 14 | 1.4s |
| grype | 135 | 9 | 42 | 68 | 16 | 1.6s |
| trivy fs | 135 | 9 | 42 | 68 | 16 | 0.1s |
| safety ¹ | 113 | 0 | 0 | 0 | 0 | 3.4s |
| pip-audit ¹ | 0 | 0 | 0 | 0 | 0 | 11.7s |
| npm audit | — | — | — | — | — | _no package.json_ |
| retire | — | — | — | — | — | _no package.json_ |

### SAST scanners

| Tool | Total | HIGH | MEDIUM | LOW | Time |
|------|------:|:----:|:------:|:---:|-----:|
| bandit (SAST) | 65 | 6 | 15 | 44 | 0.5s |

> ¹ **safety:** safety doesn't report severity (uses own ID system)
> ¹ **pip-audit:** pip-audit doesn't report severity
> ¹ **bandit (SAST):** SAST only — code patterns, not CVEs

## dvna

> DVNA — Damn Vulnerable Node Application (OWASP Top 10)  
> Ecosystems: `npm`

### Dependency / CVE scanners

| Tool | Total | CRITICAL | HIGH | MEDIUM | LOW | Time |
|------|------:|:--------:|:----:|:------:|:---:|-----:|
| **vuln-scanner-agent** | 41 | 13 | 14 | 12 | 2 | 1.9s |
| osv-scanner | 52 | 13 | 22 | 15 | 2 | 2.1s |
| grype | 52 | 13 | 22 | 15 | 2 | 1.6s |
| trivy fs | 53 | 14 | 22 | 15 | 2 | 0.1s |
| safety | — | — | — | — | — | _no requirements.txt_ |
| pip-audit | — | — | — | — | — | _no requirements.txt_ |
| npm audit | 24 | 9 | 9 | 4 | 2 | 1.3s |
| retire | 3 | 0 | 0 | 3 | 0 | 0.5s |
| bandit | — | — | — | — | — | _no Python files_ |

## railsgoat

> RailsGoat — intentionally insecure Ruby on Rails app (OWASP)  
> Ecosystems: `ruby`

### Dependency / CVE scanners

| Tool | Total | CRITICAL | HIGH | MEDIUM | LOW | Time |
|------|------:|:--------:|:----:|:------:|:---:|-----:|
| **vuln-scanner-agent** | 54 | 1 | 14 | 24 | 15 | 2.2s |
| osv-scanner | 142 | 1 | 22 | 48 | 71 | 2.5s |
| grype | 142 | 1 | 22 | 48 | 71 | 1.6s |
| trivy fs | 55 | 6 | 15 | 20 | 13 | 0.2s |
| safety | — | — | — | — | — | _no requirements.txt_ |
| pip-audit | — | — | — | — | — | _no requirements.txt_ |
| npm audit | — | — | — | — | — | _no package.json_ |
| retire | — | — | — | — | — | _no package.json_ |
| bandit | — | — | — | — | — | _no Python files_ |
