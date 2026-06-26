# Benchmark — vuln-scanner-agent vs 8 tools

**Date:** 2026-06-26 14:06 UTC  

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

## pygoat

> PyGoat — intentionally insecure Django app (OWASP)  
> Ecosystems: `pip`

### Dependency / CVE scanners

| Tool | Total | CRITICAL | HIGH | MEDIUM | LOW | Time |
|------|------:|:--------:|:----:|:------:|:---:|-----:|
| **vuln-scanner-agent** | 223 | 9 | 58 | 141 | 15 | 13.6s |
| osv-scanner | 167 | 7 | 34 | 44 | 14 | 1.8s |
| grype | 135 | 9 | 42 | 68 | 16 | 62.6s |
| trivy fs | 135 | 9 | 42 | 68 | 16 | 28.0s |
| safety ¹ | 113 | 0 | 0 | 0 | 0 | 8.7s |
| pip-audit ¹ | 0 | 0 | 0 | 0 | 0 | 16.0s |
| npm audit | — | — | — | — | — | _no package.json_ |
| retire | — | — | — | — | — | _no package.json_ |

### SAST scanners

| Tool | Total | HIGH | MEDIUM | LOW | Time |
|------|------:|:----:|:------:|:---:|-----:|
| bandit (SAST) | 65 | 6 | 15 | 44 | 0.5s |

> ¹ **safety:** safety doesn't report severity (uses own ID system)
> ¹ **pip-audit:** pip-audit doesn't report severity
> ¹ **bandit (SAST):** SAST only — code patterns, not CVEs

## juice-shop

> OWASP Juice Shop — intentionally insecure Node.js e-commerce app  
> Ecosystems: `npm`

### Dependency / CVE scanners

| Tool | Total | CRITICAL | HIGH | MEDIUM | LOW | Time |
|------|------:|:--------:|:----:|:------:|:---:|-----:|
| **vuln-scanner-agent** | 106 | 3 | 45 | 56 | 2 | 39.9s |
| osv-scanner | 65 | 5 | 33 | 24 | 3 | 4.9s |
| grype | 62 | 5 | 32 | 23 | 2 | 2.2s |
| trivy fs | 67 | 5 | 35 | 23 | 4 | 0.2s |
| safety | — | — | — | — | — | _no requirements.txt_ |
| pip-audit | — | — | — | — | — | _no requirements.txt_ |
| npm audit | 45 | 5 | 22 | 15 | 3 | 1.9s |
| retire | 0 | 0 | 0 | 0 | 0 | 0.7s |

### SAST scanners

| Tool | Total | HIGH | MEDIUM | LOW | Time |
|------|------:|:----:|:------:|:---:|-----:|
| bandit (SAST) | 0 | 0 | 0 | 0 | 0.2s |

> ¹ **bandit (SAST):** SAST only — code patterns, not CVEs
