# 🛡️ VaultScan

**A web security scanning platform** — OSINT reconnaissance, 37 vulnerability detection modules, a local-AI security analyst, OWASP/CWE classification, and continuous monitoring.

Built as a portfolio project to demonstrate full-stack engineering and security tooling.

> ⚠️ **Authorized use only.** Active/aggressive testing sends real attack payloads. Only scan systems you own or have explicit written permission to test. Unauthorized scanning may be illegal.

---

## ✨ Features

### 🔍 37 detection modules across 4 phases
- **Recon** — async crawler mapping URLs, parameters and forms
- **OSINT** — WHOIS, DNS (AXFR, CAA, DNSSEC, SPF/DMARC), SSL/TLS versions & ciphers, subdomain enumeration (CT logs + brute, wildcard-aware), tech fingerprinting, email harvesting
- **Scanner** — security headers, cookies, ports (DB/service exposure), subdomain takeover, CMS + version (WP user-enum/xmlrpc), WAF, HTTP methods, CSRF, clickjacking (+PoC), GraphQL introspection, outdated JS libraries (retire.js-style), JWT analysis, directory & sensitive-file discovery (soft-404 guarded), robots/sitemap, CORS, open redirect, JS secrets
- **Intelligence** — software-version → known-CVE matching
- **Active (opt-in, aggressive mode)** — reflected XSS, error-based SQLi, LFI/path traversal, SSRF (cloud-metadata), CRLF, host-header injection, IDOR, default credentials

### 🤖 AI Security Analyst — runs locally, free, private
A local LLM (via [Ollama](https://ollama.com)) turns raw findings into an **executive summary, prioritized risks, and a remediation plan**, plus a chat to ask questions about the scan. No API key, no cost, and **your audit data never leaves the machine**.

### 🏆 Professional reporting
- Every finding mapped to **OWASP Top 10 (2021)** + **CWE** with a **confidence level** (Confirmed / Probable / Possible)
- **CVSS** per finding + a **risk score (0–100) and A–F grade**
- **Print-ready PDF report** + JSON / CSV export
- Scan-to-scan **diff** (what changed since last time)

### 📡 Continuous monitoring
Schedule recurring scans (hourly/daily/weekly) and get **alerts** when a new finding appears or the risk score rises.

### 🛡️ Safe vs Aggressive modes
**Safe** runs passive recon + intelligence only. **Aggressive** adds active injection tests (XSS, SQLi, SSRF…) — off by default, with an authorization warning.

---

## 🚀 Quick start

### Option A — Docker (one command)
```bash
git clone <your-repo-url> vaultscan && cd vaultscan
docker compose up --build
# then pull the AI model (one-off):
docker compose exec ollama ollama pull llama3.1:8b
```
Open **http://localhost:8080** and start scanning.

### Option B — Local (macOS / Linux)
```bash
bash start.sh          # creates a venv, installs deps, runs the server
# AI Analyst (optional): brew install --cask ollama-app && ollama serve && ollama pull llama3.1:8b
```

---

## 🏗️ Architecture

```
Frontend (vanilla JS, dark UI)         Backend (FastAPI)
  ├─ dashboard / scan (live)             ├─ ScanContext → 37 modules (engine.py)
  ├─ monitoring (schedules/alerts)       ├─ background scheduler (asyncio)
  └─                                     ├─ taxonomy: OWASP + CWE + confidence
        │  REST + WebSocket + SSE         ├─ AI Analyst → Ollama (SSE stream)
        └──────────────────────────────► └─ SQLite (SQLAlchemy)
```

**Scan flow:** crawler builds a shared `ScanContext` → passive + intelligence modules always run → active modules run only in aggressive mode → findings are enriched (OWASP/CWE/confidence/CVSS), scored, streamed live over WebSocket, and stored.

---

## 🧰 Stack

| Layer | Tech |
|-------|------|
| Backend | Python 3.12, FastAPI, SQLAlchemy, httpx, dnspython, BeautifulSoup |
| Realtime | WebSocket (live scan), Server-Sent Events (AI stream) |
| AI | Ollama (local LLM, `llama3.1:8b`) |
| Frontend | Vanilla JS, custom CSS (no framework), marked.js |
| Deploy | Docker + docker-compose |

---

## 🔒 Responsible use

VaultScan is a defensive/authorized-testing tool. Active exploitation modules are off by default (Safe mode). You are responsible for having written authorization before testing any system. Unauthorized scanning may be illegal in your jurisdiction.

---

## 📄 License

MIT — see `LICENSE`. Built by a DAW student as a cybersecurity portfolio project.
