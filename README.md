# 🛡️ VaultScan

**A multi-tenant web security scanning platform** — OSINT reconnaissance, 37 vulnerability detection modules, a local-AI security analyst, OWASP/CWE classification, continuous monitoring, and domain-ownership verification.

Built as a portfolio project to demonstrate full-stack engineering, security tooling, and SaaS architecture.

> ⚠️ **Authorized use only.** VaultScan enforces **domain-ownership verification** — you can only scan domains you've proven you control (via DNS TXT or a `.well-known` file). Active/aggressive testing requires an explicit opt-in. Never scan systems you don't own or aren't authorized to test.

---

## ✨ Features

### 🔍 37 detection modules across 4 phases
- **Recon** — async crawler mapping URLs, parameters and forms
- **OSINT** — WHOIS, DNS (AXFR, CAA, DNSSEC, SPF/DMARC), SSL/TLS versions & ciphers, subdomain enumeration (CT logs + brute, wildcard-aware), tech fingerprinting, email harvesting
- **Scanner** — security headers, cookies, ports (DB/service exposure), subdomain takeover, CMS + version (WP user-enum/xmlrpc), WAF, HTTP methods, CSRF, clickjacking (+PoC), GraphQL introspection, outdated JS libraries (retire.js-style), JWT analysis, directory & sensitive-file discovery (soft-404 guarded), robots/sitemap, CORS, open redirect, JS secrets
- **Intelligence** — software-version → known-CVE matching
- **Active (opt-in, Pro)** — reflected XSS, error-based SQLi, LFI/path traversal, SSRF (cloud-metadata), CRLF, host-header injection, IDOR, default credentials

### 🤖 AI Security Analyst — runs locally, free, private
A local LLM (via [Ollama](https://ollama.com)) turns raw findings into an **executive summary, prioritized risks, and a remediation plan**, plus a chat to ask questions about the scan. No API key, no cost, and **your audit data never leaves the machine**.

### 🏆 Professional reporting
- Every finding mapped to **OWASP Top 10 (2021)** + **CWE** with a **confidence level** (Confirmed / Probable / Possible)
- **CVSS** per finding + a **risk score (0–100) and A–F grade**
- **Print-ready PDF report** + JSON / CSV export
- Scan-to-scan **diff** (what changed since last time)

### 📡 Continuous monitoring
Schedule recurring scans (hourly/daily/weekly) and get **alerts** when a new finding appears or the risk score rises.

### 🔐 SaaS-ready
Multi-tenant accounts (JWT auth), per-user data isolation, **domain-ownership verification** (the legal gate), and **Free / Pro plans** with enforced limits.

---

## 🚀 Quick start

### Option A — Docker (one command)
```bash
git clone <your-repo-url> vaultscan && cd vaultscan
docker compose up --build
# then pull the AI model (one-off):
docker compose exec ollama ollama pull llama3.1:8b
```
Open **http://localhost:8080** — register an account and add a domain to verify.

### Option B — Local (macOS / Linux)
```bash
bash start.sh          # creates a venv, installs deps, runs the server
# AI Analyst (optional): brew install --cask ollama-app && ollama serve && ollama pull llama3.1:8b
```

Default admin (first run, change it): `admin@vaultscan.local` / `changeme123`.

---

## 🏗️ Architecture

```
Frontend (vanilla JS, dark UI)         Backend (FastAPI)
  ├─ login / dashboard / scan            ├─ JWT auth + multi-tenancy
  ├─ domains (ownership verify)          ├─ ScanContext → 37 modules (engine.py)
  ├─ monitoring (schedules/alerts)       ├─ background scheduler (asyncio)
  └─ account (plans)                     ├─ taxonomy: OWASP + CWE + confidence
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
| Auth | JWT (python-jose) + pbkdf2_sha256 (passlib) |
| Deploy | Docker + docker-compose |

---

## 🔒 Responsible use

VaultScan is a defensive/authorized-testing tool. It will **refuse to scan a domain you haven't verified you own**, and active exploitation modules are off by default. You are responsible for having written authorization before testing any system. Unauthorized scanning may be illegal in your jurisdiction.

---

## 📄 License

MIT — see `LICENSE`. Built by a DAW student as a cybersecurity portfolio project.
