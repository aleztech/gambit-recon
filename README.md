# 🛡️ GAMBIT

GAMBIT is an operator-first attack surface reconnaissance framework designed for
professional red teams and defensive security practitioners.

It maps exposed domains, subdomains, IPs, infrastructure posture, web technologies and
low-hanging exposures, with a strict focus on signal over noise and explicit operator control.

Built for defenders. Designed for owned or explicitly authorized assets only.

By default, GAMBIT runs in a passive-first, low-impact mode.
Active vulnerability scanning is disabled by default and must be explicitly enabled
and confirmed by the operator.

---

## ✨ Key Features

### Passive & Infrastructure Recon
- Subdomain discovery (subfinder)
- DNS resolution (A / AAAA)
- DNS posture analysis:
  - NS, MX, SPF, DMARC, CAA
  - DNSSEC detection
  - Wildcard DNS detection
  - Provider / cloud inference
- Reverse DNS (PTR) on discovered IPs
- TLS certificate reconnaissance (SANs, issuer, validity)

### Low-Impact Web Recon
- HTTP fingerprinting with structured output (httpx JSONL)
- Deterministic target selection
  - One URL per host
  - HTTPS prioritized
  - Operator-defined status codes only
- Lightweight endpoint checks (HEAD requests only)
- Technology and server identification

### Optional Active Checks
- Nuclei scanning (explicit opt-in only)
  - Exposure & misconfiguration profiles
  - CVE profiles (medium / high)
  - Fixed rate limits and concurrency budgets
  - No OOB interactions by default (-no-interactsh)

### Operator Experience
- Streamlit-based operator UI
- All parameters configurable before execution
- Visual summaries, tables and charts
- Optional local analysis with Ollama (offline)
- Optional Tor SOCKS5 support for controlled egress
- Structured outputs for post-processing and diffing

---

## 🎯 Design Philosophy

- Minimize noise
- Maximize actionable signal
- Deterministic and repeatable results
- Explicit scope, budget and intent
- Safe defaults, operator-controlled escalation

GAMBIT is not a brute-force vulnerability scanner.
It is an attack surface mapping, posture analysis and prioritization framework.

---

## 🧪 Typical Use Cases

- Asset inventory and exposure review
- Pre-engagement reconnaissance on owned infrastructure
- Red team surface preparation and prioritization
- Blue team posture monitoring
- Purple team analysis
- Security labs and learning environments

---

## 🚀 Installation

### Requirements

The following tools should be available in your PATH (depending on enabled modules):

- Python 3.9 or newer
- streamlit
- subfinder
- httpx
- curl
- dnsutils (dig)
- openssl

Optional:
- nuclei
- ollama
- tor

### Python setup (recommended)

    python3 -m venv .venv
    source .venv/bin/activate
    pip install streamlit pandas plotly

---

## ▶️ Usage

    streamlit run gambit.py

From the UI you can:
- Select recon modules
- Tune budgets (scope, concurrency, rate limits)
- Enable Tor (SOCKS5)
- Enable optional active checks (Nuclei) with explicit confirmation
- Review summaries directly in the browser

All results are written to:

    ~/gambit_out/<domain>_<timestamp>/

---

## 📂 Output Structure

    run_config.json
    subdomains.txt
    dns.json
    dns_posture.json
    rdns.json
    tls_certs.json
    httpx.jsonl
    targets.txt
    endpoints.txt
    nuclei_exposure.jsonl
    nuclei_cve.jsonl
    ollama_summary.txt

Structured formats (JSON / JSONL) are intentionally used to allow:
- Filtering
- Correlation
- Automation
- Historical comparison and diffing

---

## 🔐 OPSEC Notes

- Passive-first execution by default
- Deterministic budgets (scope and concurrency limits)
- HEAD requests for lightweight endpoint checks
- No OOB interactions by default
- Explicit target filtering before optional active scans

The operator is responsible for scope, authorization and intent.

---

## ⚠️ Disclaimer

GAMBIT is intended only for defensive security testing on systems you own
or are explicitly authorized to assess.

The author assumes no responsibility for misuse.

---

## 🧭 Roadmap

- Tech-aware CVE scanning per detected stack
- Result caching and historical diffing
- Exportable consolidated reports
- Modular engine refactor

---

## 📌 Versioning

This project follows semantic versioning.

Current release:
- v1.0.0 – Operator-first recon framework

---

## 🤝 License

Copyright (c) 2026 aleztech

All rights reserved.

Permission is hereby granted to view, fork, and modify this source code
for personal, educational, or non-commercial purposes only.

Commercial use is strictly prohibited.

Commercial use includes, but is not limited to:
- Selling this software or derivatives
- Using this software as part of a paid product or service
- Offering paid security services, assessments, or consulting
  based on this software

Redistribution of modified versions must retain this license
and must not be for commercial purposes.

This software is provided "as is", without warranty of any kind.
