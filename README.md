# 🛡️ GAMBIT

**GAMBIT** is a defensive black-box attack surface reconnaissance platform designed to
map exposed domains, subdomains, IPs, web technologies and weakly exposed endpoints,
with a strong focus on **signal over noise** and **OPSEC-friendly defaults**.

> Built for defenders. Designed for owned or authorized assets only.

---

## ✨ Key Features

- 🌐 Subdomain discovery (via `subfinder`)
- 🔎 HTTP fingerprinting with structured output (`httpx` JSONL)
- 🎯 Target selection
  - 1 URL per host
  - HTTPS prioritized
  - Useful status codes only
- 🧩 Low-noise Nuclei scanning
  - Exposure & misconfiguration templates
  - CVE templates (medium / high)
  - Fixed rate limits and concurrency controls
- 🧠 Optional local analysis with Ollama
- 🕵️ Tor support (SOCKS5) for controlled egress
- 📦 Streamlit UI for interactive runs and summaries

---

## 🎯 Design Goals

- Reduce scan volume without losing visibility
- Favor deterministic results over brute-force coverage
- Be safe to run repeatedly in defensive environments
- Avoid unnecessary or high-impact checks by default

GAMBIT is **not** a vulnerability scanner meant for aggressive discovery.
It is an **attack surface mapping and prioritization tool**.

---

## 🧪 Typical Use Cases

- Asset inventory and exposure review
- Pre-engagement recon on owned infrastructure
- Blue-team surface monitoring
- Learning and lab environments
- Defensive security research

---

## 🚀 Installation

### Requirements

The following tools must be available in your `$PATH`:

- Python >= 3.9
- streamlit
- subfinder
- httpx
- nuclei
- curl
- (optional) ollama
- (optional) tor

### Python setup (recommended)

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install streamlit
```

---

## ▶️ Usage

```bash
streamlit run gambit.py
```

From the UI you can:
- Select recon modules
- Tune concurrency and limits
- Enable Tor
- Generate structured output
- Review summaries directly in the browser

All results are written to:

```
~/gambit_out/<domain>_<timestamp>/
```

---

## 📂 Output Structure

Typical output directory:

```
subdomains.txt
dns.json
httpx.jsonl
targets.txt
endpoints.txt
nuclei_exposure.jsonl
nuclei_cve.jsonl
ollama_summary.txt
```

Structured formats (JSONL) are intentionally used to allow:
- Post-processing
- Filtering
- Correlation
- Historical comparison

---

## 🔐 OPSEC Notes

- Fixed rate limits and concurrency
- No OOB interactions by default (`-no-interactsh`)
- HEAD requests for lightweight endpoint checks
- Explicit target filtering before deeper scans

You are expected to **understand and control where this tool is run**.

---

## ⚠️ Disclaimer

GAMBIT is intended **only** for defensive security testing on systems you own
or are explicitly authorized to assess.

The author assumes **no responsibility** for misuse.

---

## 🧭 Roadmap

- Tech-aware CVE scanning (per detected stack)
- Result caching and diffing
- Exportable consolidated reports
- Modular engine refactor

---

## 📌 Versioning

This project follows **semantic versioning**.

Current release:
- **v0.2.0** – Low-noise recon pipeline

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
