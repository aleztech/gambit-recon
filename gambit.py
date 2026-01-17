#!/usr/bin/env python3
# ==========================================
#  GAMBIT – Attack Surface Recon (Operator UI)
# ==========================================
# - Everything configurable from the web UI BEFORE run
# - Clean sidebar (tabs + expanders + conditional controls)
# - Passive posture (DNS/rDNS/TLS) + Low-impact web (httpx + HEAD endpoints)
# - Optional active checks (Nuclei) behind explicit opt-in
# - Pro UI: header cards, progress, live log panel, filters, downloads, charts
#
# System tools (depending on modules):
#   subfinder, httpx, curl, dig (dnsutils), openssl, nuclei (optional), ollama (optional)
#
# Optional python deps for charts/tables:
#   pip install pandas plotly
# ==========================================

import os
import re
import json
import shutil
import socket
import subprocess
from datetime import datetime
from pathlib import Path
from urllib.parse import urlparse

import streamlit as st

# Optional deps
try:
    import pandas as pd  # type: ignore
except Exception:
    pd = None  # type: ignore

try:
    import plotly.express as px  # type: ignore
except Exception:
    px = None  # type: ignore


# ==========================================
# Utils
# ==========================================
def which(cmd: str):
    return shutil.which(cmd)


def run(cmd, timeout=180, env=None):
    try:
        p = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            env=env or os.environ.copy(),
        )
        return p.returncode, (p.stdout or "").strip(), (p.stderr or "").strip()
    except subprocess.TimeoutExpired:
        return 124, "", "TIMEOUT"
    except Exception as e:
        return 1, "", str(e)


def safe_write(path: Path, data: str):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(data or "", encoding="utf-8", errors="ignore")


def sanitize_domain(d: str) -> str:
    d = (d or "").strip().lower()
    d = re.sub(r"^https?://", "", d)
    d = d.split("/")[0]
    if not re.match(r"^[a-z0-9.-]+\.[a-z]{2,}$", d):
        raise ValueError("Dominio no válido (ej: example.com)")
    return d


def uniq(items):
    return sorted(set([i.strip() for i in items if i and i.strip()]))


def resolve_dns(host: str):
    res = {"host": host, "A": [], "AAAA": []}
    try:
        for fam in (socket.AF_INET, socket.AF_INET6):
            try:
                infos = socket.getaddrinfo(host, None, fam)
                ips = sorted(set([i[4][0] for i in infos]))
                if fam == socket.AF_INET:
                    res["A"] = ips
                else:
                    res["AAAA"] = ips
            except Exception:
                pass
    except Exception:
        pass
    return res


def check_ip(mode: str):
    if mode == "direct":
        return run(["bash", "-lc", "curl -s https://check.torproject.org/api/ip"], 20)
    if mode == "tor":
        return run(
            [
                "bash",
                "-lc",
                "curl -s --socks5-hostname 127.0.0.1:9050 https://check.torproject.org/api/ip",
            ],
            25,
        )
    return 1, "", "invalid mode"


def parse_httpx_jsonl(httpx_jsonl_path: Path):
    rows = []
    if not httpx_jsonl_path.exists():
        return rows
    for line in httpx_jsonl_path.read_text(encoding="utf-8", errors="ignore").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            rows.append(json.loads(line))
        except Exception:
            continue
    return rows


def host_from_url(u: str) -> str:
    try:
        p = urlparse(u)
        return (p.netloc or "").lower()
    except Exception:
        return re.sub(r"^https?://", "", u).split("/")[0].lower()


def pick_targets_from_httpx(rows, allowed_status, max_hosts, prefer_https=True):
    """
    1 URL por host. Filtra por status y prioriza HTTPS si existe.
    """
    best = {}
    for r in rows:
        url = (r.get("url") or "").strip()
        if not url:
            continue

        sc = r.get("status_code")
        try:
            sc = int(sc)
        except Exception:
            continue
        if sc not in allowed_status:
            continue

        host = host_from_url(url)
        if not host:
            continue

        scheme = "https" if url.lower().startswith("https://") else "http"

        status_score = 0
        if 200 <= sc <= 299:
            status_score = 3
        elif 300 <= sc <= 399:
            status_score = 2
        elif sc in (401, 403):
            status_score = 1

        scheme_score = 1 if (prefer_https and scheme == "https") else 0
        score = (scheme_score, status_score)

        if host not in best or score > best[host]["score"]:
            best[host] = {"url": url, "score": score, "row": r}

    hosts = sorted(best.keys())
    targets = []
    picked_rows = []
    for h in hosts[:max_hosts]:
        targets.append(best[h]["url"])
        picked_rows.append(best[h]["row"])
    return targets, picked_rows


def summarize_nuclei_jsonl(jsonl_path: Path, max_samples=30):
    if not jsonl_path.exists() or jsonl_path.stat().st_size == 0:
        return {"total": 0, "by_sev": {}, "samples": []}

    by_sev = {}
    samples = []
    total = 0

    for line in jsonl_path.read_text(encoding="utf-8", errors="ignore").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except Exception:
            continue

        total += 1
        info = obj.get("info") or {}
        sev = info.get("severity", "unknown")
        by_sev[sev] = by_sev.get(sev, 0) + 1

        if len(samples) < max_samples:
            tmpl = obj.get("templateID") or obj.get("template-id") or "template"
            name = info.get("name", "")
            matched = obj.get("matched-at") or obj.get("matched_at") or obj.get("host") or ""
            samples.append(f"[{sev}] {tmpl} :: {name} :: {matched}")

    return {"total": total, "by_sev": dict(sorted(by_sev.items())), "samples": samples}


# ==========================================
# Passive posture helpers (DNS/rDNS/TLS)
# ==========================================
def dig(name: str, rr: str, timeout=5):
    cmd = f"dig +time={timeout} +tries=1 +short {rr} {name}"
    rc, out, err = run(["bash", "-lc", cmd], timeout=timeout + 2)
    return [l.strip() for l in out.splitlines() if l.strip()]


def rdns(ip: str, timeout=5):
    cmd = f"dig +time={timeout} +tries=1 +short -x {ip}"
    rc, out, err = run(["bash", "-lc", cmd], timeout=timeout + 2)
    return [l.strip() for l in out.splitlines() if l.strip()]


def is_dnssec_enabled(domain: str) -> bool:
    return len(dig(domain, "DNSKEY")) > 0


def parse_spf(txt_records):
    for t in txt_records:
        if "v=spf1" in t.lower():
            return t
    return ""


def parse_dmarc(txt_records):
    for t in txt_records:
        if "v=dmarc1" in t.lower():
            return t
    return ""


def wildcard_dns(domain: str) -> dict:
    import random
    import string

    r = "".join(random.choice(string.ascii_lowercase) for _ in range(16))
    test = f"{r}.{domain}"
    a = dig(test, "A")
    aaaa = dig(test, "AAAA")
    return {"test": test, "A": a, "AAAA": aaaa, "wildcard": bool(a or aaaa)}


def infer_provider_from_token(token: str) -> str:
    c = (token or "").lower()
    # CDN / edge
    if "cloudflare" in c or c.endswith(".cdn.cloudflare.net.") or "cf-" in c:
        return "Cloudflare"
    if "cloudfront" in c:
        return "AWS CloudFront"
    if "fastly" in c:
        return "Fastly"
    if "akamai" in c or "akamaiedge" in c or "edgesuite" in c:
        return "Akamai"
    if "azurefd" in c or "azureedge" in c or "trafficmanager" in c or "frontdoor" in c:
        return "Azure"
    if "google" in c or "googlehosted" in c or "goog" in c:
        return "Google"
    if "amazonaws" in c:
        return "AWS"
    # Email providers (via MX hints)
    if "protection.outlook.com" in c or "mail.protection.outlook.com" in c:
        return "Microsoft 365"
    if "google.com" in c or "googlemail.com" in c:
        return "Google Workspace"
    return ""


def tls_cert_brief(host: str, timeout=8) -> dict:
    cmd = (
        f"echo | openssl s_client -servername {host} -connect {host}:443 "
        f"-showcerts 2>/dev/null | openssl x509 -noout -subject -issuer -dates -ext subjectAltName 2>/dev/null"
    )
    rc, out, err = run(["bash", "-lc", cmd], timeout=timeout)
    if rc != 0 or not out:
        return {}
    info = {"host": host}
    for line in out.splitlines():
        line = line.strip()
        if line.startswith("subject="):
            info["subject"] = line
        elif line.startswith("issuer="):
            info["issuer"] = line
        elif line.startswith("notBefore="):
            info["notBefore"] = line.replace("notBefore=", "")
        elif line.startswith("notAfter="):
            info["notAfter"] = line.replace("notAfter=", "")
        elif "DNS:" in line:
            info["SAN"] = line
    return info


# ==========================================
# UI helpers
# ==========================================
def parse_list_textarea(text: str):
    items = []
    for line in (text or "").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        items.append(line)
    return items


def parse_headers_textarea(text: str):
    headers = []
    for line in parse_list_textarea(text):
        if ":" in line:
            headers.append(line)
    return headers


def httpx_to_rows(rows):
    out = []
    for r in rows:
        url = (r.get("url") or "").strip()
        if not url:
            continue
        tech = r.get("tech")
        if isinstance(tech, list):
            tech_str = ", ".join(tech[:12])
        else:
            tech_str = tech or ""
        out.append(
            {
                "host": host_from_url(url),
                "url": url,
                "status_code": r.get("status_code"),
                "title": r.get("title"),
                "webserver": r.get("webserver") or r.get("server"),
                "tech": tech_str,
                "ip": r.get("ip"),
            }
        )
    return out


def nuclei_jsonl_to_rows(path: Path, profile: str):
    rows = []
    if not path.exists() or path.stat().st_size == 0:
        return rows
    for line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except Exception:
            continue
        info = obj.get("info") or {}
        rows.append(
            {
                "profile": profile,
                "severity": info.get("severity", "unknown"),
                "template": obj.get("templateID") or obj.get("template-id") or "unknown",
                "name": info.get("name", ""),
                "matched": obj.get("matched-at") or obj.get("matched_at") or obj.get("host") or "",
            }
        )
    return rows


def ui_css():
    st.markdown(
        """
<style>
:root { --card:#0f172a; --border:#243047; --muted:#94a3b8; }
.card { padding:14px; border-radius:16px; border:1px solid var(--border); background:var(--card); }
.badge { display:inline-block; padding:4px 10px; border-radius:999px; font-size:12px; margin-right:6px; border:1px solid #334155; }
.b1 { background:#111827; color:#e5e7eb; }
.b2 { background:#1f2937; color:#a78bfa; }
.small { opacity:.9; font-size:13px; color:var(--muted); }
.kv { display:flex; gap:10px; flex-wrap:wrap; }
.kv > div { padding:8px 10px; border-radius:12px; border:1px solid var(--border); background:#0b1220; }
.hr { height:1px; background:#1f2a44; margin:12px 0; }
</style>
""",
        unsafe_allow_html=True,
    )


def pill(text: str, level: str = "info"):
    colors = {
        "info": ("#0b1220", "#93c5fd"),
        "warn": ("#201a0b", "#fbbf24"),
        "bad": ("#220b12", "#fb7185"),
        "ok": ("#0b1f14", "#34d399"),
    }
    bg, fg = colors.get(level, colors["info"])
    return f"<span class='badge' style='background:{bg}; color:{fg};'>{text}</span>"


# ==========================================
# Streamlit page
# ==========================================
st.set_page_config(page_title="GAMBIT Recon", layout="wide", initial_sidebar_state="expanded")
ui_css()

st.title("GAMBIT – Attack Surface Recon")
st.caption("Operator-first UI · Passive posture + low-impact web · Optional active checks")

tab_overview, tab_targets, tab_findings, tab_raw = st.tabs(["Overview", "Targets", "Findings", "Raw output"])

# ==========================================
# Sidebar: all knobs BEFORE run
# ==========================================
with st.sidebar:
    st.header("Configuration")

    sb_tabs = st.tabs(["Run", "Modules", "Budgets", "Advanced"])

    with sb_tabs[0]:
        domain_in = st.text_input("Target domain", placeholder="example.com")
        out_dir_base = st.text_input("Output directory", value=str(Path.home() / "gambit_out"))

        use_tor = st.checkbox("Use Tor SOCKS5 (127.0.0.1:9050)", value=False)
        use_ollama = st.checkbox("Ollama summary (if available)", value=False)

        st.caption("HTTP identity (optional)")
        http_user_agent = st.text_input("User-Agent", value="")
        http_headers_raw = st.text_area(
            "Extra headers (one per line: Header: value)",
            value="",
            height=90,
        )

    with sb_tabs[1]:
        st.subheader("Passive posture")
        m_subs = st.checkbox("Subdomains (subfinder)", True)
        m_dns_resolve = st.checkbox("DNS resolve (A/AAAA)", True)
        m_dns_posture = st.checkbox("DNS posture (NS/MX/SPF/DMARC/CAA/DNSSEC/Wildcard)", True)
        m_rdns = st.checkbox("Reverse DNS (IPs discovered)", True)
        m_tls = st.checkbox("TLS cert recon (443 handshake)", False)

        st.divider()
        st.subheader("Low-impact web")
        m_httpx = st.checkbox("HTTP fingerprint (httpx JSONL)", True)
        m_endpoints = st.checkbox("Common endpoints (HEAD)", True)

        st.divider()
        st.subheader("Active (explicit opt-in)")
        enable_nuclei = st.checkbox("Enable Nuclei", value=False)
        confirm_nuclei = False
        if enable_nuclei:
            confirm_nuclei = st.checkbox("I confirm I am authorized to actively test these targets", value=False)
        run_nuclei = bool(enable_nuclei and confirm_nuclei)

    with sb_tabs[2]:
        st.subheader("Selection / scope controls")
        allowed_status = st.multiselect(
            "HTTP status codes allowed for follow-up",
            options=[200, 301, 302, 401, 403],
            default=[200, 301, 302, 401, 403],
        )
        prefer_https = st.checkbox("Prefer HTTPS when available", value=True)
        max_hosts = st.slider("Max selected targets (1 URL/host)", 5, 400, 80, 5)

        st.divider()
        st.subheader("Passive limits")
        max_rdns_ips = st.slider("Max IPs for rDNS", 0, 1000, 200, 50)
        max_tls_hosts = st.slider("Max hosts for TLS cert recon", 0, 400, 50, 10)

        st.divider()
        st.subheader("Endpoints budget")
        endpoints_per_host = st.slider("Max endpoints per host", 0, 30, 5, 1)

    with sb_tabs[3]:
        st.subheader("HTTPX advanced")
        threads = st.slider("httpx threads", 5, 200, 50, 5)
        httpx_timeout = st.slider("httpx timeout (s)", 2, 30, 8, 1)
        httpx_retries = st.slider("httpx retries", 0, 3, 1, 1)
        httpx_follow_redirects = st.checkbox("Follow redirects", value=True)
        httpx_tech_detect = st.checkbox("Tech detect", value=True)
        httpx_title = st.checkbox("Fetch title", value=True)
        httpx_store_ip = st.checkbox("Include IP", value=True)
        httpx_method = st.selectbox("httpx method", ["GET", "HEAD"], index=0)

        st.divider()
        st.subheader("Endpoints list")
        endpoints_default = "\n".join(
            [
                "/robots.txt",
                "/sitemap.xml",
                "/.env",
                "/.git/HEAD",
                "/wp-login.php",
            ]
        )
        endpoints_text = st.text_area(
            "Paths (one per line). Keep small for low-impact.",
            value=endpoints_default,
            height=140,
            disabled=not m_endpoints,
        )

        st.divider()
        st.subheader("Nuclei controls")
        if run_nuclei:
            nuclei_run_exposure = st.checkbox("Run profile: exposure/misconfig", value=True)
            nuclei_run_cve = st.checkbox("Run profile: CVE (more traffic)", value=False)

            nuclei_tags_exposure = st.text_input("Tags (exposure)", value="exposure,misconfig")
            nuclei_sev_exposure = st.text_input("Severities (exposure)", value="info,low,medium")

            nuclei_tags_cve = st.text_input("Tags (CVE)", value="cve")
            nuclei_sev_cve = st.text_input("Severities (CVE)", value="medium,high")

            nuclei_jsonl = st.checkbox("JSONL output", value=True)
            nuclei_silent = st.checkbox("Silent output", value=True)
            nuclei_no_interactsh = st.checkbox("Disable interactsh", value=True)

            nuclei_timeout = st.slider("Timeout (s)", 3, 30, 6, 1)
            nuclei_retries = st.slider("Retries", 0, 3, 1, 1)
            nuclei_max_host_error = st.slider("Max host errors", 1, 50, 10, 1)

            st.caption("Load tuning (direct vs Tor)")
            nuclei_conc_direct = st.slider("Concurrency (direct)", 1, 80, 10, 1)
            nuclei_ratelimit_direct = st.slider("Rate-limit req/s (direct)", 1, 400, 25, 1)
            nuclei_conc_tor = st.slider("Concurrency (Tor)", 1, 30, 5, 1)
            nuclei_ratelimit_tor = st.slider("Rate-limit req/s (Tor)", 1, 80, 10, 1)
        else:
            # Defaults if not armed (keeps code simpler)
            nuclei_run_exposure = True
            nuclei_run_cve = False
            nuclei_tags_exposure = "exposure,misconfig"
            nuclei_sev_exposure = "info,low,medium"
            nuclei_tags_cve = "cve"
            nuclei_sev_cve = "medium,high"
            nuclei_jsonl = True
            nuclei_silent = True
            nuclei_no_interactsh = True
            nuclei_timeout = 6
            nuclei_retries = 1
            nuclei_max_host_error = 10
            nuclei_conc_direct = 10
            nuclei_ratelimit_direct = 25
            nuclei_conc_tor = 5
            nuclei_ratelimit_tor = 10

    st.divider()
    run_btn = st.button("▶ Run GAMBIT", type="primary")


# ==========================================
# Pre-run screen
# ==========================================
if not run_btn:
    with tab_overview:
        st.markdown(
            """
<div class="card">
  <div class="small">Set your configuration in the sidebar and click <b>Run</b>.</div>
  <div class="hr"></div>
  <div class="kv">
    <div><b>Charts</b><br><span class="small">pip install pandas plotly</span></div>
    <div><b>DNS tools</b><br><span class="small">sudo apt install dnsutils openssl</span></div>
    <div><b>Web tools</b><br><span class="small">subfinder / httpx / curl</span></div>
  </div>
</div>
""",
            unsafe_allow_html=True,
        )
    st.stop()


# ==========================================
# Live execution UI (progress + log)
# ==========================================
log_box = st.empty()
progress = st.progress(0, text="Ready")
try:
    status_box = st.status("Running pipeline…", expanded=True)  # Streamlit newer versions
    status_supported = True
except Exception:
    status_supported = False
    status_box = None


logs = []


def add_log(msg: str):
    logs.append(msg)
    log_box.code("\n".join(logs[-120:]))


def set_progress(p: float, text: str):
    p = max(0.0, min(1.0, p))
    progress.progress(int(p * 100), text=text)


# ==========================================
# Validate domain
# ==========================================
try:
    domain = sanitize_domain(domain_in)
except Exception as e:
    st.error(str(e))
    st.stop()

# Determine mode (informational)
mode = "PASSIVE"
if m_httpx or m_endpoints or m_tls:
    mode = "LOW-IMPACT"
if enable_nuclei and confirm_nuclei:
    mode = "ACTIVE"

# Output directory
ts = datetime.now().strftime("%Y%m%d_%H%M%S")
out_dir = Path(out_dir_base) / f"{domain}_{ts}"
out_dir.mkdir(parents=True, exist_ok=True)

# Tools sanity
tools = {
    "subfinder": which("subfinder") or "NO",
    "httpx": which("httpx") or "NO",
    "nuclei": which("nuclei") or "NO",
    "ollama": which("ollama") or "NO",
    "dig": which("dig") or "NO",
    "openssl": which("openssl") or "NO",
    "curl": which("curl") or "NO",
}

# Egress
set_progress(0.02, "Checking egress…")
add_log("[egress] checking direct IP")
_, ip_direct, _ = check_ip("direct")
ip_tor = None
if use_tor:
    add_log("[egress] checking tor IP")
    _, ip_tor, _ = check_ip("tor")

# Save run config
run_config = {
    "domain": domain,
    "timestamp": ts,
    "mode": mode,
    "use_tor": use_tor,
    "modules": {
        "subfinder": m_subs,
        "dns_resolve": m_dns_resolve,
        "dns_posture": m_dns_posture,
        "rdns": m_rdns,
        "tls": m_tls,
        "httpx": m_httpx,
        "endpoints": m_endpoints,
        "nuclei_enabled": bool(enable_nuclei),
        "nuclei_armed": bool(confirm_nuclei),
        "nuclei_profile_exposure": bool(run_nuclei and nuclei_run_exposure),
        "nuclei_profile_cve": bool(run_nuclei and nuclei_run_cve),
    },
    "budgets": {
        "allowed_status": allowed_status,
        "prefer_https": prefer_https,
        "max_hosts": max_hosts,
        "max_rdns_ips": max_rdns_ips,
        "max_tls_hosts": max_tls_hosts,
        "endpoints_per_host": endpoints_per_host,
    },
    "http_identity": {
        "user_agent": http_user_agent,
        "headers": parse_headers_textarea(http_headers_raw),
    },
    "httpx": {
        "threads": threads,
        "timeout": httpx_timeout,
        "retries": httpx_retries,
        "follow_redirects": httpx_follow_redirects,
        "tech_detect": httpx_tech_detect,
        "title": httpx_title,
        "ip": httpx_store_ip,
        "method": httpx_method,
    },
    "endpoints": {"paths": parse_list_textarea(endpoints_text)},
    "nuclei": {
        "run": bool(run_nuclei),
        "profile_exposure": bool(nuclei_run_exposure),
        "profile_cve": bool(nuclei_run_cve),
        "tags_exposure": nuclei_tags_exposure,
        "sev_exposure": nuclei_sev_exposure,
        "tags_cve": nuclei_tags_cve,
        "sev_cve": nuclei_sev_cve,
        "jsonl": bool(nuclei_jsonl),
        "silent": bool(nuclei_silent),
        "no_interactsh": bool(nuclei_no_interactsh),
        "timeout": nuclei_timeout,
        "retries": nuclei_retries,
        "max_host_error": nuclei_max_host_error,
        "conc_direct": nuclei_conc_direct,
        "rlimit_direct": nuclei_ratelimit_direct,
        "conc_tor": nuclei_conc_tor,
        "rlimit_tor": nuclei_ratelimit_tor,
    },
    "tools": tools,
    "egress": {"direct": ip_direct, "tor": ip_tor},
}
safe_write(out_dir / "run_config.json", json.dumps(run_config, indent=2))

# Header card
with tab_overview:
    st.markdown(
        f"""
<div class="card">
  <div>
    <span class="badge b2">GAMBIT</span>
    <span class="badge b1">Mode: {mode}</span>
    <span class="badge b1">Egress: {"Tor" if use_tor else "Direct"}</span>
  </div>
  <div style="margin-top:10px; font-size:20px;"><b>{domain}</b></div>
  <div class="small">Output: {out_dir}</div>
</div>
""",
        unsafe_allow_html=True,
    )
    st.write("Tools:", tools)
    st.write("Direct egress:", ip_direct)
    if use_tor:
        st.write("Tor egress:", ip_tor)

# ==========================================
# Pipeline
# ==========================================
subs = []
resolved = []
dns_posture = {}
rdns_map = {}
ip_set = set()
httpx_rows = []
targets = []
picked_rows = []
endpoints_hits = []
tls_certs = []

# 1) Subdomains
set_progress(0.08, "Subdomains…")
if m_subs:
    add_log("[subfinder] starting")
    if not which("subfinder"):
        add_log("[subfinder] ERROR: not in PATH")
    else:
        rc, out, err = run(["bash", "-lc", f"subfinder -d {domain} -silent"], timeout=240)
        if rc != 0 and err:
            add_log("[subfinder] WARN: " + err[:160])
        subs = uniq(out.splitlines())
        safe_write(out_dir / "subdomains.txt", "\n".join(subs))
        add_log(f"[subfinder] found: {len(subs)}")
else:
    add_log("[subfinder] skipped")

# 2) DNS resolve
set_progress(0.18, "DNS resolve…")
if m_dns_resolve and subs:
    add_log("[dns] resolving A/AAAA for subdomains")
    resolved = [resolve_dns(s) for s in subs]
    safe_write(out_dir / "dns.json", json.dumps(resolved, indent=2))
    for r in resolved:
        for ip in (r.get("A") or []) + (r.get("AAAA") or []):
            ip_set.add(ip)
    add_log(f"[dns] resolved hosts: {len(resolved)} | ips: {len(ip_set)}")
else:
    add_log("[dns] resolve skipped (no subs or module off)")

# 3) DNS posture (apex)
set_progress(0.30, "DNS posture…")
if m_dns_posture:
    if not which("dig"):
        add_log("[dns-posture] ERROR: dig missing (sudo apt install dnsutils)")
    else:
        add_log("[dns-posture] collecting RRsets")
        dns_posture["apex"] = domain
        dns_posture["A"] = dig(domain, "A")
        dns_posture["AAAA"] = dig(domain, "AAAA")
        dns_posture["CNAME"] = dig(domain, "CNAME")
        dns_posture["NS"] = dig(domain, "NS")
        dns_posture["SOA"] = dig(domain, "SOA")
        dns_posture["MX"] = dig(domain, "MX")
        dns_posture["TXT"] = dig(domain, "TXT")
        dns_posture["CAA"] = dig(domain, "CAA")
        dns_posture["DNSSEC"] = is_dnssec_enabled(domain)
        dns_posture["wildcard"] = wildcard_dns(domain)

        dns_posture["SPF"] = parse_spf(dns_posture["TXT"])
        dmarc_txt = dig(f"_dmarc.{domain}", "TXT")
        dns_posture["DMARC"] = parse_dmarc(dmarc_txt)

        provider_hits = []
        for token in (dns_posture.get("CNAME") or []) + (dns_posture.get("NS") or []) + (dns_posture.get("MX") or []):
            p = infer_provider_from_token(token)
            if p:
                provider_hits.append(p)
        dns_posture["provider_guess"] = sorted(set(provider_hits))

        for ip in (dns_posture.get("A") or []) + (dns_posture.get("AAAA") or []):
            ip_set.add(ip)

        safe_write(out_dir / "dns_posture.json", json.dumps(dns_posture, indent=2))
        add_log("[dns-posture] done")
else:
    add_log("[dns-posture] skipped")

# 4) Reverse DNS
set_progress(0.40, "Reverse DNS…")
if m_rdns and ip_set and max_rdns_ips > 0:
    if not which("dig"):
        add_log("[rdns] ERROR: dig missing (sudo apt install dnsutils)")
    else:
        add_log(f"[rdns] resolving PTR for up to {max_rdns_ips} IPs")
        for ip in sorted(ip_set)[:max_rdns_ips]:
            rdns_map[ip] = rdns(ip)
        safe_write(out_dir / "rdns.json", json.dumps(rdns_map, indent=2))
        add_log("[rdns] done")
else:
    add_log("[rdns] skipped")

# 5) HTTPX
set_progress(0.55, "HTTP fingerprint (httpx)…")
if m_httpx and subs:
    if not which("httpx"):
        add_log("[httpx] ERROR: httpx missing in PATH")
    else:
        subs_file = out_dir / "subs.txt"
        safe_write(subs_file, "\n".join(subs))

        proxy = "-proxy socks5://127.0.0.1:9050" if use_tor else ""
        extra_headers = parse_headers_textarea(http_headers_raw)

        # httpx supports repeated -H "k:v"
        headers_flags = " ".join([f"-H {json.dumps(h)}" for h in extra_headers]) if extra_headers else ""
        ua_flag = f"-H {json.dumps('User-Agent: ' + http_user_agent)}" if http_user_agent.strip() else ""

        flags = []
        flags.append("-silent")
        flags.append("-json")
        flags.append(f"-threads {threads}")
        flags.append(f"-timeout {httpx_timeout}")
        if httpx_retries > 0:
            flags.append(f"-retries {httpx_retries}")
        if httpx_follow_redirects:
            flags.append("-follow-redirects")
        if httpx_method.upper() == "HEAD":
            flags.append("-method HEAD")
        if httpx_title:
            flags.append("-title")
        flags.append("-status-code")
        if httpx_tech_detect:
            flags.append("-tech-detect")
        flags.append("-server")
        if httpx_store_ip:
            flags.append("-ip")

        flags_str = " ".join(flags)
        cmd = f"cat {subs_file} | httpx {flags_str} {proxy} {ua_flag} {headers_flags}"

        add_log("[httpx] running")
        rc, out, err = run(["bash", "-lc", cmd], timeout=700)
        safe_write(out_dir / "httpx.jsonl", out + ("\n" if out else ""))
        safe_write(out_dir / "httpx.err.txt", err or "")
        httpx_rows = parse_httpx_jsonl(out_dir / "httpx.jsonl")
        add_log(f"[httpx] rows: {len(httpx_rows)}")
else:
    add_log("[httpx] skipped")

# 6) Targets
set_progress(0.63, "Selecting targets…")
if httpx_rows:
    targets, picked_rows = pick_targets_from_httpx(
        httpx_rows,
        allowed_status=set(int(x) for x in allowed_status),
        max_hosts=max_hosts,
        prefer_https=prefer_https,
    )
    safe_write(out_dir / "targets.txt", "\n".join(targets))
    add_log(f"[targets] selected: {len(targets)} (1 url/host)")
else:
    add_log("[targets] none (httpx disabled or no results)")

# 7) Endpoints HEAD
set_progress(0.73, "Endpoints (HEAD)…")
if m_endpoints and targets and endpoints_per_host > 0:
    if not which("curl"):
        add_log("[endpoints] ERROR: curl missing")
    else:
        paths = parse_list_textarea(endpoints_text)[: max(0, endpoints_per_host)]
        add_log(f"[endpoints] checking {len(paths)} paths/host across {len(targets)} targets")
        for base in targets:
            for p in paths:
                curl_cmd = f"curl -skI -m 6 {base}{p}"
                if use_tor:
                    curl_cmd = f"curl -skI --socks5-hostname 127.0.0.1:9050 -m 8 {base}{p}"

                # headers
                if http_user_agent.strip():
                    curl_cmd += f" -H {json.dumps('User-Agent: ' + http_user_agent)}"
                for h in parse_headers_textarea(http_headers_raw):
                    curl_cmd += f" -H {json.dumps(h)}"

                _, hdrs, _ = run(["bash", "-lc", curl_cmd], timeout=15)
                first = (hdrs.splitlines()[0] if hdrs else "")
                m = re.search(r"\s(\d{3})\s", first)
                code = m.group(1) if m else ""
                if code in ("200", "301", "302", "401", "403"):
                    endpoints_hits.append(f"{base}{p} [{code}]")
        safe_write(out_dir / "endpoints.txt", "\n".join(endpoints_hits))
        add_log(f"[endpoints] hits: {len(endpoints_hits)}")
else:
    add_log("[endpoints] skipped")

# 8) TLS cert recon
set_progress(0.80, "TLS cert recon…")
if m_tls and targets and max_tls_hosts > 0:
    if not which("openssl"):
        add_log("[tls] ERROR: openssl missing (sudo apt install openssl)")
    else:
        add_log(f"[tls] checking up to {max_tls_hosts} hosts")
        for u in targets[: max_tls_hosts]:
            h = host_from_url(u)
            c = tls_cert_brief(h)
            if c:
                tls_certs.append(c)
        safe_write(out_dir / "tls_certs.json", json.dumps(tls_certs, indent=2))
        add_log(f"[tls] certs parsed: {len(tls_certs)}")
else:
    add_log("[tls] skipped")

# 9) Nuclei (optional active)
set_progress(0.90, "Nuclei (optional)…")
nuclei_exposure_path = out_dir / "nuclei_exposure.jsonl"
nuclei_cve_path = out_dir / "nuclei_cve.jsonl"

if run_nuclei and targets:
    if not which("nuclei"):
        add_log("[nuclei] ERROR: nuclei missing in PATH")
    else:
        ufile = out_dir / "targets.txt"
        proxy = "-proxy socks5://127.0.0.1:9050" if use_tor else ""
        conc = nuclei_conc_tor if use_tor else nuclei_conc_direct
        rlimit = nuclei_ratelimit_tor if use_tor else nuclei_ratelimit_direct

        base_flags = []
        if nuclei_silent:
            base_flags.append("-silent")
        if nuclei_no_interactsh:
            base_flags.append("-no-interactsh")
        base_flags.append(f"-timeout {nuclei_timeout}")
        base_flags.append(f"-retries {nuclei_retries}")
        base_flags.append(f"-c {conc}")
        base_flags.append(f"-rate-limit {rlimit}")
        base_flags.append(f"-max-host-error {nuclei_max_host_error}")
        if nuclei_jsonl:
            base_flags.append("-jsonl")
        base_flags.append(proxy)
        base_flags_str = " ".join([f for f in base_flags if f])

        debug_parts = []
        if nuclei_run_exposure:
            add_log("[nuclei] exposure/misconfig profile")
            cmd_a = (
                f"nuclei -l {ufile} "
                f"-tags {nuclei_tags_exposure} "
                f"-severity {nuclei_sev_exposure} "
                f"{base_flags_str} -output {nuclei_exposure_path}"
            )
            rcA, outA, errA = run(["bash", "-lc", cmd_a], timeout=1400)
            debug_parts += ["=== exposure/misconfig ===", outA or "", errA or ""]
        if nuclei_run_cve:
            add_log("[nuclei] cve profile")
            cmd_b = (
                f"nuclei -l {ufile} "
                f"-tags {nuclei_tags_cve} "
                f"-severity {nuclei_sev_cve} "
                f"{base_flags_str} -output {nuclei_cve_path}"
            )
            rcB, outB, errB = run(["bash", "-lc", cmd_b], timeout=1400)
            debug_parts += ["=== cve ===", outB or "", errB or ""]
        safe_write(out_dir / "nuclei_debug.log", "\n".join(debug_parts).strip())
else:
    add_log("[nuclei] skipped")

# 10) Ollama summary
set_progress(0.96, "Summarizing…")
if use_ollama and which("ollama"):
    add_log("[ollama] generating local summary")
    prompt = f"""
Analyze these recon results for domain {domain}.
Summarize:
- Exposed surface (hosts, technologies)
- Notable passive posture signals (DNS/TLS)
- Web posture (status, tech) if present
- Active findings if present
"""
    data = ""
    for f in [
        "run_config.json",
        "subdomains.txt",
        "dns_posture.json",
        "rdns.json",
        "tls_certs.json",
        "httpx.jsonl",
        "endpoints.txt",
        "nuclei_exposure.jsonl",
        "nuclei_cve.jsonl",
    ]:
        p = out_dir / f
        if p.exists():
            data += f"\n\n### {f}\n" + p.read_text(encoding="utf-8", errors="ignore")[:8000]

    proc = subprocess.Popen(
        ["ollama", "run", "llama3"],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    out, _ = proc.communicate(prompt + "\n\n" + data[:14000])
    safe_write(out_dir / "ollama_summary.txt", out)
    add_log("[ollama] done")
else:
    add_log("[ollama] skipped")

set_progress(1.0, "Completed")
if status_supported and status_box is not None:
    try:
        status_box.update(label="Completed", state="complete")
    except Exception:
        pass

# ==========================================
# Build UI data
# ==========================================
httpx_table_rows = httpx_to_rows(httpx_rows) if httpx_rows else []
nuclei_rows = []
if nuclei_exposure_path.exists():
    nuclei_rows += nuclei_jsonl_to_rows(nuclei_exposure_path, "exposure/misconfig")
if nuclei_cve_path.exists():
    nuclei_rows += nuclei_jsonl_to_rows(nuclei_cve_path, "cve")

n_subs = len(subs)
n_ips = len(ip_set)
n_httpx = len(httpx_rows)
n_targets = len(targets)
n_endpoints = len(endpoints_hits)
n_findings = len(nuclei_rows)

provider_guess = (dns_posture.get("provider_guess") or []) if isinstance(dns_posture, dict) else []


# ==========================================
# Render tabs
# ==========================================
with tab_overview:
    c1, c2, c3, c4, c5, c6 = st.columns(6)
    c1.metric("Subdomains", n_subs)
    c2.metric("IPs", n_ips)
    c3.metric("HTTPX rows", n_httpx)
    c4.metric("Targets", n_targets)
    c5.metric("Endpoint hits", n_endpoints)
    c6.metric("Findings", n_findings)

    # Signals panel (operator-friendly)
    signals = []
    if isinstance(dns_posture, dict) and dns_posture:
        dmarc = (dns_posture.get("DMARC") or "").lower()
        if "p=none" in dmarc:
            signals.append(("DMARC policy: none", "warn"))
        elif "p=reject" in dmarc:
            signals.append(("DMARC policy: reject", "ok"))
        elif "p=quarantine" in dmarc:
            signals.append(("DMARC policy: quarantine", "ok"))

        if not (dns_posture.get("CAA") or []):
            signals.append(("CAA: missing", "warn"))

        if dns_posture.get("DNSSEC") is False:
            signals.append(("DNSSEC: disabled", "info"))

        wc = dns_posture.get("wildcard", {}).get("wildcard") if isinstance(dns_posture.get("wildcard"), dict) else None
        if wc is True:
            signals.append(("Wildcard DNS: enabled", "warn"))
        elif wc is False:
            signals.append(("Wildcard DNS: no", "ok"))

        if dns_posture.get("A"):
            signals.append(("Apex resolves to IP", "info"))

    if provider_guess:
        signals.append(("Provider hint: " + ", ".join(provider_guess), "info"))

    if signals:
        st.markdown("<div class='card'><b>Notable signals</b><div class='hr'></div>", unsafe_allow_html=True)
        st.markdown("".join(pill(t, l) for t, l in signals), unsafe_allow_html=True)
        st.markdown("</div>", unsafe_allow_html=True)

    # DNS posture highlights
    if isinstance(dns_posture, dict) and dns_posture:
        st.markdown("<div class='card'><b>DNS posture</b><div class='hr'></div>", unsafe_allow_html=True)
        colA, colB = st.columns(2)
        with colA:
            if dns_posture.get("SPF"):
                st.code(f"SPF: {dns_posture['SPF']}")
            if dns_posture.get("DMARC"):
                st.code(f"DMARC: {dns_posture['DMARC']}")
        with colB:
            st.write("DNSSEC:", dns_posture.get("DNSSEC"))
            wc = dns_posture.get("wildcard", {}).get("wildcard") if isinstance(dns_posture.get("wildcard"), dict) else None
            st.write("Wildcard DNS:", wc)
            st.write("NS:", ", ".join(dns_posture.get("NS") or []))
        st.markdown("</div>", unsafe_allow_html=True)

    # Charts
    if pd is not None and httpx_table_rows:
        dfh = pd.DataFrame(httpx_table_rows)

        left, right = st.columns(2)
        with left:
            st.subheader("HTTP status distribution")
            sc = dfh["status_code"].fillna("unknown").astype(str).value_counts().reset_index()
            sc.columns = ["status_code", "count"]
            if px is not None:
                st.plotly_chart(px.pie(sc, names="status_code", values="count", hole=0.45), use_container_width=True)
            else:
                st.bar_chart(sc.set_index("status_code"))

        with right:
            st.subheader("Top technologies (httpx)")
            tech_counts = {}
            for t in dfh["tech"].fillna("").astype(str).tolist():
                for part in [x.strip().lower() for x in t.split(",") if x.strip()]:
                    tech_counts[part] = tech_counts.get(part, 0) + 1
            if tech_counts:
                top = sorted(tech_counts.items(), key=lambda x: x[1], reverse=True)[:15]
                dft = pd.DataFrame(top, columns=["tech", "count"])
                if px is not None:
                    st.plotly_chart(px.bar(dft, x="count", y="tech", orientation="h"), use_container_width=True)
                else:
                    st.bar_chart(dft.set_index("tech"))

    if pd is not None and nuclei_rows:
        dfn = pd.DataFrame(nuclei_rows)
        st.subheader("Findings by severity")
        sev = dfn.groupby(["profile", "severity"]).size().reset_index(name="count")
        if px is not None:
            st.plotly_chart(px.bar(sev, x="severity", y="count", color="profile", barmode="group"), use_container_width=True)
        else:
            st.bar_chart(sev.set_index("severity")["count"])

    if (pd is None or px is None) and (httpx_table_rows or nuclei_rows):
        st.caption("Optional charts: pip install pandas plotly")

    # Download buttons (key artifacts)
    st.subheader("Downloads")
    dl_cols = st.columns(4)

    def dl_btn(label: str, filename: str, mime: str):
        p = out_dir / filename
        if p.exists() and p.stat().st_size > 0:
            dl_cols[0].download_button(
                label,
                data=p.read_bytes(),
                file_name=filename,
                mime=mime,
                use_container_width=True,
            )

    # Put core downloads across columns
    p_run = out_dir / "run_config.json"
    if p_run.exists():
        dl_cols[0].download_button("Download run_config.json", p_run.read_bytes(), "run_config.json", "application/json", use_container_width=True)

    p_sub = out_dir / "subdomains.txt"
    if p_sub.exists() and p_sub.stat().st_size > 0:
        dl_cols[1].download_button("Download subdomains.txt", p_sub.read_bytes(), "subdomains.txt", "text/plain", use_container_width=True)

    p_dns = out_dir / "dns_posture.json"
    if p_dns.exists() and p_dns.stat().st_size > 0:
        dl_cols[2].download_button("Download dns_posture.json", p_dns.read_bytes(), "dns_posture.json", "application/json", use_container_width=True)

    p_tgt = out_dir / "targets.txt"
    if p_tgt.exists() and p_tgt.stat().st_size > 0:
        dl_cols[3].download_button("Download targets.txt", p_tgt.read_bytes(), "targets.txt", "text/plain", use_container_width=True)

with tab_targets:
    st.subheader("Selected targets (1 URL per host)")
    if targets:
        st.code("\n".join(targets[:400]))
    else:
        st.caption("No targets selected (httpx disabled or no parseable results).")

    st.subheader("Filter & explore (httpx)")
    if pd is not None and httpx_table_rows:
        dfh = pd.DataFrame(httpx_table_rows)
        fq = st.text_input("Filter (host/url/tech/title)", value="")
        f_status = st.multiselect(
            "Filter status_code",
            options=sorted([x for x in dfh["status_code"].dropna().unique().tolist() if str(x).strip() != ""]),
            default=[],
        )
        view = dfh.copy()
        if fq.strip():
            q = fq.lower()
            mask = view.apply(lambda r: q in " ".join(map(lambda v: str(v).lower(), r.values)), axis=1)
            view = view[mask]
        if f_status:
            view = view[view["status_code"].isin(f_status)]
        st.dataframe(view.head(1500), use_container_width=True, hide_index=True)
    else:
        st.caption("Install pandas to view/filter tables (pip install pandas).")

    st.subheader("Endpoint hits")
    if endpoints_hits:
        st.code("\n".join(endpoints_hits[:500]))
    else:
        st.caption("No endpoint hits (or endpoints disabled).")

with tab_findings:
    st.subheader("Nuclei results")
    if not enable_nuclei:
        st.caption("Nuclei is disabled.")
    elif enable_nuclei and not confirm_nuclei:
        st.caption("Nuclei enabled but not armed (confirmation missing).")
    elif enable_nuclei and confirm_nuclei and not targets:
        st.caption("Nuclei armed but no targets were selected.")
    else:
        if nuclei_exposure_path.exists():
            sumA = summarize_nuclei_jsonl(nuclei_exposure_path)
            st.write("Exposure/misconfig:", sumA["by_sev"], "Total:", sumA["total"])
            if sumA["samples"]:
                st.code("\n".join(sumA["samples"]))

        if nuclei_cve_path.exists():
            sumB = summarize_nuclei_jsonl(nuclei_cve_path)
            st.write("CVE:", sumB["by_sev"], "Total:", sumB["total"])
            if sumB["samples"]:
                st.code("\n".join(sumB["samples"]))

        if pd is not None and nuclei_rows:
            st.subheader("Findings table")
            st.dataframe(pd.DataFrame(nuclei_rows).head(2000), use_container_width=True, hide_index=True)

    if (out_dir / "nuclei_debug.log").exists():
        st.subheader("Nuclei debug log (tail)")
        log = (out_dir / "nuclei_debug.log").read_text(encoding="utf-8", errors="ignore")
        st.code("\n".join(log.splitlines()[-200:]))

    st.divider()
    st.subheader("Passive posture artifacts")
    st.write("dns_posture.json:", "✅" if (out_dir / "dns_posture.json").exists() else "—")
    st.write("rdns.json:", "✅" if (out_dir / "rdns.json").exists() else "—")
    st.write("tls_certs.json:", "✅" if (out_dir / "tls_certs.json").exists() else "—")

    if pd is not None and tls_certs:
        st.subheader("TLS certs")
        st.dataframe(pd.DataFrame(tls_certs).head(500), use_container_width=True, hide_index=True)

with tab_raw:
    st.subheader("Output directory")
    st.code(str(out_dir))

    st.subheader("Raw files preview")
    files = [
        "run_config.json",
        "subdomains.txt",
        "dns.json",
        "dns_posture.json",
        "rdns.json",
        "tls_certs.json",
        "subs.txt",
        "httpx.jsonl",
        "httpx.err.txt",
        "targets.txt",
        "endpoints.txt",
        "nuclei_exposure.jsonl",
        "nuclei_cve.jsonl",
        "nuclei_debug.log",
        "ollama_summary.txt",
    ]
    for f in files:
        p = out_dir / f
        if p.exists() and p.stat().st_size > 0:
            with st.expander(f, expanded=False):
                txt = p.read_text(encoding="utf-8", errors="ignore")
                st.code(txt[:12000] + ("\n...\n" if len(txt) > 12000 else ""))
