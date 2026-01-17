#!/usr/bin/env python3
# ==========================================
#  GAMBIT – Surface & Exposure Recon
# ==========================================

import os
import re
import json
import time
import shutil
import socket
import subprocess
from datetime import datetime
from pathlib import Path

import streamlit as st

# ==========================================
# Utils
# ==========================================
def which(cmd):
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
        return p.returncode, p.stdout.strip(), p.stderr.strip()
    except subprocess.TimeoutExpired:
        return 124, "", "TIMEOUT"
    except Exception as e:
        return 1, "", str(e)

def sanitize_domain(d):
    d = d.strip().lower()
    d = re.sub(r"^https?://", "", d)
    d = d.split("/")[0]
    if not re.match(r"^[a-z0-9.-]+\.[a-z]{2,}$", d):
        raise ValueError("Dominio no válido (ej: example.com)")
    return d

def uniq(items):
    return sorted(set([i.strip() for i in items if i.strip()]))

def resolve_dns(host):
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
            except:
                pass
    except:
        pass
    return res

def check_ip(mode):
    if mode == "direct":
        return run(["bash", "-lc", "curl -s https://check.torproject.org/api/ip"], 20)
    if mode == "tor":
        return run(["bash", "-lc", "curl -s --socks5-hostname 127.0.0.1:9050 https://check.torproject.org/api/ip"], 25)
    return 1, "", "invalid mode"

# ==========================================
# Streamlit UI
# ==========================================
st.set_page_config(
    page_title="GAMBIT Recon",
    layout="wide",
)

ASCII = r"""
 ██████╗  █████╗ ███╗   ███╗██████╗ ██╗████████╗
██╔════╝ ██╔══██╗████╗ ████║██╔══██╗██║╚══██╔══╝
██║  ███╗███████║██╔████╔██║██████╔╝██║   ██║   
██║   ██║██╔══██║██║╚██╔╝██║██╔══██╗██║   ██║   
╚██████╔╝██║  ██║██║ ╚═╝ ██║██████╔╝██║   ██║   
 ╚═════╝ ╚═╝  ╚═╝╚═╝     ╚═╝╚═════╝ ╚═╝   ╚═╝   
"""

st.markdown(f"```{ASCII}```")
st.title("GAMBIT – Attack Surface Recon")
st.caption("Black-box recon defensivo · Dominios propios · OPSEC-friendly")

# ==========================================
# Inputs
# ==========================================
col1, col2 = st.columns(2)

with col1:
    domain_in = st.text_input("Dominio objetivo", placeholder="example.com")
    out_dir_base = st.text_input("Directorio de salida", value=str(Path.home() / "gambit_out"))
    use_tor = st.checkbox("Usar Tor SOCKS (127.0.0.1:9050)", value=False)
    use_ollama = st.checkbox("Interpretar resultados con Ollama (si existe)", value=False)

with col2:
    st.subheader("Módulos")
    m_subs = st.checkbox("Subdominios (subfinder)", True)
    m_dns = st.checkbox("DNS resolve", True)
    m_httpx = st.checkbox("HTTP fingerprint (httpx)", True)
    m_endpoints = st.checkbox("Endpoints comunes", True)
    m_nuclei = st.checkbox("Nuclei (info/low)", False)

    st.subheader("Límites")
    threads = st.slider("Concurrencia httpx", 10, 200, 50, 10)
    max_hosts = st.slider("Máx hosts para checks ligeros", 10, 200, 50, 10)

run_btn = st.button("▶ Run GAMBIT", type="primary")

# ==========================================
# Execution
# ==========================================
if run_btn:
    try:
        domain = sanitize_domain(domain_in)
    except Exception as e:
        st.error(str(e))
        st.stop()

    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    out_dir = Path(out_dir_base) / f"{domain}_{ts}"
    out_dir.mkdir(parents=True, exist_ok=True)

    st.success(f"Output → {out_dir}")

    # ---- Egress
    st.subheader("Egreso de red")
    _, ip_direct, _ = check_ip("direct")
    st.write("Directo:", ip_direct)

    if use_tor:
        _, ip_tor, _ = check_ip("tor")
        st.write("Tor:", ip_tor)

    # ---- Subdomains
    subs = []
    if m_subs:
        st.subheader("Subdominios")
        if not which("subfinder"):
            st.warning("subfinder no está en PATH")
        else:
            _, out, _ = run(["bash", "-lc", f"subfinder -d {domain} -silent"])
            subs = uniq(out.splitlines())
            (out_dir / "subdomains.txt").write_text("\n".join(subs))
            st.write(f"Encontrados: {len(subs)}")
            st.code("\n".join(subs[:40]))

    # ---- DNS
    resolved = []
    if m_dns and subs:
        st.subheader("DNS Resolution")
        for s in subs:
            resolved.append(resolve_dns(s))
        (out_dir / "dns.json").write_text(json.dumps(resolved, indent=2))
        st.write("DNS guardado")

    # ---- HTTPX
    httpx_out = []
    if m_httpx and subs:
        st.subheader("HTTP Fingerprint")
        tmp = out_dir / "subs.txt"
        tmp.write_text("\n".join(subs))
        proxy = "-proxy socks5://127.0.0.1:9050" if use_tor else ""
        cmd = f"cat {tmp} | httpx -silent -title -status-code -tech-detect -server -ip -threads {threads} {proxy}"
        _, out, _ = run(["bash", "-lc", cmd])
        httpx_out = out.splitlines()
        (out_dir / "httpx.txt").write_text(out)
        st.code("\n".join(httpx_out[:40]))

    # ---- Endpoints
    if m_endpoints and httpx_out:
        st.subheader("Endpoints comunes")
        paths = ["/robots.txt", "/sitemap.xml", "/.env", "/.git/HEAD", "/wp-login.php"]
        hits = []
        for line in httpx_out[:max_hosts]:
            url = line.split(" ")[0]
            for p in paths:
                curl = f"curl -skI -m 6 {url}{p}"
                if use_tor:
                    curl = f"curl -skI --socks5-hostname 127.0.0.1:9050 -m 8 {url}{p}"
                _, out, _ = run(["bash", "-lc", curl])
                if "200" in out or "301" in out:
                    hits.append(f"{url}{p}")
        (out_dir / "endpoints.txt").write_text("\n".join(hits))
        st.write(f"Endpoints interesantes: {len(hits)}")
        st.code("\n".join(hits[:30]))

    # ---- Nuclei
    if m_nuclei and httpx_out:
        st.subheader("Nuclei (info/low)")
        urls = [l.split(" ")[0] for l in httpx_out]
        ufile = out_dir / "urls.txt"
        ufile.write_text("\n".join(urls))
        proxy = "-proxy socks5://127.0.0.1:9050" if use_tor else ""
        cmd = f"nuclei -l {ufile} -severity info,low -silent {proxy}"
        _, out, _ = run(["bash", "-lc", cmd], 300)
        (out_dir / "nuclei.txt").write_text(out)
        st.code(out[:1500] or "Sin hallazgos")

    # ---- Ollama summary
    if use_ollama and which("ollama"):
        st.subheader("Análisis con Ollama")
        prompt = f"""
Analiza estos resultados de recon para el dominio {domain}.
Resume:
- Superficie expuesta
- Riesgos visibles
- Prioridades defensivas
"""
        data = ""
        for f in ["subdomains.txt", "httpx.txt", "endpoints.txt"]:
            p = out_dir / f
            if p.exists():
                data += p.read_text() + "\n"

        proc = subprocess.Popen(
            ["ollama", "run", "llama3"],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            text=True,
        )
        out, _ = proc.communicate(prompt + "\n\n" + data[:6000])
        (out_dir / "ollama_summary.txt").write_text(out)
        st.code(out)

    st.success("GAMBIT finalizado")
