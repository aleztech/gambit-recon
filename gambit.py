#!/usr/bin/env python3
# ==========================================
#  GAMBIT – Surface & Exposure Recon (low-impact tuned)
# ==========================================
# Nota: Diseñado para minimizar carga (scope + límites fijos).
# No implementa técnicas de evasión.
# Requiere (según módulos): subfinder, httpx, nuclei, curl, (opcional) ollama.

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

        # score: https preferido, luego 2xx>3xx>401/403
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
# Streamlit UI
# ==========================================
st.set_page_config(page_title="GAMBIT Recon", layout="wide")

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
st.caption("Recon defensivo · Dominios propios · Low-impact por diseño")

# ==========================================
# Inputs
# ==========================================
col1, col2 = st.columns(2)

with col1:
    domain_in = st.text_input("Dominio objetivo", placeholder="example.com")
    out_dir_base = st.text_input("Directorio de salida", value=str(Path.home() / "gambit_out"))
    use_tor = st.checkbox("Usar Tor SOCKS (127.0.0.1:9050)", value=False)
    use_ollama = st.checkbox("Resumen con Ollama (si existe)", value=False)

    st.subheader("Selección de targets (menos ruido)")
    allowed_status = st.multiselect(
        "Status permitidos para escaneos posteriores",
        options=[200, 301, 302, 401, 403],
        default=[200, 301, 302, 401, 403],
    )
    prefer_https = st.checkbox("Priorizar HTTPS cuando exista", value=True)

with col2:
    st.subheader("Módulos")
    m_subs = st.checkbox("Subdominios (subfinder)", True)
    m_dns = st.checkbox("DNS resolve", True)
    m_httpx = st.checkbox("HTTP fingerprint (httpx JSON)", True)
    m_endpoints = st.checkbox("Endpoints comunes (HEAD)", True)
    m_nuclei = st.checkbox("Nuclei (perfiles low-impact)", False)

    st.subheader("Límites")
    threads = st.slider("Concurrencia httpx", 10, 200, 50, 10)
    max_hosts = st.slider("Máx hosts para checks ligeros (targets)", 10, 400, 80, 10)

    st.subheader("Nuclei control de carga (fijo)")
    nuclei_timeout = st.slider("Timeout (s)", 3, 20, 6, 1)
    nuclei_retries = st.slider("Retries", 0, 3, 1, 1)

    nuclei_conc_direct = st.slider("Concurrencia (directo)", 1, 50, 10, 1)
    nuclei_ratelimit_direct = st.slider("Rate-limit req/s (directo)", 1, 200, 25, 1)
    nuclei_conc_tor = st.slider("Concurrencia (Tor)", 1, 20, 5, 1)
    nuclei_ratelimit_tor = st.slider("Rate-limit req/s (Tor)", 1, 60, 10, 1)

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

    # Tool sanity
    st.subheader("Tooling")
    st.write("subfinder:", which("subfinder") or "NO")
    st.write("httpx:", which("httpx") or "NO")
    st.write("nuclei:", which("nuclei") or "NO")
    st.write("ollama:", which("ollama") or "NO")

    # Egress
    st.subheader("Egreso de red")
    _, ip_direct, _ = check_ip("direct")
    st.write("Directo:", ip_direct)
    if use_tor:
        _, ip_tor, _ = check_ip("tor")
        st.write("Tor:", ip_tor)

    # Subdomains
    subs = []
    if m_subs:
        st.subheader("Subdominios")
        if not which("subfinder"):
            st.warning("subfinder no está en PATH")
        else:
            rc, out, err = run(["bash", "-lc", f"subfinder -d {domain} -silent"], timeout=240)
            if rc != 0 and err:
                st.warning(f"subfinder error: {err[:200]}")
            subs = uniq(out.splitlines())
            safe_write(out_dir / "subdomains.txt", "\n".join(subs))
            st.write(f"Encontrados: {len(subs)}")
            st.code("\n".join(subs[:40]))

    # DNS
    if m_dns and subs:
        st.subheader("DNS Resolution")
        resolved = [resolve_dns(s) for s in subs]
        safe_write(out_dir / "dns.json", json.dumps(resolved, indent=2))
        st.write("DNS guardado")

    # HTTPX (JSONL)
    httpx_rows = []
    if m_httpx and subs:
        st.subheader("HTTP Fingerprint (httpx JSONL)")
        if not which("httpx"):
            st.warning("httpx no está en PATH")
        else:
            subs_file = out_dir / "subs.txt"
            safe_write(subs_file, "\n".join(subs))

            proxy = "-proxy socks5://127.0.0.1:9050" if use_tor else ""
            cmd = (
                f"cat {subs_file} | "
                f"httpx -silent -json "
                f"-title -status-code -tech-detect -server -ip "
                f"-threads {threads} {proxy}"
            )
            rc, out, err = run(["bash", "-lc", cmd], timeout=420)
            safe_write(out_dir / "httpx.jsonl", out + ("\n" if out else ""))
            safe_write(out_dir / "httpx.err.txt", err or "")

            httpx_rows = parse_httpx_jsonl(out_dir / "httpx.jsonl")
            st.write(f"Respuestas parseadas: {len(httpx_rows)}")
            if httpx_rows:
                st.code("\n".join((out_dir / "httpx.jsonl").read_text().splitlines()[:8]))
            else:
                st.warning("httpx no devolvió JSON parseable (revisa httpx.err.txt).")

    # Targets
    st.subheader("Targets (1 URL por host)")
    targets = []
    if httpx_rows:
        targets, _picked = pick_targets_from_httpx(
            httpx_rows,
            allowed_status=set(int(x) for x in allowed_status),
            max_hosts=max_hosts,
            prefer_https=prefer_https,
        )
        safe_write(out_dir / "targets.txt", "\n".join(targets))
        st.write(f"Targets seleccionados: {len(targets)}")
        st.code("\n".join(targets[:30]))
    else:
        st.caption("Sin targets (httpx no corrió o no devolvió datos).")

    # Endpoints (HEAD)
    if m_endpoints and targets:
        st.subheader("Endpoints comunes (HEAD, bajo impacto)")
        paths = ["/robots.txt", "/sitemap.xml", "/.env", "/.git/HEAD", "/wp-login.php"]
        hits = []

        for base in targets:
            for p in paths:
                if use_tor:
                    curl = f"curl -skI --socks5-hostname 127.0.0.1:9050 -m 8 {base}{p}"
                else:
                    curl = f"curl -skI -m 6 {base}{p}"

                _, hdrs, _ = run(["bash", "-lc", curl], timeout=12)
                first = (hdrs.splitlines()[0] if hdrs else "")
                m = re.search(r"\s(\d{3})\s", first)
                code = m.group(1) if m else ""
                if code in ("200", "301", "302", "401", "403"):
                    hits.append(f"{base}{p} [{code}]")

        safe_write(out_dir / "endpoints.txt", "\n".join(hits))
        st.write(f"Endpoints interesantes: {len(hits)}")
        st.code("\n".join(hits[:30]))

    # Nuclei profiles (JSONL)
    if m_nuclei and targets:
        st.subheader("Nuclei (perfiles low-impact)")
        if not which("nuclei"):
            st.warning("nuclei no está en PATH")
        else:
            ufile = out_dir / "targets.txt"
            proxy = "-proxy socks5://127.0.0.1:9050" if use_tor else ""
            conc = nuclei_conc_tor if use_tor else nuclei_conc_direct
            rlimit = nuclei_ratelimit_tor if use_tor else nuclei_ratelimit_direct

            # Perfil A: exposures/misconfig
            out_a = out_dir / "nuclei_exposure.jsonl"
            cmd_a = (
                f"nuclei -l {ufile} "
                f"-tags exposure,misconfig "
                f"-severity info,low,medium "
                f"-no-interactsh "
                f"-jsonl -output {out_a} "
                f"-silent {proxy} "
                f"-timeout {nuclei_timeout} -retries {nuclei_retries} "
                f"-c {conc} -rate-limit {rlimit} "
                f"-max-host-error 10 "
            )
            rcA, outA, errA = run(["bash", "-lc", cmd_a], timeout=900)

            # Perfil B: CVE (controlado)
            out_b = out_dir / "nuclei_cve.jsonl"
            cmd_b = (
                f"nuclei -l {ufile} "
                f"-tags cve "
                f"-severity medium,high "
                f"-no-interactsh "
                f"-jsonl -output {out_b} "
                f"-silent {proxy} "
                f"-timeout {nuclei_timeout} -retries {nuclei_retries} "
                f"-c {conc} -rate-limit {rlimit} "
                f"-max-host-error 10 "
            )
            rcB, outB, errB = run(["bash", "-lc", cmd_b], timeout=900)

            safe_write(
                out_dir / "nuclei_debug.log",
                "=== exposure/misconfig ===\n"
                + (outA or "")
                + "\n"
                + (errA or "")
                + "\n\n=== cve ===\n"
                + (outB or "")
                + "\n"
                + (errB or ""),
            )

            sumA = summarize_nuclei_jsonl(out_a)
            sumB = summarize_nuclei_jsonl(out_b)

            st.write("Resumen exposure/misconfig:", sumA["by_sev"], "Total:", sumA["total"])
            if sumA["samples"]:
                st.code("\n".join(sumA["samples"]))

            st.write("Resumen CVE:", sumB["by_sev"], "Total:", sumB["total"])
            if sumB["samples"]:
                st.code("\n".join(sumB["samples"]))

    # Ollama summary (optional)
    if use_ollama and which("ollama"):
        st.subheader("Resumen con Ollama (local)")
        prompt = f"""
Analiza estos resultados de recon para el dominio {domain}.
Resume:
- Superficie expuesta (hosts, tecnologías)
- Hallazgos exposure/misconfig y CVE (si hay)
- Prioridades defensivas y quick wins
"""

        data = ""
        for f in [
            "subdomains.txt",
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
        out, _ = proc.communicate(prompt + "\n\n" + data[:12000])
        safe_write(out_dir / "ollama_summary.txt", out)
        st.code(out)

    st.success("GAMBIT finalizado")
