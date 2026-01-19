# ==========================================
# GAMBIT Dockerfile (multi-stage, stable)
# - Go recon tools
# - Python 3.11 + Streamlit UI
# - cloud_enum
# - nuclei templates (best effort)
# - Output: /gambit/gambit_out
# ==========================================

# ---------- Stage 1: Go tools ----------
FROM golang:1.22-bookworm AS go-tools

ENV CGO_ENABLED=1
ENV GOTOOLCHAIN=auto
ENV GOBIN=/go/bin
ENV PATH="${PATH}:${GOBIN}"

RUN apt-get update && apt-get install -y --no-install-recommends \
    git ca-certificates build-essential libpcap-dev \
 && rm -rf /var/lib/apt/lists/*

RUN go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest \
 && go install github.com/projectdiscovery/httpx/cmd/httpx@latest \
 && go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest \
 && go install github.com/projectdiscovery/naabu/v2/cmd/naabu@latest \
 && go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest \
 && go install github.com/projectdiscovery/katana/cmd/katana@latest \
 && go install github.com/lc/gau/v2/cmd/gau@latest \
 && go install github.com/tomnomnom/waybackurls@latest \
 && go install github.com/tomnomnom/unfurl@latest

# ---------- Stage 2: Runtime ----------
FROM python:3.11-slim-bookworm AS runtime

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    curl \
    openssl \
    dnsutils \
    jq \
    whois \
    git \
    procps \
    libpcap0.8 \
 && rm -rf /var/lib/apt/lists/*

COPY --from=go-tools /go/bin/ /usr/local/bin/

WORKDIR /app

# Python deps (pinning mínimo para estabilidad)
RUN pip install --upgrade pip \
 && pip install --no-cache-dir \
    streamlit==1.36.0 \
    streamlit-autorefresh==1.0.1 \
    pandas==2.2.2 \
    plotly==5.22.0

# cloud_enum
ARG CLOUD_ENUM_REF=master
RUN pip install --no-cache-dir "git+https://github.com/initstring/cloud_enum.git@${CLOUD_ENUM_REF}"

# Output path
ENV GAMBIT_OUT=/gambit/gambit_out
RUN mkdir -p /gambit/gambit_out && chmod -R 777 /gambit

# Nuclei templates (best effort)
RUN nuclei -update-templates || true

# App
COPY gambit.py /app/gambit.py
COPY .streamlit /app/.streamlit

ENV STREAMLIT_SERVER_ADDRESS=0.0.0.0
ENV STREAMLIT_SERVER_PORT=8501
EXPOSE 8501

CMD ["python", "-m", "streamlit", "run", "/app/gambit.py", "--server.address=0.0.0.0", "--server.port=8501"]
