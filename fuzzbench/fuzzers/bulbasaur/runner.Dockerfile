# Copyright 2026 Bulbasaur contributors

FROM gcr.io/fuzzbench/base-image

ARG BULBASAUR_REPO_URL=https://github.com/vul337/Bulbasaur.git
ARG BULBASAUR_REF=main

RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y \
    bubblewrap ca-certificates git python3-venv && \
    rm -rf /var/lib/apt/lists/*

RUN git clone --depth 1 --branch "${BULBASAUR_REF}" \
      "${BULBASAUR_REPO_URL}" /Bulbasaur && \
    cd /Bulbasaur/llm_scripts && \
    python3 -m venv --system-site-packages /opt/bulbasaur-venv && \
    /opt/bulbasaur-venv/bin/pip install --no-cache-dir -r requirements.txt

ENV PATH="/opt/bulbasaur-venv/bin:${PATH}"
ENV PYTHONPATH="/Bulbasaur/llm_scripts"
ENV LD_LIBRARY_PATH="/out/src/shared:/out"

# The runner itself is already isolated by FuzzBench. This is only for
# environments whose container profile rejects nested user namespaces.
ENV BULBASAUR_MINI_ALLOW_UNSANDBOXED=1
