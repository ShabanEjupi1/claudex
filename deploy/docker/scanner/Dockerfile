# Background scanner: nmap + the converter, on a schedule. Separate from the
# read-only dashboard tier on purpose (it initiates scans and holds the ingest
# token). Build context is the repo root.
FROM python:3.12-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends nmap curl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /srv
COPY scripts/discovery/nmap_to_findings.py /srv/nmap_to_findings.py
COPY deploy/docker/scanner/run-scans.sh /srv/run-scans.sh
RUN chmod +x /srv/run-scans.sh

ENTRYPOINT ["/srv/run-scans.sh"]
