# Suricata alert shipper — tails eve.json and pushes IDS alerts to the ingest API.
# Tiny: just python3 + the shipper script (Suricata itself runs in its own image).
FROM python:3.12-slim
WORKDIR /srv
COPY scripts/discovery/suricata_to_findings.py /srv/suricata_to_findings.py
ENTRYPOINT ["python3", "/srv/suricata_to_findings.py"]
