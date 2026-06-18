#!/usr/bin/env python3
"""
threatwatch - fetch_feeds.py

Haalt recente indicators of compromise op uit drie abuse.ch projecten
(ThreatFox, URLhaus, MalwareBazaar), normaliseert ze naar één
gemeenschappelijk formaat, en schrijft het resultaat naar data/feed.json
voor het statische dashboard.

Auth-Key wordt verwacht in de omgevingsvariabele ABUSECH_AUTH_KEY
(in GitHub Actions: een repository secret).

Bronnen:
- ThreatFox API:      https://threatfox.abuse.ch/api/
- URLhaus API:        https://urlhaus.abuse.ch/api/
- MalwareBazaar API:  https://bazaar.abuse.ch/api/

Alle drie zijn gratis te gebruiken onder de "fair use" voorwaarden van
abuse.ch. Dit script doet alleen lezen (geen submits) en respecteert de
aanbevolen ophaalfrequentie (niet vaker dan elke 5-10 minuten).
"""

import json
import os
import sys
import time
import hashlib
import logging
from datetime import datetime, timezone
from pathlib import Path

import requests

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)
log = logging.getLogger("threatwatch")

AUTH_KEY = os.environ.get("ABUSECH_AUTH_KEY", "").strip()
DATA_DIR = Path(__file__).resolve().parent.parent / "data"
OUTPUT_FILE = DATA_DIR / "feed.json"
HISTORY_FILE = DATA_DIR / "history.json"

# Hoeveel historie we bewaren voor de "nieuw vs totaal" trend op het dashboard
MAX_HISTORY_POINTS = 200

THREATFOX_URL = "https://threatfox-api.abuse.ch/api/v1/"
URLHAUS_URL = "https://urlhaus-api.abuse.ch/v1/urls/recent/"
MALWAREBAZAAR_URL = "https://mb-api.abuse.ch/api/v1/"

HEADERS = {"Auth-Key": AUTH_KEY} if AUTH_KEY else {}
REQUEST_TIMEOUT = 30


def stable_id(*parts: str) -> str:
    """Maakt een stabiele, korte id voor dedupe/sorting puzzn over bronnen heen."""
    raw = "|".join(p or "" for p in parts)
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:16]


def fetch_threatfox(days: int = 1) -> list[dict]:
    """Haalt recente C2/malware IOC's op uit ThreatFox."""
    if not AUTH_KEY:
        log.warning("Geen ABUSECH_AUTH_KEY gezet — sla ThreatFox over.")
        return []
    try:
        resp = requests.post(
            THREATFOX_URL,
            headers=HEADERS,
            json={"query": "get_iocs", "days": days},
            timeout=REQUEST_TIMEOUT,
        )
        resp.raise_for_status()
        payload = resp.json()
    except Exception as exc:
        log.error("ThreatFox fetch mislukt: %s", exc)
        return []

    if payload.get("query_status") != "ok":
        log.warning("ThreatFox query_status niet ok: %s", payload.get("query_status"))
        return []

    items = []
    for entry in payload.get("data", []):
        ioc_value = entry.get("ioc") or ""
        items.append({
            "id": stable_id("threatfox", str(entry.get("id", "")), ioc_value),
            "source": "ThreatFox",
            "ioc": ioc_value,
            "ioc_type": entry.get("ioc_type", "unknown"),
            "threat_type": entry.get("threat_type", "unknown"),
            "threat_type_description": entry.get("threat_type_description", ""),
            "malware": entry.get("malware_printable") or entry.get("malware") or "Unknown",
            "confidence": entry.get("confidence_level", 0),
            "tags": entry.get("tags") or [],
            "first_seen": entry.get("first_seen_utc", ""),
            "reference": f"https://threatfox.abuse.ch/ioc/{entry.get('id')}/" if entry.get("id") else "",
        })
    log.info("ThreatFox: %d IOC's opgehaald", len(items))
    return items


def fetch_urlhaus(limit: int = 100) -> list[dict]:
    """Haalt recent toegevoegde malware-distributie URL's op uit URLhaus."""
    if not AUTH_KEY:
        log.warning("Geen ABUSECH_AUTH_KEY gezet — sla URLhaus over.")
        return []
    try:
        resp = requests.get(
            f"{URLHAUS_URL}limit/{limit}/",
            headers=HEADERS,
            timeout=REQUEST_TIMEOUT,
        )
        resp.raise_for_status()
        payload = resp.json()
    except Exception as exc:
        log.error("URLhaus fetch mislukt: %s", exc)
        return []

    if payload.get("query_status") != "ok":
        log.warning("URLhaus query_status niet ok: %s", payload.get("query_status"))
        return []

    items = []
    for entry in payload.get("urls", []):
        url_value = entry.get("url") or ""
        items.append({
            "id": stable_id("urlhaus", str(entry.get("id", "")), url_value),
            "source": "URLhaus",
            "ioc": url_value,
            "ioc_type": "url",
            "threat_type": entry.get("threat", "malware_download"),
            "threat_type_description": "Malware distribution URL",
            "malware": ", ".join(entry.get("tags") or []) or "Unknown",
            "confidence": 100 if entry.get("url_status") == "online" else 50,
            "tags": entry.get("tags") or [],
            "first_seen": entry.get("date_added", ""),
            "reference": entry.get("urlhaus_reference", ""),
        })
    log.info("URLhaus: %d URL's opgehaald", len(items))
    return items


def fetch_malwarebazaar() -> list[dict]:
    """Haalt recente malware-sample detecties op uit MalwareBazaar."""
    if not AUTH_KEY:
        log.warning("Geen ABUSECH_AUTH_KEY gezet — sla MalwareBazaar over.")
        return []
    try:
        resp = requests.post(
            MALWAREBAZAAR_URL,
            headers=HEADERS,
            data={"query": "get_recent", "selector": "100"},
            timeout=REQUEST_TIMEOUT,
        )
        resp.raise_for_status()
        payload = resp.json()
    except Exception as exc:
        log.error("MalwareBazaar fetch mislukt: %s", exc)
        return []

    if payload.get("query_status") != "ok":
        log.warning("MalwareBazaar query_status niet ok: %s", payload.get("query_status"))
        return []

    items = []
    for entry in payload.get("data", []):
        sha256 = entry.get("sha256_hash") or ""
        items.append({
            "id": stable_id("malwarebazaar", sha256),
            "source": "MalwareBazaar",
            "ioc": sha256,
            "ioc_type": "sha256_hash",
            "threat_type": "payload",
            "threat_type_description": entry.get("file_type", "binary"),
            "malware": entry.get("signature") or "Unknown",
            "confidence": 100,
            "tags": entry.get("tags") or [],
            "first_seen": entry.get("first_seen", ""),
            "reference": f"https://bazaar.abuse.ch/sample/{sha256}/" if sha256 else "",
        })
    log.info("MalwareBazaar: %d samples opgehaald", len(items))
    return items


def load_json(path: Path, default):
    if path.exists():
        try:
            return json.loads(path.read_text(encoding="utf-8"))
        except Exception:
            log.warning("Kon %s niet parsen, start met lege state.", path)
    return default


def main() -> int:
    DATA_DIR.mkdir(parents=True, exist_ok=True)

    all_items: list[dict] = []
    all_items.extend(fetch_threatfox(days=1))
    all_items.extend(fetch_urlhaus(limit=100))
    all_items.extend(fetch_malwarebazaar())

    if not all_items and not AUTH_KEY:
        log.error(
            "Geen ABUSECH_AUTH_KEY beschikbaar en geen data opgehaald. "
            "Zet de secret ABUSECH_AUTH_KEY in de repository settings."
        )

    # Dedupe op stabiele id, sorteer nieuwste eerst
    dedup: dict[str, dict] = {item["id"]: item for item in all_items}
    items = sorted(dedup.values(), key=lambda x: x.get("first_seen", ""), reverse=True)

    now_iso = datetime.now(timezone.utc).isoformat()

    stats = {
        "total": len(items),
        "by_source": {},
        "by_threat_type": {},
        "generated_at": now_iso,
    }
    for item in items:
        stats["by_source"][item["source"]] = stats["by_source"].get(item["source"], 0) + 1
        stats["by_threat_type"][item["threat_type"]] = stats["by_threat_type"].get(item["threat_type"], 0) + 1

    output = {
        "generated_at": now_iso,
        "stats": stats,
        "items": items[:500],  # cap voor dashboard performance
    }
    OUTPUT_FILE.write_text(json.dumps(output, indent=2, ensure_ascii=False), encoding="utf-8")
    log.info("Geschreven: %s (%d items)", OUTPUT_FILE, len(items))

    # Lichte historie bijhouden voor een trend-lijntje op het dashboard
    history = load_json(HISTORY_FILE, [])
    history.append({"ts": now_iso, "total": len(items)})
    history = history[-MAX_HISTORY_POINTS:]
    HISTORY_FILE.write_text(json.dumps(history, indent=2), encoding="utf-8")

    return 0


if __name__ == "__main__":
    sys.exit(main())
