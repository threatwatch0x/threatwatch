#!/usr/bin/env python3
"""
threatwatch - fetch_feeds.py v2

Haalt IOC's op uit ThreatFox, URLhaus en MalwareBazaar, verrijkt
IP-gebaseerde indicators met ASN/geo-data via ip-api.com (gratis,
geen key nodig, max 45 batch-requests/minuut), en schrijft het
resultaat naar data/feed.json.
"""

import json
import os
import sys
import hashlib
import logging
import re
from datetime import datetime, timezone
from pathlib import Path

import requests

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
log = logging.getLogger("threatwatch")

AUTH_KEY        = os.environ.get("ABUSECH_AUTH_KEY", "").strip()
DATA_DIR        = Path(__file__).resolve().parent.parent / "data"
OUTPUT_FILE     = DATA_DIR / "feed.json"
HISTORY_FILE    = DATA_DIR / "history.json"
MAX_HISTORY     = 200

THREATFOX_URL   = "https://threatfox-api.abuse.ch/api/v1/"
URLHAUS_URL     = "https://urlhaus-api.abuse.ch/v1/urls/recent/"
BAZAAR_URL      = "https://mb-api.abuse.ch/api/v1/"
IPAPI_BATCH_URL = "http://ip-api.com/batch"

HEADERS  = {"Auth-Key": AUTH_KEY} if AUTH_KEY else {}
TIMEOUT  = 30

# Regex voor IPv4-adres (puur IP, of IP:port)
RE_IP = re.compile(r"^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})")


def stable_id(*parts):
    raw = "|".join(p or "" for p in parts)
    return hashlib.sha256(raw.encode()).hexdigest()[:16]


# ─── Abuse.ch fetchers ────────────────────────────────────────────────────────

def fetch_threatfox(days=1):
    if not AUTH_KEY:
        log.warning("Geen ABUSECH_AUTH_KEY — sla ThreatFox over.")
        return []
    try:
        r = requests.post(THREATFOX_URL, headers=HEADERS,
                          json={"query": "get_iocs", "days": days}, timeout=TIMEOUT)
        r.raise_for_status()
        payload = r.json()
    except Exception as e:
        log.error("ThreatFox: %s", e); return []

    if payload.get("query_status") != "ok":
        log.warning("ThreatFox status: %s", payload.get("query_status")); return []

    items = []
    for e in payload.get("data", []):
        ioc = e.get("ioc") or ""
        items.append({
            "id":                   stable_id("tf", str(e.get("id", "")), ioc),
            "source":               "ThreatFox",
            "ioc":                  ioc,
            "ioc_type":             e.get("ioc_type", "unknown"),
            "threat_type":          e.get("threat_type", "unknown"),
            "threat_type_description": e.get("threat_type_description", ""),
            "malware":              e.get("malware_printable") or e.get("malware") or "Unknown",
            "confidence":           e.get("confidence_level", 0),
            "tags":                 e.get("tags") or [],
            "first_seen":           e.get("first_seen_utc", ""),
            "reference":            f"https://threatfox.abuse.ch/ioc/{e.get('id')}/" if e.get("id") else "",
            "ip":                   None, "asn": None, "asn_org": None,
            "country": None, "country_code": None,
        })
    log.info("ThreatFox: %d IOC's", len(items))
    return items


def fetch_urlhaus(limit=100):
    if not AUTH_KEY:
        log.warning("Geen ABUSECH_AUTH_KEY — sla URLhaus over.")
        return []
    try:
        r = requests.get(f"{URLHAUS_URL}limit/{limit}/", headers=HEADERS, timeout=TIMEOUT)
        r.raise_for_status()
        payload = r.json()
    except Exception as e:
        log.error("URLhaus: %s", e); return []

    if payload.get("query_status") != "ok":
        log.warning("URLhaus status: %s", payload.get("query_status")); return []

    items = []
    for e in payload.get("urls", []):
        url = e.get("url") or ""
        items.append({
            "id":                   stable_id("uh", str(e.get("id", "")), url),
            "source":               "URLhaus",
            "ioc":                  url,
            "ioc_type":             "url",
            "threat_type":          e.get("threat", "malware_download"),
            "threat_type_description": "Malware distribution URL",
            "malware":              ", ".join(e.get("tags") or []) or "Unknown",
            "confidence":           100 if e.get("url_status") == "online" else 50,
            "tags":                 e.get("tags") or [],
            "first_seen":           e.get("date_added", ""),
            "reference":            e.get("urlhaus_reference", ""),
            "ip":                   e.get("host") if re.match(r"^\d+\.\d+\.\d+\.\d+$", e.get("host","")) else None,
            "asn": None, "asn_org": None, "country": None, "country_code": None,
        })
    log.info("URLhaus: %d URL's", len(items))
    return items


def fetch_malwarebazaar():
    if not AUTH_KEY:
        log.warning("Geen ABUSECH_AUTH_KEY — sla MalwareBazaar over.")
        return []
    try:
        r = requests.post(BAZAAR_URL, headers=HEADERS,
                          data={"query": "get_recent", "selector": "100"}, timeout=TIMEOUT)
        r.raise_for_status()
        payload = r.json()
    except Exception as e:
        log.error("MalwareBazaar: %s", e); return []

    if payload.get("query_status") != "ok":
        log.warning("MalwareBazaar status: %s", payload.get("query_status")); return []

    items = []
    for e in payload.get("data", []):
        sha = e.get("sha256_hash") or ""
        items.append({
            "id":                   stable_id("mb", sha),
            "source":               "MalwareBazaar",
            "ioc":                  sha,
            "ioc_type":             "sha256_hash",
            "threat_type":          "payload",
            "threat_type_description": e.get("file_type", "binary"),
            "malware":              e.get("signature") or "Unknown",
            "confidence":           100,
            "tags":                 e.get("tags") or [],
            "first_seen":           e.get("first_seen", ""),
            "reference":            f"https://bazaar.abuse.ch/sample/{sha}/" if sha else "",
            "ip": None, "asn": None, "asn_org": None,
            "country": None, "country_code": None,
        })
    log.info("MalwareBazaar: %d samples", len(items))
    return items


# ─── IP/ASN verrijking via ip-api.com ────────────────────────────────────────

def extract_ip(item):
    """Haal het IP-adres op uit een IOC-item, of None als er geen IP in zit."""
    # ThreatFox: ioc_type "ip:port" of "ip"
    if item.get("ioc_type") in ("ip:port", "ip"):
        m = RE_IP.match(item.get("ioc", ""))
        if m: return m.group(1)
    # Explicit ip-veld (URLhaus vult dit al in)
    if item.get("ip"):
        return item["ip"]
    return None


def enrich_with_geo(items):
    """
    Verrijkt items met ASN/geo via ip-api.com batch endpoint.
    Gratis tier: 45 batch-calls/minuut, 100 IPs per call.
    We sturen maximaal 100 unieke IPs per run — ruim voldoende.
    """
    # Verzamel unieke IPs en welke items ze gebruiken
    ip_to_items = {}
    for item in items:
        ip = extract_ip(item)
        if ip:
            ip_to_items.setdefault(ip, []).append(item)

    if not ip_to_items:
        log.info("Geen IP-gebaseerde IOC's om te verrijken.")
        return

    unique_ips = list(ip_to_items.keys())[:100]
    log.info("ASN/geo opzoeken voor %d unieke IP's...", len(unique_ips))

    try:
        r = requests.post(
            IPAPI_BATCH_URL,
            json=[{"query": ip, "fields": "status,query,country,countryCode,as,org,isp"} for ip in unique_ips],
            timeout=TIMEOUT,
        )
        r.raise_for_status()
        results = r.json()
    except Exception as e:
        log.error("ip-api.com batch mislukt: %s", e)
        return

    for result in results:
        if result.get("status") != "success":
            continue
        ip = result.get("query")
        # Parseer ASN uit "AS12345 Organisatienaam"
        asn_raw = result.get("as", "")
        asn_num = asn_raw.split(" ")[0] if asn_raw else None
        asn_org = result.get("org") or result.get("isp") or ""

        for item in ip_to_items.get(ip, []):
            item["ip"]           = ip
            item["asn"]          = asn_num
            item["asn_org"]      = asn_org
            item["country"]      = result.get("country")
            item["country_code"] = result.get("countryCode")

    log.info("ASN/geo verrijking klaar.")


# ─── Hulpfuncties ─────────────────────────────────────────────────────────────

def load_json(path, default):
    if path.exists():
        try: return json.loads(path.read_text(encoding="utf-8"))
        except Exception: pass
    return default


# ─── Main ─────────────────────────────────────────────────────────────────────

def main():
    DATA_DIR.mkdir(parents=True, exist_ok=True)

    all_items = []
    all_items.extend(fetch_threatfox(days=1))
    all_items.extend(fetch_urlhaus(limit=100))
    all_items.extend(fetch_malwarebazaar())

    if not all_items and not AUTH_KEY:
        log.error("Geen ABUSECH_AUTH_KEY en geen data. Zet de secret in GitHub.")

    # Dedupe + sorteren
    dedup = {item["id"]: item for item in all_items}
    items = sorted(dedup.values(), key=lambda x: x.get("first_seen", ""), reverse=True)

    # ASN/geo verrijken
    enrich_with_geo(items)

    now = datetime.now(timezone.utc).isoformat()

    # Stats — inclusief per-land en per-ASN top
    by_source     = {}
    by_threat     = {}
    by_country    = {}
    by_asn        = {}

    for item in items:
        by_source[item["source"]]           = by_source.get(item["source"], 0) + 1
        by_threat[item["threat_type"]]      = by_threat.get(item["threat_type"], 0) + 1
        if item.get("country_code"):
            by_country[item["country_code"]] = by_country.get(item["country_code"], 0) + 1
        if item.get("asn"):
            key = f"{item['asn']} {item.get('asn_org','')}"
            by_asn[key] = by_asn.get(key, 0) + 1

    # Top 10 landen en ASN's voor dashboard
    top_countries = sorted(by_country.items(), key=lambda x: x[1], reverse=True)[:10]
    top_asns      = sorted(by_asn.items(),     key=lambda x: x[1], reverse=True)[:10]

    output = {
        "generated_at": now,
        "stats": {
            "total":        len(items),
            "by_source":    by_source,
            "by_threat_type": by_threat,
            "by_country":   dict(top_countries),
            "top_asns":     dict(top_asns),
            "generated_at": now,
        },
        "items": items[:500],
    }

    OUTPUT_FILE.write_text(json.dumps(output, indent=2, ensure_ascii=False), encoding="utf-8")
    log.info("Geschreven: %s (%d items)", OUTPUT_FILE, len(items))

    # Historie
    history = load_json(HISTORY_FILE, [])
    history.append({"ts": now, "total": len(items)})
    history = history[-MAX_HISTORY:]
    HISTORY_FILE.write_text(json.dumps(history, indent=2), encoding="utf-8")

    return 0


if __name__ == "__main__":
    sys.exit(main())
