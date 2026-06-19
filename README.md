# threatwatch

Open, transparant dashboard boven drie gratis abuse.ch threat-intelligence
feeds: **ThreatFox** (C2-infrastructuur), **URLhaus** (malware-distributie-URL's)
en **MalwareBazaar** (malwaresamples). Geen eigen scanning, geen black box.
Alleen aggregatie van publiek beschikbare, community-vetted IOC's, automatisch
bijgewerkt en gepubliceerd via GitHub Pages.

Gebouwd als persoonlijk CSIRT-hulpmiddel. Geen X-posting, geen externe
afhankelijkheden buiten abuse.ch en ip-api.com.

Live: https://threatwatch0x.github.io/threatwatch/

## Wat het doet

- Haalt elke 30 minuten nieuwe IOC's op via de officiele abuse.ch API's
- Normaliseert alles naar één formaat en verrijkt IP-gebaseerde IOC's met ASN en geo-data
- Publiceert een statisch dashboard met zoekbalk, bronfilters, ATT&CK heatmap, top landen en top ASN's
- IOC lookup: plak een IP, domein, hash, ASN of landcode en zie direct of het bekend is

## Hoe het werkt

```
scripts/fetch_feeds.py     haalt IOC's op, verrijkt met ASN/geo, schrijft data/feed.json

docs/index.html + app.js   statisch dashboard dat feed.json inleest en rendert

.github/workflows/         draait fetch_feeds.py elke 30 minuten via GitHub Actions,
update-feed.yml            commit de nieuwe data, en publiceert docs/ naar GitHub Pages
```

## Setup

### 1. Auth-Key bij abuse.ch

Maak een gratis account op https://auth.abuse.ch/ en genereer een Auth-Key.
Die key werkt voor ThreatFox, URLhaus en MalwareBazaar tegelijk.

### 2. Repository secret instellen

Settings > Secrets and variables > Actions > New repository secret

```
Name:  ABUSECH_AUTH_KEY
Value: jouw auth key
```

### 3. GitHub Pages activeren

Settings > Pages > Source: GitHub Actions

Na de eerste succesvolle workflow-run is het dashboard bereikbaar op
https://<jouw-gebruikersnaam>.github.io/<repo-naam>/

### 4. Lokaal testen

```bash
pip install -r requirements.txt
export ABUSECH_AUTH_KEY="jouw-key-hier"
python3 scripts/fetch_feeds.py
cd docs && python3 -m http.server 8000
```

## Databronnen

| Bron | Type | Licentie |
|------|------|---------|
| ThreatFox (abuse.ch) | C2-infrastructuur, IOC's | CC0 |
| URLhaus (abuse.ch) | Malware-distributie-URL's | CC0 |
| MalwareBazaar (abuse.ch) | Malwaresamples | CC0 |
| ip-api.com | ASN en geo-verrijking | Gratis voor niet-commercieel gebruik |

## Gebruik

Uitsluitend bedoeld voor defensief gebruik: threat hunting, IOC-verificatie
bij incidenten, blocklisting en bewustwording. Niet bedoeld om
aanvallersinfrastructuur actief te benaderen of te verstoren.

Alle abuse.ch data is CC0. Geef ze credit als je deze data verder deelt,
dat wordt in de CTI-community gewaardeerd.
# laatste handmatige sync: Fri Jun 19 07:01:44 AM UTC 2026
# permissions fix: Fri Jun 19 08:43:36 AM UTC 2026
