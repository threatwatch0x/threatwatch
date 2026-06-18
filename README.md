# threatwatch

Open, transparant dashboard boven drie gratis abuse.ch threat-intelligence
feeds: **ThreatFox** (C2-infrastructuur), **URLhaus** (malware-distributie-URL's)
en **MalwareBazaar** (malwaresamples). Geen eigen scanning, geen black box —
alleen aggregatie van publiek beschikbare, community-vetted IOC's, automatisch
bijgewerkt en gepubliceerd als statisch dashboard via GitHub Pages.

Gemaakt naar voorbeeld van commerciële CTI-platforms zoals etugen.io en
SOCRadar, maar volledig open: elke regel code en elke databron is inzichtelijk.

## Hoe het werkt

```
scripts/fetch_feeds.py   →  haalt IOC's op via de officiële abuse.ch API's,
                             normaliseert ze naar één formaat, schrijft
                             data/feed.json

docs/index.html + app.js →  statisch dashboard dat data/feed.json inleest
                             en rendert (stats, filters, zoekbare tabel)

.github/workflows/       →  draait fetch_feeds.py elke 30 minuten via
update-feed.yml             GitHub Actions, commit de nieuwe data, en
                             publiceert docs/ naar GitHub Pages

scripts/post_to_x.py     →  optionele module om nieuwe high-confidence
                             IOC's naar X te posten. Staat in dry-run
                             totdat je de X API keys instelt.
```

## Setup

### 1. Auth-Key bij abuse.ch

Je hebt al een account. Maak (of bekijk) je personal Auth-Key op
<https://auth.abuse.ch/>. Deze key werkt voor ThreatFox, URLhaus én
MalwareBazaar — het is dezelfde key voor alle drie.

### 2. Repository secret instellen

In je GitHub repo: **Settings → Secrets and variables → Actions → New repository secret**

```
Name:  ABUSECH_AUTH_KEY
Value: <jouw auth key>
```

### 3. GitHub Pages activeren

**Settings → Pages → Source: GitHub Actions**

Na de eerste succesvolle workflow-run (handmatig te triggeren via de
**Actions**-tab → "Update threat feed" → **Run workflow**) is het dashboard
bereikbaar op `https://<jouw-gebruikersnaam>.github.io/<repo-naam>/`.

### 4. Lokaal testen (optioneel)

```bash
pip install -r requirements.txt
export ABUSECH_AUTH_KEY="jouw-key-hier"
python3 scripts/fetch_feeds.py
# open docs/index.html in de browser, of serveer lokaal:
cd docs && python3 -m http.server 8000
```

## X (Twitter) posting later activeren

`scripts/post_to_x.py` draait nu altijd in **dry-run**: het logt alleen wat
het zou posten, zonder iets te versturen. Zodra je X API keys hebt:

1. `pip install tweepy` (of voeg `tweepy` toe aan `requirements.txt`)
2. Voeg deze vier repository secrets toe:
   `X_API_KEY`, `X_API_SECRET`, `X_ACCESS_TOKEN`, `X_ACCESS_TOKEN_SECRET`
3. Klaar — de workflow plukt ze automatisch op bij de volgende run.

Het script post alleen IOC's met `confidence >= 75` en maximaal 3 per run,
om geen ruis naar volgers te sturen. Pas `MIN_CONFIDENCE_TO_POST` en
`MAX_POSTS_PER_RUN` aan in het script als je dat wilt bijstellen.

## Attributie en gebruik

Alle data is afkomstig van [abuse.ch](https://abuse.ch) en beschikbaar onder
CC0. abuse.ch is een non-profit onderzoeksinitiatief van de Bern University
of Applied Sciences — geef ze credit als je deze data verder deelt, dat
wordt in de CTI-community gewaardeerd.

Dit project is uitsluitend bedoeld voor defensief gebruik: threat hunting,
blocklisting, onderzoek en bewustwording. Niet bedoeld om aanvallersinfra
actief te benaderen of te verstoren.
