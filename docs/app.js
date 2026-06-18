/* threatwatch — dashboard logic v3
 * IOC lookup (incl. ASN/land), ATT&CK heatmap, geo-stats, filterbare feed
 */

const FEED_URL = "feed.json";

let state = {
  items: [],
  sourceFilter: "all",
  query: "",
};

// ─── Data laden ───────────────────────────────────────────────────────────────

async function loadFeed() {
  try {
    const res = await fetch(FEED_URL, { cache: "no-store" });
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const data = await res.json();
    state.items = data.items || [];
    renderStats(data.stats || {});
    renderUpdatedAt(data.generated_at);
    renderTable();
    renderAttackHeatmap();
    renderGeoStats(data.stats || {});
  } catch (err) {
    console.error("Kon feed.json niet laden:", err);
    showError();
  }
}

// ─── Stats ────────────────────────────────────────────────────────────────────

function renderStats(stats) {
  const bySource = stats.by_source || {};
  setText("stat-total",         formatNumber(stats.total ?? 0));
  setText("stat-threatfox",     formatNumber(bySource.ThreatFox || 0));
  setText("stat-urlhaus",       formatNumber(bySource.URLhaus || 0));
  setText("stat-malwarebazaar", formatNumber(bySource.MalwareBazaar || 0));
}

function renderUpdatedAt(isoString) {
  const el = document.getElementById("last-updated");
  if (!isoString) { el.textContent = "laatst bijgewerkt: onbekend"; return; }
  const date = new Date(isoString);
  el.textContent = `laatst bijgewerkt: ${date.toLocaleString("nl-NL", {
    day: "2-digit", month: "short", year: "numeric",
    hour: "2-digit", minute: "2-digit",
  })} UTC`;
}

// ─── Geo stats (top landen + ASN's) ──────────────────────────────────────────

function renderGeoStats(stats) {
  const countries = Object.entries(stats.by_country || {});
  const asns      = Object.entries(stats.top_asns   || {});
  if (countries.length === 0 && asns.length === 0) return;

  const maxC = countries[0]?.[1] || 1;
  const maxA = asns[0]?.[1]      || 1;

  const countryHtml = countries.map(([code, count]) => `
    <div class="geo-row">
      <span class="geo-flag">${countryFlag(code)}</span>
      <span class="geo-label">${code}</span>
      <div class="geo-bar-wrap">
        <div class="geo-bar" style="width:${Math.round(count/maxC*100)}%"></div>
      </div>
      <span class="geo-count">${formatNumber(count)}</span>
    </div>`).join("");

  const asnHtml = asns.map(([asn, count]) => `
    <div class="geo-row">
      <span class="geo-label geo-asn-label" title="${escapeHtml(asn)}">${escapeHtml(asn.length > 30 ? asn.slice(0,30)+"…" : asn)}</span>
      <div class="geo-bar-wrap">
        <div class="geo-bar geo-bar-asn" style="width:${Math.round(count/maxA*100)}%"></div>
      </div>
      <span class="geo-count">${formatNumber(count)}</span>
    </div>`).join("");

  const container = document.getElementById("geo-stats");
  if (!container) return;
  container.innerHTML = `
    <div class="geo-col">
      <div class="lookup-label" style="margin-bottom:12px">
        <svg width="12" height="12" viewBox="0 0 16 16" fill="none">
          <circle cx="8" cy="8" r="6" stroke="var(--signal)" stroke-width="1.5"/>
          <line x1="8" y1="2" x2="8" y2="14" stroke="var(--signal)" stroke-width="1.5"/>
          <line x1="2" y1="8" x2="14" y2="8" stroke="var(--signal)" stroke-width="1.5"/>
        </svg>
        Top landen
      </div>
      ${countryHtml || "<p style='color:var(--ink-faint);font-size:.8rem'>Geen geo-data — voer de workflow opnieuw uit.</p>"}
    </div>
    <div class="geo-col">
      <div class="lookup-label" style="margin-bottom:12px">
        <svg width="12" height="12" viewBox="0 0 16 16" fill="none">
          <rect x="2" y="2" width="5" height="12" rx="1" stroke="var(--signal)" stroke-width="1.5"/>
          <rect x="9" y="5" width="5" height="9" rx="1" stroke="var(--signal)" stroke-width="1.5" opacity=".6"/>
        </svg>
        Top ASN's
      </div>
      ${asnHtml || "<p style='color:var(--ink-faint);font-size:.8rem'>Geen ASN-data.</p>"}
    </div>`;
}

function countryFlag(code) {
  if (!code || code.length !== 2) return "🌐";
  return String.fromCodePoint(...[...code.toUpperCase()].map(c => 0x1F1E6 + c.charCodeAt(0) - 65));
}

// ─── IOC Lookup ───────────────────────────────────────────────────────────────

function setupLookup() {
  const input  = document.getElementById("lookup-input");
  const btn    = document.getElementById("lookup-btn");
  const result = document.getElementById("lookup-result");

  function doLookup() {
    const raw = input.value.trim().toLowerCase();
    if (!raw) { result.innerHTML = ""; return; }

    if (state.items.length === 0) {
      result.innerHTML = `<span class="lookup-warning">Feed nog niet geladen — even wachten.</span>`;
      return;
    }

    const matches = state.items.filter(item =>
      (item.ioc        || "").toLowerCase().includes(raw) ||
      (item.malware    || "").toLowerCase().includes(raw) ||
      (item.asn        || "").toLowerCase().includes(raw) ||
      (item.asn_org    || "").toLowerCase().includes(raw) ||
      (item.country    || "").toLowerCase().includes(raw) ||
      (item.country_code || "").toLowerCase().includes(raw) ||
      (item.tags || []).some(t => t.toLowerCase().includes(raw))
    );

    if (matches.length === 0) {
      result.innerHTML = `
        <span class="lookup-clean">✓ Niet gevonden in huidige feed.</span>
        <span class="lookup-note">Let op: feed bevat alleen de laatste 24u. Oudere IOC's kunnen verlopen zijn.</span>`;
      return;
    }

    const rows = matches.slice(0, 5).map(item => {
      const geo = [item.country_code, item.asn].filter(Boolean).join(" · ");
      return `
        <div class="lookup-hit">
          <span class="source-badge source-${escapeAttr(item.source)}">${escapeHtml(item.source)}</span>
          <span class="lookup-hit-ioc" title="${escapeAttr(item.ioc)}">${escapeHtml(item.ioc)}</span>
          <span class="lookup-hit-malware">${escapeHtml(item.malware)}</span>
          ${geo ? `<span class="lookup-hit-geo">${escapeHtml(geo)}</span>` : ""}
          <span class="lookup-hit-conf">${item.confidence}%</span>
          ${item.reference ? `<a href="${escapeAttr(item.reference)}" target="_blank" rel="noopener" class="ref-link">bekijk →</a>` : ""}
        </div>`;
    }).join("");

    result.innerHTML = `
      <div class="lookup-found">
        <span class="lookup-found-label">⚠ ${matches.length} match${matches.length > 1 ? "es" : ""} gevonden</span>
        ${rows}
        ${matches.length > 5 ? `<p class="lookup-more">+ ${matches.length - 5} meer — gebruik de zoekbalk hieronder.</p>` : ""}
      </div>`;

    state.query = raw;
    document.getElementById("search-input").value = raw;
    renderTable();
    document.querySelector(".panel").scrollIntoView({ behavior: "smooth", block: "start" });
  }

  btn.addEventListener("click", doLookup);
  input.addEventListener("keydown", e => { if (e.key === "Enter") doLookup(); });
}

// ─── ATT&CK Heatmap ───────────────────────────────────────────────────────────

const THREAT_TO_TACTIC = {
  botnet_cc:        { label: "Command & Control", tactic: "C2", color: "#36f2a1" },
  malware_download: { label: "Initial Access",    tactic: "IA", color: "#f2b545" },
  payload:          { label: "Execution",         tactic: "EX", color: "#8fb4ff" },
  payload_delivery: { label: "Delivery",          tactic: "DE", color: "#f2b545" },
  phishing:         { label: "Phishing",          tactic: "PH", color: "#f25c54" },
  ransomware:       { label: "Impact",            tactic: "IM", color: "#f25c54" },
  exploit:          { label: "Exploitation",      tactic: "EP", color: "#c084fc" },
};

function renderAttackHeatmap() {
  const container = document.getElementById("attack-heatmap");
  if (!container || state.items.length === 0) return;

  const counts = {};
  for (const item of state.items) {
    const t = item.threat_type || "unknown";
    counts[t] = (counts[t] || 0) + 1;
  }

  const total  = state.items.length;
  const sorted = Object.entries(counts).sort((a, b) => b[1] - a[1]);
  const max    = sorted[0]?.[1] || 1;

  container.innerHTML = sorted.map(([type, count]) => {
    const meta = THREAT_TO_TACTIC[type] || { label: type, tactic: "?", color: "#4e6059" };
    const pct  = Math.round((count / total) * 100);
    const intensity = Math.max(0.15, count / max);
    return `
      <div class="attack-cell" style="--intensity:${intensity};--cell-color:${meta.color}">
        <div class="attack-cell-bar"></div>
        <div class="attack-cell-info">
          <span class="attack-tactic">${meta.tactic}</span>
          <span class="attack-label">${meta.label}</span>
          <span class="attack-count">${formatNumber(count)} <span class="attack-pct">(${pct}%)</span></span>
        </div>
      </div>`;
  }).join("");
}

// ─── Feed tabel ───────────────────────────────────────────────────────────────

function getFilteredItems() {
  const q = state.query.trim().toLowerCase();
  return state.items.filter(item => {
    if (state.sourceFilter !== "all" && item.source !== state.sourceFilter) return false;
    if (!q) return true;
    return [
      item.malware, item.ioc, item.threat_type, item.threat_type_description,
      item.asn, item.asn_org, item.country, item.country_code,
      ...(item.tags || []),
    ].join(" ").toLowerCase().includes(q);
  });
}

function renderTable() {
  const tbody    = document.getElementById("feed-body");
  const filtered = getFilteredItems();

  if (filtered.length === 0) {
    tbody.innerHTML = `<tr class="empty-row"><td colspan="8">geen indicators gevonden — pas je filter aan</td></tr>`;
    updateFootnote(0);
    return;
  }

  tbody.innerHTML = filtered.slice(0, 200).map(rowHtml).join("");
  updateFootnote(filtered.length);
}

function updateFootnote(count) {
  const el = document.getElementById("table-footnote");
  el.textContent = `${formatNumber(Math.min(count, 200))} van ${formatNumber(count)} indicators weergegeven`;
}

function rowHtml(item) {
  const confidence = Number(item.confidence) || 0;
  const ref  = item.reference
    ? `<a class="ref-link" href="${escapeAttr(item.reference)}" target="_blank" rel="noopener">bekijk →</a>`
    : "";
  const geo = item.country_code
    ? `<span title="${escapeHtml(item.country || "")} · ${escapeHtml(item.asn_org || "")}">${countryFlag(item.country_code)} ${escapeHtml(item.country_code)}${item.asn ? ` <span class="asn-tag">${escapeHtml(item.asn)}</span>` : ""}</span>`
    : `<span class="cell-dim">—</span>`;

  return `
    <tr>
      <td class="cell-time">${escapeHtml(formatRelative(item.first_seen))}</td>
      <td><span class="source-badge source-${escapeAttr(item.source)}">${escapeHtml(item.source)}</span></td>
      <td class="cell-ioc" title="${escapeAttr(item.ioc)}">${escapeHtml(item.ioc)}</td>
      <td class="cell-type">${escapeHtml(item.ioc_type)}</td>
      <td class="cell-malware">${escapeHtml(item.malware)}</td>
      <td class="cell-geo">${geo}</td>
      <td>
        <div class="confidence-bar-wrap">
          <div class="confidence-bar"><div class="confidence-bar-fill" style="width:${confidence}%"></div></div>
          <span class="confidence-value">${confidence}%</span>
        </div>
      </td>
      <td>${ref}</td>
    </tr>`;
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

function formatRelative(value) {
  if (!value) return "—";
  const date = new Date(value.replace(" UTC","Z").replace(" ","T"));
  if (isNaN(date.getTime())) return value;
  const diffMin = Math.round((Date.now() - date.getTime()) / 60000);
  if (diffMin < 1)  return "net nu";
  if (diffMin < 60) return `${diffMin} min geleden`;
  const diffH = Math.round(diffMin / 60);
  if (diffH < 24)   return `${diffH} u geleden`;
  return `${Math.round(diffH / 24)} d geleden`;
}

function formatNumber(n) { return new Intl.NumberFormat("nl-NL").format(n); }
function setText(id, v)  { const el = document.getElementById(id); if (el) el.textContent = v; }
function escapeHtml(s)   { return String(s ?? "").replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;"); }
function escapeAttr(s)   { return escapeHtml(s).replace(/"/g,"&quot;"); }

function showError() {
  document.getElementById("feed-body").innerHTML = `
    <tr class="empty-row">
      <td colspan="8">kon de feed niet laden. Wacht op de volgende GitHub Actions run.</td>
    </tr>`;
}

// ─── Controls ─────────────────────────────────────────────────────────────────

function setupControls() {
  document.querySelectorAll("[data-filter-source]").forEach(btn => {
    btn.addEventListener("click", () => {
      document.querySelectorAll("[data-filter-source]").forEach(b => b.classList.remove("is-active"));
      btn.classList.add("is-active");
      state.sourceFilter = btn.dataset.filterSource;
      renderTable();
    });
  });

  document.getElementById("search-input").addEventListener("input", e => {
    state.query = e.target.value;
    renderTable();
  });
}

// ─── Init ─────────────────────────────────────────────────────────────────────

setupControls();
setupLookup();
loadFeed();

setInterval(loadFeed, 2 * 60 * 1000);
