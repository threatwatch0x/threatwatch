/* threatwatch — dashboard logic
 * Leest data/feed.json (gegenereerd door scripts/fetch_feeds.py)
 * en rendert stats + een filterbare/zoekbare tabel.
 */

const FEED_URL = "feed.json";

let state = {
  items: [],
  sourceFilter: "all",
  query: "",
};

async function loadFeed() {
  try {
    const res = await fetch(FEED_URL, { cache: "no-store" });
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const data = await res.json();
    state.items = data.items || [];
    renderStats(data.stats || {});
    renderUpdatedAt(data.generated_at);
    renderTable();
  } catch (err) {
    console.error("Kon feed.json niet laden:", err);
    showError();
  }
}

function renderStats(stats) {
  const total = stats.total ?? 0;
  const bySource = stats.by_source || {};
  setText("stat-total", formatNumber(total));
  setText("stat-threatfox", formatNumber(bySource.ThreatFox || 0));
  setText("stat-urlhaus", formatNumber(bySource.URLhaus || 0));
  setText("stat-malwarebazaar", formatNumber(bySource.MalwareBazaar || 0));
}

function renderUpdatedAt(isoString) {
  const el = document.getElementById("last-updated");
  if (!isoString) {
    el.textContent = "laatst bijgewerkt: onbekend";
    return;
  }
  const date = new Date(isoString);
  const formatted = date.toLocaleString("nl-NL", {
    day: "2-digit", month: "short", year: "numeric",
    hour: "2-digit", minute: "2-digit",
  });
  el.textContent = `laatst bijgewerkt: ${formatted} UTC`;
}

function setText(id, value) {
  const el = document.getElementById(id);
  if (el) el.textContent = value;
}

function formatNumber(n) {
  return new Intl.NumberFormat("nl-NL").format(n);
}

function getFilteredItems() {
  const q = state.query.trim().toLowerCase();
  return state.items.filter((item) => {
    if (state.sourceFilter !== "all" && item.source !== state.sourceFilter) return false;
    if (!q) return true;
    const haystack = [
      item.malware, item.ioc, item.threat_type, item.threat_type_description,
      ...(item.tags || []),
    ].join(" ").toLowerCase();
    return haystack.includes(q);
  });
}

function renderTable() {
  const tbody = document.getElementById("feed-body");
  const filtered = getFilteredItems();

  if (filtered.length === 0) {
    tbody.innerHTML = `
      <tr class="empty-row">
        <td colspan="7">geen indicators gevonden voor dit filter — pas je zoekopdracht aan</td>
      </tr>`;
    updateFootnote(0);
    return;
  }

  const rows = filtered.slice(0, 200).map(rowHtml).join("");
  tbody.innerHTML = rows;
  updateFootnote(filtered.length);
}

function updateFootnote(count) {
  const el = document.getElementById("table-footnote");
  const shown = Math.min(count, 200);
  el.textContent = `${formatNumber(shown)} van ${formatNumber(count)} indicators weergegeven`;
}

function rowHtml(item) {
  const time = formatRelativeOrDate(item.first_seen);
  const confidence = Number(item.confidence) || 0;
  const ref = item.reference
    ? `<a class="ref-link" href="${escapeAttr(item.reference)}" target="_blank" rel="noopener">bekijk →</a>`
    : "";

  return `
    <tr>
      <td class="cell-time">${escapeHtml(time)}</td>
      <td><span class="source-badge source-${escapeAttr(item.source)}">${escapeHtml(item.source)}</span></td>
      <td class="cell-ioc" title="${escapeAttr(item.ioc)}">${escapeHtml(item.ioc)}</td>
      <td class="cell-type">${escapeHtml(item.ioc_type)}</td>
      <td class="cell-malware">${escapeHtml(item.malware)}</td>
      <td>
        <div class="confidence-bar-wrap">
          <div class="confidence-bar"><div class="confidence-bar-fill" style="width:${confidence}%"></div></div>
          <span class="confidence-value">${confidence}%</span>
        </div>
      </td>
      <td>${ref}</td>
    </tr>`;
}

function formatRelativeOrDate(value) {
  if (!value) return "—";
  // abuse.ch geeft vaak "YYYY-MM-DD HH:MM:SS UTC" of soortgelijk
  const normalized = value.replace(" UTC", "Z").replace(" ", "T");
  const date = new Date(normalized);
  if (isNaN(date.getTime())) return value;

  const diffMs = Date.now() - date.getTime();
  const diffMin = Math.round(diffMs / 60000);
  if (diffMin < 1) return "net nu";
  if (diffMin < 60) return `${diffMin} min geleden`;
  const diffH = Math.round(diffMin / 60);
  if (diffH < 24) return `${diffH} u geleden`;
  const diffD = Math.round(diffH / 24);
  if (diffD < 7) return `${diffD} d geleden`;
  return date.toLocaleDateString("nl-NL", { day: "2-digit", month: "short" });
}

function escapeHtml(str) {
  if (str === undefined || str === null) return "";
  return String(str)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;");
}

function escapeAttr(str) {
  return escapeHtml(str).replace(/"/g, "&quot;");
}

function showError() {
  const tbody = document.getElementById("feed-body");
  tbody.innerHTML = `
    <tr class="empty-row">
      <td colspan="7">
        kon de feed niet laden. Is data/feed.json al gegenereerd?
        Draai scripts/fetch_feeds.py of wacht op de eerste GitHub Actions run.
      </td>
    </tr>`;
}

function setupControls() {
  document.querySelectorAll("[data-filter-source]").forEach((btn) => {
    btn.addEventListener("click", () => {
      document.querySelectorAll("[data-filter-source]").forEach((b) => b.classList.remove("is-active"));
      btn.classList.add("is-active");
      state.sourceFilter = btn.dataset.filterSource;
      renderTable();
    });
  });

  const searchInput = document.getElementById("search-input");
  searchInput.addEventListener("input", (e) => {
    state.query = e.target.value;
    renderTable();
  });
}

setupControls();
loadFeed();

// Live feel: herlaad de data periodiek zonder dat de gebruiker moet verversen.
// De onderliggende feed.json wordt door GitHub Actions elke 30 min bijgewerkt,
// dus elke 2 minuten checken is ruim voldoende en kost niets extra (statisch bestand).
setInterval(loadFeed, 2 * 60 * 1000);
