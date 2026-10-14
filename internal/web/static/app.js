// Device list behaviour: live refresh, client-side filtering, and the archived
// toggle. Naming, history and everything else about a single device live on its
// own page; see device.js.
//
// No framework, no build step; the page works (statically) without any of this.
(() => {
  "use strict";

  const csrf = document.body.dataset.csrf || "";
  const WEB_CLIENT = document.body.dataset.webclient === "1";
  const list = document.getElementById("devices");
  const filter = document.getElementById("filter");
  const REFRESH_MS = 10000;

  const esc = (s) => String(s ?? "").replace(/[&<>"']/g,
    (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));

  const formatID = (id) => (id.length < 7 ? id : id.replace(/\B(?=(\d{3})+(?!\d))/g, " "));

  function relTime(iso) {
    if (!iso) return null;
    const secs = (Date.now() - new Date(iso).getTime()) / 1000;
    if (secs < 60) return "just now";
    if (secs < 3600) return `${Math.floor(secs / 60)}m ago`;
    if (secs < 86400) return `${Math.floor(secs / 3600)}h ago`;
    return `${Math.floor(secs / 86400)}d ago`;
  }

  async function api(url, options = {}) {
    const res = await fetch(url, {
      ...options,
      headers: { "X-CSRF-Token": csrf, "Content-Type": "application/json", ...(options.headers || {}) },
    });
    if (res.status === 401) { location.href = "/login"; throw new Error("unauthenticated"); }
    if (!res.ok) {
      const body = await res.json().catch(() => ({}));
      throw new Error(body.error || `request failed (${res.status})`);
    }
    return res.json();
  }

  // Which devices have a saved password, and whether saving is configured at
  // all. Both come from /api/devices so a refresh cannot wipe the indicator.
  let saved = {};
  let canSave = false;
  let intel = {};

  function renderDevice(d) {
    const seen = d.online ? "online now"
      : d.last_seen ? `last seen ${relTime(d.last_seen)}`
      : "not seen yet";
    // Alias wins, then a reverse-DNS hostname, then the bare ID.
    const name = d.alias || d.hostname || "";
    const label = name || formatID(d.id);
    const title = d.alias ? "Click to rename"
      : d.hostname ? "Name from reverse DNS — click to override"
      : "Click to name";
    const addr = d.ip ? ` <span class="addr">(${esc(d.ip)})</span>` : "";
    const href = `/device/${encodeURIComponent(d.id)}`;
    const alias = `<a class="alias${name ? "" : " unnamed"}" href="${href}" `
      + `title="Everything known about this device">${esc(label)}${addr}</a>`;

    return `<li class="device${d.online ? " online" : ""}${d.archived ? " archived" : ""}"
        data-id="${esc(d.id)}" data-alias="${esc(d.alias)}"
        data-archived="${d.archived ? "1" : "0"}"
        data-search="${esc(`${d.alias} ${d.hostname} ${d.id} ${d.ip} ${d.note}`)}">
      <span class="dot" title="${d.online ? "Online" : "Offline"}" aria-hidden="true"></span>
      <div class="identity">
        ${alias}
        <p class="meta">
          ${name ? `<span class="id">${esc(formatID(d.id))}</span><span class="sep">·</span>` : ""}
          <span class="seen">${esc(seen)}</span>
          ${intel[d.id] ? `<span class="sep">·</span><span class="has-intel">intel</span>` : ""}
        </p>
        ${d.note ? `<p class="note">${esc(d.note)}</p>` : ""}
      </div>
      <div class="actions">
        ${WEB_CLIENT ? `<a class="connect" href="/client?id=${encodeURIComponent(d.id)}"
           title="Control this device in your browser">Browser</a>
        <a class="connect ghost-link" href="/files?id=${encodeURIComponent(d.id)}"
           title="Files only — the desktop is never shown">Files</a>
        <a class="connect ghost-link" href="/terminal?id=${encodeURIComponent(d.id)}"
           title="Terminal only — the desktop is never shown">Terminal</a>` : ""}
        <a class="connect ghost-link" href="rustdesk://connection/new/${encodeURIComponent(d.id)}"
           title="Open in your RustDesk app">App</a>
        <a class="connect ghost-link" href="${href}"
           title="Everything known about this device">Details</a>
        ${canSave && saved[d.id] ? `<button class="ghost saved" data-action="forget"
           title="This device's password is saved — click to forget it">Password saved</button>` : ""}
      </div>
    </li>`;
  }

  async function refresh() {
    try {
      const snap = await api("/api/devices");
      const devices = snap.devices || [];
      saved = snap.saved || {};
      canSave = !!snap.can_save;
      intel = snap.intel || {};
      if (list) list.innerHTML = devices.map(renderDevice).join("");
      document.getElementById("count-total").textContent =
        devices.length - (snap.archived || 0);
      document.getElementById("count-online").textContent = snap.online;
      const archivedToggle = document.getElementById("archived-toggle");
      if (archivedToggle) {
        document.getElementById("count-archived").textContent = snap.archived || 0;
        archivedToggle.hidden = !snap.archived;
      }
      document.getElementById("updated").textContent = relTime(snap.updated_at) || "just now";
      applyFilter();
    } catch (err) {
      // A failed refresh leaves the last good list on screen; the server-rendered
      // banner covers poller-side failures.
      console.warn("refresh failed:", err.message);
    }
  }

  function applyFilter() {
    const q = (filter?.value || "").trim().toLowerCase();
    const showArchived = !!document.getElementById("show-archived")?.checked;
    for (const el of document.querySelectorAll(".device")) {
      const hay = (el.dataset.search || "").toLowerCase();
      const archived = el.dataset.archived === "1";
      el.hidden = (q !== "" && !hay.includes(q)) || (archived && !showArchived);
    }
  }

  document.addEventListener("click", (e) => {
    const btn = e.target.closest("[data-action]");
    if (!btn) return;
    const li = btn.closest(".device");
    if (!li) return;

    if (btn.dataset.action === "forget") {
      forgetPassword(li.dataset.id, btn);
    }
  });

  // Drop a saved device password. The row is updated immediately rather than
  // waiting for the next refresh, so the click visibly did something.
  async function forgetPassword(id, btn) {
    if (!confirm("Forget the saved password for this device?")) return;
    btn.disabled = true;
    try {
      await api(`/api/devices/${encodeURIComponent(id)}/secret`, { method: "DELETE" });
      delete saved[id];
      btn.remove();
    } catch (err) {
      btn.disabled = false;
      alert(`Could not forget the password: ${err.message}`);
    }
  }

  filter?.addEventListener("input", applyFilter);
  document.getElementById("show-archived")?.addEventListener("change", applyFilter);
  // The page arrives server-rendered with every device in it, archived ones
  // included. Filter once now rather than leaving them on screen until the
  // first refresh.
  applyFilter();
  setInterval(refresh, REFRESH_MS);
})();
