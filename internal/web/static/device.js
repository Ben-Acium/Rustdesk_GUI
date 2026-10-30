// The device detail page: show everything known about one machine, and run a
// collection to learn more.
//
// The collection itself happens in the browser because that is where the
// RustDesk client is — see webclient-ext/rdgui-intel.ts. This file owns the
// page: the password prompt, the progress log, the rendering, and sending the
// result back to the server. It never parses probe output; the server does
// that, so there is one parser rather than two that drift.
(() => {
  "use strict";

  const body = document.body;
  const csrf = body.dataset.csrf || "";
  const peerId = body.dataset.peerId || "";
  const canCollect = body.dataset.webclient === "1";
  const canSave = body.dataset.canSave === "1";
  const PW_PREFIX = "cortendesk.rdpw.";

  const dialog = document.getElementById("dialog");
  const statusEl = document.getElementById("intel-status");
  const progressEl = document.getElementById("intel-progress");
  const bodyEl = document.getElementById("intel-body");
  const runBtn = document.getElementById("intel-run");
  const discardBtn = document.getElementById("intel-discard");

  const esc = (s) => String(s ?? "").replace(/[&<>"']/g,
    (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));

  async function api(url, options = {}) {
    const res = await fetch(url, {
      ...options,
      headers: { "X-CSRF-Token": csrf, "Content-Type": "application/json", ...(options.headers || {}) },
    });
    if (res.status === 401) { location.href = "/login"; throw new Error("unauthenticated"); }
    if (!res.ok) {
      const payload = await res.json().catch(() => ({}));
      throw new Error(payload.error || `request failed (${res.status})`);
    }
    return res.status === 204 ? null : res.json();
  }

  // ---- formatting -------------------------------------------------------

  function fmtKB(kb) {
    const n = Number(kb);
    if (!Number.isFinite(n) || n < 0) return "";
    if (n === 0) return "0";
    const units = ["KB", "MB", "GB", "TB", "PB"];
    let v = n, i = 0;
    while (v >= 1024 && i < units.length - 1) { v /= 1024; i++; }
    return `${v >= 100 || i === 0 ? Math.round(v) : v.toFixed(1)} ${units[i]}`;
  }

  function fmtDuration(secs) {
    const n = Math.floor(Number(secs));
    if (!Number.isFinite(n) || n <= 0) return "";
    const d = Math.floor(n / 86400);
    const h = Math.floor((n % 86400) / 3600);
    const m = Math.floor((n % 3600) / 60);
    if (d > 0) return `${d}d ${h}h`;
    if (h > 0) return `${h}h ${m}m`;
    return `${m}m`;
  }

  function fmtMHz(mhz) {
    const n = Number(mhz);
    return Number.isFinite(n) && n > 0 ? `${(n / 1000).toFixed(2)} GHz` : "";
  }

  function relTime(iso) {
    if (!iso) return "never";
    const secs = (Date.now() - new Date(iso).getTime()) / 1000;
    const ago = (n, unit) => `${n} ${unit}${n === 1 ? "" : "s"} ago`;
    if (secs < 60) return "just now";
    if (secs < 3600) return ago(Math.floor(secs / 60), "minute");
    if (secs < 86400) return ago(Math.floor(secs / 3600), "hour");
    return ago(Math.floor(secs / 86400), "day");
  }

  // ---- what each key is called, and in what order -----------------------
  //
  // A key not listed here still renders, under "Other". That is deliberate:
  // adding a line to a probe script should show up in the UI without needing
  // a matching change in this file.
  const SECTIONS = [
    { title: "Identity", fields: [
      ["host.name", "Hostname"],
      ["host.fqdn", "Fully-qualified name"],
      ["user.current", "Signed-in user"],
      ["user.logged", "Logged in now"],
      ["hw.domain", "Domain"],
      ["hw.machine_id", "Machine ID"],
    ] },
    { title: "Operating system", fields: [
      ["os.name", "Name"],
      ["os.version", "Version"],
      ["os.build", "Build"],
      ["os.kernel", "Kernel"],
      ["os.arch", "Architecture"],
      ["os.virt", "Virtualisation"],
      ["os.uptime_s", "Uptime", fmtDuration],
      ["os.boot", "Last booted"],
      ["os.load", "Load average"],
      ["os.shell", "Default shell"],
      ["os.install", "Installed"],
      ["os.updates", "Latest update"],
    ] },
    { title: "Processor and memory", fields: [
      ["cpu.model", "Processor", null, true],
      ["cpu.cores", "Cores"],
      ["cpu.threads", "Threads"],
      ["cpu.mhz", "Clock", fmtMHz],
      ["mem.total_kb", "Memory", fmtKB],
      ["mem.available_kb", "Memory free", fmtKB],
      ["mem.swap_kb", "Swap", fmtKB],
    ] },
    { title: "Chassis and firmware", fields: [
      ["hw.vendor", "Manufacturer"],
      ["hw.model", "Model", null, true],
      ["hw.version", "Model version"],
      ["hw.serial", "Serial number"],
      ["hw.board", "Mainboard"],
      ["hw.bios", "Firmware", null, true],
      ["hw.battery", "Battery", (v) => (v ? `${v}%` : "")],
    ] },
    { title: "Software", fields: [
      ["pkg.dpkg", "Debian packages"],
      ["pkg.rpm", "RPM packages"],
      ["pkg.pacman", "Pacman packages"],
      ["pkg.brew", "Homebrew formulae"],
      ["pkg.apps", "Applications"],
      ["pkg.installed", "Installed programs"],
      ["pkg.updates", "Updates pending"],
      ["svc.running", "Services running"],
      ["svc.failed", "Services failed", null, true],
    ] },
  ];

  // Keys rendered by a dedicated block rather than as a plain field.
  const SPECIAL = new Set([
    "disk", "blockdev", "net.iface", "net.ipv4", "net.ipv6", "net.gateway",
    "net.dns", "net.listening", "gpu", "sw", "time.zone", "time.local",
    "time.offset", "probe.platform",
  ]);

  // ---- rendering --------------------------------------------------------

  function factsGrid(facts, fields, used) {
    const items = [];
    for (const [key, label, fmt, wrap] of fields) {
      const raw = (facts[key] || [])[0];
      if (raw === undefined) continue;
      used.add(key);
      const value = fmt ? fmt(raw) : raw;
      if (!value) continue;
      items.push(`<div><dt>${esc(label)}</dt><dd class="${wrap ? "wrap" : ""}">${esc(value)}</dd></div>`);
    }
    return items;
  }

  function section(title, inner) {
    return inner ? `<section class="intel-section"><h3>${esc(title)}</h3>${inner}</section>` : "";
  }

  function usageBar(percentText) {
    const pct = Math.max(0, Math.min(100, parseInt(percentText, 10)));
    if (!Number.isFinite(pct)) return esc(percentText || "");
    const cls = pct >= 90 ? "bar full" : pct >= 75 ? "bar warn" : "bar";
    return `<span class="${cls}"><i style="width:${pct}%"></i><span>${pct}%</span></span>`;
  }

  function renderStorage(facts, used) {
    const rows = [];
    for (const line of facts["disk"] || []) {
      used.add("disk");
      const [mount, fs, total, usedKB, avail, pct] = line.split("|");
      rows.push(`<tr>
        <td class="name">${esc(mount)}</td>
        <td class="name">${esc(fs || "")}</td>
        <td class="num">${esc(fmtKB(total))}</td>
        <td class="num">${esc(fmtKB(usedKB))}</td>
        <td class="num">${esc(fmtKB(avail))}</td>
        <td>${usageBar(pct)}</td></tr>`);
    }
    let out = "";
    if (rows.length) {
      out += `<table class="intel"><thead><tr>
        <th>Mounted at</th><th>Type</th><th>Size</th><th>Used</th><th>Free</th><th>Usage</th>
      </tr></thead><tbody>${rows.join("")}</tbody></table>`;
    }
    const drives = (facts["blockdev"] || []).map((l) => {
      used.add("blockdev");
      return l.split("|").map((f) => f.trim()).filter(Boolean).join(" · ");
    });
    if (drives.length) {
      out += `<dl class="facts" style="margin-top:10px">${drives
        .map((d) => `<div><dt>Drive</dt><dd class="wrap">${esc(d)}</dd></div>`).join("")}</dl>`;
    }
    return out;
  }

  function renderNetwork(facts, used) {
    const addrs = new Map();
    for (const key of ["net.ipv4", "net.ipv6"]) {
      for (const line of facts[key] || []) {
        used.add(key);
        const [iface, addr] = line.split("|");
        if (!addrs.has(iface)) addrs.set(iface, []);
        addrs.get(iface).push(addr);
      }
    }

    const rows = [];
    for (const line of facts["net.iface"] || []) {
      used.add("net.iface");
      const [name, mac, state] = line.split("|");
      const cls = /up|connected/i.test(state || "") ? "pill up" : "pill";
      rows.push(`<tr>
        <td class="name">${esc(name)}</td>
        <td class="name">${esc((addrs.get(name) || []).join(", "))}</td>
        <td class="name">${esc(mac || "")}</td>
        <td>${state ? `<span class="${cls}">${esc(state)}</span>` : ""}</td></tr>`);
      addrs.delete(name);
    }
    // Addresses on interfaces the probe did not list separately.
    for (const [name, list] of addrs) {
      rows.push(`<tr><td class="name">${esc(name)}</td>
        <td class="name">${esc(list.join(", "))}</td><td></td><td></td></tr>`);
    }

    let out = "";
    if (rows.length) {
      out += `<table class="intel"><thead><tr>
        <th>Interface</th><th>Addresses</th><th>MAC</th><th>State</th>
      </tr></thead><tbody>${rows.join("")}</tbody></table>`;
    }
    const extra = factsGrid(facts, [
      ["net.gateway", "Default gateway"],
      ["net.dns", "DNS servers", null, true],
      ["net.listening", "Listening on", null, true],
    ], used);
    if (extra.length) out += `<dl class="facts" style="margin-top:10px">${extra.join("")}</dl>`;
    return out;
  }

  function renderGraphics(report, facts, used) {
    const items = (facts["gpu"] || []).map((g) => {
      used.add("gpu");
      return `<div><dt>Adapter</dt><dd class="wrap">${esc(g)}</dd></div>`;
    });
    for (const d of report.peer?.displays || []) {
      const label = d.name || "Display";
      const size = d.width && d.height ? `${d.width} × ${d.height}` : "";
      const scale = d.scale && d.scale !== 1 ? ` @ ${d.scale}×` : "";
      items.push(`<div><dt>${esc(label)}</dt><dd>${esc(size + scale)}</dd></div>`);
    }
    return items.length ? `<dl class="facts">${items.join("")}</dl>` : "";
  }

  function renderInstalled(facts, used) {
    const items = (facts["sw"] || []).map((line) => {
      used.add("sw");
      const [name, ...rest] = line.split("|");
      return `<div><dt>${esc(name)}</dt><dd class="wrap">${esc(rest.join("|"))}</dd></div>`;
    });
    return items.length ? `<dl class="facts">${items.join("")}</dl>` : "";
  }

  function renderLocation(report, facts, used) {
    const items = factsGrid(facts, [
      ["time.zone", "Time zone"],
      ["time.local", "Local time"],
      ["time.offset", "UTC offset"],
    ], used);

    const geo = report.geo;
    if (geo) {
      const place = [geo.city, geo.region, geo.country].filter(Boolean).join(", ");
      if (place) items.push(`<div><dt>Approximate location</dt><dd class="wrap">${esc(place)}</dd></div>`);
      if (geo.zip) items.push(`<div><dt>Postcode</dt><dd>${esc(geo.zip)}</dd></div>`);
      if (geo.isp) items.push(`<div><dt>Network</dt><dd class="wrap">${esc(geo.isp)}</dd></div>`);
      if (geo.org && geo.org !== geo.isp) items.push(`<div><dt>Organisation</dt><dd class="wrap">${esc(geo.org)}</dd></div>`);
      if (geo.as) items.push(`<div><dt>Autonomous system</dt><dd class="wrap">${esc(geo.as)}</dd></div>`);
      if (geo.lat || geo.lon) {
        const q = encodeURIComponent(`${geo.lat},${geo.lon}`);
        items.push(`<div><dt>Coordinates</dt><dd><a href="https://www.openstreetmap.org/?mlat=${encodeURIComponent(geo.lat)}&amp;mlon=${encodeURIComponent(geo.lon)}#map=10/${q.replace("%2C", "/")}" target="_blank" rel="noreferrer noopener">${esc(geo.lat)}, ${esc(geo.lon)}</a></dd></div>`);
      }
    }
    if (report.server_ip) {
      items.push(`<div><dt>Address seen by the server</dt><dd>${esc(report.server_ip)}</dd></div>`);
    }
    if (!items.length) return "";

    const note = geo
      ? `<p class="meta" style="margin-top:8px">Location is approximate, derived from
         the device's public address by ${esc(geo.source)}. It locates the network,
         not the machine.</p>`
      : "";
    return `<dl class="facts">${items.join("")}</dl>${note}`;
  }

  function renderOther(facts, used) {
    const items = [];
    for (const key of Object.keys(facts).sort()) {
      if (used.has(key) || SPECIAL.has(key)) continue;
      for (const value of facts[key]) {
        items.push(`<div><dt>${esc(key)}</dt><dd class="wrap">${esc(value)}</dd></div>`);
      }
    }
    return items.length ? `<dl class="facts">${items.join("")}</dl>` : "";
  }

  function renderReport(report) {
    if (!report) {
      discardBtn.hidden = true;
      document.querySelector(".probe-tail")?.remove();
      statusEl.textContent = canCollect
        ? "Nothing collected yet."
        : "Nothing collected yet, and the browser client is not available to collect it.";
      bodyEl.innerHTML = `
        <p class="intel-empty">The RustDesk server records only a device's ID and the
           address it last registered from. Everything else — hostname, operating system,
           hardware, disks, network — has to be asked for.</p>
        <p class="intel-empty">Collecting opens a terminal connection to the device, reads
           the handshake, runs one read-only script, and stores the answers here. The
           remote screen is never requested and nothing on the device is changed.</p>`;
      return;
    }

    discardBtn.hidden = false;
    document.querySelector(".probe-tail")?.remove();
    const probe = report.probe || {};
    const facts = report.facts || {};
    const used = new Set();

    const bits = [`Collected ${relTime(report.collected_at)}`];
    if (probe.ran && probe.complete) {
      bits.push(`probe finished in ${(probe.duration_ms / 1000).toFixed(1)}s`);
    } else if (probe.error) {
      bits.push(probe.error);
    }
    statusEl.textContent = bits.join(" · ");

    // What the shell was actually doing beats "it did not finish in time".
    if (probe.tail) {
      statusEl.insertAdjacentHTML("afterend",
        `<details class="probe-tail"><summary>What the terminal said</summary>
           <pre>${esc(probe.tail)}</pre></details>`);
    }

    const peer = report.peer || {};
    const handshake = [];
    if (peer.version) handshake.push(["RustDesk version", peer.version]);
    if (peer.platform) handshake.push(["Platform", peer.platform]);
    if (peer.hostname && !facts["host.name"]) handshake.push(["Hostname", peer.hostname]);
    if (peer.username && !facts["user.current"]) handshake.push(["Signed-in user", peer.username]);
    handshake.push(["Terminal access", peer.terminal_supported ? "Offered" : "Not offered"]);

    let html = "";
    for (const sec of SECTIONS) {
      const items = factsGrid(facts, sec.fields, used);
      // The handshake facts belong with identity, not in a box of their own.
      if (sec.title === "Identity") {
        for (const [label, value] of handshake) {
          items.push(`<div><dt>${esc(label)}</dt><dd class="wrap">${esc(value)}</dd></div>`);
        }
      }
      html += section(sec.title, items.length ? `<dl class="facts">${items.join("")}</dl>` : "");
    }
    html += section("Storage", renderStorage(facts, used));
    html += section("Network", renderNetwork(facts, used));
    html += section("Graphics and displays", renderGraphics(report, facts, used));
    html += section("Installed software", renderInstalled(facts, used));
    html += section("Time and location", renderLocation(report, facts, used));
    html += section("Other", renderOther(facts, used));

    if (!Object.keys(facts).length) {
      html = `<p class="intel-empty">Only handshake facts were collected${
        probe.error ? `: ${esc(probe.error)}` : "."
      }</p>` + html;
    }
    bodyEl.innerHTML = html;
  }

  // ---- collecting -------------------------------------------------------

  let logLines = [];

  function log(message, failed) {
    logLines.push(`<li${failed ? ' class="failed"' : ""}>${esc(message)}</li>`);
    progressEl.innerHTML = logLines.join("");
    progressEl.hidden = false;
    progressEl.scrollTop = progressEl.scrollHeight;
  }

  async function collectIntel() {
    if (!canCollect) return;

    const savedHash = (() => {
      try { return localStorage.getItem(PW_PREFIX + peerId) || ""; } catch { return ""; }
    })();

    let password = "";
    let remember = false;
    if (!savedHash) {
      const asked = await askForPassword();
      if (asked === null) return;
      password = asked.password;
      remember = asked.remember;
    }

    runBtn.disabled = true;
    const label = runBtn.textContent;
    runBtn.textContent = "Collecting…";
    logLines = [];
    log("Starting…");

    // Saving the credential is upstream's own path: writing it to localStorage
    // is what sends it to this server, via the mirror in rdclient-compat.js.
    if (remember && window.__RDGUI__ && window.__RDGUI__.onCredential) {
      window.__RDGUI__.onCredential((hash) => {
        try { localStorage.setItem(PW_PREFIX + peerId, hash); } catch { /* blocked storage */ }
      });
    }

    try {
      const mod = await import("/rdclient/rdgui-intel.js");
      const collector = (window.__RDGUI_INTEL__ || mod);
      const result = await collector.collect({
        peerId,
        password,
        savedHash: savedHash || undefined,
        onProgress: (m) => log(m),
        fetchProbe: (platform) =>
          api(`/api/devices/${encodeURIComponent(peerId)}/probe?platform=${encodeURIComponent(platform || "")}`),
      });

      if (result.probe && result.probe.error) log(result.probe.error, true);
      log("Storing…");
      const stored = await api(`/api/devices/${encodeURIComponent(peerId)}/intel`, {
        method: "PUT",
        body: JSON.stringify(result),
      });
      log(`Done — ${Object.keys(stored.facts || {}).length} facts recorded.`);
      renderReport(stored);
      setTimeout(() => { progressEl.hidden = true; }, 4000);
    } catch (err) {
      log(err.message || String(err), true);
    } finally {
      runBtn.disabled = false;
      runBtn.textContent = label;
    }
  }

  function askForPassword() {
    return new Promise((resolve) => {
      dialog.innerHTML = `
        <form method="dialog" id="pw-form">
          <h2>Connect to collect</h2>
          <p class="meta">Intel opens a terminal connection to this device. The remote
             screen is never requested and nothing is changed.</p>
          <label for="pw-input">Device password</label>
          <input id="pw-input" type="password" autocomplete="off" autofocus>
          <p class="meta">Leave empty to ask the person at the device to approve instead.</p>
          ${canSave ? `<label class="check"><input type="checkbox" id="pw-remember">
             Remember this device's password</label>` : ""}
          <div class="dialog-actions">
            <button type="button" class="ghost" data-action="cancel">Cancel</button>
            <button type="submit">Connect</button>
          </div>
        </form>`;
      dialog.showModal();

      const done = (value) => { dialog.close(); dialog.innerHTML = ""; resolve(value); };
      dialog.querySelector('[data-action="cancel"]').addEventListener("click", () => done(null));
      dialog.querySelector("#pw-form").addEventListener("submit", (e) => {
        e.preventDefault();
        done({
          password: dialog.querySelector("#pw-input").value,
          remember: !!dialog.querySelector("#pw-remember")?.checked,
        });
      });
    });
  }

  // ---- the rest of the page ---------------------------------------------

  async function loadReport() {
    try {
      renderReport(await api(`/api/devices/${encodeURIComponent(peerId)}/intel`));
    } catch (err) {
      statusEl.textContent = `Could not load: ${err.message}`;
    }
  }

  async function discardIntel() {
    if (!confirm("Discard what has been collected about this device?")) return;
    try {
      await api(`/api/devices/${encodeURIComponent(peerId)}/intel`, { method: "DELETE" });
      renderReport(null);
    } catch (err) {
      alert(`Could not discard: ${err.message}`);
    }
  }

  async function loadHistory() {
    const el = document.getElementById("history-body");
    try {
      const data = await api(`/api/devices/${encodeURIComponent(peerId)}/history?days=7`);
      const events = (data.events || []).slice().reverse();
      const pct = (data.uptime * 100).toFixed(1);
      el.innerHTML = `
        <p class="meta">${pct}% online over the last 7 days</p>
        <div class="uptime-bar"><i class="up" style="width:${pct}%"></i></div>
        ${events.length
          ? `<ul class="timeline">${events.map((e) => `
              <li><span class="${e.Online ? "up" : "down"}">${e.Online ? "came online" : "went offline"}</span>
                  <span class="meta">${esc(new Date(e.At).toLocaleString())}</span></li>`).join("")}</ul>`
          : `<p class="meta">No transitions recorded yet.</p>`}`;
    } catch (err) {
      el.innerHTML = `<p class="meta">Could not load history: ${esc(err.message)}</p>`;
    }
  }

  function openRename() {
    const current = document.getElementById("device-name").textContent.trim();
    const note = document.getElementById("device-note")?.textContent.trim() || "";
    dialog.innerHTML = `
      <form method="dialog" id="rename-form">
        <h2>Name this device</h2>
        <label for="alias-input">Name</label>
        <input id="alias-input" type="text" maxlength="64" value="${esc(current)}" autofocus>
        <label for="note-input">Note</label>
        <textarea id="note-input" maxlength="1000">${esc(note)}</textarea>
        <p class="error" id="rename-error" hidden></p>
        <div class="dialog-actions">
          <button type="button" class="ghost" data-action="cancel">Cancel</button>
          <button type="submit">Save</button>
        </div>
      </form>`;
    dialog.showModal();
    const close = () => { dialog.close(); dialog.innerHTML = ""; };
    dialog.querySelector('[data-action="cancel"]').addEventListener("click", close);
    dialog.querySelector("#rename-form").addEventListener("submit", async (e) => {
      e.preventDefault();
      const errEl = dialog.querySelector("#rename-error");
      try {
        await api(`/api/devices/${encodeURIComponent(peerId)}/meta`, {
          method: "POST",
          body: JSON.stringify({
            alias: dialog.querySelector("#alias-input").value,
            note: dialog.querySelector("#note-input").value,
          }),
        });
        close();
        location.reload();
      } catch (err) {
        errEl.textContent = err.message;
        errEl.hidden = false;
      }
    });
  }

  async function toggleArchive() {
    const archived = body.dataset.archived === "1";
    try {
      await api(`/api/devices/${encodeURIComponent(peerId)}/archive`, {
        method: "POST",
        body: JSON.stringify({ archived: !archived }),
      });
      location.reload();
    } catch (err) {
      alert(`Could not change: ${err.message}`);
    }
  }

  async function removePeer() {
    if (!confirm(
      "Remove this device from the RustDesk server?\n\n" +
      "This deletes it from hbbs's peer table and erases all console records. " +
      "If the RustDesk client is still running on the device, hbbs will re-register it " +
      "the next time the client connects. Stop or uninstall the client on the device " +
      "for removal to stick.")) return;
    try {
      await api(`/api/devices/${encodeURIComponent(peerId)}/peer`, { method: "DELETE" });
      location.href = "/";
    } catch (err) {
      alert(`Could not remove: ${err.message}`);
    }
  }

  async function forgetDevice() {
    if (!confirm(
      "Erase this device's name, note, presence history, saved password and collected intel?\n\n" +
      "The device itself is not affected and will reappear in the list, unnamed, " +
      "the next time the server sees it. Archive it instead to hide it for good.")) return;
    try {
      await api(`/api/devices/${encodeURIComponent(peerId)}`, { method: "DELETE" });
      location.href = "/";
    } catch (err) {
      alert(`Could not erase: ${err.message}`);
    }
  }

  document.addEventListener("click", (e) => {
    const btn = e.target.closest("[data-action]");
    if (!btn || !btn.closest(".head")) return;
    if (btn.dataset.action === "rename") openRename();
    else if (btn.dataset.action === "archive") toggleArchive();
    else if (btn.dataset.action === "forget") forgetDevice();
    else if (btn.dataset.action === "remove-peer") removePeer();
  });

  runBtn?.addEventListener("click", collectIntel);
  discardBtn?.addEventListener("click", discardIntel);
  dialog?.addEventListener("cancel", () => { dialog.innerHTML = ""; });

  loadReport();
  loadHistory();
})();
