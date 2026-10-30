/* Local UI. Treat every imported field as untrusted text. */
const $ = (selector, parent = document) => parent.querySelector(selector);
const escapeHTML = (value) =>
  String(value ?? "—").replace(
    /[&<>"']/g,
    (c) =>
      ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[
        c
      ],
  );
const fmt = (value) => Number(value).toLocaleString("en-US");
const shortTime = (value) =>
  value
    ? new Date(value).toLocaleString("en-GB", {
        timeZone: "UTC",
        day: "2-digit",
        month: "short",
        hour: "2-digit",
        minute: "2-digit",
        second: "2-digit",
        hour12: false,
      })
    : "No events";
const label = (value) => String(value).replaceAll("_", " ");
const badge = (value) =>
  `<span class="badge ${["critical", "high", "medium", "success", "failure"].includes(value) ? value : "neutral"}">${escapeHTML(label(value))}</span>`;
let page = "dashboard",
  logOffset = 0,
  alertOffset = 0,
  logFilters = {},
  alertFilters = {},
  revision = 0,
  toastTimer;

async function api(path, options = {}) {
  const response = await fetch(`/api${path}`, options);
  const value = await response.json();
  if (!response.ok)
    throw new Error(
      typeof value.detail === "string"
        ? value.detail
        : JSON.stringify(value.detail),
    );
  return value;
}
function toast(message, error = false) {
  const target = $("#toast");
  target.textContent = message;
  target.className = error ? "error" : "";
  target.hidden = false;
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => (target.hidden = true), error ? 15000 : 9000);
}
async function busy(button, work) {
  button.disabled = true;
  try {
    await work();
  } catch (error) {
    toast(error.message, true);
  } finally {
    button.disabled = false;
  }
}
function empty(title, description, demo = false) {
  return `<div class="panel empty"><div class="empty-icon">◈</div><h3>${escapeHTML(title)}</h3><p>${escapeHTML(description)}</p>${demo ? '<button class="button primary" id="empty-demo">Load sample investigation</button>' : ""}</div>`;
}
function datasetNotice(dataset) {
  if (!dataset) return "";
  return `<div class="notice dataset-notice"><strong>Dataset context</strong><span>${fmt(dataset.bundled_synthetic_match)} records match the bundled synthetic demo · ${fmt(dataset.unverified_import)} other imported records</span><small>Content match uses normalized event IDs. Other imports are unverified; they are not assumed to be real or benign.</small></div>`;
}
function metric(name, value, icon, note, color = "") {
  return `<div class="metric ${color}"><div class="metric-top">${name}<span class="metric-icon">${icon}</span></div><div class="metric-number">${fmt(value)}</div><div class="metric-note">${note}</div></div>`;
}
function activityChart(timeline) {
  // Last 24 populated UTC hours; labels show actual event time, never ingest time.
  const data = timeline.slice(-24),
    max = Math.max(1, ...data.map((d) => d.events));
  const w = 620,
    h = 210,
    left = 32,
    top = 20,
    height = 145,
    width = 566;
  const step = width / Math.max(data.length, 1),
    barWidth = Math.min(38, step * 0.48);
  let svg = "";
  for (let i = 0; i <= 3; i++) {
    const y = top + height * (i / 3);
    svg += `<line class="grid" x1="${left}" y1="${y}" x2="610" y2="${y}"/><text x="23" y="${y + 3}" text-anchor="end">${Math.round(max * (1 - i / 3))}</text>`;
  }
  data.forEach((d, i) => {
    const x = left + step * i + step / 2;
    const eh = (d.events / max) * height,
      ah = (d.alerts / max) * height;
    svg += `<rect class="bar" x="${x - barWidth / 2}" y="${top + height - eh}" width="${barWidth}" height="${eh}" rx="3"><title>${escapeHTML(d.hour)} · ${d.events} events</title></rect>`;
    svg += `<rect class="alert-bar" x="${x + barWidth * 0.62}" y="${top + height - ah}" width="${Math.max(3, barWidth * 0.22)}" height="${ah}" rx="2"><title>${d.alerts} alerts</title></rect>`;
    if (data.length < 9 || i % Math.ceil(data.length / 6) === 0)
      svg += `<text x="${x}" y="192" text-anchor="middle">${new Date(d.hour).toISOString().slice(11, 16)}</text>`;
  });
  return `<svg viewBox="0 0 ${w} ${h}" role="img" aria-label="Event and alert counts by UTC hour">${svg}</svg>`;
}
function severityChart(stats) {
  let offset = 0;
  const total = stats.alerts,
    circ = 2 * Math.PI * 61;
  const colors = { critical: "#ff7285", high: "#f7b66b", medium: "#7aafff" };
  let rings = '<circle class="donut-bg" cx="80" cy="80" r="61"/>';
  for (const severity of Object.keys(colors)) {
    const length = total ? (stats.severity[severity] / total) * circ : 0;
    rings += `<circle cx="80" cy="80" r="61" stroke="${colors[severity]}" stroke-dasharray="${length} ${circ - length}" stroke-dashoffset="${-offset}"/>`;
    offset += length;
  }
  return `<svg class="donut" viewBox="0 0 160 160" role="img" aria-label="${stats.severity.critical} critical, ${stats.severity.high} high, ${stats.severity.medium} medium alerts">${rings}<g class="donut-center"><text class="total" x="80" y="79">${total}</text><text class="label" x="80" y="97">TOTAL ALERTS</text></g></svg><div class="severity-legend">${Object.keys(
    colors,
  )
    .map(
      (s) =>
        `<div><span><i class="${s}-color"></i>${label(s)[0].toUpperCase() + label(s).slice(1)}</span><b>${stats.severity[s]}</b></div>`,
    )
    .join("")}</div>`;
}
function alertRows(items) {
  return items
    .map(
      (a) =>
        `<tr><td>${badge(a.severity)}</td><td><button class="row-button" data-alert="${a.id}"><span class="title">${escapeHTML(a.title)}</span><span class="cell-secondary">${escapeHTML(a.user)} · ${a.evidence.length} evidence records</span></button></td><td class="mono">${escapeHTML(a.source_ip)}</td><td>${escapeHTML(a.host)}</td><td><span class="status ${a.status}">${escapeHTML(label(a.status))}</span></td><td class="mono">${shortTime(a.last_seen)}</td><td><button class="text-link" data-alert="${a.id}" aria-label="Investigate ${escapeHTML(a.title)}">↗</button></td></tr>`,
    )
    .join("");
}
const alertTable = (items) =>
  `<div class="table-wrapper"><table><thead><tr><th>SEVERITY</th><th>DETECTION</th><th>SOURCE IP</th><th>HOST</th><th>STATUS</th><th>LAST SEEN · UTC</th><th></th></tr></thead><tbody>${alertRows(items)}</tbody></table></div>`;

async function dashboard(token) {
  const s = await api("/stats");
  if (token !== revision) return;
  $("#nav-alert-count").textContent = s.open_alerts;
  if (!s.events) {
    $("#page-content").innerHTML = empty(
      "Your investigation starts here",
      "Load realistic synthetic logs to explore five detection scenarios, or import your own security logs.",
      true,
    );
    $("#empty-demo").onclick = (e) => loadDemo(e.currentTarget);
    return;
  }
  $("#page-content").innerHTML = `
    <div class="scope-line"><span><span class="online-dot"></span> <strong>All imported activity</strong> · Latest event ${shortTime(s.latest_event)} UTC</span><span class="scope-pill">◷ &nbsp; Event-time analysis</span></div>
    ${datasetNotice(s.dataset)}<div class="metrics">${metric("Total events", s.events, "≡", "Normalized & deduplicated")}${metric("Security alerts", s.alerts, "◇", `${s.severity.critical} critical detections`, "red")}${metric("Open investigations", s.open_alerts, "⌁", "New + investigating alerts", "orange")}${metric("Monitored hosts", s.hosts, "▣", "Hosts found in imported files", "blue")}</div>
    <div class="chart-grid"><section class="panel"><div class="panel-heading"><div><h3>Security activity</h3><p class="panel-subtitle">Authentication events & rule detections</p></div><div class="legend"><span><i></i>Events</span><span><i class="alert-dot"></i>Alerts</span></div></div><div class="chart">${activityChart(s.timeline)}</div><div class="activity-caption">Last ${Math.min(24, s.timeline.length)} populated hours · UTC · Shared count scale</div></section><section class="panel"><div class="panel-heading"><div><h3>Alert severity</h3><p class="panel-subtitle">Distribution across all detections</p></div><span class="tag">ALL TIME</span></div><div class="donut-area">${severityChart(s)}</div><div class="panel-foot"><b>${s.severity.critical + s.severity.high}</b> detections require priority review</div></section></div>
    <section class="panel"><div class="panel-heading table-title"><div><h3>Recent security alerts</h3><p class="panel-subtitle">Investigate the evidence behind each detection</p></div><a class="text-link" href="#alerts">View all alerts →</a></div>${s.alerts ? alertTable(s.recent_alerts) : '<div class="empty">No detections at the current thresholds.</div>'}</section>
    <div class="bottom-grid"><section class="panel"><div class="panel-heading"><h3>Log sources</h3><span class="tag">2 SUPPORTED</span></div><div class="source-list">${["linux", "windows"].map((source) => `<div class="source-row"><span class="source-label ${source}"><i></i>${source === "linux" ? "Linux authentication" : "Windows Security"}</span><small>${fmt(s.sources[source] || 0)} events</small></div>`).join("")}</div></section><section class="panel"><div class="engine-info"><div class="engine-icon">◈</div><div><h3>Transparent by design</h3><p>Five deterministic rules. Every alert links to its source evidence.</p></div></div><div class="engine-tags"><span>MITRE ATT&CK</span><span>Event-time correlation</span><span>No external services</span></div></section></div>
    ${s.uncorrelated_events ? `<div class="notice">${s.uncorrelated_events} events are ineligible for correlation because of missing identity, sudo summaries, or public-key failures. They remain available in Log Explorer.</div>` : ""}`;
  bindAlertButtons();
}
function pager(total, offset) {
  return `<div class="pagination"><span>${total ? offset + 1 : 0}–${Math.min(offset + 50, total)} of ${fmt(total)}</span><div><button class="button secondary" id="previous" ${offset === 0 ? "disabled" : ""}>← Previous</button><button class="button secondary" id="next" ${offset + 50 >= total ? "disabled" : ""}>Next →</button></div></div>`;
}
async function logs(token) {
  const params = new URLSearchParams({ ...logFilters, offset: logOffset });
  const data = await api(`/events?${params}`);
  if (token !== revision) return;
  $("#page-content").innerHTML =
    `<form class="filters" id="log-filters"><label class="search-label">Search raw logs<input name="q" placeholder="Search events, hosts or users…"></label><label>Source<select name="source"><option value="">All sources</option><option value="linux">Linux</option><option value="windows">Windows</option></select></label><label>Event type<select name="event_type"><option value="">All event types</option>${["ssh_failure", "ssh_success", "windows_failure", "windows_success", "sudo_failure"].map((v) => `<option value="${v}">${label(v)}</option>`).join("")}</select></label><label>Source IP<input name="source_ip" placeholder="Exact IP"></label><label>User<input name="user" placeholder="Exact user"></label><label>Host<input name="host" placeholder="Exact host"></label><label>From · UTC<input name="start" type="datetime-local" step="1"></label><label>To · UTC<input name="end" type="datetime-local" step="1"></label><button class="button primary" type="submit">Apply filters</button><button class="button secondary" type="button" id="reset-filters">Reset</button></form><section class="panel"><div class="panel-heading table-title"><div><h3>Authentication events</h3><p class="panel-subtitle">${fmt(data.total)} matching records · Select an event to inspect its raw log</p></div></div>${data.total ? `<div class="table-wrapper"><table><thead><tr><th>TIME · UTC</th><th>EVENT</th><th>SOURCE</th><th>USER</th><th>SOURCE IP</th><th>HOST</th></tr></thead><tbody>${data.items.map((e) => `<tr><td class="mono">${shortTime(e.timestamp)}</td><td><button class="row-button" data-event="${e.id}"><span class="title">${escapeHTML(label(e.event_type))} ↗</span><span class="cell-secondary">${e.id.slice(0, 12)}</span></button></td><td><span class="source-label ${e.source}"><i></i>${e.source === "linux" ? "Linux" : "Windows"}</span></td><td>${escapeHTML(e.user)}</td><td class="mono">${escapeHTML(e.source_ip)}</td><td>${escapeHTML(e.host)}</td></tr>`).join("")}</tbody></table></div>` : '<div class="empty">No events match these filters.</div>'}${pager(data.total, logOffset)}</section>`;
  const form = $("#log-filters");
  Object.entries(logFilters).forEach(([name, value]) => {
    if (form.elements[name])
      form.elements[name].value = ["start", "end"].includes(name)
        ? value.replace(/Z$/, "")
        : value;
  });
  form.onsubmit = (e) => {
    e.preventDefault();
    logFilters = Object.fromEntries(
      [...new FormData(form)]
        .filter(([, v]) => v)
        .map(([k, v]) => [k, ["start", "end"].includes(k) ? `${v}Z` : v]),
    );
    logOffset = 0;
    render();
  };
  $("#reset-filters").onclick = () => {
    logFilters = {};
    logOffset = 0;
    render();
  };
  $("#previous").onclick = () => {
    logOffset = Math.max(0, logOffset - 50);
    render();
  };
  $("#next").onclick = () => {
    logOffset += 50;
    render();
  };
  bindEventButtons();
}
async function alerts(token) {
  const data = await api(
    `/alerts?${new URLSearchParams({ ...alertFilters, offset: alertOffset })}`,
  );
  if (token !== revision) return;
  $("#page-content").innerHTML =
    `<form class="filters" id="alert-filters"><label>Severity<select name="severity"><option value="">All severities</option><option value="critical">Critical</option><option value="high">High</option><option value="medium">Medium</option></select></label><label>Status<select name="status"><option value="">All statuses</option><option value="new">New</option><option value="investigating">Investigating</option><option value="resolved">Resolved</option></select></label><button class="button primary" type="submit">Apply filters</button></form><div class="notice">Detections identify suspicious patterns. A successful login after failures suggests possible compromise; it does not establish that an attack succeeded.</div><section class="panel"><div class="panel-heading table-title"><div><h3>Security detections</h3><p class="panel-subtitle">${fmt(data.total)} matching alerts · Rule-based analysis with linked evidence</p></div></div>${data.total ? alertTable(data.items) : '<div class="empty">No alerts match the current rules and filters.</div>'}${pager(data.total, alertOffset)}</section>`;
  const form = $("#alert-filters");
  Object.entries(alertFilters).forEach(
    ([k, v]) => (form.elements[k].value = v),
  );
  form.onsubmit = (e) => {
    e.preventDefault();
    alertFilters = Object.fromEntries(
      [...new FormData(form)].filter(([, v]) => v),
    );
    alertOffset = 0;
    render();
  };
  $("#previous").onclick = () => {
    alertOffset = Math.max(0, alertOffset - 50);
    render();
  };
  $("#next").onclick = () => {
    alertOffset += 50;
    render();
  };
  bindAlertButtons();
}
function bindAlertButtons() {
  document
    .querySelectorAll("[data-alert]")
    .forEach((b) => (b.onclick = () => showAlert(b.dataset.alert)));
}
function bindEventButtons() {
  document
    .querySelectorAll("[data-event]")
    .forEach((b) => (b.onclick = () => showEvent(b.dataset.event)));
}
function showDetail(html) {
  $("#detail-content").innerHTML = html;
  const d = $("#detail-dialog");
  if (!d.open) d.showModal();
  d.scrollTop = 0;
  $("[data-detail-close]").onclick = () => d.close();
  $("[data-detail-close]").focus();
}
const detailHeading = (eyebrow, title) =>
  `<div class="dialog-heading"><div><div class="eyebrow">${eyebrow}</div><h2>${escapeHTML(title)}</h2></div><button class="icon-button" data-detail-close aria-label="Close details">×</button></div>`;
function field(name, value) {
  return `<div><small>${name}</small>${escapeHTML(value)}</div>`;
}
async function showEvent(id, returnAlert = null) {
  try {
    const e = await api(`/events/${id}`);
    showDetail(
      `${detailHeading("NORMALIZED EVENT", label(e.event_type))}${returnAlert ? '<button class="text-link" id="return-alert">← Back to investigation</button>' : ""}<div class="detail-fields">${field("Time · UTC", e.timestamp)}${field("Source", e.source)}${field("Host", e.host)}${field("User", e.user)}${e.source === "windows" ? field("Domain", e.metadata.domain) + field("Logon type", e.metadata.logon_type) : ""}${field("Source IP", e.source_ip)}${field("Imported from", e.filename)}${field("Dataset context", e.dataset_kind === "bundled_synthetic_match" ? "Matches bundled synthetic demo" : "Unverified import")}</div><div class="detail-section"><h3>Raw source record</h3><pre>${escapeHTML(e.raw)}</pre></div><div class="detail-section"><h3>Normalized record</h3><pre>${escapeHTML(JSON.stringify(e, null, 2))}</pre></div>`,
    );
    if (returnAlert) $("#return-alert").onclick = () => showAlert(returnAlert);
  } catch (error) {
    toast(error.message, true);
  }
}
function explainDetection(a) {
  const info = a.explanation;
  const parameters = info.parameters;
  const success = info.success_count > 0;
  const observation = `${info.failure_count} failure records${success ? ` followed by ${info.success_count} successful logon` : ""} share this correlation identity. ${info.evidence_count} source records support the alert.`;
  const threshold = `${parameters.threshold} failures within ${parameters.window_seconds} seconds${success ? ", strictly before success" : ""}. Setting: ${info.threshold_setting}.`;
  return `<section class="detail-section" aria-labelledby="observation-title"><h3 id="observation-title">What was observed?</h3><p>${escapeHTML(observation)}</p><p>${escapeHTML(info.importance)}</p></section>
    <section class="detail-section" aria-labelledby="identity-title"><h3 id="identity-title">Matching identity</h3><dl class="identity-grid">${Object.entries(
      info.identity,
    )
      .map(
        ([key, value]) =>
          `<div><dt>${escapeHTML(label(key))}</dt><dd>${escapeHTML(value)}</dd></div>`,
      )
      .join(
        "",
      )}</dl><h3>Threshold and time window</h3><p id="alert-parameters">${escapeHTML(threshold)}</p></section>
    <details class="interpretation"><summary>Interpretation and analyst checks</summary><h3>Could this be normal?</h3><p>${escapeHTML(info.benign)}</p><h3>Suggested analyst checks · not automated</h3><ol>${info.checks.map((check) => `<li>${escapeHTML(check)}</li>`).join("")}</ol><h3>What can this rule miss?</h3><p>${escapeHTML(info.limits)}</p>${a.rule.startsWith("windows") ? "<p>Source declarations are checked when present. Missing source fields remain compatible; an imported file is not authenticated.</p>" : ""}</details><p><a class="text-link" href="${escapeHTML(info.guide_url)}" target="_blank" rel="noopener">Read the measured scenario and limitations ↗</a></p>`;
}
async function showAlert(id) {
  try {
    const a = await api(`/alerts/${id}`);
    showDetail(
      `${detailHeading("SECURITY INVESTIGATION", a.title)}<p>${badge(a.severity)} &nbsp; ${a.mitre.map((t) => `<a class="text-link" href="https://attack.mitre.org/techniques/${t.replace(".", "/")}/" target="_blank" rel="noopener">${t} ↗</a>`).join(" &nbsp; ")}</p><div class="detail-fields">${field("Source IP", a.source_ip)}${field("Host", a.host)}${field("User", a.user)}${a.rule.startsWith("windows") ? field("Domain", a.events[0].metadata.domain) + field("Logon type", a.events[0].metadata.logon_type) : ""}${field("First seen · UTC", shortTime(a.first_seen))}${field("Last seen · UTC", shortTime(a.last_seen))}${field("Rule", a.rule)}</div><div class="detail-section"><h3>Why this alert fired</h3><p>${escapeHTML(a.reason)}</p></div>${datasetNotice(a.dataset)}<div class="investigation-flow" aria-label="Investigation workflow"><span>01 · Observe evidence</span><span>→</span><span>02 · Test the rule</span><span>→</span><span>03 · Record reasoning</span></div><p><a class="button secondary" id="replay-alert" href="#lab?alert=${a.id}">Replay this evidence in Detection Lab →</a></p>${explainDetection(a)}<div class="detail-status"><label for="investigation-status">Investigation status</label><select id="investigation-status">${["new", "investigating", "resolved"].map((s) => `<option value="${s}" ${s === a.status ? "selected" : ""}>${label(s)}</option>`).join("")}</select><button class="button secondary" id="save-status">Save status</button></div><div class="detail-section"><h3>Evidence timeline · ${a.events.length} records</h3><div class="timeline">${a.events.map((e) => `<div class="timeline-item"><time>${shortTime(e.timestamp)} UTC</time><div>${badge(e.event_type.endsWith("success") ? "success" : "failure")} &nbsp; ${escapeHTML(e.user)} @ ${escapeHTML(e.host)} <button class="text-link" data-event="${e.id}">Inspect record ↗</button></div></div>`).join("")}</div></div>${noteEditor(a)}`,
    );
    $("#replay-alert").onclick = () => $("#detail-dialog").close();
    bindNoteEditor(a);
    $("#save-status").onclick = (e) =>
      busy(e.currentTarget, async () => {
        await api(`/alerts/${id}`, {
          method: "PATCH",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ status: $("#investigation-status").value }),
        });
        toast("Investigation status saved.");
        await render();
      });
    document.querySelectorAll("#detail-content [data-event]").forEach(b => {
      b.onclick = () => showEvent(b.dataset.event, id);
    });
  } catch (error) {
    toast(error.message, true);
  }
}
async function render() {
  const token = ++revision;
  const route = location.hash.slice(1).split("?")[0];
  page = ["dashboard", "logs", "alerts", "lab", "notebooks"].includes(route) ? route : "dashboard";
  const titles = {
    lab: ["Detection Lab", "Understand the detection", "Replay records. Change one parameter. Follow what the engine actually detects."],
    notebooks: ["Case Notes", "Keep the reasoning", "Manual observations, hypotheses and next steps with saved evidence snapshots."],
    dashboard: [
      "Dashboard",
      "Security overview",
      "A clear view of your authentication activity and detected threats.",
    ],
    logs: [
      "Log Explorer",
      "Log Explorer",
      "Search normalized events and inspect their original source records.",
    ],
    alerts: [
      "Security Alerts",
      "Security Alerts",
      "Follow the evidence. Understand each detection. Track your investigation.",
    ],
  };
  $("#breadcrumb").textContent = titles[page][0];
  $("#page-title").textContent = titles[page][1];
  $("#page-description").textContent = titles[page][2];
  document.querySelectorAll("nav a").forEach((a) => {
    a.classList.toggle("active", a.dataset.page === page);
    if (a.dataset.page === page) a.setAttribute("aria-current", "page");
    else a.removeAttribute("aria-current");
  });
  $("#page-content").innerHTML =
    '<div class="loading">Reading local security data…</div>';
  try {
    await { dashboard, logs, alerts, lab, notebooks }[page](token);
    if (page !== "dashboard") {
      const s = await api("/stats");
      if (token === revision) $("#nav-alert-count").textContent = s.open_alerts;
    }
    if (token === revision) {
      $("#engine-status").textContent = "Engine operational";
      $("#engine-dot").classList.remove("offline-dot");
    }
  } catch (error) {
    if (token === revision) {
      $("#page-content").innerHTML =
        `<div class="error-panel">Could not load data: ${escapeHTML(error.message)}. <button class="button secondary" id="retry">Retry</button></div>`;
      $("#engine-status").textContent = "Connection unavailable";
      $("#engine-dot").classList.add("offline-dot");
    }
    if ($("#retry")) $("#retry").onclick = render;
  }
}
async function loadDemo(button) {
  await busy(button, async () => {
    const r = await api("/demo", { method: "POST" });
    toast(
      `Demo analyzed: ${r.inserted} new events · ${r.duplicates} duplicates · ${r.alerts_total} total alerts.`,
    );
    await render();
  });
}
$("#load-demo").onclick = (e) => loadDemo(e.currentTarget);
$("#import-open").onclick = () => $("#import-dialog").showModal();
$("#import-year").value = new Date().getUTCFullYear();
document
  .querySelectorAll("[data-close]")
  .forEach((b) => (b.onclick = () => b.closest("dialog").close()));
$("#import-form").onsubmit = (e) => {
  e.preventDefault();
  const form = e.currentTarget;
  busy($('button[type="submit"]', form), async () => {
    const file = form.elements.file.files[0];
    if (file.size > 5 * 1024 * 1024)
      throw new Error("File exceeds the 5 MiB upload limit.");
    const r = await api("/import", {
      method: "POST",
      body: new FormData(form),
    });
    $("#import-dialog").close();
    toast(
      `${r.inserted} events imported · ${r.duplicates} duplicates · ${r.rejected} rejected · ${r.ignored} ignored.\n${r.alerts_total} total alerts.${r.errors.length ? "\n" + r.errors.map((e) => `Record ${e.record}: ${e.reason}`).join("\n") : ""}`,
      r.rejected > 0,
    );
    await render();
  });
};
document.querySelectorAll("[data-settings-open]").forEach(
  (button) =>
    (button.onclick = async () => {
      try {
        const r = await api("/settings");
        Object.entries(r.settings).forEach(
          ([key, value]) => ($("#settings-form").elements[key].value = value),
        );
        $("#settings-dialog").showModal();
      } catch (error) {
        toast(error.message, true);
      }
    }),
);
$("#settings-form").onsubmit = (e) => {
  e.preventDefault();
  const form = e.currentTarget;
  busy($('button[type="submit"]', form), async () => {
    const settings = Object.fromEntries(
      [...new FormData(form)].map(([k, v]) => [k, Number(v)]),
    );
    const r = await api("/settings", {
      method: "PUT",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(settings),
    });
    $("#settings-dialog").close();
    toast(`Rules saved. ${r.alerts_total} alerts after reanalysis.`);
    await render();
  });
};
window.addEventListener("hashchange", render);
window.addEventListener("DOMContentLoaded", render);
