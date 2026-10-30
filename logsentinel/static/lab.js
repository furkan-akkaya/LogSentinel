/* Experiments call the real engine; the browser only presents returned steps. */
const settingLabels = {
  ssh_threshold: "SSH failures",
  windows_threshold: "Windows failures",
  sudo_threshold: "Sudo failures",
  success_threshold: "Failures before success",
  window_seconds: "Time window · seconds",
};
async function lab(token) {
  const [catalog, config] = await Promise.all([api("/lab"), api("/settings")]);
  if (token !== revision) return;
  const alertId = new URLSearchParams(location.hash.split("?")[1] || "").get("alert");
  let requestRevision = 0, replayData = null, selectedStep = 0;
  $("#page-content").innerHTML = `
    <div class="lab-banner"><div><span class="tag">ISOLATED EXPERIMENT</span><h2>From a log line to a detection.</h2><p>The same engine powers this lab and your alerts. Workspace data and settings stay unchanged.</p></div><span class="lab-mark" aria-hidden="true">⌁</span></div>
    <div class="investigation-flow" aria-label="Detection pipeline"><span>01 · Raw event</span><span>→</span><span>02 · Matching identity</span><span>→</span><span>03 · Window + threshold</span><span>→</span><span>04 · Evidence-linked alert</span></div>
    <div class="lab-layout"><section class="panel lab-controls" aria-label="Experiment controls"><div class="eyebrow">01 / CHOOSE THE EVIDENCE</div><label for="lab-scenario">Dataset</label><select id="lab-scenario">${alertId ? '<option value="alert">Selected alert evidence</option>' : ""}${catalog.scenarios.map(s => `<option value="${s.id}">${escapeHTML(s.title)}</option>`).join("")}</select><div id="lab-objective"></div>${alertId ? '<button class="text-link" id="lab-source-alert">← Back to source alert</button>' : ""}
    <form id="lab-form"><div class="eyebrow">02 / CHANGE ONE PARAMETER</div>${Object.entries(settingLabels).map(([key, name]) => `<label class="range-label" for="lab-${key}">${name}<output id="output-${key}">${config.settings[key]}</output></label><input id="lab-${key}" name="${key}" type="range" min="${key === "window_seconds" ? 10 : 2}" max="${key === "window_seconds" ? 3600 : 100}" value="${config.settings[key]}" step="1" aria-label="${name}">`).join("")}<div class="lab-actions"><button class="button primary" type="submit">Run experiment</button><button class="text-link" type="button" id="lab-reset">Use workspace settings</button></div><p class="hint">Parameters apply to all five rules. SSH-only records cannot trigger a Windows or sudo rule.</p></form></section>
    <div class="lab-results"><section class="panel replay-panel" aria-label="Replay results"><div class="panel-heading"><div><div class="eyebrow">03 / FOLLOW THE ENGINE</div><h3>Event-time replay</h3></div><span class="tag">UTC</span></div><div id="lab-result" aria-live="polite">Reading the selected evidence…</div></section><section class="panel reasoning-panel" id="lab-check"></section></div></div>`;
  const form = $("#lab-form"), select = $("#lab-scenario");
  if (alertId) $("#lab-source-alert").onclick = () => showAlert(alertId);
  form.querySelectorAll("input").forEach(input => input.oninput = () => {
    $(`#output-${input.name}`).textContent = input.value;
    ++requestRevision;
    $("#lab-result").innerHTML = '<div class="notice">Parameters changed. Run the experiment to update the result.</div>';
    replayData = null;
  });
  function describe() {
    const scenario = catalog.scenarios.find(s => s.id === select.value);
    $("#lab-objective").innerHTML = scenario ? `<span class="lab-topic">${escapeHTML(scenario.tag)}</span><p>${escapeHTML(scenario.objective)}</p><small>Synthetic scenario · never imported</small>` : '<p>Only the selected alert’s evidence records are replayed. Other events and identities are outside this experiment.</p>';
    $("#lab-check").innerHTML = scenario ? `<div class="eyebrow">04 / CHECK YOUR REASONING</div><h3>${escapeHTML(scenario.question)}</h3><details><summary>Show a hint</summary><p>${escapeHTML(scenario.hint)}</p></details><details><summary>Reveal the explanation</summary><p>${escapeHTML(scenario.answer)}</p></details>` : '<div class="eyebrow">04 / CHECK YOUR REASONING</div><h3>What could change your interpretation?</h3><p>Compare the identity, raw records and benign explanation. An absent alert is not a safety verdict.</p><p>Save your observation and next step in the original alert’s Case Notes.</p>';
  }
  function drawStep() {
    if (!replayData || token !== revision) return;
    const data = replayData, step = data.steps[selectedStep], event = data.events[selectedStep];
    if (!step) return;
    const change = step.triggered.length ? `${step.triggered.length} new alert${step.triggered.length > 1 ? "s" : ""}` : step.updated.length ? "Existing evidence updated" : "No new alert at this step";
    $("#lab-result").innerHTML = `<div class="replay-body"><p class="scope-description">${escapeHTML(data.scope.title)} · ${data.events.length} records</p><div class="notice">${escapeHTML(data.scope.limits)}</div>
      ${data.scope.dataset ? datasetNotice(data.scope.dataset) : ""}
      <div class="comparison-strip"><div><small>Workspace settings · same evidence</small><strong>${data.baseline.alerts_total} ${data.baseline.alerts_total === 1 ? "alert" : "alerts"}</strong></div><span aria-hidden="true">→</span><div><small>Experiment settings · same evidence</small><strong>${data.alerts.length} ${data.alerts.length === 1 ? "alert" : "alerts"}</strong></div></div><p class="hint">Counts are for the complete selected dataset. The replay below shows the selected prefix.</p>
      <div class="step-controls"><button class="button secondary" id="step-prev" ${selectedStep === 0 ? "disabled" : ""}>← Previous event</button><label for="replay-step">Event ${selectedStep + 1} / ${data.steps.length}</label><button class="button secondary" id="step-next" ${selectedStep === data.steps.length - 1 ? "disabled" : ""}>Next event →</button></div>
      <input type="range" id="replay-step" min="0" max="${data.steps.length - 1}" value="${selectedStep}" aria-label="Replay event">
      <div class="replay-events" aria-label="Event timeline">${data.events.map((e,i) => `<button class="event-chip ${i === selectedStep ? "selected" : ""} ${e.event_type.endsWith("success") ? "event-success" : ""}" data-step="${i}" aria-label="Event ${i+1}: ${escapeHTML(label(e.event_type))}" aria-pressed="${i === selectedStep}">${i+1}<span>${e.event_type.endsWith("success") ? "S" : "F"}</span></button>`).join("")}</div>
      <div class="step-outcome ${step.triggered.length ? "triggered" : ""}"><span class="tag">${step.alerts_total} ${step.alerts_total === 1 ? "ALERT" : "ALERTS"} IN PREFIX</span><h3>${escapeHTML(change)}</h3><p>${step.eligible ? "Eligible identity: " + escapeHTML(step.identity.join(" · ")) : "Excluded from correlation: missing required identity, a summary, or an excluded authentication method."}</p>${[...step.triggered, ...step.updated].map(a => `<p><strong>${escapeHTML(a.title)}</strong> · ${a.evidence.length} evidence records<br>${escapeHTML(a.reason)}</p>`).join("")}</div>
      <details class="raw-step" open><summary>Record ${selectedStep + 1} · ${escapeHTML(event.timestamp)} · ${escapeHTML(label(event.event_type))}</summary><pre>${escapeHTML(event.raw)}</pre><dl class="identity-grid">${Object.entries({host:event.host, user:event.user, source_ip:event.source_ip, ...event.metadata}).filter(([,v])=>v != null).map(([k,v])=>`<div><dt>${escapeHTML(label(k))}</dt><dd>${escapeHTML(v)}</dd></div>`).join("")}</dl></details><p class="hint">Prefixes follow normalized UTC time. Equal timestamps do not prove that a failure preceded a success.</p></div>`;
    $("#step-prev").onclick = () => { selectedStep--; drawStep(); };
    $("#step-next").onclick = () => { selectedStep++; drawStep(); };
    $("#replay-step").oninput = e => { selectedStep = Number(e.target.value); drawStep(); $("#replay-step").focus(); };
    document.querySelectorAll("[data-step]").forEach(b => b.onclick = () => { selectedStep = Number(b.dataset.step); drawStep(); $(`[data-step="${selectedStep}"]`).focus(); });
  }
  async function run() {
    const current = ++requestRevision;
    const parameters = Object.fromEntries([...new FormData(form)].map(([k,v]) => [k,Number(v)]));
    const selected = select.value;
    $("#lab-result").innerHTML = '<div class="loading">Running the production detection engine…</div>';
    try {
      const data = await api("/lab/replay", {method:"POST", headers:{"Content-Type":"application/json"}, body:JSON.stringify({settings:parameters, ...(selected === "alert" ? {alert_id:alertId} : {scenario:selected})})});
      if (token !== revision || current !== requestRevision) return;
      replayData = data;
      selectedStep = data.steps.length - 1;
      drawStep();
    } catch(error) {
      if (token === revision && current === requestRevision) $("#lab-result").innerHTML = `<div class="error-panel">${escapeHTML(error.message)}. Select another dataset or run again.</div>`;
    }
  }
  form.onsubmit = e => { e.preventDefault(); run(); };
  select.onchange = () => { describe(); run(); };
  $("#lab-reset").onclick = async () => {
    try {
      const latest = await api("/settings");
      if (token !== revision) return;
      Object.entries(latest.settings).forEach(([k,v]) => {form.elements[k].value = v; $(`#output-${k}`).textContent = v;});
      await run();
    } catch(error) {toast(error.message,true);}
  };
  describe();
  await run();
}
function noteEditor(alert) {
  const note = alert.notebook?.note || {};
  return `<section class="detail-section notebook-editor"><div class="eyebrow">YOUR INVESTIGATION</div><h3>Separate observation from interpretation</h3><p>Save your reasoning with up to 200 raw evidence records. Notes survive rule reanalysis; each save replaces the previous snapshot.</p><form id="note-form"><label>Assessment<select name="assessment">${["undetermined","likely_benign","suspicious"].map(v=>`<option value="${v}" ${note.assessment === v ? "selected" : ""}>${escapeHTML(label(v))}</option>`).join("")}</select></label>${[["observation","Observation · what do the records show?"],["hypothesis","Hypothesis · what could explain it?"],["next_step","Next step · what evidence is missing?"]].map(([key,title])=>`<label>${title}<textarea name="${key}" rows="3" maxlength="4000">${escapeHTML(note[key] || "")}</textarea></label>`).join("")}<button class="button primary" type="submit">Save Case Notes</button><span id="note-saved" role="status">${alert.notebook ? "Saved " + escapeHTML(shortTime(alert.notebook.saved_at)) + " UTC" : "No saved notes"}</span></form></section>`;
}
function bindNoteEditor(alert) {
  $("#note-form").onsubmit = e => {
    e.preventDefault();
    const form = e.currentTarget;
    busy($("button[type=submit]",form), async () => {
      const note = await api(`/alerts/${alert.id}/notebook`,{method:"PUT",headers:{"Content-Type":"application/json"},body:JSON.stringify(Object.fromEntries(new FormData(form)))});
      if (form.isConnected) $("#note-saved").textContent = `Saved ${shortTime(note.saved_at)} UTC`;
      toast("Case Notes saved with an evidence snapshot.");
    });
  };
}
async function notebooks(token) {
  const data = await api("/notebooks");
  if (token !== revision) return;
  $("#page-content").innerHTML = `<div class="notice">These are your manual assessments. A saved snapshot survives removed alerts. Saving again replaces it; this is not an audit history.</div>${data.items.length ? `<section class="panel"><div class="panel-heading"><h3>Saved investigations · ${data.items.length}</h3></div><div class="case-list">${data.items.map(n=>`<article><div><span class="tag">${escapeHTML(label(n.assessment))}</span><h3><button class="row-button" data-note="${n.alert_id}">${escapeHTML(n.title)} ↗</button></h3><p>${escapeHTML(shortTime(n.saved_at))} UTC · ${n.active ? "Alert currently present" : "Alert no longer present · snapshot retained"}</p></div><button class="button secondary" data-note="${n.alert_id}">Open notes</button></article>`).join("")}</div></section>` : empty("No saved investigations yet", "Open a security alert, record an observation, hypothesis and next step, then save Case Notes.")}`;
  document.querySelectorAll("[data-note]").forEach(b => b.onclick = () => showNotebook(b.dataset.note));
}
async function showNotebook(id) {
  try {
    const n = await api(`/notebooks/${id}`);
    showDetail(`${detailHeading("SAVED EVIDENCE SNAPSHOT",n.alert.title)}<p class="notice">${escapeHTML(n.scope)}</p><div class="detail-fields">${field("Saved · UTC",n.saved_at)}${field("Manual assessment",label(n.note.assessment))}${field("Original rule",n.alert.rule)}</div>${["observation","hypothesis","next_step"].map(key=>`<section class="detail-section"><h3>${escapeHTML(label(key))}</h3><p class="note-text">${escapeHTML(n.note[key] || "No note recorded.")}</p></section>`).join("")}<section class="detail-section"><h3>Evidence at save time</h3><p>${n.events.length} records saved · ${n.evidence_omitted} raw records omitted · ${n.alert.evidence.length} total evidence IDs retained</p><p>${n.snapshot_policy === "first_and_final" ? `Includes the first ${n.events.length - 1} records and the final record.` : n.evidence_omitted ? "This older snapshot retains a partial evidence selection." : "All evidence records are retained."}</p>${datasetNotice({bundled_synthetic_match:n.events.filter(e=>e.dataset_kind === "bundled_synthetic_match").length,unverified_import:n.events.filter(e=>e.dataset_kind !== "bundled_synthetic_match").length})}<pre>${escapeHTML(n.alert.reason)}</pre><details><summary>Saved source records</summary>${n.events.map(e=>`<pre>${escapeHTML(e.timestamp)}\n${escapeHTML(e.raw)}</pre>`).join("")}</details></section><div class="lab-actions"><button class="button secondary" id="export-note">Download JSON snapshot</button><button class="text-link" id="open-live-alert">Open current alert</button></div><p class="hint">The downloaded file contains raw logs and your notes. Keep it private.</p>`);
    $("#export-note").onclick = () => {
      const url = URL.createObjectURL(new Blob([JSON.stringify(n,null,2)],{type:"application/json"}));
      const anchor = document.createElement("a"); anchor.href = url; anchor.download = `logsentinel-case-${id.slice(0,12)}.json`; anchor.click();
      setTimeout(()=>URL.revokeObjectURL(url),1000);
    };
    $("#open-live-alert").onclick = () => showAlert(id);
  } catch(error) {toast(error.message,true);}
}
