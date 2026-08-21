"use strict";

// Lifecycle order for the detail stepper.
const FLOW = [
  ["received", "Received"],
  ["awaiting_password", "Requested"],
  ["password_submitted", "Submitted"],
  ["resubmitted", "Resubmitted"],
  ["rechecking", "Re-checking"],
  ["__verdict__", "Verdict"],
];
const TERMINAL = { done_passed: "Released", done_quarantined: "Quarantined", failed_max_retries: "Wrong password", expired: "Expired", notify_failed: "Email failed", bounced: "Bounced" };

let cases = [];
let openId = null, openSig = null, openState = null;  // the case shown in the drawer
const $ = (id) => document.getElementById(id);
const esc = (s) => (s == null ? "" : String(s)).replace(/[&<>"]/g, (c) =>
  ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]));

async function api(path) {
  const r = await fetch(path, { headers: { Accept: "application/json" } });
  if (r.status === 401) { window.location = "/login"; throw new Error("unauth"); }
  if (!r.ok) throw new Error("HTTP " + r.status);
  return r.json();
}

async function post(path) {
  const r = await fetch(path, { method: "POST", headers: { Accept: "application/json" } });
  if (r.status === 401) { window.location = "/login"; throw new Error("unauth"); }
  if (!r.ok) throw new Error("HTTP " + r.status);
  return r.json();
}

function fmtTime(iso) {
  if (!iso) return "";
  const d = new Date(iso);
  return isNaN(d) ? iso : d.toLocaleString();
}

function rowHtml(c) {
  const fails = c.attempts || 0;
  return `<tr data-id="${esc(c.id)}">
    <td><span class="badge ${c.status_kind}">${esc(c.status_label)}</span></td>
    <td class="recipient" title="${esc(c.recipient)}">${esc(c.recipient)}</td>
    <td class="sender" title="${esc(c.sender || "")}">${esc(c.sender || "")}</td>
    <td class="subject" title="${esc(c.subject || "")}">${esc(c.subject || "")}</td>
    <td class="attach" title="${esc(c.attachment || "")}">${esc(c.attachment || "")}</td>
    <td class="mono">${esc(c.queue_id)}</td>
    <td class="num fails ${fails ? "has" : ""}">${fails}</td>
    <td class="mono">${esc(fmtTime(c.updated_at))}</td>
  </tr>`;
}

function render() {
  const q = $("search").value.trim().toLowerCase();
  const shown = !q ? cases : cases.filter((c) =>
    [c.recipient, c.sender, c.subject, c.attachment, c.queue_id, c.status_label]
      .some((v) => (v || "").toLowerCase().includes(q)));
  $("rows").innerHTML = shown.map(rowHtml).join("");
  $("empty").hidden = shown.length > 0;
  $("summary").textContent = `${cases.length} case${cases.length === 1 ? "" : "s"}` +
    (q ? ` · ${shown.length} match${shown.length === 1 ? "" : "es"}` : "");
  $("rows").querySelectorAll("tr").forEach((tr) =>
    tr.addEventListener("click", () => openDrawer(tr.dataset.id)));
}

async function refresh() {
  try { cases = (await api("/api/cases")).cases; render(); } catch (e) { /* handled in api() */ }
}

function stepper(state) {
  const idx = FLOW.findIndex(([s]) => s === state);
  const verdict = TERMINAL[state];
  return `<div class="stepper">` + FLOW.map(([s, label], i) => {
    let cls = "";
    if (verdict) { cls = "done"; if (s === "__verdict__") { cls = "current"; label = verdict; } }
    else if (i < idx) cls = "done"; else if (i === idx) cls = "current";
    return `<div class="step ${cls}"><div class="dot"></div>${esc(label)}</div>`;
  }).join("") + `</div>`;
}

// The dynamic part of the drawer (everything except the EX alert-details section, which
// is loaded separately and preserved across live updates).
function drawerMainHtml(c) {
  return `
    <h2><span class="badge ${c.status_kind}">${esc(c.status_label)}</span></h2>
    ${stepper(c.state)}
    <dl class="kv">
      <dt>Recipient</dt><dd>${esc(c.recipient)}</dd>
      <dt>Sender</dt><dd>${esc(c.sender || "—")}</dd>
      <dt>Subject</dt><dd>${esc(c.subject || "—")}</dd>
      <dt>Attachment</dt><dd>${esc(c.attachment || "—")}</dd>
      <dt>Queue ID</dt><dd class="mono">${esc(c.queue_id)}</dd>
      <dt>Password fails</dt><dd>${c.attempts || 0}</dd>
      <dt>Email attempts</dt><dd>${c.notify_attempts || 0}</dd>
      <dt>Created</dt><dd class="mono">${esc(fmtTime(c.created_at))}</dd>
    </dl>
    ${["notify_failed", "awaiting_password", "bounced"].includes(c.state)
      ? `<button id="resend-btn" class="btn" data-id="${esc(c.id)}">Resend email</button>` : ""}
    ${c.state === "resubmit_failed"
      ? `<button id="rescan-btn" class="btn" data-id="${esc(c.id)}">Retry rescan</button>` : ""}
    <h3 style="font-size:14px;margin:18px 0 0;">Timeline</h3>
    <ul class="timeline">${(c.events || []).map((e) => `
      <li><div class="t-state">${esc((e.state || "").replace(/_/g, " "))}</div>
      <div class="t-detail">${esc(e.detail || "")}</div>
      <div class="t-time">${esc(fmtTime(e.at))}</div></li>`).join("")}</ul>`;
}

function wireDrawerButtons(id) {
  const resend = document.getElementById("resend-btn");
  if (resend) resend.addEventListener("click", async () => {
    resend.disabled = true; resend.textContent = "Sending…";
    try { await post("/api/cases/" + encodeURIComponent(id) + "/resend"); await openDrawer(id); refresh(); }
    catch (e) { resend.disabled = false; resend.textContent = "Resend failed — try again"; }
  });
  const rescan = document.getElementById("rescan-btn");
  if (rescan) rescan.addEventListener("click", async () => {
    rescan.disabled = true; rescan.textContent = "Rescanning…";
    try { await post("/api/cases/" + encodeURIComponent(id) + "/rescan"); await openDrawer(id); refresh(); }
    catch (e) { rescan.disabled = false; rescan.textContent = "Rescan failed — try again"; }
  });
}

// Cheap change signature so live refresh only re-renders when something actually changed.
function drawerSig(c) {
  return [c.state, c.updated_at, (c.events || []).length, c.attempts || 0, c.notify_attempts || 0].join("|");
}

async function openDrawer(id) {
  openId = id;
  const c = await api("/api/cases/" + encodeURIComponent(id));
  $("drawer-body").innerHTML = `<div id="drawer-main">${drawerMainHtml(c)}</div>
    <h3 style="font-size:14px;margin:18px 0 0;">EX alert details</h3>
    <div id="alert-extra" class="alert-extra">Loading…</div>`;
  wireDrawerButtons(id);
  openState = c.state; openSig = drawerSig(c);
  $("drawer").hidden = false;
  loadAlertDetails(id);
}

// Live-update the open drawer on the refresh tick — updates the badge, stepper, counters
// and timeline in place (no flicker, keeps scroll), and re-fetches the EX alert details
// only when the case state actually changed.
async function refreshDrawer() {
  if (!openId || $("drawer").hidden) return;
  let c;
  try { c = await api("/api/cases/" + encodeURIComponent(openId)); }
  catch (e) { return; }  // transient error / case gone — keep the current view
  if (drawerSig(c) === openSig) return;  // nothing changed
  const stateChanged = c.state !== openState;
  const main = $("drawer-main");
  if (main) { main.innerHTML = drawerMainHtml(c); wireDrawerButtons(openId); }
  openSig = drawerSig(c); openState = c.state;
  if (stateChanged) loadAlertDetails(openId);
}

// Extra, best-effort EX alert detail (fetched by UUID) — populated after the drawer
// renders so a slow/unavailable EX never blocks the case view.
async function loadAlertDetails(id) {
  const box = document.getElementById("alert-extra");
  if (!box) return;
  try {
    const r = await api("/api/cases/" + encodeURIComponent(id) + "/alerts");
    box.innerHTML = renderAlertDetails(r);
  } catch (e) {
    box.innerHTML = `<div class="ax-empty">Could not load alert details.</div>`;
  }
}

function renderAlertDetails(r) {
  const alerts = (r && r.alerts) || [];
  if (!alerts.length) {
    return `<div class="ax-empty">${esc(r && r.error ? r.error : "No alert details available.")}</div>`;
  }
  return alerts.map((a) => {
    const mal = (a.malware || []).map((m) => `
      <div class="ax-mal"><span class="ax-mal-name">${esc(m.name || "—")}</span>
      ${m.sha256 ? `<code class="mono ax-hash" title="${esc(m.sha256)}">${esc(m.sha256.slice(0, 16))}…</code>` : ""}</div>`).join("");
    // These alerts come from a quarantined record, so they're detections — never label
    // them "clean". The encrypted-attachment alert is the pre-password-extraction one.
    const names = (a.malware || []).map((m) => (m.name || "").toLowerCase());
    const encrypted = names.some((n) =>
      n.includes("custompolicy.mvx") || n.includes("passextractfailed") || n.includes("password_extraction_failed"));
    const riskware = (a.name || "").toLowerCase().includes("riskware");
    let verdict, tag = "";
    if (a.malicious) verdict = `<span class="badge quarantined">malicious</span>`;
    else if (encrypted) {
      verdict = `<span class="badge rechecking">extraction failed</span>`;
      tag = `<span class="ax-tag">pre-password-extraction alert</span>`;
    } else if (riskware) verdict = `<span class="badge rechecking">riskware</span>`;
    else verdict = `<span class="badge received">detected</span>`;
    return `<div class="ax-alert">
      <div class="ax-head">${esc(a.name || "alert")} ${verdict}
        ${a.severity ? `<span class="ax-sev">${esc(a.severity)}</span>` : ""}${tag}</div>
      <dl class="kv ax-kv">
        ${a.action ? `<dt>Action</dt><dd>${esc(a.action)}</dd>` : ""}
        ${a.occurred ? `<dt>Occurred</dt><dd class="mono">${esc(a.occurred)}</dd>` : ""}
        ${a.queue_id ? `<dt>Queue ID</dt><dd class="mono">${esc(a.queue_id)}</dd>` : ""}
        ${a.uuid ? `<dt>Alert UUID</dt><dd class="mono">${esc(a.uuid)}</dd>` : ""}
      </dl>
      ${mal ? `<div class="ax-mals">${mal}</div>` : ""}
      ${a.alert_url ? `<a class="ax-link" href="${esc(a.alert_url)}" target="_blank" rel="noopener">Open in EX console ↗</a>` : ""}
    </div>`;
  }).join("");
}

function closeDrawer() { $("drawer").hidden = true; openId = null; }

$("search").addEventListener("input", render);
$("drawer-close").addEventListener("click", closeDrawer);
$("drawer").addEventListener("click", (e) => { if (e.target.id === "drawer") closeDrawer(); });
document.addEventListener("keydown", (e) => { if (e.key === "Escape") closeDrawer(); });

async function checkConfig() {
  const b = $("config-banner");
  if (!b) return;
  try {
    const s = await api("/api/status");
    if (s.configured) { b.className = "banner"; b.textContent = ""; return; }
    b.className = "banner warn";
    b.innerHTML = "<strong>Configuration incomplete.</strong> The webhook is disabled (503) until setup is finished. "
      + "<a href=\"/settings\">Open settings →</a>";
  } catch (_) { /* ignore — banner is best-effort */ }
}

async function reconcile() {
  const btn = $("reconcile-btn"), out = $("reconcile-status");
  if (!btn) return;
  btn.disabled = true;
  out.className = "banner"; out.textContent = "Reconciling with EX…";
  try {
    const r = await post("/api/reconcile");
    if (r.ok) {
      const s = r.result || {};
      out.className = "banner ok";
      out.textContent = `Reconcile done — scanned ${s.scanned || 0}, created ${s.created || 0}, `
        + `already known ${s.already_known || 0}` + (s.note ? ` (${s.note})` : "");
      if (s.created) refresh();
    } else {
      out.className = "banner warn";
      out.textContent = r.error || "Reconcile failed.";
    }
  } catch (e) {
    out.className = "banner warn";
    out.textContent = "Reconcile failed: " + e.message;
  } finally {
    btn.disabled = false;
  }
}
const _rc = $("reconcile-btn");
if (_rc) _rc.addEventListener("click", reconcile);

refresh();
checkConfig();
setInterval(() => { refresh(); refreshDrawer(); }, 5000);
