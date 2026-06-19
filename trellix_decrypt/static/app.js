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
const TERMINAL = { done_clean: "Clean", done_malicious: "Malicious", failed_max_retries: "Wrong password", expired: "Expired" };

let cases = [];
const $ = (id) => document.getElementById(id);
const esc = (s) => (s == null ? "" : String(s)).replace(/[&<>"]/g, (c) =>
  ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]));

async function api(path) {
  const r = await fetch(path, { headers: { Accept: "application/json" } });
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
    <td>${esc(c.recipient)}</td>
    <td>${esc(c.sender || "")}</td>
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

async function openDrawer(id) {
  const c = await api("/api/cases/" + encodeURIComponent(id));
  $("drawer-body").innerHTML = `
    <h2><span class="badge ${c.status_kind}">${esc(c.status_label)}</span></h2>
    ${stepper(c.state)}
    <dl class="kv">
      <dt>Recipient</dt><dd>${esc(c.recipient)}</dd>
      <dt>Sender</dt><dd>${esc(c.sender || "—")}</dd>
      <dt>Subject</dt><dd>${esc(c.subject || "—")}</dd>
      <dt>Attachment</dt><dd>${esc(c.attachment || "—")}</dd>
      <dt>Queue ID</dt><dd class="mono">${esc(c.queue_id)}</dd>
      <dt>Password fails</dt><dd>${c.attempts || 0}</dd>
      <dt>Created</dt><dd class="mono">${esc(fmtTime(c.created_at))}</dd>
    </dl>
    <h3 style="font-size:14px;margin:18px 0 0;">Timeline</h3>
    <ul class="timeline">${(c.events || []).map((e) => `
      <li><div class="t-state">${esc((e.state || "").replace(/_/g, " "))}</div>
      <div class="t-detail">${esc(e.detail || "")}</div>
      <div class="t-time">${esc(fmtTime(e.at))}</div></li>`).join("")}</ul>`;
  $("drawer").hidden = false;
}

function closeDrawer() { $("drawer").hidden = true; }

$("search").addEventListener("input", render);
$("drawer-close").addEventListener("click", closeDrawer);
$("drawer").addEventListener("click", (e) => { if (e.target.id === "drawer") closeDrawer(); });
document.addEventListener("keydown", (e) => { if (e.key === "Escape") closeDrawer(); });

refresh();
setInterval(refresh, 5000);
