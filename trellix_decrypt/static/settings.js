"use strict";

const form = document.getElementById("settings-form");
const status = document.getElementById("save-status");

async function api(path, opts) {
  const r = await fetch(path, opts);
  if (r.status === 401) { window.location = "/login"; throw new Error("unauth"); }
  if (!r.ok) throw new Error("HTTP " + r.status);
  return r.json();
}

function fill(values) {
  for (const [key, val] of Object.entries(values)) {
    const field = form.elements[key];
    if (!field) continue;
    if (field.type === "checkbox") field.checked = !!val;
    else field.value = val == null ? "" : val;
  }
}

function collect() {
  const out = {};
  for (const el of form.elements) {
    if (!el.name) continue;
    if (el.type === "checkbox") out[el.name] = el.checked;
    else if (el.type === "password" && el.value === "") continue; // blank secret = keep existing
    else out[el.name] = el.value;
  }
  return out;
}

form.addEventListener("submit", async (e) => {
  e.preventDefault();
  status.className = "save-status";
  status.textContent = "Saving…";
  try {
    const res = await api("/api/settings", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(collect()),
    });
    fill(res.settings);
    status.textContent = "Saved — applied live.";
  } catch (err) {
    status.className = "save-status err";
    status.textContent = "Save failed: " + err.message;
  }
});

api("/api/settings").then(fill).catch(() => {});
