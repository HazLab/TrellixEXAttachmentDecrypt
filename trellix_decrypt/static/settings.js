"use strict";

const form = document.getElementById("settings-form");
const status = document.getElementById("save-status");
const banner = document.getElementById("setup-banner");

// Make the whole "remove" pill clickable, not just its checkbox.
form.querySelectorAll(".rm").forEach((pill) => {
  pill.addEventListener("click", (e) => {
    if (e.target.tagName === "INPUT") return; // native toggle already fired
    const cb = pill.querySelector(".clear-secret");
    if (cb) cb.checked = !cb.checked;
  });
});

const LABELS = {
  ex_base_url: "Trellix EX base URL", ex_username: "EX username", ex_password: "EX password",
  smtp_host: "SMTP host", smtp_from: "From address", public_base_url: "Public base URL",
  ui_password: "Admin password", webhook_auth: "Webhook auth (username+password or IP allowlist)",
};

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

function renderBanner(res) {
  if (!banner) return;
  const missing = res.missing || [];
  if (res.setup_mode) {
    banner.className = "banner setup";
    banner.innerHTML = "<strong>Setup mode.</strong> Set an <em>Admin password</em> and the required "
      + "fields below, then Save. Sign-in and the webhook stay disabled until then." + missingHtml(missing);
  } else if (missing.length) {
    banner.className = "banner warn";
    banner.innerHTML = "<strong>Configuration incomplete.</strong> The webhook returns 503 until these are set:"
      + missingHtml(missing);
  } else {
    banner.className = "banner ok";
    banner.textContent = "Configuration complete.";
  }
}

function missingHtml(missing) {
  if (!missing.length) return "";
  return " <ul>" + missing.map((m) => "<li>" + (LABELS[m] || m) + "</li>").join("") + "</ul>";
}

function collect() {
  const out = {};
  for (const el of form.elements) {
    if (!el.name) continue;
    if (el.classList.contains("clear-secret")) continue;   // handled below
    if (el.type === "checkbox") out[el.name] = el.checked;
    else if (el.type === "password" && el.value === "") continue; // blank secret = keep existing
    else out[el.name] = el.value;
  }
  // Explicit removals: ticked "remove" boxes clear that secret (blank alone = keep).
  const clear = [];
  form.querySelectorAll(".clear-secret:checked").forEach((c) => clear.push(c.dataset.for));
  if (clear.length) out.__clear__ = clear;
  return out;
}

form.addEventListener("submit", async (e) => {
  e.preventDefault();
  status.className = "save-status";
  status.textContent = "Saving…";
  try {
    const wasSetup = banner && banner.classList.contains("setup");
    const res = await api("/api/settings", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(collect()),
    });
    fill(res.settings);
    renderBanner(res);
    form.querySelectorAll(".clear-secret:checked").forEach((c) => (c.checked = false));  // reset removals
    status.textContent = "Saved — applied live.";
    // Leaving setup mode (an admin password was just set) means sign-in is now required.
    if (wasSetup && !res.setup_mode) {
      status.textContent = "Saved. Admin password set — redirecting to sign in…";
      setTimeout(() => { window.location = "/login"; }, 1200);
    }
  } catch (err) {
    status.className = "save-status err";
    status.textContent = "Save failed: " + err.message;
  }
});

api("/api/settings").then((res) => { fill(res.settings); renderBanner(res); }).catch(() => {});
