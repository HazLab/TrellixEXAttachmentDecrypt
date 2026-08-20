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

// Per-field help: a "?" with a hover/focus tooltip explaining each option.
const RESTART = new Set(["web_host", "web_port", "log_level", "log_file", "log_file_max_bytes",
  "log_file_backups", "login_rate_limit", "login_rate_window", "form_rate_limit", "form_rate_window"]);
const HELP = {
  ui_password: "Password for signing in to this dashboard. Required — setting it for the first time ends setup mode.",
  ex_base_url: "Base URL of the Trellix EX appliance, e.g. https://ex.example.com.",
  ex_username: "EX API account username (needs the API Analyst role).",
  ex_password: "Password for the EX API account. Leave blank to keep the current one; tick remove to clear.",
  ex_verify_tls: "Verify the EX TLS certificate. Off by default — EX appliances commonly use self-signed certs.",
  ex_client_token: "Optional X-FeClient-Token issued by Trellix. Leave blank if unused.",
  ex_rescan_id_field: "Which id the rescan endpoint expects in its path. Try email_uuid if rescan returns an authorization error.",
  ex_timeout: "HTTP timeout (seconds) for EX API calls. Raise if EX is slow (ReadTimeout).",
  smtp_host: "SMTP relay hostname used to send the recipient emails.",
  smtp_port: "SMTP port (587 = STARTTLS, 465 = implicit TLS, 25 = plain).",
  smtp_username: "SMTP auth username. Leave blank if the relay needs no auth.",
  smtp_password: "SMTP auth password. Leave blank to keep the current one; tick remove to clear.",
  smtp_from: "From address shown on the recipient emails.",
  smtp_tls_mode: "How TLS is negotiated: opportunistic, required STARTTLS, none, or implicit SSL (port 465).",
  smtp_verify_tls: "Verify the SMTP server's TLS certificate. Off by default for lab/self-signed CAs.",
  smtp_helo_hostname: "HELO/EHLO name sent to the server. Set an FQDN if the server rejects the OS hostname (504 5.5.2).",
  trigger_alert_name: "The EX alert top-level name that triggers the flow (e.g. RISKWARE_OBJECT).",
  trigger_malware_names: "Comma-separated malware names that trigger the flow (the encrypted-attachment policy emits CustomPolicy.MVX.<ext>). Empty disables triggering.",
  max_password_attempts: "How many wrong-password rounds before giving up (cap 5).",
  recheck_delay: "Seconds before the first recheck poll after a resubmission.",
  recheck_interval: "Steady-state seconds between later recheck polls.",
  recheck_max_attempts: "Number of recheck polls before concluding the verdict from the list.",
  reconcile_lookback: "EX alerts-query window scanned to backfill missed alerts (e.g. 1_hour, 24_hours, 48_hours).",
  reconcile_interval: "Seconds between periodic reconcile sweeps (0 = run only on startup).",
  notify_max_retries: "How many times to retry a failed recipient email.",
  notify_retry_interval: "Seconds between email retry sweeps.",
  resubmit_max_retries: "How many times to retry a failed EX rescan.",
  resubmit_retry_interval: "Seconds between rescan retry sweeps.",
  imap_host: "IMAP host to poll for bounce (DSN) detection. Blank disables bounce monitoring.",
  imap_port: "IMAP port (993 for IMAPS).",
  imap_username: "IMAP account username for the bounce mailbox.",
  imap_password: "IMAP account password. Leave blank to keep the current one; tick remove to clear.",
  imap_ssl: "Connect to IMAP over SSL (IMAPS).",
  imap_mailbox: "Mailbox scanned for bounces (e.g. INBOX).",
  bounce_poll_interval: "Seconds between IMAP bounce polls.",
  public_base_url: "Public URL recipients use — the one-time links are built from it. Must match how they reach this server.",
  webhook_username: "HTTP Basic-auth username EX must send to the webhook.",
  webhook_password: "HTTP Basic-auth password EX must send. Leave blank to keep the current one; tick remove to clear.",
  webhook_ip_allowlist: "Comma-separated source IPs allowed to POST the webhook (blank = any). The webhook needs Basic auth and/or an allowlist.",
  token_ttl: "Lifetime (seconds) of a one-time recipient link before it expires.",
  login_rate_limit: "Failed admin sign-ins allowed per IP within the window before HTTP 429.",
  login_rate_window: "Window (seconds) for the login rate limit.",
  form_rate_limit: "Password-form submissions allowed per IP + link within the window.",
  form_rate_window: "Window (seconds) for the password-form rate limit.",
  trust_forwarded_for: "Trust X-Forwarded-For for the client IP. Enable only behind a trusted reverse proxy (otherwise spoofable).",
  max_request_bytes: "Reject webhook/form request bodies larger than this many bytes (DoS guard).",
  web_host: "Network interface the server binds to (0.0.0.0 = all).",
  web_port: "Port the server listens on. In Docker set the WEB_PORT env var instead, so the mapping/healthcheck stay in sync.",
  log_level: "Logging verbosity: DEBUG, INFO, WARNING, or ERROR.",
  log_file: "File to write logs to (blank = console only).",
  log_file_max_bytes: "Rotate the log file when it reaches this size (bytes).",
  log_file_backups: "How many rotated log files to keep.",
};

function injectHelp() {
  for (const [name, tip] of Object.entries(HELP)) {
    const field = form.elements[name];
    if (!field) continue;
    const label = (field.closest && field.closest("label")) || null;
    if (!label || label.querySelector(".help")) continue;
    const span = document.createElement("span");
    span.className = "help";
    span.tabIndex = 0;
    span.setAttribute("aria-label", tip);
    span.textContent = "?";
    span.dataset.tip = tip + (RESTART.has(name) ? "  ·  Restart required to apply." : "");
    label.appendChild(span);
    label.classList.add("has-help");
  }
}
injectHelp();

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
