use anyhow::{Context, Result};
use axum::{
    body::Body,
    extract::{Path, State},
    http::{Request, StatusCode},
    middleware::{self, Next},
    response::{Html, IntoResponse, Json, Response},
    routing::{delete, get, post},
    Router,
};
use chrono::Utc;
use covertwo_core::{
    audit::{AuditAction, AuditEvent},
    aws::{create_s3_client, download_blocklist, upload_blocklist, write_audit_event, S3Client},
    blocklist::{BlocklistEntry, Category, EntryType},
    config::Config,
    logging::setup_tracing,
};
use serde::{Deserialize, Serialize};
use std::{path::PathBuf, str::FromStr, sync::Arc};
use uuid::Uuid;

// ---------------------------------------------------------------------------
// Embedded UI
// ---------------------------------------------------------------------------

const INDEX_HTML: &str = r#"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>CoverTwo — Blocklist Manager</title>
<style>
  :root { --bg: #0d1117; --bg2: #161b22; --border: #30363d; --text: #c9d1d9; --accent: #58a6ff; --green: #238636; --red: #da3633; --yellow: #e3b341; --orange: #d29922; --muted: #8b949e; }
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body { background: var(--bg); color: var(--text); font-family: 'SF Mono', 'Fira Code', monospace; font-size: 13px; padding: 2rem; }
  h1 { color: var(--accent); font-size: 1.4rem; margin-bottom: 1.5rem; letter-spacing: 0.05em; }
  h2 { color: var(--text); font-size: 1rem; margin: 1.5rem 0 0.75rem; }
  .card { background: var(--bg2); border: 1px solid var(--border); border-radius: 6px; padding: 1rem; margin-bottom: 1rem; }
  .row { display: flex; gap: 0.5rem; align-items: center; flex-wrap: wrap; }
  input, select { background: var(--bg); color: var(--text); border: 1px solid var(--border); border-radius: 4px; padding: 6px 10px; font-family: inherit; font-size: 13px; }
  input:focus, select:focus { outline: none; border-color: var(--accent); }
  button { border: none; border-radius: 4px; padding: 6px 14px; font-family: inherit; font-size: 13px; cursor: pointer; }
  .btn-primary { background: var(--green); color: #fff; }
  .btn-danger  { background: var(--red);   color: #fff; }
  .btn-primary:hover { background: #2ea043; }
  .btn-danger:hover  { background: #b91c1c; }
  table { width: 100%; border-collapse: collapse; margin-top: 0.5rem; }
  th, td { padding: 8px 12px; border: 1px solid var(--border); text-align: left; vertical-align: middle; }
  th { background: var(--bg2); color: var(--muted); font-weight: normal; text-transform: uppercase; font-size: 11px; letter-spacing: 0.08em; }
  tr:hover td { background: rgba(88,166,255,0.04); }
  .badge { display: inline-block; padding: 2px 8px; border-radius: 10px; font-size: 11px; font-weight: bold; text-transform: uppercase; letter-spacing: 0.04em; }
  .malicious  { background: var(--red);    color: #fff; }
  .spam       { background: var(--yellow); color: #0d1117; }
  .suspicious { background: var(--orange); color: #0d1117; }
  .other      { background: var(--muted);  color: #0d1117; }
  .status { font-size: 12px; color: var(--muted); margin-left: 1rem; }
  .error { color: var(--red); font-size: 12px; margin-top: 0.4rem; }
  #count { color: var(--accent); }
  .token-hint { color: var(--muted); font-size: 11px; margin-top: 0.3rem; }
</style>
</head>
<body>
<h1>&#x1F6E1; CoverTwo — Blocklist Manager</h1>

<div class="card">
  <div class="row">
    <input type="password" id="token" placeholder="API Token" style="width:240px" />
    <button class="btn-primary" onclick="connect()">Connect</button>
    <span class="status" id="conn-status"></span>
  </div>
  <div class="token-hint">Token is stored in localStorage and never sent in plain text over HTTP.</div>
</div>

<div class="card">
  <h2>Add Entry</h2>
  <div class="row">
    <input type="text" id="new-value"    placeholder="1.2.3.4 or 10.0.0.0/8" style="width:200px" />
    <select id="new-type">
      <option value="ip">IP</option>
      <option value="cidr">CIDR</option>
      <option value="domain">Domain</option>
    </select>
    <select id="new-category">
      <option value="malicious">Malicious</option>
      <option value="spam">Spam</option>
      <option value="suspicious">Suspicious</option>
      <option value="other">Other</option>
    </select>
    <input type="text" id="new-by"    placeholder="your@email.com"   style="width:180px" />
    <input type="text" id="new-notes" placeholder="Notes (optional)" style="width:200px" />
    <button class="btn-primary" onclick="addEntry()">Add</button>
  </div>
  <div class="error" id="add-error"></div>
</div>

<h2>Blocklist &mdash; <span id="count">0</span> entries</h2>
<table>
  <thead>
    <tr>
      <th>Value</th><th>Type</th><th>Category</th>
      <th>Added By</th><th>Added At</th><th>Notes</th><th></th>
    </tr>
  </thead>
  <tbody id="tbl"></tbody>
</table>

<script>
let tok = localStorage.getItem('ct_tok') || '';
if (tok) { document.getElementById('token').placeholder = '(stored)'; load(); }

function connect() {
  tok = document.getElementById('token').value || tok;
  if (!tok) { setStatus('Enter a token first', true); return; }
  localStorage.setItem('ct_tok', tok);
  load();
}

function headers() { return { 'Authorization': 'Bearer ' + tok, 'Content-Type': 'application/json' }; }

function esc(s) {
  return String(s ?? '').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}

function setStatus(msg, err) {
  const el = document.getElementById('conn-status');
  el.textContent = msg;
  el.style.color = err ? 'var(--red)' : 'var(--muted)';
}

async function load() {
  try {
    const r = await fetch('/api/blocklist', { headers: headers() });
    if (r.status === 401) { setStatus('Invalid token', true); return; }
    if (!r.ok)            { setStatus('Error ' + r.status, true); return; }
    const data = await r.json();
    render(data.entries || []);
    setStatus('Connected \u2713', false);
  } catch(e) { setStatus('Cannot reach server', true); }
}

function render(entries) {
  document.getElementById('count').textContent = entries.length;
  const tbl = document.getElementById('tbl');
  tbl.innerHTML = '';
  entries.forEach(e => {
    const tr = document.createElement('tr');
    const cat = esc(e.category || '');
    tr.innerHTML =
      '<td>' + esc(e.value) + '</td>' +
      '<td>' + esc(e.entry_type) + '</td>' +
      '<td><span class="badge ' + cat + '">' + cat + '</span></td>' +
      '<td>' + esc(e.added_by) + '</td>' +
      '<td>' + esc(e.added_at ? new Date(e.added_at).toLocaleString() : '') + '</td>' +
      '<td>' + esc(e.notes) + '</td>' +
      '<td><button class="btn-danger" onclick="remove(' + JSON.stringify(esc(e.value)) + ')">Remove</button></td>';
    tbl.appendChild(tr);
  });
}

async function addEntry() {
  document.getElementById('add-error').textContent = '';
  const val   = document.getElementById('new-value').value.trim();
  const etype = document.getElementById('new-type').value;
  const cat   = document.getElementById('new-category').value;
  const by    = document.getElementById('new-by').value.trim();
  const notes = document.getElementById('new-notes').value.trim();

  if (!val || !by) { document.getElementById('add-error').textContent = 'Value and Added By are required.'; return; }

  const r = await fetch('/api/blocklist', {
    method: 'POST', headers: headers(),
    body: JSON.stringify({ value: val, entry_type: etype, category: cat, added_by: by, notes })
  });

  if (!r.ok) {
    const msg = await r.text().catch(() => r.status.toString());
    document.getElementById('add-error').textContent = msg;
    return;
  }
  document.getElementById('new-value').value = '';
  document.getElementById('new-notes').value = '';
  load();
}

async function remove(value) {
  if (!confirm('Remove ' + value + ' from the blocklist?')) return;
  const by = prompt('Your identity (email / username):');
  if (!by) return;

  const r = await fetch('/api/blocklist/' + encodeURIComponent(value) + '?by=' + encodeURIComponent(by), {
    method: 'DELETE', headers: headers()
  });
  if (r.ok) { load(); } else { alert('Failed to remove entry: ' + r.status); }
}

setInterval(load, 30000);
</script>
</body>
</html>"#;

// ---------------------------------------------------------------------------
// App state
// ---------------------------------------------------------------------------

#[derive(Clone)]
struct AppState {
    s3: S3Client,
    config: Arc<Config>,
    machine_id: String,
    hostname: String,
}

// ---------------------------------------------------------------------------
// Auth middleware
// ---------------------------------------------------------------------------

async fn require_auth(
    State(state): State<Arc<AppState>>,
    req: Request<Body>,
    next: Next,
) -> Response {
    let token = &state.config.web.api_token;

    let auth = req
        .headers()
        .get("Authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .unwrap_or("");

    if auth != token {
        return (StatusCode::UNAUTHORIZED, "Unauthorized").into_response();
    }

    next.run(req).await
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

async fn index_handler() -> Html<&'static str> {
    Html(INDEX_HTML)
}

async fn health_handler() -> Json<serde_json::Value> {
    Json(serde_json::json!({ "status": "ok", "version": env!("CARGO_PKG_VERSION") }))
}

async fn get_blocklist(State(state): State<Arc<AppState>>) -> Response {
    match download_blocklist(&state.s3, &state.config.aws).await {
        Ok(bl) => Json(bl).into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
}

#[derive(Deserialize)]
struct AddEntryRequest {
    value: String,
    entry_type: String,
    category: String,
    added_by: String,
    #[serde(default)]
    notes: String,
}

async fn add_entry(
    State(state): State<Arc<AppState>>,
    Json(req): Json<AddEntryRequest>,
) -> Response {
    let etype = match EntryType::from_str(&req.entry_type) {
        Ok(t) => t,
        Err(e) => return (StatusCode::BAD_REQUEST, e.to_string()).into_response(),
    };
    let cat = match Category::from_str(&req.category) {
        Ok(c) => c,
        Err(e) => return (StatusCode::BAD_REQUEST, e.to_string()).into_response(),
    };

    let mut bl = match download_blocklist(&state.s3, &state.config.aws).await {
        Ok(bl) => bl,
        Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    };

    let entry = BlocklistEntry {
        id: Uuid::new_v4().to_string(),
        value: req.value.clone(),
        entry_type: etype,
        category: cat,
        added_by: req.added_by.clone(),
        added_at: Utc::now(),
        machine_id: state.machine_id.clone(),
        notes: req.notes.clone(),
    };

    if let Err(e) = bl.add_entry(entry) {
        return (StatusCode::CONFLICT, e.to_string()).into_response();
    }

    if let Err(e) = upload_blocklist(&state.s3, &state.config.aws, &bl).await {
        return (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response();
    }

    let audit = AuditEvent::new(
        AuditAction::EntryAdded,
        &req.added_by,
        &state.machine_id,
        &state.hostname,
    )
    .with_target(&req.value)
    .with_details(format!("category={} via=web", req.category));

    if let Err(e) = write_audit_event(&state.s3, &state.config.aws, &audit).await {
        tracing::warn!(error = %e, "Failed to write audit event");
    }

    StatusCode::CREATED.into_response()
}

#[derive(Deserialize)]
struct RemoveQuery {
    by: Option<String>,
}

async fn remove_entry(
    State(state): State<Arc<AppState>>,
    Path(value): Path<String>,
    axum::extract::Query(q): axum::extract::Query<RemoveQuery>,
) -> Response {
    let by = q.by.unwrap_or_else(|| "web-ui".to_string());

    let mut bl = match download_blocklist(&state.s3, &state.config.aws).await {
        Ok(bl) => bl,
        Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    };

    if let Err(e) = bl.remove_entry(&value) {
        return (StatusCode::NOT_FOUND, e.to_string()).into_response();
    }

    if let Err(e) = upload_blocklist(&state.s3, &state.config.aws, &bl).await {
        return (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response();
    }

    let audit = AuditEvent::new(
        AuditAction::EntryRemoved,
        &by,
        &state.machine_id,
        &state.hostname,
    )
    .with_target(&value)
    .with_details("via=web".to_string());

    if let Err(e) = write_audit_event(&state.s3, &state.config.aws, &audit).await {
        tracing::warn!(error = %e, "Failed to write audit event");
    }

    StatusCode::NO_CONTENT.into_response()
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

fn machine_id() -> String {
    let out = std::process::Command::new("ioreg")
        .args(["-rd1", "-c", "IOPlatformExpertDevice"])
        .output()
        .unwrap_or_default();

    for line in String::from_utf8_lossy(&out.stdout).lines() {
        if line.contains("IOPlatformSerialNumber") {
            if let Some(serial) = line.split('"').nth(3) {
                if !serial.is_empty() {
                    return serial.to_string();
                }
            }
        }
    }

    hostname::get()
        .unwrap_or_default()
        .to_string_lossy()
        .to_string()
}

fn hostname() -> String {
    hostname::get()
        .unwrap_or_default()
        .to_string_lossy()
        .to_string()
}

#[tokio::main]
async fn main() -> Result<()> {
    setup_tracing();

    let config_path: PathBuf = std::env::args()
        .nth(1)
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/etc/covertwo/config.toml"));

    let config = Config::load(&config_path)
        .with_context(|| format!("Failed to load config from {}", config_path.display()))?;

    if config.web.api_token.is_empty() {
        anyhow::bail!("web.api_token must be set in config before starting the web UI");
    }

    let s3 = create_s3_client(&config.aws.region)
        .await
        .context("Failed to create S3 client")?;

    let bind_addr = config.web.bind_addr.clone();

    let state = Arc::new(AppState {
        s3,
        config: Arc::new(config),
        machine_id: machine_id(),
        hostname: hostname(),
    });

    let protected = Router::new()
        .route("/api/blocklist", get(get_blocklist).post(add_entry))
        .route("/api/blocklist/:value", delete(remove_entry))
        .layer(middleware::from_fn_with_state(state.clone(), require_auth));

    let app = Router::new()
        .route("/", get(index_handler))
        .route("/api/health", get(health_handler))
        .merge(protected)
        .with_state(state);

    let listener = tokio::net::TcpListener::bind(&bind_addr)
        .await
        .with_context(|| format!("Failed to bind to {}", bind_addr))?;

    tracing::info!(addr = %bind_addr, "CoverTwo web UI listening");

    axum::serve(listener, app)
        .await
        .context("Web server failed")?;

    Ok(())
}
