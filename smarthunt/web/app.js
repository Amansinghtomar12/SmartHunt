/* SmartHunt web UI — vanilla JS, no dependencies.
 *
 * Talks to the local Python server: starts scans, polls status + log events
 * while one runs, and renders results into filterable, sortable tables.
 */
'use strict';

const $ = (sel) => document.querySelector(sel);
const $$ = (sel) => Array.from(document.querySelectorAll(sel));

const STAGE_ICONS = { pending: '○', running: '◐', done: '●', skipped: '◌' };
const SEVERITIES = ['critical', 'high', 'medium', 'low', 'info'];
const CARD_LABELS = ['Subdomains', 'Live hosts', 'URLs', 'JS files', 'Endpoints',
                     'Parameters', 'Secrets', 'Findings', 'Critical/High'];

const state = {
  mode: 'domain',
  stages: [],          // catalog from the server
  tools: [],
  categories: [],
  enabled: new Set(),
  cursor: 0,
  run: null,           // server's scan counter; a change means resync
  polling: null,
  running: false,
  results: null,
  tableState: {},      // pane -> {sort, desc, filter}
};

/* ── helpers ─────────────────────────────────────────────── */
const esc = (v) => String(v ?? '').replace(/[&<>"']/g,
  (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));

async function api(path, options) {
  const res = await fetch(path, options);
  let body = {};
  try { body = await res.json(); } catch (_) { /* empty body */ }
  if (!res.ok) throw new Error(body.error || `HTTP ${res.status}`);
  return body;
}

// Stamped into the page by the server. Sending it as a custom header also
// forces a CORS preflight, which the server refuses — so a cross-origin page
// cannot reach these endpoints at all.
const CSRF_TOKEN = (document.querySelector('meta[name=smarthunt-token]') || {}).content || '';

const post = (path, payload) => api(path, {
  method: 'POST',
  headers: { 'Content-Type': 'application/json', 'X-SmartHunt-Token': CSRF_TOKEN },
  body: JSON.stringify(payload || {}),
});

function setStatus(text) { $('#status').textContent = text; }

function copyText(text) {
  if (navigator.clipboard && window.isSecureContext) {
    navigator.clipboard.writeText(text);
  } else {
    const ta = document.createElement('textarea');
    ta.value = text;
    ta.style.position = 'fixed';
    ta.style.opacity = '0';
    document.body.appendChild(ta);
    ta.select();
    try { document.execCommand('copy'); } finally { document.body.removeChild(ta); }
  }
}

/* ── target parsing (mirrors engine.normalize_target) ────── */
const DOMAIN_RE = /^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$/;

function parseTarget(raw) {
  let t = (raw || '').trim().toLowerCase();
  if (!t) return { error: '' };
  t = t.replace(/^https?:\/\//, '').split('/')[0].split('?')[0];
  t = t.split('@').pop().split(':')[0];
  let mode = null;
  if (t.startsWith('*.')) { mode = 'wildcard'; t = t.slice(2); }
  else if (t.startsWith('.')) { mode = 'wildcard'; t = t.slice(1); }
  t = t.replace(/^\.+|\.+$/g, '');
  if (!t || !DOMAIN_RE.test(t)) return { error: `'${raw}' is not a valid domain` };
  return { apex: t, mode };
}

/* ── mode + target ───────────────────────────────────────── */
function setMode(mode) {
  state.mode = mode;
  $$('.mode-card').forEach((card) => {
    const on = card.dataset.mode === mode;
    card.classList.toggle('selected', on);
    card.setAttribute('aria-checked', String(on));
  });
  $('#target').placeholder = mode === 'wildcard' ? '*.example.com' : 'example.com';
  renderStages({ applyModeDefaults: true });
}

function updateHint() {
  const raw = $('#target').value;
  const hint = $('#targetHint');
  if (!raw.trim()) { hint.textContent = ''; hint.className = 'hint'; return; }
  const parsed = parseTarget(raw);
  if (parsed.error) {
    hint.textContent = `✗ ${parsed.error}`;
    hint.className = 'hint bad';
    return;
  }
  if (parsed.mode === 'wildcard' && state.mode !== 'wildcard') {
    setMode('wildcard');
  }
  hint.textContent = `✓ scope: ${parsed.mode === 'wildcard' || state.mode === 'wildcard'
    ? '*.' + parsed.apex : parsed.apex}`;
  hint.className = 'hint ok';
}

/* ── modules ─────────────────────────────────────────────── */
// Mirrors the desktop GUI's _on_mode_change / _reset_stages so both front-ends
// behave identically:
//   applyModeDefaults - switching mode turns ON that mode's defaults and turns
//     OFF anything the mode can't run, but leaves non-default stages the user
//     ticked by hand (ports, screenshots) alone.
//   hardReset - the "Defaults" button: exactly this mode's defaults, nothing else.
function renderStages({ applyModeDefaults = false, hardReset = false } = {}) {
  const host = $('#stageList');
  host.innerHTML = '';
  state.stages.forEach((stage) => {
    const applies = stage.modes.includes(state.mode);
    const isDefault = state.mode === 'wildcard' ? stage.default_wildcard : stage.default_domain;
    if (hardReset) {
      if (applies && isDefault) state.enabled.add(stage.key);
      else state.enabled.delete(stage.key);
    } else if (!applies) {
      state.enabled.delete(stage.key);
    } else if (applyModeDefaults && isDefault) {
      state.enabled.add(stage.key);
    }

    const row = document.createElement('div');
    row.className = 'stage-row' + (applies ? '' : ' disabled');
    row.innerHTML = `
      <input type="checkbox" id="st-${stage.key}" ${applies ? '' : 'disabled'}
             ${state.enabled.has(stage.key) ? 'checked' : ''}>
      <label for="st-${stage.key}">${esc(stage.title)}</label>
      <span class="stage-state" id="ss-${stage.key}">${STAGE_ICONS.pending}</span>`;
    row.querySelector('input').addEventListener('change', (e) => {
      if (e.target.checked) state.enabled.add(stage.key);
      else state.enabled.delete(stage.key);
    });
    host.appendChild(row);
  });
  renderPipeline();
}

function renderPipeline(stageStates = {}) {
  const host = $('#pipeline');
  host.innerHTML = state.stages.map((stage) => {
    const st = stageStates[stage.key] || 'pending';
    return `<div class="pipe-row ${st}">${STAGE_ICONS[st] || '○'}&nbsp;&nbsp;${esc(stage.title)}</div>`;
  }).join('');
}

/* ── tabs ────────────────────────────────────────────────── */
const TAB_NAMES = ['dashboard', 'findings', 'secrets', 'hosts', 'subdomains', 'urls',
                   'js', 'endpoints', 'params', 'content', 'log', 'arsenal'];

function selectTab(name, { updateHash = true } = {}) {
  if (!TAB_NAMES.includes(name)) name = 'dashboard';
  $$('.tab').forEach((t) => t.classList.toggle('active', t.dataset.tab === name));
  $$('.pane').forEach((p) => p.classList.toggle('active', p.id === `pane-${name}`));
  if (updateHash && location.hash.slice(1) !== name) {
    history.replaceState(null, '', `#${name}`);
  }
}

function tabFromHash() {
  const name = decodeURIComponent(location.hash.replace(/^#/, ''));
  return TAB_NAMES.includes(name) ? name : null;
}

/* ── generic table renderer ──────────────────────────────── */
function renderTable(paneId, columns, rows, opts = {}) {
  const pane = $(`#pane-${paneId}`);
  const ts = state.tableState[paneId] || (state.tableState[paneId] = { sort: null, desc: false, filter: '' });

  let view = rows;
  if (ts.filter) {
    const needle = ts.filter.toLowerCase();
    view = rows.filter((r) => r.some((c) => String(c ?? '').toLowerCase().includes(needle)));
  }
  if (ts.sort !== null) {
    const i = ts.sort;
    view = view.slice().sort((a, b) => {
      const x = a[i], y = b[i];
      const nx = parseFloat(x), ny = parseFloat(y);
      const bothNumeric = !Number.isNaN(nx) && !Number.isNaN(ny)
        && String(x).trim() !== '' && String(y).trim() !== '';
      const cmp = bothNumeric ? nx - ny
        : String(x ?? '').toLowerCase().localeCompare(String(y ?? '').toLowerCase());
      return ts.desc ? -cmp : cmp;
    });
  }

  const head = columns.map((c, i) => {
    const arrow = ts.sort === i ? (ts.desc ? ' ▼' : ' ▲') : '';
    return `<th data-col="${i}">${esc(c)}<span class="arrow">${arrow}</span></th>`;
  }).join('');

  const body = view.length
    ? view.map((r) => '<tr>' + r.map((cell, i) => {
        const render = opts.cell && opts.cell[i];
        return `<td>${render ? render(cell, r) : esc(cell)}</td>`;
      }).join('') + '</tr>').join('')
    : '';

  pane.innerHTML = `
    <div class="pane-bar">
      <input type="text" placeholder="Filter…" value="${esc(ts.filter)}" data-role="filter">
      <span class="muted">${view.length === rows.length
        ? `${rows.length} rows` : `${view.length} of ${rows.length} rows`}</span>
      <div class="spacer"></div>
      <button class="btn btn-sm" data-role="copy">Copy all</button>
    </div>
    <div class="table-wrap">
      ${body ? `<table><thead><tr>${head}</tr></thead><tbody>${body}</tbody></table>`
             : '<div class="empty">Nothing found.</div>'}
    </div>`;

  const filterInput = pane.querySelector('[data-role=filter]');
  filterInput.addEventListener('input', (e) => {
    ts.filter = e.target.value;
    renderTable(paneId, columns, rows, opts);
    const again = pane.querySelector('[data-role=filter]');
    again.focus();
    again.setSelectionRange(again.value.length, again.value.length);
  });
  pane.querySelector('[data-role=copy]').addEventListener('click', () => {
    copyText(view.map((r) => r.join('\t')).join('\n'));
    setStatus(`Copied ${view.length} rows`);
  });
  pane.querySelectorAll('th').forEach((th) => th.addEventListener('click', () => {
    const i = Number(th.dataset.col);
    ts.desc = ts.sort === i ? !ts.desc : false;
    ts.sort = i;
    renderTable(paneId, columns, rows, opts);
  }));
}

function renderList(paneId, items) {
  const pane = $(`#pane-${paneId}`);
  const ts = state.tableState[paneId] || (state.tableState[paneId] = { filter: '' });
  const view = ts.filter
    ? items.filter((i) => String(i).toLowerCase().includes(ts.filter.toLowerCase()))
    : items;

  pane.innerHTML = `
    <div class="pane-bar">
      <input type="text" placeholder="Filter…" value="${esc(ts.filter)}" data-role="filter">
      <span class="muted">${view.length === items.length
        ? `${items.length} items` : `${view.length} of ${items.length} items`}</span>
      <div class="spacer"></div>
      <button class="btn btn-sm" data-role="copy">Copy all</button>
    </div>
    ${view.length ? `<pre class="list">${view.map(esc).join('\n')}</pre>`
                  : '<div class="empty">Nothing found.</div>'}`;

  const filterInput = pane.querySelector('[data-role=filter]');
  filterInput.addEventListener('input', (e) => {
    ts.filter = e.target.value;
    renderList(paneId, items);
    const again = pane.querySelector('[data-role=filter]');
    again.focus();
    again.setSelectionRange(again.value.length, again.value.length);
  });
  pane.querySelector('[data-role=copy]').addEventListener('click', () => {
    copyText(view.join('\n'));
    setStatus(`Copied ${view.length} items`);
  });
}

/* ── results ─────────────────────────────────────────────── */
const sevPill = (v) => `<span class="pill ${esc(String(v).toLowerCase())}">${esc(String(v).toUpperCase())}</span>`;
const linkCell = (v) => (String(v).startsWith('http')
  ? `<a href="${esc(v)}" target="_blank" rel="noopener noreferrer">${esc(v)}</a>` : esc(v));

function renderResults(res) {
  state.results = res;
  const stats = res.stats || {};

  $('#cards').innerHTML = CARD_LABELS.map((label) =>
    `<div class="card"><div class="num">${esc(stats[label] ?? 0)}</div>
     <div class="lbl">${esc(label)}</div></div>`).join('');

  const counts = {};
  (res.findings || []).forEach((f) => {
    counts[f.severity] = (counts[f.severity] || 0) + 1;
  });
  $('#sevList').innerHTML = SEVERITIES.map((s) =>
    `<div class="sev-row"><span class="pill ${s}">${s.toUpperCase()}</span>
     <span class="n">${counts[s] || 0}</span></div>`).join('');

  renderTable('findings',
    ['Severity', 'Host', 'Finding', 'Detail', 'Source'],
    (res.findings || []).map((f) => [f.severity, f.host, f.name, f.detail, f.source]),
    { cell: { 0: sevPill, 3: (v) => `<code>${esc(v)}</code>` } });

  renderTable('secrets',
    ['Severity', 'Type', 'Value', 'Source file'],
    (res.secrets || []).map((s) => [s.severity, s.type, s.value, s.source]),
    { cell: { 0: sevPill, 2: (v) => `<code>${esc(v)}</code>`, 3: linkCell } });

  renderTable('hosts',
    ['Host', 'Status', 'Title', 'Tech', 'Ports', 'IPs', 'URL'],
    (res.hosts || []).map((h) => [h.host, h.status ?? '', h.title,
      (h.tech || []).join(', '), (h.ports || []).join(', '), (h.ips || []).join(', '), h.url]),
    { cell: { 6: linkCell } });

  renderTable('content',
    ['URL', 'Status', 'Length', 'Type'],
    (res.content || []).map((c) => [c.url, c.status, c.length, c.type]),
    { cell: { 0: linkCell } });

  renderList('subdomains', res.subdomains || []);
  renderList('urls', res.urls || []);
  renderList('js', res.js_files || []);
  renderList('endpoints', res.js_endpoints || []);
  renderList('params', (res.params && res.params.names) || []);

  const badges = {
    findings: (res.findings || []).length,
    secrets: (res.secrets || []).length,
    hosts: (res.hosts || []).length,
    subdomains: (res.subdomains || []).length,
    urls: (res.urls || []).length,
    js: (res.js_files || []).length,
    endpoints: (res.js_endpoints || []).length,
    params: ((res.params && res.params.names) || []).length,
    content: (res.content || []).length,
  };
  Object.entries(badges).forEach(([k, v]) => {
    const el = $(`#b-${k}`);
    if (el) el.textContent = v;
  });
}

/* ── log ─────────────────────────────────────────────────── */
function appendLog(events) {
  if (!events.length) return;
  const out = $('#logOut');
  const frag = document.createDocumentFragment();
  events.forEach((ev) => {
    const line = document.createElement('div');
    line.innerHTML = `<span class="ts">${esc(ev.ts)}</span> ` +
                     `<span class="l-${esc(ev.level)}">${esc(ev.msg)}</span>`;
    frag.appendChild(line);
  });
  out.appendChild(frag);
  if ($('#autoscroll').checked) out.scrollTop = out.scrollHeight;
}

/* ── polling ─────────────────────────────────────────────── */
async function poll() {
  let status;
  try {
    status = await api('/api/status');
  } catch (err) {
    setStatus(`Lost connection to the SmartHunt server (${err.message})`);
    return;
  }

  $('#progressBar').style.width = `${status.progress}%`;
  $('#elapsed').textContent = status.elapsed ? `${status.elapsed}s` : '';
  renderPipeline(status.stages);
  Object.entries(status.stages).forEach(([key, st]) => {
    const el = $(`#ss-${key}`);
    if (el) { el.textContent = STAGE_ICONS[st] || '○'; el.className = `stage-state ${st}`; }
  });

  // Another tab started a scan: our cursor and buffered log belong to the old
  // run, so drop them rather than silently interleaving two scans.
  if (state.run !== null && status.run !== state.run) {
    state.cursor = 0;
    $('#logOut').innerHTML = '';
  }
  state.run = status.run;

  try {
    const chunk = await api(`/api/events?cursor=${state.cursor}`);
    state.cursor = chunk.cursor;
    appendLog(chunk.events || []);
  } catch (_) { /* transient */ }

  const running = status.running;
  const runningStage = Object.entries(status.stages).find(([, st]) => st === 'running');
  if (running) {
    const stage = state.stages.find((s) => runningStage && s.key === runningStage[0]);
    $('#stageText').textContent = status.paused
      ? 'Paused — will halt at the next module boundary'
      : (stage ? `Running: ${stage.title}` : 'Running…');
  }

  if (!running && state.running) {
    state.running = false;
    setControls(false);
    try {
      const res = await api('/api/results');
      if (res.ready) {
        renderResults(res);
        $('#exportBtn').disabled = false;
        const stats = res.stats || {};
        if (status.error) {
          $('#stageText').textContent = 'Scan failed — see the Log tab';
          setStatus(`Error: ${status.error}`);
        } else if (status.stopped) {
          $('#stageText').textContent = 'Scan stopped — partial results shown';
          setStatus('Stopped by user');
        } else {
          $('#stageText').textContent = 'Scan complete';
          setStatus(`Done in ${res.duration}s — ${stats.Findings || 0} findings ` +
                    `(${stats['Critical/High'] || 0} critical/high), ` +
                    `${stats['Live hosts'] || 0} live hosts`);
          selectTab('findings');
        }
      }
    } catch (err) {
      setStatus(`Could not load results: ${err.message}`);
    }
    stopPolling();
  }
}

function startPolling() {
  stopPolling();
  poll();
  state.polling = setInterval(poll, 900);
}

function stopPolling() {
  if (state.polling) { clearInterval(state.polling); state.polling = null; }
}

function setControls(running) {
  $('#startBtn').disabled = running;
  $('#stopBtn').disabled = !running;
  $('#pauseBtn').disabled = !running;
  $('#pauseBtn').textContent = 'Pause';
  $('#pauseBtn').dataset.paused = 'false';
}

/* ── scan lifecycle ──────────────────────────────────────── */
function collectOptions() {
  return {
    threads: Number($('#optThreads').value) || 40,
    depth: Number($('#optDepth').value) || 2,
    max_pages: Number($('#optPages').value) || 300,
    max_js: Number($('#optJs').value) || 400,
    ports: $('#optPorts').value,
    severity: $('#optSeverity').value,
    bruteforce: $('#optBrute').checked,
    include_subs: $('#optSubs').checked,
    sub_wordlist: $('#optSubWl').value,
    content_wordlist: $('#optContentWl').value,
    out: $('#optOut').value,
  };
}

function askAuthorization() {
  const parsed = parseTarget($('#target').value);
  if (parsed.error || !parsed.apex) {
    setStatus(parsed.error || 'Enter a target first');
    $('#target').focus();
    return;
  }
  if (!state.enabled.size) {
    setStatus('Enable at least one module before starting.');
    return;
  }
  const mode = parsed.mode === 'wildcard' ? 'wildcard' : state.mode;
  $('#authScope').textContent = mode === 'wildcard' ? `*.${parsed.apex}` : parsed.apex;
  $('#authMode').textContent = mode;
  $('#authModules').textContent = `${state.enabled.size} enabled`;
  $('#authCheck').checked = false;
  $('#authConfirm').disabled = true;
  $('#authModal').hidden = false;
}

async function beginScan() {
  const parsed = parseTarget($('#target').value);
  const mode = parsed.mode === 'wildcard' ? 'wildcard' : state.mode;
  $('#authModal').hidden = true;

  $('#logOut').innerHTML = '';
  state.cursor = 0;
  state.results = null;
  $('#exportBtn').disabled = true;
  $('#reportBtn').disabled = true;
  $('#exportHint').textContent = '';
  selectTab('dashboard');

  try {
    await post('/api/scan/start', {
      target: $('#target').value,
      mode,
      stages: Array.from(state.enabled),
      authorized: true,
      ...collectOptions(),
    });
  } catch (err) {
    setStatus(`Could not start: ${err.message}`);
    return;
  }

  state.running = true;
  setControls(true);
  setStatus(`Scanning ${mode === 'wildcard' ? '*.' : ''}${parsed.apex} …`);
  $('#stageText').textContent = 'Starting…';
  startPolling();
}

/* ── arsenal ─────────────────────────────────────────────── */
function renderArsenal() {
  const found = state.tools.filter((t) => t.installed).length;
  $('#toolCount').textContent = `⚙ ${found}/${state.tools.length} external tools`;
  $('#arsenalSummary').textContent = found
    ? `${found}/${state.tools.length} external tools found: ` +
      state.tools.filter((t) => t.installed).map((t) => t.name).join(', ')
    : `0/${state.tools.length} external tools found — running in pure-Python fallback mode.`;

  $('#arsenal').innerHTML = state.categories.map((cat) => {
    const tools = state.tools.filter((t) => t.category === cat);
    if (!tools.length) return '';
    return `<div class="ars-cat">${esc(cat)}</div>` + tools.map((t) => `
      <div class="ars-row ${t.installed ? 'on' : 'off'}">
        <span class="ars-mark">${t.installed ? '●' : '○'}</span>
        <span class="ars-name">${esc(t.name)}</span>
        <span class="ars-desc">${esc(t.description)}</span>
        ${t.installed ? '' : `<span class="ars-install">${esc(t.install)}</span>`}
      </div>`).join('');
  }).join('');
}

/* ── init ────────────────────────────────────────────────── */
async function init() {
  let meta;
  try {
    meta = await api('/api/meta');
  } catch (err) {
    setStatus(`Could not reach the SmartHunt server: ${err.message}`);
    return;
  }
  state.stages = meta.stages;
  state.tools = meta.tools;
  state.categories = meta.categories;
  $('#optOut').value = meta.default_out;
  renderArsenal();
  setMode('domain');
  setStatus(`Ready — SmartHunt v${meta.version}`);

  ['findings', 'secrets', 'hosts', 'content'].forEach((p) => renderTable(p, [], []));
  ['subdomains', 'urls', 'js', 'endpoints', 'params'].forEach((p) => renderList(p, []));

  const initial = tabFromHash();
  if (initial) selectTab(initial, { updateHash: false });

  // If a scan is already running (page reloaded mid-scan), reattach to it.
  try {
    const status = await api('/api/status');
    state.run = status.run;
    if (status.running) {
      state.running = true;
      setControls(true);
      $('#target').value = status.mode === 'wildcard' ? `*.${status.target}` : status.target;
      setMode(status.mode);
      updateHint();
      startPolling();
    } else if (status.has_results) {
      const res = await api('/api/results');
      if (res.ready) {
        renderResults(res);
        renderPipeline(status.stages);
        Object.entries(status.stages).forEach(([key, st]) => {
          const el = $(`#ss-${key}`);
          if (el) { el.textContent = STAGE_ICONS[st] || '○'; el.className = `stage-state ${st}`; }
        });
        $('#exportBtn').disabled = false;
        $('#progressBar').style.width = '100%';
        $('#stageText').textContent = status.stopped
          ? 'Previous scan stopped — partial results shown'
          : `Results for ${status.target}`;
        const stats = res.stats || {};
        setStatus(`${stats.Findings || 0} findings (${stats['Critical/High'] || 0} critical/high), ` +
                  `${stats['Live hosts'] || 0} live hosts — from the last scan`);
      }
    }
  } catch (_) { /* first run */ }
}

/* ── event wiring ────────────────────────────────────────── */
$$('.mode-card').forEach((card) => {
  card.addEventListener('click', () => { setMode(card.dataset.mode); updateHint(); });
  card.addEventListener('keydown', (e) => {
    if (e.key === 'Enter' || e.key === ' ') {
      e.preventDefault();
      setMode(card.dataset.mode);
      updateHint();
    }
  });
});

$('#target').addEventListener('input', updateHint);
$('#target').addEventListener('keydown', (e) => {
  if (e.key === 'Enter' && !state.running) askAuthorization();
});

$('#startBtn').addEventListener('click', askAuthorization);

$('#stopBtn').addEventListener('click', async () => {
  $('#stopBtn').disabled = true;
  setStatus('Stopping — finishing the current module…');
  try { await post('/api/scan/stop'); } catch (err) { setStatus(err.message); }
});

$('#pauseBtn').addEventListener('click', async () => {
  const btn = $('#pauseBtn');
  const paused = btn.dataset.paused !== 'true';
  try {
    await post('/api/scan/pause', { paused });
    btn.dataset.paused = String(paused);
    btn.textContent = paused ? 'Resume' : 'Pause';
    setStatus(paused ? 'Paused' : 'Resumed');
  } catch (err) { setStatus(err.message); }
});

$('#authCheck').addEventListener('change', (e) => {
  $('#authConfirm').disabled = !e.target.checked;
});
$('#authConfirm').addEventListener('click', beginScan);
$('#authCancel').addEventListener('click', () => { $('#authModal').hidden = true; });
$('#authModal').addEventListener('click', (e) => {
  if (e.target === $('#authModal')) $('#authModal').hidden = true;
});
document.addEventListener('keydown', (e) => {
  if (e.key === 'Escape' && !$('#authModal').hidden) $('#authModal').hidden = true;
});

$$('[data-stages]').forEach((btn) => btn.addEventListener('click', () => {
  const which = btn.dataset.stages;
  if (which === 'default') { renderStages({ hardReset: true }); return; }
  state.stages.forEach((s) => {
    if (!s.modes.includes(state.mode)) return;
    if (which === 'all') state.enabled.add(s.key);
    else state.enabled.delete(s.key);
  });
  renderStages();
}));

$$('.tab').forEach((tab) => tab.addEventListener('click', () => selectTab(tab.dataset.tab)));
window.addEventListener('hashchange', () => {
  const name = tabFromHash();
  if (name) selectTab(name, { updateHash: false });
});

$('#exportBtn').addEventListener('click', async () => {
  try {
    const out = await post('/api/export', { out: $('#optOut').value });
    $('#exportHint').textContent = `Wrote ${out.files.length} files to ${out.dir}`;
    $('#reportBtn').disabled = !out.report;
    setStatus(`Exported ${out.files.length} files`);
  } catch (err) {
    setStatus(`Export failed: ${err.message}`);
  }
});

$('#reportBtn').addEventListener('click', () => window.open('/report', '_blank', 'noopener'));

$('#rescanTools').addEventListener('click', async () => {
  try {
    const out = await api('/api/rescan-tools');
    state.tools = out.tools;
    renderArsenal();
    setStatus(`Re-scanned: ${out.tools_found} external tools found`);
  } catch (err) { setStatus(err.message); }
});

$('#clearLog').addEventListener('click', () => { $('#logOut').innerHTML = ''; });
$('#copyLog').addEventListener('click', () => {
  copyText($('#logOut').innerText);
  setStatus('Log copied');
});

init();
