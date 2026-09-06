const API = window.CYCLOPS_API || location.origin;
const $ = (selector) => document.querySelector(selector);
const $$ = (selector) => Array.from(document.querySelectorAll(selector));

const state = {
  alerts: [], incidents: [], evidence: [], flows: [], metrics: null,
  filters: {
    incidents: { q: '', severity: 'all', sort: 'score_desc' },
    alerts: { q: '', severity: 'all', sort: 'confidence_desc' },
    flows: { q: '', protocol: 'all', sort: 'bytes_desc' },
    evidence: { q: '', status: 'all', sort: 'ts_desc' },
  },
  page: { incidents: 1, alerts: 1, flows: 1, evidence: 1 },
  pageSize: 15,
};
let autoTimer = null;

const SEVERITY_ORDER = ['critical', 'high', 'medium', 'low', 'info'];
const SEVERITY_COLOR = { critical: '#ff5470', high: '#ec835a', medium: '#f6b23d', low: '#3ddc84', info: '#9aabc0' };
const SEVERITY_RANK = { critical: 4, high: 3, medium: 2, low: 1, info: 0 };

const live = {
  running: true, speed: 1, mode: 'all',
  nodes: [], particles: [], cx: 0, cy: 0,
  raf: null, lastSpawn: 0, feedShown: new Set(), feedInitialized: false,
};

const escapeHtml = (value) => String(value ?? '').replace(/[&<>"']/g, (char) => ({ '&':'&amp;', '<':'&lt;', '>':'&gt;', '"':'&quot;', "'":'&#039;' })[char]);
const debounce = (fn, delay) => { let timer; return (...args) => { clearTimeout(timer); timer = setTimeout(() => fn(...args), delay); }; };
const hostOf = (addr) => String(addr || '').split(':')[0];
function hexToRgba(hex, alpha) {
  const clean = hex.replace('#', '');
  const value = parseInt(clean.length === 3 ? clean.split('').map((c) => c + c).join('') : clean, 16);
  return `rgba(${(value >> 16) & 255},${(value >> 8) & 255},${value & 255},${alpha})`;
}

function notify(message) { const toast = $('#toast'); toast.textContent = message; toast.classList.add('show'); setTimeout(() => toast.classList.remove('show'), 3200); }
function setConnection(online) { const node = $('#connection'); node.className = `status ${online ? 'online' : 'offline'}`; node.innerHTML = `<i></i> ${online ? 'API CONNECTED' : 'API OFFLINE'}`; }
function copyText(text, label) { navigator.clipboard?.writeText(String(text ?? '')).then(() => notify(`Copied ${label || 'value'}`)).catch(() => notify('Copy failed')); }

function download(filename, content, type) {
  const blob = new Blob([content], { type });
  const url = URL.createObjectURL(blob);
  const link = document.createElement('a');
  link.href = url; link.download = filename;
  document.body.appendChild(link); link.click(); link.remove();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}
function toCsv(rows) {
  if (!rows.length) return '';
  const cols = Object.keys(rows[0]);
  const cell = (value) => `"${String(typeof value === 'object' && value !== null ? JSON.stringify(value) : value ?? '').replace(/"/g, '""')}"`;
  return [cols.join(','), ...rows.map((row) => cols.map((c) => cell(row[c])).join(','))].join('\n');
}

// ---- filtering / sorting ----
const matches = (haystack, q) => !q || haystack.toLowerCase().includes(q.toLowerCase());

function filteredIncidents() {
  const f = state.filters.incidents;
  const sorters = {
    score_desc: (a, b) => b.threat_score - a.threat_score,
    score_asc: (a, b) => a.threat_score - b.threat_score,
    confidence_desc: (a, b) => b.confidence - a.confidence,
    id_asc: (a, b) => a.incident_id.localeCompare(b.incident_id),
  };
  return state.incidents
    .filter((item) => matches([item.incident_id, item.host, item.severity, (item.detections || []).map((d) => d.type).join(' '), item.explanation?.summary].join(' '), f.q)
      && (f.severity === 'all' || item.severity === f.severity))
    .sort(sorters[f.sort] || sorters.score_desc);
}

function filteredAlerts() {
  const f = state.filters.alerts;
  const sorters = {
    confidence_desc: (a, b) => b.confidence - a.confidence,
    confidence_asc: (a, b) => a.confidence - b.confidence,
    id_asc: (a, b) => a.id.localeCompare(b.id),
    severity: (a, b) => (SEVERITY_RANK[b.severity] || 0) - (SEVERITY_RANK[a.severity] || 0),
  };
  return state.alerts
    .filter((item) => matches([item.id, item.threat, item.detector, item.flow_key, item.severity].join(' '), f.q)
      && (f.severity === 'all' || item.severity === f.severity))
    .sort(sorters[f.sort] || sorters.confidence_desc);
}

function filteredFlows() {
  const f = state.filters.flows;
  const sorters = {
    bytes_desc: (a, b) => b.bytes - a.bytes,
    bytes_asc: (a, b) => a.bytes - b.bytes,
    packets_desc: (a, b) => b.packets - a.packets,
    duration_desc: (a, b) => b.duration_s - a.duration_s,
  };
  return state.flows
    .filter((item) => matches([item.id, item.source, item.destination, item.protocol].join(' '), f.q)
      && (f.protocol === 'all' || item.protocol === f.protocol))
    .sort(sorters[f.sort] || sorters.bytes_desc);
}

function filteredEvidence() {
  const f = state.filters.evidence;
  const sorters = {
    ts_desc: (a, b) => (b.ts || 0) - (a.ts || 0),
    ts_asc: (a, b) => (a.ts || 0) - (b.ts || 0),
    id_asc: (a, b) => a.id.localeCompare(b.id),
  };
  return state.evidence
    .filter((item) => {
      const verified = item.verified !== false;
      const statusOk = f.status === 'all' || (f.status === 'verified' && verified) || (f.status === 'failed' && !verified);
      return matches([item.id, item.alert_id, item.threat, item.sha256].join(' '), f.q) && statusOk;
    })
    .sort(sorters[f.sort] || sorters.ts_desc);
}

function populateProtocolOptions() {
  const select = $('#flows-protocol');
  const current = select.value;
  const protocols = Array.from(new Set(state.flows.map((f) => f.protocol).filter(Boolean))).sort();
  select.innerHTML = '<option value="all">All protocols</option>' + protocols.map((p) => `<option value="${escapeHtml(p)}">${escapeHtml(String(p).toUpperCase())}</option>`).join('');
  if (protocols.includes(current)) select.value = current;
}

// ---- pagination ----
function paginate(list, view) {
  const total = list.length;
  const pages = Math.max(1, Math.ceil(total / state.pageSize));
  state.page[view] = Math.min(Math.max(state.page[view], 1), pages);
  const start = (state.page[view] - 1) * state.pageSize;
  return { items: list.slice(start, start + state.pageSize), total, pages, start };
}
function renderPagination(view, total, pages) {
  const el = $(`#${view}-pagination`);
  if (!el) return;
  if (!total) { el.innerHTML = ''; return; }
  const page = state.page[view];
  el.innerHTML = `<button type="button" class="ghost" ${page <= 1 ? 'disabled' : ''} data-prev>‹ Prev</button><span>Page ${page} / ${pages}</span><button type="button" class="ghost" ${page >= pages ? 'disabled' : ''} data-next>Next ›</button>`;
  el.querySelector('[data-prev]')?.addEventListener('click', () => { state.page[view] -= 1; renderView(view); });
  el.querySelector('[data-next]')?.addEventListener('click', () => { state.page[view] += 1; renderView(view); });
}
function countLabel(view, shown, total, grand) { return `Showing ${shown ? countLabel.start(view) : 0}-${countLabel.start(view) + shown - (shown ? 1 : 0)} of ${total} (${grand} total)`; }
countLabel.start = (view) => (state.page[view] - 1) * state.pageSize + 1;

// ---- rendering ----
function renderOverview() {
  const metrics = state.metrics || {};
  $('#packets').textContent = (metrics.packets_processed || 0).toLocaleString();
  $('#flows').textContent = (metrics.flows_created || 0).toLocaleString();
  $('#alerts').textContent = (metrics.alerts_generated || state.alerts.length).toLocaleString();
  $('#incidents').textContent = (metrics.incidents_created || state.incidents.length).toLocaleString();
  $('#pps').textContent = `${(metrics.processing?.packets_per_second || 0).toLocaleString()} packets/sec`;
  $('#fps').textContent = `${(metrics.processing?.flows_per_second || 0).toLocaleString()} flows/sec`;
  $('#alert-count').textContent = state.alerts.length;
  $('#incident-count').textContent = state.incidents.length;
  $('#flow-count').textContent = state.flows.length;
  $('#evidence-count').textContent = state.evidence.length;
  $('#tap-health').textContent = state.metrics ? 'ONLINE' : '--';
  const incidents = state.incidents.slice(0, 5);
  $('#incident-preview').innerHTML = incidents.length ? incidents.map((item) => `<div class="row" data-jump-incident="${escapeHtml(item.incident_id)}"><i class="dot"></i><div><h3>${escapeHtml(item.incident_id)} / ${escapeHtml(item.host)}</h3><p>${escapeHtml(item.detections.map((d) => d.type).join(' + '))}</p></div><span class="score">${item.threat_score}/100</span></div>`).join('') : '<p class="empty">No correlated incidents available.</p>';
  $$('[data-jump-incident]').forEach((row) => row.addEventListener('click', () => { location.hash = '#incidents'; setView('incidents'); openIncidentDetail(row.dataset.jumpIncident); }));
  const verified = state.evidence.filter((item) => item.verified !== false).length;
  $('#verified').textContent = `${verified}/${state.evidence.length || 0}`;
  $('#chain').textContent = state.evidence.length && verified === state.evidence.length ? 'CHAIN INTACT' : 'WAITING';
  $('#storage').textContent = state.metrics ? 'Storage: persistent API records' : 'Storage: offline';
}

function renderIncidents() {
  const { items, total, pages } = paginate(filteredIncidents(), 'incidents');
  $('#incidents-count-label').textContent = countLabel('incidents', items.length, total, state.incidents.length);
  $('#incident-list').innerHTML = `<div class="table-head"><span>ID</span><span>DETECTIONS</span><span>HOST</span><span>SCORE</span><span>SEVERITY</span></div>` +
    (items.length ? items.map((item) => `<div class="table-row" data-incident="${escapeHtml(item.incident_id)}"><strong>${escapeHtml(item.incident_id)}</strong><span><strong>${escapeHtml(item.detections.map((d) => d.type).join(' + '))}</strong><small>${escapeHtml(item.explanation?.summary)}</small></span><span>${escapeHtml(item.host)}</span><span class="score-text">${item.threat_score}/100</span><span class="severity ${item.severity}">${escapeHtml(item.severity)}</span></div>`).join('')
      : '<p class="empty">No incidents match the current filters.</p>');
  $$('#incident-list [data-incident]').forEach((row) => row.addEventListener('click', () => openIncidentDetail(row.dataset.incident)));
  renderPagination('incidents', total, pages);
}

function renderAlerts() {
  const { items, total, pages } = paginate(filteredAlerts(), 'alerts');
  $('#alerts-count-label').textContent = countLabel('alerts', items.length, total, state.alerts.length);
  $('#alert-list').innerHTML = `<div class="table-head"><span>ID</span><span>THREAT</span><span>FLOW</span><span>CONFIDENCE</span><span>SEVERITY</span></div>` +
    (items.length ? items.map((item) => `<div class="table-row" data-alert="${escapeHtml(item.id)}"><strong>${escapeHtml(item.id)}</strong><span><strong>${escapeHtml(item.threat)}</strong><small>${escapeHtml(item.detector)}</small></span><span>${escapeHtml(item.flow_key)}</span><span class="score-text">${Math.round(item.confidence * 100)}%</span><span class="severity ${item.severity}">${escapeHtml(item.severity)}</span></div>`).join('')
      : '<p class="empty">No alerts match the current filters.</p>');
  $$('#alert-list [data-alert]').forEach((row) => row.addEventListener('click', () => openAlertDetail(row.dataset.alert)));
  renderPagination('alerts', total, pages);
}

function renderFlows() {
  const { items, total, pages } = paginate(filteredFlows(), 'flows');
  $('#flows-count-label').textContent = countLabel('flows', items.length, total, state.flows.length);
  $('#flow-list').innerHTML = `<div class="table-head"><span>KEY</span><span>SOURCE → DEST</span><span>PROTOCOL</span><span>PACKETS</span><span>BYTES</span></div>` +
    (items.length ? items.map((item) => `<div class="table-row" data-flow="${escapeHtml(item.id)}"><strong>${escapeHtml(item.id)}</strong><span>${escapeHtml(item.source)} → ${escapeHtml(item.destination)}</span><span class="score-text">${escapeHtml(item.protocol)}</span><span>${(item.packets || 0).toLocaleString()}</span><span>${(item.bytes || 0).toLocaleString()}</span></div>`).join('')
      : '<p class="empty">No flows match the current filters.</p>');
  $$('#flow-list [data-flow]').forEach((row) => row.addEventListener('click', () => openFlowDetail(row.dataset.flow)));
  renderPagination('flows', total, pages);
}

function renderEvidence() {
  const { items, total, pages } = paginate(filteredEvidence(), 'evidence');
  $('#evidence-count-label').textContent = countLabel('evidence', items.length, total, state.evidence.length);
  $('#evidence-list').innerHTML = `<div class="table-head"><span>ID</span><span>ALERT</span><span>SHA-256</span><span>STATUS</span><span>CHECK</span></div>` +
    (items.length ? items.map((item) => {
      const verified = item.verified !== false;
      const hash = item.sha256 || 'sealed';
      return `<div class="table-row" data-evidence="${escapeHtml(item.id)}"><strong>${escapeHtml(item.id)}</strong><span>${escapeHtml(item.alert_id)}<small>${escapeHtml(item.threat)}</small></span><span class="hash" title="${escapeHtml(hash)}">${escapeHtml(hash.slice(0, 14))}…</span><span class="severity">${escapeHtml(item.status)}</span><span class="row-actions"><span class="score-text">${verified ? 'VERIFIED' : 'FAILED'}</span><button type="button" class="ghost tiny" data-verify="${escapeHtml(item.id)}">Verify</button></span></div>`;
    }).join('')
      : '<p class="empty">No evidence matches the current filters.</p>');
  $$('#evidence-list [data-evidence]').forEach((row) => row.addEventListener('click', () => openEvidenceDetail(row.dataset.evidence)));
  $$('#evidence-list [data-verify]').forEach((btn) => btn.addEventListener('click', (event) => { event.stopPropagation(); verifyEvidence(btn.dataset.verify); }));
  renderPagination('evidence', total, pages);
}

function renderSeverityChart() {
  const counts = Object.fromEntries(SEVERITY_ORDER.map((s) => [s, 0]));
  state.alerts.forEach((a) => { if (a.severity in counts) counts[a.severity] += 1; });
  const total = state.alerts.length;
  const el = $('#severity-chart');
  if (!total) { el.innerHTML = '<p class="empty">No alerts available yet.</p>'; return; }
  const max = Math.max(1, ...Object.values(counts));
  el.innerHTML = SEVERITY_ORDER.map((sev) => {
    const count = counts[sev];
    const pct = Math.round((count / total) * 100);
    const width = Math.round((count / max) * 100);
    const color = SEVERITY_COLOR[sev];
    return `<div class="severity-row" title="${escapeHtml(sev)}: ${count} of ${total} alerts (${pct}%)">` +
      `<span class="label"><i style="background:${color}"></i>${escapeHtml(sev)}</span>` +
      `<span class="track"><span class="fill" style="width:${width}%;background:${color}"></span></span>` +
      `<span class="count">${count}</span></div>`;
  }).join('');
}

const renderers = { incidents: renderIncidents, alerts: renderAlerts, flows: renderFlows, evidence: renderEvidence };
function renderView(view) { renderers[view]?.(); }
function renderAll() { renderOverview(); renderSeverityChart(); renderIncidents(); renderAlerts(); renderFlows(); renderEvidence(); }

// ---- live traffic + detection visualizer ----
function computeLiveNodes(width, height) {
  const byHost = new Map();
  state.flows.forEach((f) => {
    const host = hostOf(f.source);
    if (!host || host === '*') return;
    byHost.set(host, (byHost.get(host) || 0) + (f.bytes || 0));
  });
  const alertSeverity = new Map();
  state.alerts.forEach((a) => {
    const host = hostOf(a.source);
    if (!host || host === '*') return;
    const current = alertSeverity.get(host);
    if (!current || SEVERITY_RANK[a.severity] > SEVERITY_RANK[current]) alertSeverity.set(host, a.severity);
  });
  let hosts = Array.from(byHost.entries()).sort((a, b) => b[1] - a[1]).slice(0, 10).map(([host]) => host);
  alertSeverity.forEach((_sev, host) => { if (!hosts.includes(host) && hosts.length < 12) hosts.push(host); });

  const cx = width / 2, cy = height / 2;
  const radius = Math.max(40, Math.min(cx, cy) - 46);
  const previous = new Map(live.nodes.map((n) => [n.id, n]));
  live.cx = cx; live.cy = cy;
  live.nodes = hosts.map((host, i) => {
    const angle = (i / hosts.length) * Math.PI * 2 - Math.PI / 2;
    const prior = previous.get(host);
    return {
      id: host, x: cx + Math.cos(angle) * radius, y: cy + Math.sin(angle) * radius,
      severity: alertSeverity.get(host) || null, pulse: prior?.pulse || 0,
    };
  });
}

function setupLiveCanvas() {
  const canvas = $('#live-canvas');
  if (!canvas) return;
  const rect = canvas.getBoundingClientRect();
  if (!rect.width || !rect.height) return;
  const ratio = window.devicePixelRatio || 1;
  canvas.width = rect.width * ratio;
  canvas.height = rect.height * ratio;
  canvas.getContext('2d').setTransform(ratio, 0, 0, ratio, 0, 0);
  computeLiveNodes(rect.width, rect.height);
}

function spawnLiveParticle(now, forcedNode) {
  if (!live.nodes.length) return;
  const alerted = live.nodes.filter((n) => n.severity);
  let node = forcedNode;
  if (!node) {
    if (live.mode === 'alerts') {
      if (!alerted.length) return;
      node = alerted[Math.floor(Math.random() * alerted.length)];
    } else {
      const pool = alerted.length && Math.random() < 0.35 ? alerted : live.nodes;
      node = pool[Math.floor(Math.random() * pool.length)];
    }
  }
  const color = node.severity ? SEVERITY_COLOR[node.severity] : '#33e6c9';
  live.particles.push({ x: node.x, y: node.y, start: now, dur: 950 / live.speed, color, size: node.severity ? 4.5 : 2.5 });
  if (node.severity) node.pulse = 1;
}

function drawLiveFrame(now) {
  const canvas = $('#live-canvas');
  if (!canvas) return;
  const ctx = canvas.getContext('2d');
  const w = canvas.clientWidth, h = canvas.clientHeight;
  ctx.clearRect(0, 0, w, h);

  if (!live.nodes.length) {
    ctx.fillStyle = '#64758b';
    ctx.font = '11px "IBM Plex Mono", monospace';
    ctx.textAlign = 'center';
    ctx.fillText('Waiting for observed traffic…', w / 2, h / 2);
    return;
  }

  live.nodes.forEach((n) => {
    ctx.strokeStyle = n.severity ? hexToRgba(SEVERITY_COLOR[n.severity], 0.28) : 'rgba(32,45,64,0.8)';
    ctx.lineWidth = 1;
    ctx.beginPath(); ctx.moveTo(n.x, n.y); ctx.lineTo(live.cx, live.cy); ctx.stroke();
  });

  ctx.beginPath(); ctx.arc(live.cx, live.cy, 15, 0, Math.PI * 2);
  ctx.strokeStyle = 'rgba(51,230,201,0.35)'; ctx.lineWidth = 1; ctx.stroke();
  ctx.beginPath(); ctx.arc(live.cx, live.cy, 9, 0, Math.PI * 2);
  ctx.fillStyle = '#33e6c9'; ctx.fill();

  live.nodes.forEach((n) => {
    const color = n.severity ? SEVERITY_COLOR[n.severity] : '#9aabc0';
    if (n.pulse > 0) {
      ctx.beginPath(); ctx.arc(n.x, n.y, 8 + (1 - n.pulse) * 16, 0, Math.PI * 2);
      ctx.strokeStyle = hexToRgba(color, n.pulse * 0.6); ctx.lineWidth = 2; ctx.stroke();
      if (live.running) n.pulse = Math.max(0, n.pulse - 0.018 * live.speed);
    }
    ctx.beginPath(); ctx.arc(n.x, n.y, n.severity ? 6.5 : 4.5, 0, Math.PI * 2);
    ctx.fillStyle = color; ctx.fill();
  });

  live.particles = live.particles.filter((p) => {
    const t = Math.min(1, (now - p.start) / p.dur);
    const x = p.x + (live.cx - p.x) * t;
    const y = p.y + (live.cy - p.y) * t;
    ctx.globalAlpha = 1 - t * 0.15;
    ctx.beginPath(); ctx.arc(x, y, p.size * (1 - t * 0.25), 0, Math.PI * 2);
    ctx.fillStyle = p.color; ctx.fill();
    ctx.globalAlpha = 1;
    return t < 1;
  });
}

function liveLoop(now) {
  if (live.running) {
    if (!live.lastSpawn || now - live.lastSpawn > 300 / live.speed) { spawnLiveParticle(now); live.lastSpawn = now; }
    drawLiveFrame(now);
  }
  live.raf = requestAnimationFrame(liveLoop);
}

function bindLiveHover() {
  const canvas = $('#live-canvas');
  const tooltip = $('#live-tooltip');
  if (!canvas || !tooltip) return;
  canvas.addEventListener('mousemove', (e) => {
    const rect = canvas.getBoundingClientRect();
    const x = e.clientX - rect.left, y = e.clientY - rect.top;
    const hit = live.nodes.find((n) => Math.hypot(n.x - x, n.y - y) <= 11);
    if (hit) {
      tooltip.hidden = false;
      tooltip.style.left = `${hit.x}px`;
      tooltip.style.top = `${hit.y}px`;
      tooltip.textContent = hit.severity ? `${hit.id} — ${hit.severity.toUpperCase()} alert` : `${hit.id} — observed traffic`;
    } else {
      tooltip.hidden = true;
    }
  });
  canvas.addEventListener('mouseleave', () => { tooltip.hidden = true; });
}

function addFeedItem(alert, flash) {
  const list = $('#live-feed-list');
  const empty = list.querySelector('.empty');
  if (empty) empty.remove();
  const color = SEVERITY_COLOR[alert.severity] || '#9aabc0';
  const item = document.createElement('div');
  item.className = 'feed-item';
  const label = document.createElement('b');
  label.textContent = String(alert.threat || '').toUpperCase();
  const host = document.createElement('span');
  host.className = 'feed-host';
  host.textContent = hostOf(alert.source) || 'unknown';
  const detail = document.createElement('small');
  detail.textContent = `${Math.round((alert.confidence || 0) * 100)}% confidence · ${alert.severity}`;
  const dot = document.createElement('i');
  dot.className = 'feed-dot';
  dot.style.background = color;
  const body = document.createElement('div');
  body.append(label, document.createTextNode(' on '), host, detail);
  item.append(dot, body);
  list.prepend(item);
  while (list.children.length > 30) list.removeChild(list.lastChild);
  if (flash) {
    const host_ = hostOf(alert.source);
    const node = live.nodes.find((n) => n.id === host_);
    if (node) { node.severity = alert.severity; spawnLiveParticle(performance.now(), node); }
  }
}

function ingestAlertsForLive() {
  const ordered = [...state.alerts].sort((a, b) => (a.ts || 0) - (b.ts || 0));
  const isFirstLoad = !live.feedInitialized;
  ordered.forEach((alert) => {
    if (live.feedShown.has(alert.id)) return;
    live.feedShown.add(alert.id);
    addFeedItem(alert, !isFirstLoad);
  });
  live.feedInitialized = true;
}

// ---- modal detail views ----
function kv(label, value) { return `<div class="kv"><span>${escapeHtml(label)}</span><b>${escapeHtml(value)}</b></div>`; }
function openModal(title, bodyHtml) { $('#modal-title').textContent = title; $('#modal-body').innerHTML = bodyHtml; $('#modal-overlay').hidden = false; }
function closeModal() { $('#modal-overlay').hidden = true; }

async function openIncidentDetail(id) {
  const item = state.incidents.find((i) => i.incident_id === id);
  if (!item) return;
  let explanation = item.explanation;
  try { explanation = await getJson(`/api/incidents/${encodeURIComponent(id)}/explanation`); } catch { /* use cached explanation */ }
  const detections = item.detections.map((d) => `<div class="kv"><span>${escapeHtml(d.detector)} / ${escapeHtml(d.type)}</span><b>${Math.round(d.confidence * 100)}%</b></div>`).join('');
  const timeline = (item.timeline || []).map((t) => `<li><b>${escapeHtml(t.timestamp)}</b> ${escapeHtml(t.type)} <small>${escapeHtml(t.detector)} · ${escapeHtml(t.alert_id)}</small></li>`).join('');
  const reasons = (explanation?.reasons || []).map((r) => `<li>${escapeHtml(r)}</li>`).join('');
  const chain = (item.chain || []).map((c) => `<span class="chip">${escapeHtml(c)}</span>`).join('');
  openModal(`Incident ${item.incident_id}`, `
    <div class="kv-grid">${kv('Host', item.host)}${kv('Severity', item.severity)}${kv('Threat score', `${item.threat_score}/100`)}${kv('Confidence', `${Math.round(item.confidence * 100)}%`)}${kv('Evidence verified', item.evidence_verified ? 'Yes' : 'No')}</div>
    <p class="modal-copy">${escapeHtml(explanation?.summary || '')}</p>
    <h4>Why it was flagged</h4><ul class="reasons">${reasons}</ul>
    <h4>Detections</h4>${detections}
    <h4>Timeline</h4><ul class="timeline">${timeline}</ul>
    <h4>Custody chain</h4><div class="chip-row">${chain}</div>
    <p class="recommendation"><b>Recommendation:</b> ${escapeHtml(item.recommendation)}</p>
    <div class="modal-actions"><button type="button" class="ghost" data-copy="${escapeHtml(item.incident_id)}">Copy incident ID</button></div>
  `);
  $('#modal-body [data-copy]')?.addEventListener('click', (e) => copyText(e.target.dataset.copy, 'incident ID'));
}

async function openAlertDetail(id) {
  let item = state.alerts.find((i) => i.id === id);
  try { item = await getJson(`/api/alerts/${encodeURIComponent(id)}`); } catch { /* use cached copy */ }
  if (!item) return;
  openModal(`Alert ${item.id}`, `
    <div class="kv-grid">${kv('Threat', item.threat)}${kv('Detector', item.detector)}${kv('Severity', item.severity)}${kv('Confidence', `${Math.round(item.confidence * 100)}%`)}${kv('Flow', item.flow_key)}${kv('Source', item.source)}${kv('Destination', item.destination)}${kv('Evidence', item.evidence_id)}</div>
    <div class="modal-actions"><button type="button" class="ghost" data-copy="${escapeHtml(item.id)}">Copy alert ID</button><button type="button" class="ghost" data-view-evidence="${escapeHtml(item.evidence_id)}">View evidence</button></div>
  `);
  $('#modal-body [data-copy]')?.addEventListener('click', (e) => copyText(e.target.dataset.copy, 'alert ID'));
  $('#modal-body [data-view-evidence]')?.addEventListener('click', (e) => openEvidenceDetail(e.target.dataset.viewEvidence));
}

async function openFlowDetail(id) {
  let item = state.flows.find((i) => i.id === id);
  try { item = await getJson(`/api/flows/${encodeURIComponent(id)}`); } catch { /* use cached copy */ }
  if (!item) return;
  openModal(`Flow ${item.id}`, `
    <div class="kv-grid">${kv('Source', item.source)}${kv('Destination', item.destination)}${kv('Protocol', item.protocol)}${kv('Direction', item.direction)}${kv('Packets', (item.packets || 0).toLocaleString())}${kv('Bytes', (item.bytes || 0).toLocaleString())}${kv('Duration', `${item.duration_s}s`)}</div>
    <div class="modal-actions"><button type="button" class="ghost" data-copy="${escapeHtml(item.id)}">Copy flow key</button></div>
  `);
  $('#modal-body [data-copy]')?.addEventListener('click', (e) => copyText(e.target.dataset.copy, 'flow key'));
}

async function openEvidenceDetail(id) {
  let item = state.evidence.find((i) => i.id === id);
  try { item = await getJson(`/api/evidence/${encodeURIComponent(id)}`); } catch { /* use cached copy */ }
  if (!item) return;
  const verified = item.verified !== false;
  openModal(`Evidence ${item.id}`, `
    <div class="kv-grid">${kv('Alert', item.alert_id)}${kv('Threat', item.threat)}${kv('Status', item.status)}${kv('Integrity', verified ? 'Verified' : 'Failed')}</div>
    <p class="modal-copy hash-full">SHA-256: ${escapeHtml(item.sha256 || 'sealed')}</p>
    <p class="modal-copy hash-full">Merkle root: ${escapeHtml(item.merkle_root || '--')}</p>
    <div class="modal-actions"><button type="button" class="ghost" data-copy="${escapeHtml(item.sha256 || '')}">Copy hash</button><button type="button" class="ghost" data-verify-modal="${escapeHtml(item.id)}">Re-verify</button></div>
  `);
  $('#modal-body [data-copy]')?.addEventListener('click', (e) => copyText(e.target.dataset.copy, 'hash'));
  $('#modal-body [data-verify-modal]')?.addEventListener('click', (e) => verifyEvidence(e.target.dataset.verifyModal, true));
}

async function verifyEvidence(id, reopen) {
  try {
    const result = await getJson(`/api/evidence/${encodeURIComponent(id)}/verify`);
    const item = state.evidence.find((i) => i.id === id);
    if (item) item.verified = result.verified;
    notify(result.verified ? `${id} verified` : `${id} failed verification`);
    renderEvidence();
    if (reopen) openEvidenceDetail(id);
  } catch (error) { notify(`Verify failed: ${error.message}`); }
}

// ---- export ----
function exportView(view, format) {
  const data = { incidents: filteredIncidents, alerts: filteredAlerts, flows: filteredFlows, evidence: filteredEvidence }[view]();
  if (!data.length) { notify('Nothing to export'); return; }
  const stamp = new Date().toISOString().replace(/[:.]/g, '-');
  if (format === 'json') download(`cyclops-${view}-${stamp}.json`, JSON.stringify(data, null, 2), 'application/json');
  else download(`cyclops-${view}-${stamp}.csv`, toCsv(data), 'text/csv');
}

// ---- data + transport ----
async function getJson(path) { const response = await fetch(`${API}${path}`); if (!response.ok) throw new Error(`${response.status} ${path}`); return response.json(); }
async function refresh() {
  try {
    const [status, alerts, incidents, evidence, flows, metrics] = await Promise.all([
      getJson('/api/status'), getJson('/api/alerts?limit=200'), getJson('/api/incidents?limit=200'),
      getJson('/api/evidence?limit=200'), getJson('/api/flows?limit=200'), getJson('/api/metrics'),
    ]);
    state.alerts = alerts.items; state.incidents = incidents.items; state.evidence = evidence.items;
    state.flows = flows.items; state.metrics = metrics;
    populateProtocolOptions();
    setConnection(true);
    renderAll();
    setupLiveCanvas();
    ingestAlertsForLive();
    window.dispatchEvent(new CustomEvent('cyclops:status', { detail: status }));
  } catch (error) { setConnection(false); notify('Backend unavailable. Start the FastAPI server on port 8000.'); }
}
async function upload(file) { const form = new FormData(); form.append('file', file); const response = await fetch(`${API}/api/pcap/upload`, { method: 'POST', body: form }); if (!response.ok) throw new Error(await response.text()); return response.json(); }
function setView(view) {
  document.querySelectorAll('[data-panel],[data-view]').forEach((node) => node.classList.toggle('active', node.dataset.panel === view || node.dataset.view === view));
  if (view === 'dashboard') requestAnimationFrame(setupLiveCanvas);
}
let liveReconnectTimer = null;
function scheduleLiveReconnect() {
  if (liveReconnectTimer) return;
  liveReconnectTimer = setTimeout(() => { liveReconnectTimer = null; connectLive(); }, 4000);
}
function connectLive() {
  try {
    const socket = new WebSocket(API.replace(/^http/, 'ws') + '/api/live');
    socket.onmessage = (message) => {
      let event; try { event = JSON.parse(message.data); } catch { return; }
      if (event.event === 'JOB_COMPLETED' || event.event === 'ALERTS_UPDATED') refresh();
    };
    socket.onerror = () => socket.close();
    socket.onclose = scheduleLiveReconnect;
  } catch {
    scheduleLiveReconnect(); // REST polling still covers us until the socket comes back
  }
}
function setAutoRefresh(ms) { if (autoTimer) clearInterval(autoTimer); autoTimer = ms > 0 ? setInterval(refresh, ms) : null; }

// ---- toolbar bindings ----
function bindFilters() {
  $('#incidents-q').addEventListener('input', debounce((e) => { state.filters.incidents.q = e.target.value; state.page.incidents = 1; renderIncidents(); }, 150));
  $('#incidents-severity').addEventListener('change', (e) => { state.filters.incidents.severity = e.target.value; state.page.incidents = 1; renderIncidents(); });
  $('#incidents-sort').addEventListener('change', (e) => { state.filters.incidents.sort = e.target.value; renderIncidents(); });
  $('#incidents-reset').addEventListener('click', () => { state.filters.incidents = { q: '', severity: 'all', sort: 'score_desc' }; $('#incidents-q').value = ''; $('#incidents-severity').value = 'all'; $('#incidents-sort').value = 'score_desc'; state.page.incidents = 1; renderIncidents(); });
  $('#incidents-export-csv').addEventListener('click', () => exportView('incidents', 'csv'));
  $('#incidents-export-json').addEventListener('click', () => exportView('incidents', 'json'));

  $('#alerts-q').addEventListener('input', debounce((e) => { state.filters.alerts.q = e.target.value; state.page.alerts = 1; renderAlerts(); }, 150));
  $('#alerts-severity').addEventListener('change', (e) => { state.filters.alerts.severity = e.target.value; state.page.alerts = 1; renderAlerts(); });
  $('#alerts-sort').addEventListener('change', (e) => { state.filters.alerts.sort = e.target.value; renderAlerts(); });
  $('#alerts-reset').addEventListener('click', () => { state.filters.alerts = { q: '', severity: 'all', sort: 'confidence_desc' }; $('#alerts-q').value = ''; $('#alerts-severity').value = 'all'; $('#alerts-sort').value = 'confidence_desc'; state.page.alerts = 1; renderAlerts(); });
  $('#alerts-export-csv').addEventListener('click', () => exportView('alerts', 'csv'));
  $('#alerts-export-json').addEventListener('click', () => exportView('alerts', 'json'));

  $('#flows-q').addEventListener('input', debounce((e) => { state.filters.flows.q = e.target.value; state.page.flows = 1; renderFlows(); }, 150));
  $('#flows-protocol').addEventListener('change', (e) => { state.filters.flows.protocol = e.target.value; state.page.flows = 1; renderFlows(); });
  $('#flows-sort').addEventListener('change', (e) => { state.filters.flows.sort = e.target.value; renderFlows(); });
  $('#flows-reset').addEventListener('click', () => { state.filters.flows = { q: '', protocol: 'all', sort: 'bytes_desc' }; $('#flows-q').value = ''; $('#flows-protocol').value = 'all'; $('#flows-sort').value = 'bytes_desc'; state.page.flows = 1; renderFlows(); });
  $('#flows-export-csv').addEventListener('click', () => exportView('flows', 'csv'));
  $('#flows-export-json').addEventListener('click', () => exportView('flows', 'json'));

  $('#evidence-q').addEventListener('input', debounce((e) => { state.filters.evidence.q = e.target.value; state.page.evidence = 1; renderEvidence(); }, 150));
  $('#evidence-status').addEventListener('change', (e) => { state.filters.evidence.status = e.target.value; state.page.evidence = 1; renderEvidence(); });
  $('#evidence-sort').addEventListener('change', (e) => { state.filters.evidence.sort = e.target.value; renderEvidence(); });
  $('#evidence-reset').addEventListener('click', () => { state.filters.evidence = { q: '', status: 'all', sort: 'ts_desc' }; $('#evidence-q').value = ''; $('#evidence-status').value = 'all'; $('#evidence-sort').value = 'ts_desc'; state.page.evidence = 1; renderEvidence(); });
  $('#evidence-export-csv').addEventListener('click', () => exportView('evidence', 'csv'));
  $('#evidence-export-json').addEventListener('click', () => exportView('evidence', 'json'));
}

document.querySelectorAll('[data-view]').forEach((tab) => tab.addEventListener('click', () => setView(tab.dataset.view)));
document.querySelectorAll('.metric-link').forEach((btn) => btn.addEventListener('click', () => { location.hash = `#${btn.dataset.jump}`; setView(btn.dataset.jump); }));
window.addEventListener('hashchange', () => setView(location.hash.slice(1) || 'dashboard'));
$('#refresh').addEventListener('click', refresh);
$('#auto-interval').addEventListener('change', (e) => setAutoRefresh(Number(e.target.value)));
$('#modal-close').addEventListener('click', closeModal);
$('#modal-overlay').addEventListener('click', (e) => { if (e.target.id === 'modal-overlay') closeModal(); });
window.addEventListener('keydown', (e) => { if (e.key === 'Escape') closeModal(); });
$('#pcap').addEventListener('change', async (event) => { const file = event.target.files[0]; if (!file) return; try { const job = await upload(file); notify(`Queued ${job.job_id}`); } catch (error) { notify(`Upload failed: ${error.message}`); } event.target.value = ''; });

$('#live-toggle').addEventListener('click', () => { live.running = !live.running; $('#live-toggle').textContent = live.running ? 'Pause' : 'Play'; });
$('#live-speed').addEventListener('change', (e) => { live.speed = Number(e.target.value); });
$('#live-mode').addEventListener('change', (e) => { live.mode = e.target.value; });
window.addEventListener('resize', debounce(() => { if (document.querySelector('[data-panel=dashboard]').classList.contains('active')) setupLiveCanvas(); }, 200));

bindFilters();
bindLiveHover();
setView(location.hash.slice(1) || 'dashboard');
refresh();
connectLive();
setAutoRefresh(Number($('#auto-interval').value));
live.raf = requestAnimationFrame(liveLoop);
