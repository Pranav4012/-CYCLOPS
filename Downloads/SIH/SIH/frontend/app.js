const API = window.CYCLOPS_API || 'http://127.0.0.1:8000';
const $ = (selector) => document.querySelector(selector);
const state = { alerts: [], incidents: [], evidence: [], metrics: null };
const escapeHtml = (value) => String(value ?? '').replace(/[&<>"']/g, (char) => ({ '&':'&amp;', '<':'&lt;', '>':'&gt;', '"':'&quot;', "'":'&#039;' })[char]);

function notify(message) { const toast = $('#toast'); toast.textContent = message; toast.classList.add('show'); setTimeout(() => toast.classList.remove('show'), 3200); }
function setConnection(online) { const node = $('#connection'); node.className = `status ${online ? 'online' : 'offline'}`; node.innerHTML = `<i></i> ${online ? 'API CONNECTED' : 'API OFFLINE'}`; }
function renderOverview() {
  const metrics = state.metrics || {};
  $('#packets').textContent = (metrics.packets_processed || 0).toLocaleString();
  $('#flows').textContent = (metrics.flows_created || 0).toLocaleString();
  $('#alerts').textContent = (metrics.alerts_generated || state.alerts.length).toLocaleString();
  $('#incidents').textContent = (metrics.incidents_created || state.incidents.length).toLocaleString();
  $('#pps').textContent = `${(metrics.processing?.packets_per_second || 0).toLocaleString()} packets/sec`;
  $('#fps').textContent = `${(metrics.processing?.flows_per_second || 0).toLocaleString()} flows/sec`;
  $('#alert-count').textContent = state.alerts.length; $('#incident-count').textContent = state.incidents.length;
  $('#tap-health').textContent = state.metrics ? 'ONLINE' : '--';
  const incidents = state.incidents.slice(0, 5);
  $('#incident-preview').innerHTML = incidents.length ? incidents.map((item) => `<div class="row"><i class="dot"></i><div><h3>${escapeHtml(item.incident_id)} / ${escapeHtml(item.host)}</h3><p>${escapeHtml(item.detections.map((d) => d.type).join(' + '))}</p></div><span class="score">${item.threat_score}/100</span></div>`).join('') : '<p class="empty">No correlated incidents available.</p>';
  const verified = state.evidence.filter((item) => item.verified !== false).length;
  $('#verified').textContent = `${verified}/${state.evidence.length || 0}`;
  $('#chain').textContent = state.evidence.length && verified === state.evidence.length ? 'CHAIN INTACT' : 'WAITING';
  $('#storage').textContent = state.metrics ? 'Storage: persistent API records' : 'Storage: offline';
}
function renderIncidents() { $('#incident-list').innerHTML = `<div class="table-head"><span>ID</span><span>DETECTIONS</span><span>HOST</span><span>SCORE</span><span>SEVERITY</span></div>` + (state.incidents.length ? state.incidents.map((item) => `<div class="table-row"><strong>${escapeHtml(item.incident_id)}</strong><span><strong>${escapeHtml(item.detections.map((d) => d.type).join(' + '))}</strong><small>${escapeHtml(item.explanation?.summary)}</small></span><span>${escapeHtml(item.host)}</span><span class="score-text">${item.threat_score}/100</span><span class="severity ${item.severity}">${escapeHtml(item.severity)}</span></div>`).join('') : '<p class="empty">No incidents available.</p>'); }
function renderAlerts() { $('#alert-list').innerHTML = `<div class="table-head"><span>ID</span><span>THREAT</span><span>FLOW</span><span>CONFIDENCE</span><span>SEVERITY</span></div>` + (state.alerts.length ? state.alerts.map((item) => `<div class="table-row"><strong>${escapeHtml(item.id)}</strong><span><strong>${escapeHtml(item.threat)}</strong><small>${escapeHtml(item.detector)}</small></span><span>${escapeHtml(item.flow_key)}</span><span class="score-text">${Math.round(item.confidence * 100)}%</span><span class="severity ${item.severity}">${escapeHtml(item.severity)}</span></div>`).join('') : '<p class="empty">No alerts available.</p>'); }
function renderEvidence() { $('#evidence-list').innerHTML = `<div class="table-head"><span>ID</span><span>ALERT</span><span>SHA-256</span><span>STATUS</span><span>CHECK</span></div>` + (state.evidence.length ? state.evidence.map((item) => `<div class="table-row"><strong>${escapeHtml(item.id)}</strong><span>${escapeHtml(item.alert_id)}<small>${escapeHtml(item.threat)}</small></span><span>${escapeHtml(item.sha256 || 'sealed')}</span><span class="severity">${escapeHtml(item.status)}</span><span class="score-text">${item.verified === false ? 'FAILED' : 'VERIFIED'}</span></div>`).join('') : '<p class="empty">No evidence available.</p>'); }
async function getJson(path) { const response = await fetch(`${API}${path}`); if (!response.ok) throw new Error(`${response.status} ${path}`); return response.json(); }
async function refresh() {
  try {
    const [status, alerts, incidents, evidence, metrics] = await Promise.all([getJson('/api/status'), getJson('/api/alerts?limit=200'), getJson('/api/incidents?limit=200'), getJson('/api/evidence?limit=200'), getJson('/api/metrics')]);
    state.alerts = alerts.items; state.incidents = incidents.items; state.evidence = evidence.items; state.metrics = metrics;
    setConnection(true); renderOverview(); renderIncidents(); renderAlerts(); renderEvidence();
    window.dispatchEvent(new CustomEvent('cyclops:status', { detail: status }));
  } catch (error) { setConnection(false); notify('Backend unavailable. Start the FastAPI server on port 8000.'); }
}
async function upload(file) { const form = new FormData(); form.append('file', file); const response = await fetch(`${API}/api/pcap/upload`, { method: 'POST', body: form }); if (!response.ok) throw new Error(await response.text()); return response.json(); }
function setView(view) { document.querySelectorAll('[data-panel],[data-view]').forEach((node) => node.classList.toggle('active', node.dataset.panel === view || node.dataset.view === view)); }
function connectLive() { try { const socket = new WebSocket(API.replace(/^http/, 'ws') + '/api/live'); socket.onmessage = (message) => { const event = JSON.parse(message.data); if (event.event === 'JOB_COMPLETED' || event.event === 'ALERTS_UPDATED') refresh(); }; socket.onclose = () => setTimeout(connectLive, 4000); } catch { /* REST remains available if WebSocket is unavailable. */ } }

document.querySelectorAll('[data-view]').forEach((tab) => tab.addEventListener('click', () => setView(tab.dataset.view)));
window.addEventListener('hashchange', () => setView(location.hash.slice(1) || 'dashboard'));
$('#refresh').addEventListener('click', refresh);
$('#pcap').addEventListener('change', async (event) => { const file = event.target.files[0]; if (!file) return; try { const job = await upload(file); notify(`Queued ${job.job_id}`); } catch (error) { notify(`Upload failed: ${error.message}`); } event.target.value = ''; });
setView(location.hash.slice(1) || 'dashboard'); refresh(); connectLive();
