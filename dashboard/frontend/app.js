const state = { data: null, loading: false };
const $ = selector => document.querySelector(selector);
const $$ = selector => [...document.querySelectorAll(selector)];
const esc = value => String(value ?? '').replace(/[&<>"']/g, char => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[char]));
const number = value => value == null ? '—' : new Intl.NumberFormat().format(value);
const duration = value => value == null ? '—' : value < 1 ? `${Math.round(value * 1000)} ms` : `${Number(value).toFixed(value < 10 ? 2 : 1)} s`;
const clockTime = value => value == null ? '—' : new Intl.DateTimeFormat([], {hour:'2-digit', minute:'2-digit', second:'2-digit'}).format(new Date(Number(value) * 1000));
const shortTime = value => value == null ? '—' : new Intl.DateTimeFormat([], {hour:'2-digit', minute:'2-digit'}).format(new Date(Number(value) * 1000));
const relativeTime = value => {
  if (value == null) return '—';
  const seconds = Math.max(0, Date.now() / 1000 - Number(value));
  if (seconds < 60) return `${Math.floor(seconds)}s ago`;
  if (seconds < 3600) return `${Math.floor(seconds / 60)}m ago`;
  if (seconds < 86400) return `${Math.floor(seconds / 3600)}h ago`;
  return `${Math.floor(seconds / 86400)}d ago`;
};

const pageNames = {
  overview: ['Overview', 'Security overview'],
  network: ['Network map', 'Live network map'],
  devices: ['Devices', 'Device security'],
  alerts: ['Alerts', 'Alerts & decisions'],
  actions: ['Enforcement', 'Enforcement lifecycle'],
  pipeline: ['Pipeline', 'Pipeline traces']
};

function navigate(page, updateHash = true) {
  if (!pageNames[page]) page = 'overview';
  $$('.page').forEach(element => element.classList.toggle('active', element.id === `page-${page}`));
  $$('.nav-item').forEach(element => element.classList.toggle('active', element.dataset.page === page));
  $('#breadcrumb').textContent = pageNames[page][0];
  $('#page-title').textContent = pageNames[page][1];
  document.title = `${pageNames[page][1]} · AutoMUD`;
  document.body.classList.remove('menu-open');
  if (updateHash && location.hash !== `#${page}`) history.replaceState(null, '', `#${page}`);
}

function renderMode(overview) {
  const banner = $('#mode-banner');
  const automatic = overview.automatic_enforcement_enabled;
  const unhealthy = overview.latest_health?.sensor === 'unhealthy' || overview.latest_health?.partial === true;
  banner.className = `mode-banner ${automatic ? 'danger' : unhealthy ? 'warning' : ''}`;
  const title = automatic ? 'Automatic enforcement is enabled' : unhealthy ? 'Observation is degraded' : 'Safe observation mode';
  const copy = automatic
    ? 'Approved live decisions can install scoped, TTL-bounded OpenFlow actions.'
    : unhealthy
      ? 'At least one evidence branch or sensor check is unavailable. Actions remain withheld.'
      : `${overview.observation_kind} observations are evaluated in ${overview.decision_mode} mode. No automatic network changes are permitted.`;
  banner.innerHTML = `<div class="mode-icon">${automatic ? '!' : unhealthy ? '!' : 'i'}</div><div><strong>${esc(title)}</strong><p>${esc(copy)}</p></div><span class="mode-pill">${automatic ? 'ENFORCING' : unhealthy ? 'DEGRADED' : 'NO AUTO ACTIONS'}</span>`;
}

function renderChrome(data) {
  const { overview, devices, alerts } = data;
  const healthy = overview.latest_health?.sensor === 'healthy' && overview.latest_health?.partial !== true;
  const sidebar = $('#sidebar-state');
  sidebar.innerHTML = `<span class="status-dot ${healthy ? 'live' : 'warning'}"></span><span><strong>${healthy ? 'Pipeline connected' : 'Pipeline needs attention'}</strong><small>${esc(overview.deployment_id)}</small></span>`;
  $('#device-count').textContent = devices.length;
  $('#alert-count').textContent = alerts.length || '0';
  $('#inventory-short').textContent = overview.inventory_version || '—';
  $('#last-sync').textContent = clockTime(overview.generated_at);
  renderMode(overview);
}

function renderMetrics(overview) {
  const metrics = overview.metrics || {};
  const healthPercent = metrics.windows ? Math.round((metrics.healthy_windows / metrics.windows) * 100) : null;
  const cards = [
    {label:'Protected inventory', value:number(metrics.devices), detail:`${number(metrics.active_devices)} active in latest evidence`, icon:'▦'},
    {label:'Security findings', value:number(metrics.open_security_alerts), detail:`${number(metrics.anomalous_devices)} devices flagged`, icon:'◇', tone:metrics.open_security_alerts ? 'caution' : ''},
    {label:'Active responses', value:number(metrics.active_actions), detail:'Controller-confirmed actions', icon:'⌁', tone:metrics.active_actions ? 'alert' : ''},
    {label:'Healthy observations', value:healthPercent == null ? '—' : `${healthPercent}%`, detail:`${number(metrics.healthy_windows)} of ${number(metrics.windows)} windows`, icon:'↳', tone:healthPercent != null && healthPercent < 100 ? 'caution' : ''}
  ];
  $('#metrics').innerHTML = cards.map(card => `<article class="metric ${card.tone || ''}"><span class="metric-label"><span>${esc(card.label)}</span><b class="metric-icon">${card.icon}</b></span><strong class="metric-value">${esc(card.value)}</strong><span class="metric-detail">${esc(card.detail)}</span></article>`).join('');
}

function stageState(value, healthyValue = 'available') {
  if (value === healthyValue || value === 'healthy') return ['ok', '✓'];
  if (value == null) return ['', '—'];
  return ['warn', '!'];
}

function renderHealth(overview) {
  const health = overview.latest_health || {};
  const stages = [
    ['Sensor', health.sensor, health.sensor === 'healthy' ? 'Complete · zero drops' : 'Incomplete or unhealthy'],
    ['MUD policy', health.mud, health.mud === 'available' ? 'Authorization evaluated' : 'Evidence unavailable'],
    ['E1+Q model', health.gnn, health.gnn === 'available' && health.gnn_fresh !== false ? 'Fresh model evidence' : health.gnn === 'stale' ? 'Evidence is stale' : 'Evidence unavailable'],
    ['Decision', health.partial === false ? 'healthy' : health.partial === true ? 'partial' : null, health.partial === false ? 'Branches joined' : 'Join incomplete']
  ];
  $('#health-flow').innerHTML = stages.map(([label, value, detail]) => {
    const [tone, mark] = stageState(value, 'available');
    return `<div class="health-stage ${tone}"><span class="stage-dot">${mark}</span><strong>${esc(label)}</strong><small>${esc(detail)}</small></div>`;
  }).join('');
  const sensor = health.sensor_detail || {};
  $('#health-details').innerHTML = [
    ['Capture drops', sensor.capture_drops == null ? 'Unavailable' : number(sensor.capture_drops)],
    ['Clock', sensor.clock_synchronized == null ? 'Unavailable' : sensor.clock_synchronized ? 'Synchronized' : 'Unsynchronized'],
    ['Evidence age', duration(health.gnn_age_seconds)]
  ].map(([label, value]) => `<div><span>${esc(label)}</span><strong>${esc(value)}</strong></div>`).join('');
  $('#window-time').textContent = overview.latest_window == null ? 'No windows' : shortTime(overview.latest_window);
}

function renderAttention(alerts) {
  const target = $('#attention-list');
  if (!alerts.length) {
    target.innerHTML = '<div class="empty-state compact"><strong>No findings need attention</strong><p>New security and health findings will appear here.</p></div>';
    return;
  }
  target.innerHTML = alerts.slice(0, 4).map(alert => `<div class="attention-item"><span class="attention-mark">${alert.category === 'security' ? '!' : 'i'}</span><div><strong>${esc(alert.title)}</strong><p>${esc(alert.device_name)} · ${esc(alert.explanation)}</p></div><time>${relativeTime(alert.window_start)}</time></div>`).join('');
}

function renderActivity(traces) {
  const target = $('#activity-list');
  if (!traces.length) {
    target.innerHTML = '<div class="empty-state compact"><strong>No completed observations</strong><p>The next finalized minute will appear automatically.</p></div>';
    return;
  }
  target.innerHTML = traces.slice(0, 4).map(trace => {
    const healthy = trace.health?.sensor === 'healthy' && trace.health?.partial !== true;
    const detail = `${number(trace.counts?.flows)} flows · ${number(trace.counts?.mud_denied)} denied · joined in ${duration(trace.latency_seconds?.window_close_to_join)}`;
    return `<div class="activity-item"><span class="activity-mark">${healthy ? '✓' : '!'}</span><div><strong>${healthy ? 'Observation completed' : 'Observation degraded'}</strong><p>${esc(detail)}</p></div><time>${shortTime(trace.window_start)}</time></div>`;
  }).join('');
}

function renderPosture(overview) {
  const model = overview.model || {};
  const mud = overview.mud_policy || {};
  const finalizer = overview.finalizer || {};
  const controller = overview.controller || {};
  const items = [
    ['Mode', `${overview.observation_kind} / ${overview.decision_mode}`],
    ['E1+Q bundle', model.bundle_version || 'Unavailable'],
    ['MUD policy', mud.version || 'Unavailable'],
    ['Controller', controller.available ? `${controller.switches?.length || 0} switch connected` : 'Unavailable'],
    ['Queue', `${number(finalizer.queue_depth || 0)} pending`]
  ];
  $('#posture-list').innerHTML = items.map(([term, value]) => `<div><dt>${esc(term)}</dt><dd title="${esc(value)}">${esc(value)}</dd></div>`).join('');
}

function render(data) {
  renderChrome(data);
  renderMetrics(data.overview);
  renderHealth(data.overview);
  renderAttention(data.alerts || []);
  renderActivity(data.traces || []);
  renderPosture(data.overview);
}

async function load(showToast = false) {
  if (state.loading) return;
  state.loading = true;
  $('#refresh').textContent = '↻';
  $('#refresh').disabled = true;
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 10000);
  try {
    const response = await fetch('/api/dashboard', {cache:'no-store', signal:controller.signal});
    if (!response.ok) throw new Error(`Dashboard API returned ${response.status}`);
    state.data = await response.json();
    render(state.data);
    $('#error-banner').classList.add('hidden');
    if (showToast) toast('Dashboard refreshed');
  } catch (error) {
    const message = error.name === 'AbortError' ? 'Dashboard request timed out after 10 seconds.' : `Dashboard could not load: ${error.message}`;
    $('#error-banner').textContent = message;
    $('#error-banner').classList.remove('hidden');
    $('#sidebar-state').innerHTML = '<span class="status-dot danger"></span><span><strong>Connection failed</strong><small>Check the dashboard service</small></span>';
  } finally {
    clearTimeout(timeout);
    state.loading = false;
    $('#refresh').disabled = false;
  }
}

let toastTimer;
function toast(message) {
  const target = $('#toast');
  target.textContent = message;
  target.classList.add('visible');
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => target.classList.remove('visible'), 2200);
}

function updateClock() {
  $('#clock').textContent = new Intl.DateTimeFormat([], {weekday:'short', hour:'2-digit', minute:'2-digit', second:'2-digit'}).format(new Date());
}

$$('.nav-item').forEach(button => button.addEventListener('click', () => navigate(button.dataset.page)));
$$('[data-go]').forEach(button => button.addEventListener('click', () => navigate(button.dataset.go)));
$('#refresh').addEventListener('click', () => load(true));
$('#mobile-menu').addEventListener('click', () => document.body.classList.toggle('menu-open'));
$('#scrim').addEventListener('click', () => document.body.classList.remove('menu-open'));
window.addEventListener('hashchange', () => navigate(location.hash.slice(1), false));

navigate(location.hash.slice(1) || 'overview', false);
updateClock();
setInterval(updateClock, 1000);
load();
setInterval(() => load(false), 30000);
