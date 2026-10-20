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

function initials(name) {
  return String(name || '?').split(/\s+/).map(part => part[0]).join('').slice(0, 2).toUpperCase();
}

function logit(value) {
  return value == null ? 'Not scored' : Number(value).toFixed(3);
}

function sparkline(device, field, threshold, flagged = false) {
  const values = (device.history || []).map(row => row[field]).filter(value => value != null).map(Number);
  if (!values.length) return '<svg class="score-chart" viewBox="0 0 120 28" aria-hidden="true"><line class="axis" x1="0" y1="14" x2="120" y2="14"/></svg>';
  const bounds = [...values, threshold].filter(value => value != null).map(Number);
  let low = Math.min(...bounds), high = Math.max(...bounds);
  if (low === high) { low -= 1; high += 1; }
  const x = index => values.length === 1 ? 60 : index * 120 / (values.length - 1);
  const y = value => 25 - ((value - low) / (high - low)) * 22;
  const points = values.map((value, index) => `${x(index).toFixed(1)},${y(value).toFixed(1)}`).join(' ');
  const thresholdLine = threshold == null ? '' : `<line class="threshold" x1="0" y1="${y(Number(threshold)).toFixed(1)}" x2="120" y2="${y(Number(threshold)).toFixed(1)}"/>`;
  return `<svg class="score-chart" viewBox="0 0 120 28" aria-hidden="true"><line class="axis" x1="0" y1="25" x2="120" y2="25"/>${thresholdLine}<polyline class="trend ${flagged ? 'flagged' : ''}" points="${points}"/></svg>`;
}

function deviceCard(device) {
  const reason = Object.values(device.unscored_reasons || {}).filter(Boolean)[0];
  const detail = device.binding?.ip || reason?.replaceAll('_', ' ') || 'No active binding';
  return `<button class="device-card ${esc(device.risk)}" type="button" data-device="${esc(device.device_id)}">
    <span class="device-card-head"><span class="device-avatar">${esc(initials(device.name))}</span><span class="device-identity"><strong>${esc(device.name)}</strong><small>${esc(device.device_type?.replaceAll('_', ' ') || 'Unknown type')} · ${esc(detail)}</small></span><span class="risk-pill ${esc(device.risk)}">${esc(device.risk)}</span></span>
    <span class="device-scores"><span class="score-block"><span class="score-label"><span>Head A</span><span>Behaviour</span></span><strong class="score-value ${device.behavioral_flag ? 'flagged' : ''}">${esc(logit(device.behavioral_score))}</strong>${sparkline(device, 'behavioral_score', device.behavioral_threshold, device.behavioral_flag)}</span><span class="score-block"><span class="score-label"><span>Head B</span><span>Links</span></span><strong class="score-value ${device.link_flag ? 'flagged' : ''}">${esc(logit(device.link_anomaly))}</strong>${sparkline(device, 'link_anomaly', device.link_threshold, device.link_flag)}</span></span>
    <span class="device-foot"><span>${device.history_state?.fully_warmed ? 'History warmed' : `${number(device.history_state?.prior_windows || 0)} prior windows`}</span><span>${number(device.mud?.denied || 0)} MUD denied</span></span>
  </button>`;
}

function renderDevices() {
  if (!state.data) return;
  const query = ($('#device-search')?.value || '').trim().toLowerCase();
  const filter = $('#device-filter')?.value || 'all';
  const devices = state.data.devices.filter(device => {
    const searchable = `${device.name} ${device.device_type} ${device.binding?.ip || ''}`.toLowerCase();
    return (!query || searchable.includes(query)) && (filter === 'all' || device.risk === filter);
  });
  $('#device-grid').innerHTML = devices.length
    ? devices.map(deviceCard).join('')
    : '<div class="empty-state"><strong>No devices match this view</strong><p>Change the search or status filter to see other inventory entries.</p></div>';
  $$('#device-grid [data-device]').forEach(button => button.addEventListener('click', () => openDevice(button.dataset.device)));
}

function largeHistoryChart(device) {
  const rows = device.history || [];
  const series = ['behavioral_score', 'link_anomaly'];
  const values = rows.flatMap(row => series.map(field => row[field])).filter(value => value != null).map(Number);
  if (!values.length) return '<div class="empty-state compact"><strong>No score history</strong><p>This device was inactive or unavailable in the retained observations.</p></div>';
  const thresholds = [device.behavioral_threshold, device.link_threshold].filter(value => value != null).map(Number);
  let low = Math.min(...values, ...thresholds), high = Math.max(...values, ...thresholds);
  if (low === high) { low -= 1; high += 1; }
  const x = index => rows.length === 1 ? 150 : 12 + index * 276 / (rows.length - 1);
  const y = value => 106 - ((value - low) / (high - low)) * 92;
  const polyline = (field, className) => {
    let segments = [], current = [];
    rows.forEach((row, index) => {
      if (row[field] == null) { if (current.length) segments.push(current); current = []; return; }
      current.push(`${x(index).toFixed(1)},${y(Number(row[field])).toFixed(1)}`);
    });
    if (current.length) segments.push(current);
    return segments.map(points => `<polyline class="${className}" points="${points.join(' ')}"/>`).join('');
  };
  return `<svg class="large-chart" viewBox="0 0 300 120" role="img" aria-label="Head A and Head B logit history"><line class="grid" x1="12" y1="14" x2="288" y2="14"/><line class="grid" x1="12" y1="60" x2="288" y2="60"/><line class="grid" x1="12" y1="106" x2="288" y2="106"/>${polyline('behavioral_score','trend-a')}${polyline('link_anomaly','trend-b')}</svg><div class="chart-legend"><span><i></i>Head A behaviour</span><span><i class="link"></i>Head B links</span></div>`;
}

function openDrawer(title, kicker, body) {
  $('#drawer-title').textContent = title;
  $('#drawer-kicker').textContent = kicker;
  $('#drawer-body').innerHTML = body;
  $('#drawer').setAttribute('aria-hidden', 'false');
  document.body.classList.add('drawer-open');
}

function closeDrawer() {
  document.body.classList.remove('drawer-open');
  $('#drawer').setAttribute('aria-hidden', 'true');
}

function openDevice(deviceId) {
  const device = state.data?.devices.find(row => row.device_id === deviceId);
  if (!device) return;
  const reasons = Object.entries(device.unscored_reasons || {}).filter(([, value]) => value).map(([head, value]) => `<li><strong>Head ${head.toUpperCase()}:</strong> ${esc(String(value).replaceAll('_', ' '))}</li>`).join('');
  const body = `<div class="detail-hero"><span class="device-avatar">${esc(initials(device.name))}</span><div><span class="risk-pill ${esc(device.risk)}">${esc(device.risk)}</span><p>${esc(device.device_type?.replaceAll('_',' '))} · ${esc(device.binding?.ip || 'No active IP')}</p></div></div>
    <section class="detail-section"><h3>Identity & binding</h3><div class="detail-grid"><div><span>Device ID</span><strong>${esc(device.device_id)}</strong></div><div><span>Switch port</span><strong>${esc(device.binding?.switch_port ?? 'Unavailable')}</strong></div><div><span>MAC address</span><strong>${esc(device.binding?.mac || 'Unavailable')}</strong></div><div><span>Profile support</span><strong>${device.profile_support?.known_device ? 'Known device' : 'Unknown / unavailable'}</strong></div></div></section>
    <section class="detail-section"><h3>Score history</h3>${largeHistoryChart(device)}</section>
    <section class="detail-section"><h3>Current GNN evidence</h3><div class="detail-grid"><div><span>Head A raw logit</span><strong>${esc(logit(device.behavioral_score))}</strong></div><div><span>Head A threshold</span><strong>${esc(logit(device.behavioral_threshold))}</strong></div><div><span>Head B raw logit</span><strong>${esc(logit(device.link_anomaly))}</strong></div><div><span>Head B threshold</span><strong>${esc(logit(device.link_threshold))}</strong></div><div><span>History</span><strong>${device.history_state?.fully_warmed ? 'Fully warmed' : `${number(device.history_state?.prior_windows || 0)} prior windows`}</strong></div><div><span>MUD decisions</span><strong>${number(device.mud?.allowed || 0)} allowed · ${number(device.mud?.denied || 0)} denied</strong></div></div></section>
    ${reasons ? `<section class="detail-section"><h3>Why this device is unscored</h3><ul class="reason-list">${reasons}</ul></section>` : ''}
    <section class="detail-section"><p class="drawer-note">Scores are supervised raw logits evaluated against frozen thresholds. They are not probabilities of compromise.</p></section>`;
  openDrawer(device.name, 'Device evidence', body);
}

function permissionOf(edge) {
  if ((edge.permissions?.denied || 0) > 0) return 'denied';
  if ((edge.permissions?.unknown_policy || 0) + (edge.permissions?.unknown_device || 0) > 0) return 'unknown';
  return 'allowed';
}

function normalizedTopology(filter) {
  const original = state.data?.topology || {nodes:[], edges:[]};
  const knownNodes = original.nodes.filter(node => node.type !== 'external');
  const hasExternal = original.edges.some(edge => edge.source.startsWith('external:') || edge.target.startsWith('external:'));
  const nodes = hasExternal ? [...knownNodes, {id:'external-services', name:'External services', type:'external', status:'observed'}] : knownNodes;
  const indexed = new Map();
  original.edges.forEach(edge => {
    const kind = permissionOf(edge);
    if (filter !== 'all' && kind !== filter) return;
    const source = edge.source.startsWith('external:') ? 'external-services' : edge.source;
    const target = edge.target.startsWith('external:') ? 'external-services' : edge.target;
    const key = `${source}|${target}|${kind}`;
    const current = indexed.get(key) || {source, target, kind, count:0, bytes:0, permissions:{}, protocols:new Set(), ports:new Set()};
    current.count += edge.count || 0;
    current.bytes += edge.bytes || 0;
    Object.entries(edge.permissions || {}).forEach(([name, value]) => current.permissions[name] = (current.permissions[name] || 0) + value);
    if (edge.proto) current.protocols.add(edge.proto);
    if (edge.port != null) current.ports.add(edge.port);
    indexed.set(key, current);
  });
  const edges = [...indexed.values()].sort((a,b) => b.count - a.count).slice(0, 36).map(edge => ({...edge, protocols:[...edge.protocols], ports:[...edge.ports]}));
  return {nodes, edges};
}

function renderNetwork() {
  if (!state.data) return;
  const filter = $('#network-filter')?.value || 'all';
  const {nodes, edges} = normalizedTopology(filter);
  const width = 900, height = 520, center = {x:450,y:260};
  const gateway = nodes.find(node => node.type === 'gateway');
  const external = nodes.find(node => node.type === 'external');
  const devices = nodes.filter(node => !['gateway','external'].includes(node.type));
  const positions = new Map();
  if (gateway) positions.set(gateway.id, center);
  devices.forEach((node, index) => {
    const angle = -Math.PI / 2 + index * Math.PI * 2 / Math.max(devices.length, 1);
    const radiusX = 330, radiusY = 195;
    positions.set(node.id, {x:center.x + Math.cos(angle) * radiusX, y:center.y + Math.sin(angle) * radiusY});
  });
  if (external) positions.set(external.id, {x:790,y:260});
  const edgeMarkup = edges.map((edge, index) => {
    const source = positions.get(edge.source), target = positions.get(edge.target);
    if (!source || !target) return '';
    const opacity = Math.min(.82, .25 + Math.log2(edge.count + 1) / 8);
    const widthValue = Math.min(3, 1 + Math.log2(edge.count + 1) / 3);
    return `<line class="network-edge ${edge.kind}" data-edge="${index}" x1="${source.x}" y1="${source.y}" x2="${target.x}" y2="${target.y}" stroke-opacity="${opacity}" stroke-width="${widthValue}"/>`;
  }).join('');
  const nodeMarkup = nodes.map(node => {
    const point = positions.get(node.id);
    if (!point) return '';
    const radius = node.type === 'gateway' ? 31 : node.type === 'external' ? 28 : 23;
    const label = node.type === 'external' ? 'External' : node.name.split(' ')[0].slice(0,14);
    return `<g class="network-node ${esc(node.risk || '')} ${esc(node.type)}" data-node="${esc(node.id)}" transform="translate(${point.x} ${point.y})"><circle r="${radius}"/><text text-anchor="middle" y="3">${esc(node.type === 'gateway' ? 'AM' : initials(node.name))}</text><text class="node-type" text-anchor="middle" y="${radius + 15}">${esc(label)}</text></g>`;
  }).join('');
  $('#network-canvas').innerHTML = nodes.length ? `<svg viewBox="0 0 ${width} ${height}" role="img" aria-label="Recent AutoMUD network relationships">${edgeMarkup}${nodeMarkup}</svg>` : '<div class="empty-state"><strong>No topology evidence</strong><p>Run a completed observation to populate the network map.</p></div>';
  $('#network-summary').textContent = `${number(devices.length)} devices · ${number(edges.length)} recent relationships`;
  $$('.network-edge').forEach(line => line.addEventListener('click', () => showEdge(edges[Number(line.dataset.edge)], line)));
  $$('.network-node').forEach(node => node.addEventListener('click', () => showNode(nodes.find(row => row.id === node.dataset.node), node)));
}

function selectGraphElement(element) {
  $$('.network-edge.selected, .network-node.selected').forEach(node => node.classList.remove('selected'));
  element.classList.add('selected');
}

function showEdge(edge, element) {
  selectGraphElement(element);
  const nodeName = id => state.data.topology.nodes.find(node => node.id === id)?.name || (id === 'external-services' ? 'External services' : id);
  $('#network-detail').innerHTML = `<strong>${esc(nodeName(edge.source))} → ${esc(nodeName(edge.target))}</strong><span class="detail-separator"></span><span>${esc(edge.kind.toUpperCase())}</span><span>${number(edge.count)} flows</span><span>${number(edge.bytes)} bytes</span><span>${esc(edge.protocols.join(', ').toUpperCase() || '—')}</span>`;
}

function showNode(node, element) {
  selectGraphElement(element);
  if (!node) return;
  const device = state.data.devices.find(row => row.device_id === node.id);
  $('#network-detail').innerHTML = `<strong>${esc(node.name)}</strong><span class="detail-separator"></span><span>${esc(node.type?.replaceAll('_',' '))}</span><span>${esc(node.ip || device?.binding?.ip || 'No IP')}</span><span>${esc(device?.risk || node.status || 'Observed')}</span>${device ? `<button class="text-button" id="inspect-network-device" type="button">Inspect evidence</button>` : ''}`;
  $('#inspect-network-device')?.addEventListener('click', () => openDevice(device.device_id));
}

function render(data) {
  renderChrome(data);
  renderMetrics(data.overview);
  renderHealth(data.overview);
  renderAttention(data.alerts || []);
  renderActivity(data.traces || []);
  renderPosture(data.overview);
  renderDevices();
  renderNetwork();
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
$('#scrim').addEventListener('click', () => { document.body.classList.remove('menu-open'); closeDrawer(); });
$('#close-drawer').addEventListener('click', closeDrawer);
$('#device-search').addEventListener('input', renderDevices);
$('#device-filter').addEventListener('change', renderDevices);
$('#network-filter').addEventListener('change', renderNetwork);
window.addEventListener('hashchange', () => navigate(location.hash.slice(1), false));

navigate(location.hash.slice(1) || 'overview', false);
updateClock();
setInterval(updateClock, 1000);
load();
setInterval(() => load(false), 30000);
