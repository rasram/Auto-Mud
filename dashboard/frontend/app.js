const state = { data: null, overrides: {enabled:false, overrides:[]}, adminToken: null, loading: false };
const $ = selector => document.querySelector(selector);
const $$ = selector => [...document.querySelectorAll(selector)];
const esc = value => String(value ?? '').replace(/[&<>"']/g, char => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[char]));
const number = value => value == null ? '—' : new Intl.NumberFormat().format(value);
const duration = value => value == null ? '—' : value < 1 ? `${Math.round(value * 1000)} ms` : `${Number(value).toFixed(value < 10 ? 2 : 1)} s`;
const clockTime = value => value == null ? '—' : new Intl.DateTimeFormat([], {hour:'2-digit', minute:'2-digit', second:'2-digit'}).format(new Date(Number(value) * 1000));
const shortTime = value => value == null ? '—' : new Intl.DateTimeFormat([], {hour:'2-digit', minute:'2-digit'}).format(new Date(Number(value) * 1000));
const fullTime = value => value == null ? '—' : new Intl.DateTimeFormat([], {dateStyle:'medium', timeStyle:'medium'}).format(new Date(Number(value) * 1000));
const icon = (name, className = '') => `<svg class="icon ${esc(className)}" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true" focusable="false"><use href="vendor/lucide.svg#${esc(name)}"></use></svg>`;
const deviceIcon = type => ({camera:'camera',doorbell:'door-open',speaker:'speaker',plug:'plug',printer:'printer',light:'lightbulb',motion_sensor:'radio',environmental_sensor:'thermometer',hub:'router'}[type] || 'monitor-smartphone');
const riskLabel = risk => ({anomalous:'Flag raised',normal:'No GNN flags',monitoring:'Partly assessed',unscored:'Not assessed'}[risk] || 'Not assessed');
const signalLabel = value => value === true ? 'Flag raised' : value === false ? 'No flag' : 'Unavailable';
const reasonText = value => ({inactive_or_unavailable:'No activity or sensor data for this minute',inactive_or_unavailable_or_no_initiated_relationship:'No assessable outgoing connections',current_evidence_unavailable:'Waiting for current evidence',incomplete_observation:'The observation is incomplete',incomplete_sensor_window:'The capture did not cover the full minute',sensor_unhealthy:'Sensor data is unavailable',clock_unsynchronized:'The sensor clock is not synchronized',capture_drops_or_unavailable:'Packets were dropped or capture health is unavailable',engineering_observation:'Monitoring a lab environment'}[value] || String(value || '').replaceAll('_',' '));
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
  network: ['Network map', 'Network map'],
  devices: ['Devices', 'Device security'],
  alerts: ['Findings', 'Findings'],
  actions: ['Network actions', 'Network actions'],
  pipeline: ['Activity', 'Observation history'],
  about: ['About', 'About AutoMUD']
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
  const title = automatic ? 'Automatic response is on' : unhealthy ? 'Some monitoring checks need attention' : 'Monitoring only';
  const copy = automatic
    ? 'Approved findings can trigger temporary, targeted network restrictions.'
    : unhealthy
      ? 'Some evidence is incomplete or unavailable. Automatic response remains paused.'
      : 'Findings are recorded for review. Your network is not changed automatically.';
  banner.innerHTML = `<div class="mode-icon">${icon(automatic || unhealthy ? 'shield-alert' : 'shield-check')}</div><div><strong>${esc(title)}</strong><p>${esc(copy)}</p></div><span class="mode-pill">${automatic ? 'RESPONSE ON' : 'NO AUTOMATIC ACTIONS'}</span>`;
}

function renderChrome(data) {
  const { overview, devices, alerts } = data;
  const healthy = overview.runtime?.active && overview.evidence_fresh && overview.current_run_evidence && overview.latest_health?.sensor === 'healthy' && overview.latest_health?.partial === false;
  const sidebar = $('#sidebar-state');
  sidebar.innerHTML = `<span class="status-dot ${healthy ? 'live' : 'warning'}"></span><span><strong>${healthy ? 'Monitoring connected' : 'Monitoring needs attention'}</strong><small>${overview.observation_kind === 'engineering' ? 'Lab environment' : 'Network monitoring'}</small></span>`;
  $('#device-count').textContent = devices.length;
  $('#alert-count').textContent = groupFindings(alerts).filter(alert => alert.current).length || '0';
  $('#inventory-short').textContent = overview.observation_kind === 'engineering' ? 'Lab · controlled traffic' : 'Live network';
  $('#last-sync').textContent = clockTime(overview.generated_at);
  $('#last-observation').textContent = fullTime(overview.last_observation);
  const observation = $('#observation-banner');
  const active = overview.runtime?.active === true;
  observation.className = `mode-banner ${healthy ? '' : 'warning'}`;
  const condition = !active ? 'Monitoring is stopped' : !overview.evidence_fresh ? 'Waiting for fresh observations' : !overview.current_run_evidence ? 'Waiting for this session’s first observation' : healthy ? 'Observations are up to date' : 'The latest observation needs attention';
  const lab = overview.observation_kind === 'engineering' ? ' Lab traffic includes deliberate policy violations.' : '';
  observation.innerHTML = `<div class="mode-icon">${icon(healthy ? 'activity' : 'triangle-alert')}</div><div><strong>${esc(condition)}</strong><p>Last observed ${esc(fullTime(overview.last_observation))} · ${esc(relativeTime(overview.last_observation))}.${lab}</p></div><span class="mode-pill">${active ? 'MONITORING ACTIVE' : 'STOPPED'}</span>`;
  renderMode(overview);
}

function gnnState(health) {
  if (health.gnn !== 'available') return health.gnn || 'missing';
  if (health.gnn_detail?.complete !== true) return 'incomplete';
  if (health.sensor !== 'healthy') return 'unhealthy';
  if (health.gnn_fresh === false) return 'stale';
  return 'available';
}

function groupFindings(alerts) {
  const groups = new Map();
  for (const alert of alerts) {
    const scope = alert.proposal?.scope || {};
    const key = alert.category === 'security' ? JSON.stringify([alert.window_start,alert.device_id,alert.reason,scope.proto,scope.destination_ip,scope.destination_port,alert.current,alert.severity]) : alert.id;
    const group = groups.get(key);
    if (group) group.records += alert.occurrences || 1;
    else groups.set(key, {...alert,records:alert.occurrences || 1});
  }
  return [...groups.values()];
}

function renderMetrics(overview, devices = [], alerts = []) {
  const metrics = overview.metrics || {};
  const policyCount = groupFindings(alerts).filter(row => row.current && row.category === 'security' && row.reason !== 'behavioral_anomaly_requires_flow_attribution').length;
  const cards = [
    {label:'Devices observed', value:number(metrics.devices), detail:`${number(metrics.active_devices)} active in the latest minute`, icon:'monitor-smartphone'},
    {label:'GNN flags', value:number(metrics.anomalous_devices), detail:`${devices.filter(row => row.behavioral_flag === true).length} behavior · ${devices.filter(row => row.link_flag === true).length} connection flags`, icon:'brain-circuit', tone:metrics.anomalous_devices ? 'caution' : ''},
    {label:'Policy violations', value:number(policyCount), detail:'Distinct routes to review · not confirmed attacks', icon:'shield-alert',tone:policyCount ? 'caution' : ''},
    {label:'Active responses', value:number(metrics.active_actions), detail:overview.automatic_enforcement_enabled ? 'Temporary network restrictions' : 'Monitoring only · no automatic actions', icon:'shield-check', tone:metrics.active_actions ? 'alert' : ''}
  ];
  $('#metrics').innerHTML = cards.map(card => `<article class="metric ${card.tone || ''}"><span class="metric-label"><span>${esc(card.label)}</span><span class="metric-icon">${icon(card.icon)}</span></span><strong class="metric-value">${esc(card.value)}</strong><span class="metric-detail">${esc(card.detail)}</span></article>`).join('');
}

function stageState(value, healthyValue = 'available') {
  if (value === healthyValue || value === 'healthy') return ['ok', 'check'];
  if (value == null) return ['', 'clock-3'];
  return ['warn', 'triangle-alert'];
}

function renderHealth(overview) {
  const health = overview.latest_health || {};
  const stages = [
    ['Sensor', health.sensor, health.sensor === 'healthy' ? 'Complete · zero drops' : 'Incomplete or unhealthy'],
    ['Policy', health.mud, health.mud === 'available' ? 'Permissions checked' : 'Unavailable'],
    ['GNN', overview.evidence_fresh && overview.current_run_evidence ? gnnState(health) : 'stale', overview.evidence_fresh && overview.current_run_evidence ? `${gnnState(health) === 'available' ? 'Signals assessed' : 'GNN ' + gnnState(health)}` : 'Earlier evidence'],
    ['Review', health.partial === false ? 'healthy' : health.partial === true ? 'partial' : null, health.partial === false ? 'Evidence combined' : 'Evidence incomplete']
  ];
  $('#health-flow').innerHTML = stages.map(([label, value, detail]) => {
    const [tone, mark] = stageState(value, 'available');
    return `<div class="health-stage ${tone}"><span class="stage-dot">${icon(mark)}</span><strong>${esc(label)}</strong><small>${esc(detail)}</small></div>`;
  }).join('');
  const sensor = health.sensor_detail || {};
  $('#health-details').innerHTML = [
    ['Capture quality', sensor.capture_drops == null ? 'Unavailable' : sensor.capture_drops === 0 ? 'No packets dropped' : `${number(sensor.capture_drops)} dropped`],
    ['Clock', sensor.clock_synchronized == null ? 'Unavailable' : sensor.clock_synchronized ? 'Synchronized' : 'Unsynchronized'],
    ['Observation age', duration(overview.observation_age_seconds)],
    ['Completeness', health.complete === true ? 'Complete' : 'Incomplete'],
    ['Issues', (health.issues || []).map(reasonText).join(', ') || 'None recorded'],
    ['Evidence freshness', overview.evidence_fresh ? 'Fresh' : 'Stale / unavailable']
  ].map(([label, value]) => `<div><span>${esc(label)}</span><strong>${esc(value)}</strong></div>`).join('');
  $('#window-time').textContent = overview.latest_window == null ? 'No windows' : shortTime(overview.latest_window);
}

function renderAttention(alerts) {
  alerts = groupFindings(alerts).filter(alert => alert.current);
  const target = $('#attention-list');
  if (!alerts.length) {
    target.innerHTML = '<div class="empty-state compact"><strong>No findings need attention</strong><p>New security and health findings will appear here.</p></div>';
    return;
  }
  target.innerHTML = alerts.slice(0, 4).map(alert => `<div class="attention-item"><span class="attention-mark">${icon(alert.category === 'security' ? 'shield-alert' : 'activity')}</span><div><strong>${esc(findingTitle(alert))}</strong><p>${esc(findingCopy(alert))}</p></div><time>${esc(shortTime(alert.window_start))}</time></div>`).join('');
}

function renderActivity(traces) {
  const target = $('#activity-list');
  if (!traces.length) {
    target.innerHTML = '<div class="empty-state compact"><strong>No completed observations</strong><p>The next finalized minute will appear automatically.</p></div>';
    return;
  }
  target.innerHTML = traces.slice(0, 4).map(trace => {
    const healthy = trace.health?.sensor === 'healthy' && trace.health?.partial !== true;
    const detail = `${number(trace.counts?.flows)} connections observed · ${number(trace.counts?.mud_denied)} outside policy`;
    return `<div class="activity-item"><span class="activity-mark">${icon(healthy ? 'circle-check' : 'triangle-alert')}</span><div><strong>${healthy ? 'Observation completed' : 'Observation incomplete'}</strong><p>${esc(detail)}</p></div><time>${shortTime(trace.window_start)}</time></div>`;
  }).join('');
}

function renderPosture(overview) {
  const finalizer = overview.finalizer || {};
  const controller = overview.controller || {};
  const items = [
    ['Response mode', overview.automatic_enforcement_enabled ? 'Automatic response' : 'Monitoring only'],
    ['Detection', 'GNN'],
    ['Network policy', overview.latest_health?.mud === 'available' ? 'Available' : 'Unavailable'],
    ['Network connection', controller.available && controller.switches?.length ? 'Connected' : 'Disconnected'],
    ['Monitoring', overview.runtime?.active ? 'Active' : 'Stopped'],
    ['Pending observations', number(finalizer.queue_depth || 0)]
  ];
  $('#posture-list').innerHTML = items.map(([term, value]) => `<div><dt>${esc(term)}</dt><dd title="${esc(value)}">${esc(value)}</dd></div>`).join('');
}

function renderAbout(overview) {
  const lab = overview.observation_kind === 'engineering';
  $('#about-environment').innerHTML = `<h3>${lab ? 'Controlled lab environment' : 'Current environment'}</h3><p>${lab ? 'This deployment generates permitted connections and deliberate policy violations to exercise the monitoring pipeline. Expected test violations are not evidence of an attack. Behavioral GNN flags have not been validated against attack-labelled traffic from this environment.' : 'Interpret flags alongside the captured traffic, device context and approved policy.'}</p><p>History builds as observations arrive. Full warm-up requires 15 previous observations and one hour of continuous history; a restart begins a new session.</p>`;
  const values = [['Detector','GNN'],['Release',overview.model?.bundle_version || 'Unavailable'],['Model fingerprint',overview.model?.a_checkpoint || 'Unavailable'],['Network policy',overview.mud_policy?.version || 'Unavailable'],['Inventory',overview.inventory_version || 'Unavailable'],['Deployment',overview.deployment_id || 'Unavailable'],['Observation source',overview.runtime?.run_id || 'Unavailable'],['Sensor input',overview.runtime?.sensor_interface || 'Unavailable'],['Session started',fullTime(overview.runtime?.started_at)],['Session stopped',fullTime(overview.runtime?.stopped_at)]];
  $('#about-details').innerHTML = values.map(([label,value]) => `<div><dt>${esc(label)}</dt><dd>${esc(value)}</dd></div>`).join('');
}

function initials(name) {
  return String(name || '?').split(/\s+/).map(part => part[0]).join('').slice(0, 2).toUpperCase();
}

function logit(value) {
  return value == null ? 'Not scored' : Number(value).toFixed(3);
}

function warmupLabel(device) {
  const history = device.history_state || {};
  if (history.fully_warmed) return 'History fully warmed';
  return `${number(history.prior_windows || 0)} / 15 prior windows · ${Math.floor((history.observed_age_seconds || 0) / 60)} / 60 observed minutes`;
}

function sparkline(device, field, threshold, flagged = false) {
  const rows = device.history || [];
  const values = rows.map(row => row[field]).filter(value => value != null).map(Number);
  if (!values.length) return '<svg class="score-chart" viewBox="0 0 120 28" aria-hidden="true"><line class="axis" x1="0" y1="14" x2="120" y2="14"/></svg>';
  const bounds = [...values, threshold].filter(value => value != null).map(Number);
  let low = Math.min(...bounds), high = Math.max(...bounds);
  if (low === high) { low -= 1; high += 1; }
  const x = index => rows.length === 1 ? 60 : index * 120 / (rows.length - 1);
  const y = value => 25 - ((value - low) / (high - low)) * 22;
  const segments = [];
  let segment = [];
  rows.forEach((row, index) => {
    if (row[field] == null) { if (segment.length) segments.push(segment); segment = []; return; }
    segment.push(`${x(index).toFixed(1)},${y(Number(row[field])).toFixed(1)}`);
  });
  if (segment.length) segments.push(segment);
  const thresholdLine = threshold == null ? '' : `<line class="threshold" x1="0" y1="${y(Number(threshold)).toFixed(1)}" x2="120" y2="${y(Number(threshold)).toFixed(1)}"/>`;
  return `<svg class="score-chart" viewBox="0 0 120 28" aria-hidden="true"><line class="axis" x1="0" y1="25" x2="120" y2="25"/>${thresholdLine}${segments.map(points => `<polyline class="trend ${flagged ? 'flagged' : ''}" points="${points.join(' ')}"/>`).join('')}</svg>`;
}

function deviceCard(device) {
  const reason = Object.values(device.unscored_reasons || {}).filter(Boolean)[0];
  const detail = device.binding?.ip || 'Address unavailable';
  const previous = [['a','Behavior',device.behavioral_score],['b','Connections',device.link_anomaly]].filter(([head,,score]) => score == null && device.last_valid?.[head]).map(([head,label]) => `${label}: ${signalLabel(device.last_valid[head].flag).toLowerCase()} at ${fullTime(device.last_valid[head].window_start)}`).join(' · ');
  return `<button class="device-card ${esc(device.risk)}" type="button" data-device="${esc(device.device_id)}">
    <span class="device-card-head"><span class="device-avatar">${icon(deviceIcon(device.device_type))}</span><span class="device-identity"><strong>${esc(device.name)}</strong><small>${esc(detail)}</small></span><span class="risk-pill ${esc(device.risk)}">${esc(riskLabel(device.risk))}</span></span>
    <span class="device-scores"><span class="score-block"><span class="score-label">Behavior</span><strong class="signal-value ${device.behavioral_flag ? 'flagged' : ''}">${esc(signalLabel(device.behavioral_flag))}</strong>${sparkline(device, 'behavioral_score', device.behavioral_threshold, device.behavioral_flag)}</span><span class="score-block"><span class="score-label">Connections</span><strong class="signal-value ${device.link_flag ? 'flagged' : ''}">${esc(signalLabel(device.link_flag))}</strong>${sparkline(device, 'link_anomaly', device.link_threshold, device.link_flag)}</span></span>
    <span class="drawer-note">${esc(reason ? reasonText(reason) : `Observed ${shortTime(device.evidence_window)}`)}</span>
    ${previous ? `<span class="drawer-note">Last valid result · ${esc(previous)}</span>` : ''}
    <span class="device-foot"><span>${device.history_state?.fully_warmed ? 'History ready' : 'History building'}</span><span>${number(device.mud?.denied || 0)} policy-denied connections</span></span>
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
  return `<svg class="large-chart" viewBox="0 0 300 120" role="img" aria-label="Behavior and connection signal history"><line class="grid" x1="12" y1="14" x2="288" y2="14"/><line class="grid" x1="12" y1="60" x2="288" y2="60"/><line class="grid" x1="12" y1="106" x2="288" y2="106"/>${polyline('behavioral_score','trend-a')}${polyline('link_anomaly','trend-b')}</svg><div class="chart-legend"><span><i></i>Behavior</span><span><i class="link"></i>Connections</span></div>`;
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
  const body = `<div class="detail-hero"><span class="device-avatar">${icon(deviceIcon(device.device_type))}</span><div><span class="risk-pill ${esc(device.risk)}">${esc(riskLabel(device.risk))}</span><p>${esc(device.binding?.ip || 'Address unavailable')}</p></div></div>
    <section class="detail-section"><h3>Current assessment</h3><div class="detail-grid"><div><span>Behavior</span><strong>${esc(signalLabel(device.behavioral_flag))}</strong></div><div><span>Connections</span><strong>${esc(signalLabel(device.link_flag))}</strong></div><div><span>Network policy</span><strong>${number(device.mud?.allowed || 0)} allowed · ${number(device.mud?.denied || 0)} denied</strong></div><div><span>Observation</span><strong>${esc(fullTime(device.evidence_window))}</strong></div></div><p class="drawer-note">GNN flags are unconfirmed signals. A policy violation is a separate check, and a device with no GNN flags may still violate network policy.</p></section>
    <section class="detail-section"><h3>Recent signals</h3>${largeHistoryChart(device)}</section>
    ${reasons ? `<section class="detail-section"><h3>Why a check is unavailable</h3><p>${esc(Object.values(device.unscored_reasons || {}).filter(Boolean).map(reasonText).join('. '))}</p></section>` : ''}
    <details class="technical-section"><summary>Technical readings and source</summary>
    <section class="detail-section"><h3>Identity & binding</h3><div class="detail-grid"><div><span>Device ID</span><strong>${esc(device.device_id)}</strong></div><div><span>Switch port</span><strong>${esc(device.binding?.switch_port ?? 'Unavailable')}</strong></div><div><span>MAC address</span><strong>${esc(device.binding?.mac || 'Unavailable')}</strong></div><div><span>Profile support</span><strong>${device.profile_support?.known_device ? 'Known device' : 'Unknown / unavailable'}</strong></div></div></section>
    <section class="detail-section"><h3>Warm-up</h3><p class="drawer-note">${esc(warmupLabel(device))}. Full warm-up requires 15 consecutive prior windows and 60 minutes of observed history. Earlier scores retain their warm-up state.</p></section>
    <section class="detail-section"><h3>Evidence source</h3><p class="drawer-note">Observation ${esc(fullTime(device.evidence_window))} · run ${esc(device.evidence_run_id || 'unavailable')}. Inventory ${esc(device.binding?.inventory_version)}. Binding valid from ${esc(fullTime(device.binding?.valid_from))} until ${device.binding?.valid_until == null ? 'open ended' : esc(fullTime(device.binding.valid_until))}.</p>${['a','b'].map(head => { const last = device.last_valid?.[head]; return `<p class="drawer-note">Last valid Head ${head.toUpperCase()}: ${last ? `${esc(logit(last.score))} at ${esc(fullTime(last.window_start))} · run ${esc(last.run_id)}` : 'Unavailable in retained evidence'}</p>`; }).join('')}</section>
    <section class="detail-section"><h3>Current GNN evidence</h3><div class="detail-grid"><div><span>Head A raw logit</span><strong>${esc(logit(device.behavioral_score))}</strong></div><div><span>Head A threshold</span><strong>${esc(logit(device.behavioral_threshold))}</strong></div><div><span>Head B raw logit</span><strong>${esc(logit(device.link_anomaly))}</strong></div><div><span>Head B threshold</span><strong>${esc(logit(device.link_threshold))}</strong></div><div><span>History</span><strong>${device.history_state?.fully_warmed ? 'Fully warmed' : `${number(device.history_state?.prior_windows || 0)} prior windows`}</strong></div><div><span>MUD decisions</span><strong>${number(device.mud?.allowed || 0)} allowed · ${number(device.mud?.denied || 0)} denied</strong></div></div></section>
    ${reasons ? `<section class="detail-section"><h3>Why this device is unscored</h3><ul class="reason-list">${reasons}</ul></section>` : ''}
    <section class="detail-section"><p class="drawer-note">Scores are raw logits evaluated against fixed thresholds, not probabilities of compromise. Release information is available on the About page.</p></section></details>`;
  openDrawer(device.name, 'Device evidence', body);
}

function permissionOf(edge) {
  const kinds = permissionKinds(edge);
  if (kinds.length > 1) return 'mixed';
  return kinds[0] || 'unknown';
}

function permissionKinds(edge) {
  const kinds = [];
  if ((edge.permissions?.allowed || 0) > 0) kinds.push('allowed');
  if ((edge.permissions?.denied || 0) > 0) kinds.push('denied');
  if (Object.entries(edge.permissions || {}).some(([key, count]) => key.startsWith('unknown') && count > 0)) kinds.push('unknown');
  return kinds;
}

function normalizedTopology(filter) {
  const original = state.data?.topology || {nodes:[], edges:[]};
  const knownNodes = original.nodes.filter(node => node.type !== 'external');
  const hasExternal = original.edges.some(edge => edge.source.startsWith('external:') || edge.target.startsWith('external:'));
  const nodes = hasExternal ? [...knownNodes, {id:'external-services', name:'External services', type:'external', status:'observed'}] : knownNodes;
  const indexed = new Map();
  original.edges.forEach(edge => {
    const kind = permissionOf(edge);
    if (filter !== 'all' && (filter === 'mixed' ? kind !== 'mixed' : !permissionKinds(edge).includes(filter))) return;
    const source = edge.source.startsWith('external:') ? 'external-services' : edge.source;
    const target = edge.target.startsWith('external:') ? 'external-services' : edge.target;
    const key = `${source}|${target}|${kind}`;
    const current = indexed.get(key) || {source, target, kind, count:0, bytes:0, permissions:{}, protocols:new Set(), ports:new Set(), endpoints:new Set(), relationships:0};
    current.endpoints.add(`${edge.source} → ${edge.target} ${edge.proto || ''}:${edge.port ?? '—'}`);
    current.relationships += 1;
    current.count += edge.count || 0;
    current.bytes += edge.bytes || 0;
    Object.entries(edge.permissions || {}).forEach(([name, value]) => current.permissions[name] = (current.permissions[name] || 0) + value);
    if (edge.proto) current.protocols.add(edge.proto);
    if (edge.port != null) current.ports.add(edge.port);
    indexed.set(key, current);
  });
  const matching = [...indexed.values()].sort((a,b) => b.count - a.count);
  const edges = matching.slice(0, 36).map(edge => ({...edge, protocols:[...edge.protocols], ports:[...edge.ports], endpoints:[...edge.endpoints]}));
  return {nodes, edges, totalMatching:matching.length, totalFlows:matching.reduce((sum, edge) => sum + edge.count, 0), totalRelationships:matching.reduce((sum, edge) => sum + edge.relationships, 0)};
}

function renderNetwork() {
  if (!state.data) return;
  const filter = $('#network-filter')?.value || 'all';
  const {nodes, edges, totalMatching, totalFlows, totalRelationships} = normalizedTopology(filter);
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
  if (external) positions.set(external.id, center);
  const edgeMarkup = edges.map((edge, index) => {
    const source = positions.get(edge.source), target = positions.get(edge.target);
    if (!source || !target) return '';
    const opacity = Math.min(.82, .25 + Math.log2(edge.count + 1) / 8);
    const widthValue = Math.min(3, 1 + Math.log2(edge.count + 1) / 3);
    const length = Math.hypot(target.x-source.x, target.y-source.y) || 1;
    const end = {x:target.x-(target.x-source.x)*29/length, y:target.y-(target.y-source.y)*29/length};
    const path = edge.source === edge.target
      ? `M ${source.x+20} ${source.y-20} C ${source.x+110} ${source.y-110}, ${source.x+110} ${source.y+110}, ${source.x+20} ${source.y+20}`
      : `M ${source.x} ${source.y} Q ${(source.x+target.x)/2+8} ${(source.y+target.y)/2-8}, ${end.x} ${end.y}`;
    return `<path class="network-edge ${edge.kind}" data-edge="${index}" d="${path}" fill="none" marker-end="url(#flow-arrow)" stroke-opacity="${opacity}" stroke-width="${widthValue}"/>`;
  }).join('');
  const nodeMarkup = nodes.map(node => {
    const point = positions.get(node.id);
    if (!point) return '';
    const radius = node.type === 'gateway' ? 31 : node.type === 'external' ? 28 : 23;
    const label = node.type === 'external' ? 'External' : node.name.split(' ')[0].slice(0,14);
    return `<g class="network-node ${esc(node.risk || '')} ${esc(node.type)}" data-node="${esc(node.id)}" transform="translate(${point.x} ${point.y})"><circle r="${radius}"/><g transform="translate(-10 -10)">${icon(node.type === 'external' ? 'network' : deviceIcon(node.type))}</g><text class="node-type" text-anchor="middle" y="${radius + 15}">${esc(label)}</text></g>`;
  }).join('');
  $('#network-canvas').innerHTML = nodes.length ? `<svg viewBox="0 0 ${width} ${height}" role="img" aria-label="Recent AutoMUD network relationships"><defs><marker id="flow-arrow" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="6" markerHeight="6" orient="auto"><path d="M 0 0 L 10 5 L 0 10 z" fill="#c2d4ce"/></marker></defs>${edgeMarkup}${nodeMarkup}</svg>` : '<div class="empty-state"><strong>No topology evidence</strong><p>Run a completed observation to populate the network map.</p></div>';
  $('#network-summary').textContent = `${number(edges.length)} of ${number(totalMatching)} connection groups · ${number(totalFlows)} recorded connections`;
  const topology = state.data.topology;
  $('#network-provenance').textContent = `Recorded engineering evidence · ${fullTime(topology.window_start)} – ${fullTime(topology.window_end)} · retained ${topology.retained_windows || 0} windows · runs: ${(topology.run_ids || []).join(', ')} · sessions: ${(topology.session_ids || []).join(', ')}`;
  $('#network-detail').textContent = 'Select a relationship to inspect all retained endpoints, protocols and ports.';
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
  $('#network-detail').innerHTML = `<strong>${esc(nodeName(edge.source))} → ${esc(nodeName(edge.target))}</strong><span>${esc(edge.kind === 'mixed' ? 'Mixed policy results' : edge.kind)}</span><span>${number(edge.count)} recorded connections</span><span>${esc(edge.protocols.join(', ').toUpperCase() || '—')} · ports ${esc(edge.ports.join(', '))}</span><details class="technical-section"><summary>Connection details</summary><p>${esc(Object.entries(edge.permissions).map(([key,value]) => `${reasonText(key)}: ${value}`).join(' · '))}</p><p>${esc(edge.endpoints.map(endpoint => state.data.devices.reduce((text,device) => text.replaceAll(device.device_id,device.name),endpoint)).join('; '))}</p><p>${number(edge.bytes)} bytes</p></details>`;
}

function showNode(node, element) {
  selectGraphElement(element);
  if (!node) return;
  const device = state.data.devices.find(row => row.device_id === node.id);
  $('#network-detail').innerHTML = `<strong>${esc(node.name)}</strong><span class="detail-separator"></span><span>${esc(node.type?.replaceAll('_',' '))}</span><span>${esc(node.ip || device?.binding?.ip || 'Address unavailable')}</span><span>${esc(device ? riskLabel(device.risk) : 'Observed')}</span>${device ? `<button class="text-button" id="inspect-network-device" type="button">View assessment</button>` : ''}`;
  $('#inspect-network-device')?.addEventListener('click', () => openDevice(device.device_id));
}

function findingTitle(alert) {
  if (alert.category === 'operations') return 'Monitoring needs attention';
  if (alert.reason === 'behavioral_anomaly_requires_flow_attribution') return `${alert.device_name} · behavior flag`;
  return `${alert.device_name} · policy violation`;
}

function findingCopy(alert) {
  if (alert.category === 'operations') return alert.explanation;
  if (alert.reason === 'behavioral_anomaly_requires_flow_attribution') return 'The GNN raised a behavior flag. Review is needed before drawing a security conclusion.';
  const scope = alert.proposal?.scope || {};
  return `${number(alert.records)} connection${alert.records === 1 ? '' : 's'} outside the device’s policy${scope.destination_ip ? ` to ${scope.destination_ip}` : ''}${scope.destination_port ? ` on ${String(scope.proto || 'network').toUpperCase()} ${scope.destination_port}` : ''}.${alert.proposal?.reason === 'forbidden_exchange_with_link_anomaly' ? ' The GNN also raised a connection flag.' : ''}`;
}

function renderAlerts() {
  if (!state.data) return;
  const filter = $('#alert-filter')?.value || 'all';
  const scope = $('#alert-scope').value;
  const matching = groupFindings(state.data.alerts).filter(alert => (scope === 'all' || (scope === 'current' ? alert.current : !alert.current)) && (filter === 'all' || alert.category === filter || (filter === 'critical' && alert.severity === 'critical')));
  const alerts = matching.slice(0, 200);
  $('#alert-summary').textContent = `${number(alerts.length)} of ${number(matching.length)} grouped findings · ${number(matching.reduce((count,row) => count + row.records,0))} underlying records`;
  $('#alert-feed').innerHTML = alerts.length ? alerts.map(alert => `<button class="alert-row ${esc(alert.severity)} ${esc(alert.category)}" type="button" data-alert-trace="${esc(alert.trace_id)}"><span class="alert-symbol">${icon(alert.category === 'security' ? 'shield-alert' : 'activity')}</span><span class="alert-copy"><span class="alert-title-line"><h3>${esc(findingTitle(alert))}</h3><span class="severity-pill ${esc(alert.severity)}">${alert.category === 'operations' ? 'Monitoring' : 'Review'}</span></span><p>${esc(findingCopy(alert))}</p><span class="alert-meta"><span>${alert.current ? 'Current' : 'Historical'}</span><span>${number(alert.records)} records</span><span>View observation ${icon('arrow-right')}</span></span></span><time>${esc(fullTime(alert.window_start))}</time></button>`).join('') : '<div class="empty-state"><strong>No findings match this view</strong><p>Change the category or current/historical filter to inspect other observations.</p></div>';
  $$('[data-alert-trace]').forEach(button => button.addEventListener('click', () => openTrace(button.dataset.alertTrace)));
}

function renderActions() {
  if (!state.data) return;
  const controller = state.data.overview.controller || {};
  $('#controller-state').textContent = controller.available && controller.switches?.length ? 'Network connected' : 'Disconnected';
  $('#controller-state').className = `tag ${controller.available ? 'safe-tag' : 'warning-tag'}`;
  const actions = state.data.actions || [];
  $('#action-table').innerHTML = actions.length ? actions.map(action => {
    const scope = action.scope || {};
    const scopeText = scope.destination_ip ? `${scope.destination_ip}:${scope.destination_port || 'any'} / ${scope.proto || 'any'}` : 'Device scope';
    return `<tr><td><strong>${esc(action.device_name || 'Unknown device')}</strong><small>${action.source === 'archived_acceptance' ? 'Historical lab test' : 'Recorded response'}</small></td><td>${esc(action.action || '—')}</td><td>${esc(scopeText)}</td><td><span class="status-chip ${esc(action.status || '')}">${esc(action.status === 'historical_terminal_unrecorded' ? 'Final state unavailable' : reasonText(action.status || 'unknown'))}</span><button class="text-button" type="button" data-action-id="${esc(action.decision_id)}">View details ${icon('chevron-right')}</button></td><td>${esc(fullTime(action.installed_at))}</td><td>${esc(fullTime(action.removed_at || action.expired_at || action.expires_at))}</td></tr>`;
  }).join('') : '<tr><td class="empty-cell" colspan="6">No controller actions have been recorded. Observation-mode decisions do not install rules.</td></tr>';
  $$('[data-action-id]').forEach(button => button.addEventListener('click', () => {
    const action = state.data.actions.find(row => row.decision_id === button.dataset.actionId);
    openDrawer(action.device_name, 'Network response', `<section class="detail-section"><h3>${action.source === 'archived_acceptance' ? 'Historical lab test' : 'Recorded network action'}</h3><p>This record describes a temporary network restriction. Historical test results are separate from current protection.</p><div class="detail-grid">${[['Accepted',action.accepted_at],['Applied',action.installed_at],['Expires',action.expires_at],['Ended',action.removed_at || action.expired_at]].map(([label,value]) => `<div><span>${label}</span><strong>${esc(fullTime(value))}</strong></div>`).join('')}</div>${action.status === 'historical_terminal_unrecorded' ? '<p class="drawer-note">The final controller outcome was not recorded. It is unavailable.</p>' : ''}</section><details class="technical-section"><summary>Technical record</summary><pre>${esc(JSON.stringify(action, null, 2))}</pre></details>`);
  }));
}

function renderOverrides() {
  const enabled = Boolean(state.overrides?.enabled);
  $('#override-state').textContent = enabled ? 'Enabled' : 'Locked';
  $('#override-state').className = `tag ${enabled ? 'safe-tag' : 'warning-tag'}`;
  $('#new-override').disabled = !enabled;
  const rows = state.overrides?.overrides || [];
  if (!enabled) {
    $('#override-list').innerHTML = `<div class="override-lock"><span>${icon('lock-keyhole')}</span><strong>Operator controls are locked</strong><p>Response pauses can be changed only by an authorized operator. Monitoring continues.</p></div>`;
    return;
  }
  $('#override-list').innerHTML = rows.length ? rows.map(row => `<div class="override-item"><div class="override-item-head"><strong>${esc(row.target_device_id ? (state.data.devices.find(device => device.device_id === row.target_device_id)?.name || row.target_device_id) : 'All devices')}</strong><button class="text-button" type="button" data-remove-override="${esc(row.override_id)}">Remove</button></div><p>${esc(row.reason)}</p><small>${esc(row.actor)} · expires ${esc(fullTime(row.expires_at))}</small></div>`).join('') : '<div class="empty-state compact"><strong>No active suppressions</strong><p>Automatic policy evaluation has no active human suppression.</p></div>';
  $$('[data-remove-override]').forEach(button => button.addEventListener('click', () => removeOverride(button.dataset.removeOverride)));
}

function average(values) {
  const valid = values.filter(value => value != null).map(Number);
  return valid.length ? valid.reduce((sum, value) => sum + value, 0) / valid.length : null;
}

function renderTraces() {
  if (!state.data) return;
  const traces = state.data.traces || [];
  const filter = $('#trace-filter')?.value || 'all';
  const visible = traces.filter(trace => {
    if (filter === 'healthy') return trace.health?.sensor === 'healthy' && trace.health?.partial !== true;
    if (filter === 'partial') return trace.health?.partial === true || trace.health?.sensor !== 'healthy';
    if (filter === 'decisions') return (trace.counts?.proposals || 0) > 0;
    if (filter === 'actions') return Boolean(trace.action);
    return true;
  });
  const stages = [
    ['Window → join', average(traces.map(row => row.latency_seconds?.window_close_to_join)), 'after window close'],
    ['Join → decision', average(traces.map(row => row.latency_seconds?.join_to_decision)), 'policy evaluation'],
    ['Decision → install', average(traces.map(row => row.latency_seconds?.decision_to_install)), 'controller confirmation'],
    ['Packet → action', average(traces.map(row => row.latency_seconds?.packet_to_install)), 'full measured response']
  ];
  $('#latency-grid').innerHTML = stages.map(([label, value, detail]) => `<article class="latency-card"><span>${esc(label)}</span><strong>${esc(duration(value))}</strong><small>${esc(detail)}</small></article>`).join('');
  $('#trace-table').innerHTML = visible.length ? visible.map(trace => {
    const health = trace.health || {};
    const gnnTone = gnnState(health) === 'available' ? '' : 'warn';
    const mudTone = health.mud === 'available' ? '' : 'bad';
    return `<tr data-trace="${esc(trace.trace_id)}"><td><strong>${esc(fullTime(trace.window_start))}</strong><small>${trace.observation_kind === 'engineering' ? 'Lab observation' : 'Network observation'}</small></td><td><span class="evidence-chips"><span class="evidence-chip ${gnnTone}">GNN ${esc(gnnState(health))}</span><span class="evidence-chip ${mudTone}">Policy ${esc(health.mud || 'missing')}</span></span></td><td><span class="signal-list"><span>${number(trace.counts?.behavioral_flags)} behavior flags</span><span>${number(trace.counts?.link_flags)} connection flags</span><span>${number(trace.counts?.mud_denied)} outside policy</span></span></td><td>${trace.action ? 'Recorded action' : 'No action'}</td><td><button class="trace-open" type="button" aria-label="Open observation">${icon('chevron-right')}</button></td></tr>`;
  }).join('') : '<tr><td class="empty-cell" colspan="5">No observations match this filter.</td></tr>';
  $$('#trace-table [data-trace]').forEach(row => row.addEventListener('click', () => openTrace(row.dataset.trace)));
}

function traceStage(label, timestamp, detail) {
  return `<div class="trace-stage ${timestamp == null ? 'missing' : ''}"><span class="trace-stage-dot"></span><div><strong>${esc(label)}</strong><p>${esc(detail)}</p></div><time>${esc(fullTime(timestamp))}</time></div>`;
}

async function openTrace(traceId) {
  openDrawer('Loading observation…', 'Observation details', '<div class="empty-state"><span class="spinner"></span><strong>Reading recorded evidence</strong></div>');
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 10000);
  try {
    const response = await fetch(`/api/traces/${encodeURIComponent(traceId)}`, {cache:'no-store', signal:controller.signal});
    if (!response.ok) throw new Error(`Trace API returned ${response.status}`);
    const trace = await response.json();
    const times = trace.timestamps || {};
    const decision = trace.decision || {};
    const proposals = decision.proposals || [];
    const outcome = trace.action || {};
    const body = `<section class="detail-section"><h3>Observation timeline</h3><div class="trace-stages">${traceStage('Data captured', trace.window_end, `${number(trace.counts?.flows)} recorded connections`)}${traceStage('Network policy checked', times.mud_evidence, `${number(trace.counts?.mud_allowed)} allowed · ${number(trace.counts?.mud_denied)} outside policy`)}${traceStage('GNN assessment ready', times.gnn_evidence, `${number(trace.counts?.behavioral_flags)} behavior flags · ${number(trace.counts?.link_flags)} connection flags`)}${traceStage('Checks combined', times.joined_evidence, trace.health?.partial ? 'Some evidence is unavailable' : 'Both checks are available')}${traceStage('Review recorded', times.decision, decision.enforcement_eligible ? 'Ready for approved response' : `No automatic action: ${(decision.withheld_reasons || []).map(reasonText).join(', ') || 'none proposed'}`)}${traceStage('Network response applied', outcome.installed_at, outcome.status ? reasonText(outcome.status) : 'No action was sent')}</div></section>
      <details class="technical-section"><summary>Technical source and timing</summary><section class="detail-section"><h3>Observation source</h3><div class="detail-grid"><div><span>Reference</span><strong>${esc(trace.trace_id)}</strong></div><div><span>Session</span><strong>${esc(trace.run_id || '—')}</strong></div><div><span>Sensor</span><strong>${esc(trace.sensor_id || '—')}</strong></div><div><span>Detector</span><strong>GNN</strong></div></div></section>
      <section class="detail-section"><h3>Measured latency</h3><div class="detail-grid"><div><span>Packet → window close</span><strong>${esc(duration(trace.latency_seconds?.packet_to_window_close))}</strong></div><div><span>Window → join</span><strong>${esc(duration(trace.latency_seconds?.window_close_to_join))}</strong></div><div><span>Join → decision</span><strong>${esc(duration(trace.latency_seconds?.join_to_decision))}</strong></div><div><span>Decision → install</span><strong>${esc(duration(trace.latency_seconds?.decision_to_install))}</strong></div></div></section>
      <section class="detail-section"><h3>Recorded proposals</h3><p>${number(proposals.length)} recorded proposals. These records describe policy decisions and are not confirmed attacks. Release information is available on the About page.</p></section></details>`;
    openDrawer(fullTime(trace.window_start), 'Observation details', body);
  } catch (error) {
    $('#drawer-body').innerHTML = `<div class="empty-state"><strong>Trace could not be loaded</strong><p>${esc(error.name === 'AbortError' ? 'The request timed out after 10 seconds.' : error.message)}</p></div>`;
  } finally {
    clearTimeout(timeout);
  }
}

function openOverrideDialog() {
  if (!state.overrides?.enabled) { toast('Administrative controls are locked'); return; }
  $('#override-device').innerHTML = '<option value="">All devices</option>' + state.data.devices.map(device => `<option value="${esc(device.device_id)}">${esc(device.name)}</option>`).join('');
  $('#override-error').classList.add('hidden');
  $('#override-dialog').showModal();
}

async function submitOverride(event) {
  event.preventDefault();
  const form = new FormData(event.currentTarget);
  const token = String(form.get('token') || '');
  const value = {
    target_device_id: form.get('target_device_id') || null,
    actor: form.get('actor'), reason: form.get('reason'),
    expires_at: Date.now() / 1000 + Number(form.get('duration'))
  };
  try {
    const response = await fetch('/api/overrides', {method:'POST', headers:{'Content-Type':'application/json','Authorization':`Bearer ${token}`}, body:JSON.stringify(value)});
    const result = await response.json();
    if (!response.ok) throw new Error(result.error || `Request returned ${response.status}`);
    state.adminToken = token;
    $('#override-dialog').close();
    event.currentTarget.reset();
    toast('Suppression created');
    await load(false);
  } catch (error) {
    $('#override-error').textContent = error.message;
    $('#override-error').classList.remove('hidden');
  }
}

async function removeOverride(overrideId) {
  const token = state.adminToken || window.prompt('Enter the dashboard admin token to remove this suppression');
  if (!token) return;
  const actor = window.prompt('Operator name for the removal audit');
  const reason = window.prompt('Reason for removing this suppression');
  if (!actor || !reason) return;
  if (!window.confirm('Remove this suppression? This can restore automatic response eligibility in enforce mode.')) return;
  try {
    const response = await fetch(`/api/overrides/${encodeURIComponent(overrideId)}`, {method:'DELETE', headers:{'Authorization':`Bearer ${token}`, 'Content-Type':'application/json'}, body:JSON.stringify({actor, reason})});
    const result = await response.json();
    if (!response.ok) throw new Error(result.error || `Request returned ${response.status}`);
    state.adminToken = token;
    toast('Suppression removed');
    await load(false);
  } catch (error) { toast(`Could not remove suppression: ${error.message}`); }
}

function render(data) {
  renderChrome(data);
  renderMetrics(data.overview, data.devices || [], data.alerts || []);
  renderHealth(data.overview);
  renderAttention(data.alerts || []);
  renderActivity(data.traces || []);
  renderPosture(data.overview);
  renderAbout(data.overview);
  renderDevices();
  renderNetwork();
  renderAlerts();
  renderActions();
  renderOverrides();
  renderTraces();
}

async function load(showToast = false) {
  if (state.loading) return;
  state.loading = true;
  $('#refresh').innerHTML = icon('refresh-cw');
  $('#refresh').disabled = true;
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 10000);
  try {
    const [response, overridesResponse] = await Promise.all([
      fetch('/api/dashboard', {cache:'no-store', signal:controller.signal}),
      fetch('/api/overrides', {cache:'no-store', signal:controller.signal})
    ]);
    if (!response.ok) throw new Error(`Dashboard API returned ${response.status}`);
    if (!overridesResponse.ok) throw new Error(`Override API returned ${overridesResponse.status}`);
    state.data = await response.json();
    state.overrides = await overridesResponse.json();
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
$$('[data-icon]').forEach(element => { element.innerHTML = icon(element.dataset.icon); });
$$('[data-go]').forEach(button => button.addEventListener('click', () => navigate(button.dataset.go)));
$('#refresh').addEventListener('click', () => load(true));
$('#mobile-menu').addEventListener('click', () => document.body.classList.toggle('menu-open'));
$('#scrim').addEventListener('click', () => { document.body.classList.remove('menu-open'); closeDrawer(); });
$('#close-drawer').addEventListener('click', closeDrawer);
$('#device-search').addEventListener('input', renderDevices);
$('#device-filter').addEventListener('change', renderDevices);
$('#network-filter').addEventListener('change', renderNetwork);
$('#network-reset').addEventListener('click', () => { $('#network-filter').value = 'all'; renderNetwork(); });
$('#alert-scope').addEventListener('change', renderAlerts);
$('#alert-filter').addEventListener('change', renderAlerts);
$('#trace-filter').addEventListener('change', renderTraces);
$('#new-override').addEventListener('click', openOverrideDialog);
$('#override-form').addEventListener('submit', submitOverride);
window.addEventListener('hashchange', () => navigate(location.hash.slice(1), false));

navigate(location.hash.slice(1) || 'overview', false);
updateClock();
setInterval(updateClock, 1000);
load();
setInterval(() => load(false), 30000);
