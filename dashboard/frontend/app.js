const fmt = value => value == null ? "—" : `${Number(value).toFixed(3)} s`;
const time = value => value == null ? "—" : new Date(Number(value) * 1000).toISOString();
const esc = value => String(value).replace(/[&<>"']/g, char => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[char]));

async function load() {
  const [statusResponse, tracesResponse] = await Promise.all([
    fetch('/api/status', {cache: 'no-store'}),
    fetch('/api/traces?limit=1000', {cache: 'no-store'})
  ]);
  const status = await statusResponse.json();
  const traces = (await tracesResponse.json()).traces || [];
  const safety = document.querySelector('#safety');
  safety.textContent = status.automatic_enforcement_enabled ? 'ENFORCEMENT ENABLED' : `${status.observation_kind} / ${status.decision_mode}`;
  safety.className = `badge ${status.automatic_enforcement_enabled ? 'danger' : 'safe'}`;
  const finalizer = status.finalizer || {};
  document.querySelector('#summary').innerHTML = [
    ['Inventory', status.inventory_version],
    ['Queue depth', finalizer.queue_depth ?? '—'],
    ['Oldest pending', fmt(finalizer.oldest_pending_age_seconds)],
    ['Last accepted', time(finalizer.last_accepted_window)],
    ['Open joins', finalizer.coordinator?.open_observations ?? '—'],
    ['Late branches', finalizer.coordinator?.late_branches ?? '—']
  ].map(([label, value]) => `<article><span>${esc(label)}</span><strong>${esc(value)}</strong></article>`).join('');
  document.querySelector('#traces').innerHTML = traces.map(trace => `<tr>
    <td><code>${time(trace.window_start)}</code></td>
    <td>${esc(trace.observation_kind || 'unknown')}</td>
    <td>${esc(trace.event_kinds.join(' → '))}</td>
    <td>${fmt(trace.latency_seconds.window_close_to_join)}</td>
    <td>${fmt(trace.latency_seconds.join_to_decision)}</td>
    <td>${fmt(trace.latency_seconds.decision_to_install)}</td>
  </tr>`).join('') || '<tr><td colspan="6">No trace events recorded.</td></tr>';
}

document.querySelector('#refresh').addEventListener('click', load);
load().catch(error => {
  document.querySelector('#safety').textContent = `Dashboard error: ${error.message}`;
});
