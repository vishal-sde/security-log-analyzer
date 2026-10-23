const SEVERITY_ORDER = ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'];

const ACTIONS = {
  OPEN: [['Acknowledge', 'ACKNOWLEDGED'], ['Investigate', 'INVESTIGATING'], ['Resolve', 'RESOLVED'], ['False positive', 'FALSE_POSITIVE']],
  ACKNOWLEDGED: [['Investigate', 'INVESTIGATING'], ['Resolve', 'RESOLVED'], ['False positive', 'FALSE_POSITIVE']],
  INVESTIGATING: [['Resolve', 'RESOLVED'], ['False positive', 'FALSE_POSITIVE']],
  RESOLVED: [],
  FALSE_POSITIVE: []
};

const esc = s => String(s ?? '').replace(/[&<>"']/g, c =>
  ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));

async function fetchJson(url, options) {
  const res = await fetch(url, options);
  if (!res.ok) throw new Error(url + ' -> ' + res.status);
  return res.json();
}

function renderStatStrip(eventStats, alertStats) {
  const cells = [
    { label: 'Total events', value: eventStats.totalEvents, cls: '' },
    { label: 'Open incidents', value: alertStats.activeAlerts, cls: '' },
    ...SEVERITY_ORDER.map(s => ({ label: s, value: alertStats.bySeverity[s] ?? 0, cls: 'sev-' + s }))
  ];
  document.getElementById('statStrip').innerHTML = cells.map(c => `
    <div class="stat-cell">
      <div class="stat-value ${c.cls}">${c.value}</div>
      <div class="stat-label">${c.label}</div>
    </div>`).join('');
}

function renderTimeline(alerts) {
  const el = document.getElementById('timelineStrip');
  if (alerts.length === 0) {
    el.innerHTML = '<div class="timeline-empty">No activity yet.</div>';
    return;
  }
  const recent = [...alerts].reverse().slice(-60);
  el.innerHTML = recent.map(a => `
    <div class="timeline-blip sev-${esc(a.severity)}"
         title="${esc(a.severity)} · ${esc(a.ruleTriggered)} · ${esc(a.ip)} · ${a.occurrenceCount} hits"></div>`).join('');
}

function actionCell(a) {
  const options = ACTIONS[a.status] || [];
  if (options.length === 0) return '<span class="hits">—</span>';
  return `<select class="action-select" data-id="${a.id}" aria-label="Update incident ${a.id}">
      <option value="">Update…</option>
      ${options.map(([label, value]) => `<option value="${value}">${label}</option>`).join('')}
    </select>`;
}

function renderAlerts(alerts) {
  document.getElementById('alertCount').textContent = alerts.length + ' shown';
  const body = document.getElementById('alertsBody');

  if (alerts.length === 0) {
    body.innerHTML = `
      <tr><td colspan="9">
        <div class="empty-state">
          <strong>No incidents.</strong> Click "Run attack scenario" above to seed a live attack
          and watch detection happen in real time.
        </div>
      </td></tr>`;
    return;
  }

  body.innerHTML = alerts.map(a => `
    <tr>
      <td>${new Date(a.lastSeenAt).toLocaleTimeString()}</td>
      <td>${esc(a.ip)}</td>
      <td>${esc(a.username)}</td>
      <td>${a.ruleTriggered.split(',').map(esc).join(', ')}</td>
      <td class="hits">×${a.occurrenceCount}</td>
      <td>${a.riskScore}</td>
      <td><span class="badge badge-${esc(a.severity)}">${esc(a.severity)}</span></td>
      <td><span class="status-tag status-${esc(a.status)}">${esc(a.status.replace('_', ' '))}</span></td>
      <td>${actionCell(a)}</td>
    </tr>`).join('');
}

function renderTopIps(alerts) {
  const el = document.getElementById('topIps');
  if (alerts.length === 0) {
    el.innerHTML = '<div class="ip-empty">Nothing to rank yet.</div>';
    return;
  }
  const counts = {};
  for (const a of alerts) counts[a.ip] = (counts[a.ip] || 0) + a.occurrenceCount;
  const ranked = Object.entries(counts).sort((a, b) => b[1] - a[1]).slice(0, 6);
  const max = ranked[0][1];

  el.innerHTML = ranked.map(([ip, count]) => `
    <div class="ip-row">
      <div class="ip-row-top">
        <span class="ip-address">${esc(ip)}</span>
        <span class="ip-count">${count} hits</span>
      </div>
      <div class="ip-bar-track"><div class="ip-bar-fill" style="width:${(count / max) * 100}%"></div></div>
    </div>`).join('');
}

async function refresh() {
  try {
    const filter = document.getElementById('statusFilter').value;
    const url = '/api/alerts?limit=50' + (filter === 'active' ? '&activeOnly=true' : '');
    const [eventStats, alertStats, alerts] = await Promise.all([
      fetchJson('/api/events/stats'),
      fetchJson('/api/alerts/stats'),
      fetchJson(url)
    ]);
    renderStatStrip(eventStats, alertStats);
    renderTimeline(alerts);
    renderTopIps(alerts);

    // Don't rebuild the table while an analyst has an action menu open.
    if (!document.activeElement?.classList.contains('action-select')) {
      renderAlerts(alerts);
    }
    document.getElementById('lastUpdated').textContent =
      'Last updated ' + new Date().toLocaleTimeString();
  } catch (e) {
    document.getElementById('lastUpdated').textContent = 'Error refreshing: ' + e.message;
  }
}

document.getElementById('alertsBody').addEventListener('change', async (ev) => {
  const select = ev.target.closest('.action-select');
  if (!select || !select.value) return;
  try {
    await fetchJson(`/api/alerts/${select.dataset.id}/status`, {
      method: 'PATCH',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ status: select.value })
    });
  } catch (e) {
    document.getElementById('lastUpdated').textContent = 'Update failed: ' + e.message;
  }
  select.blur();
  refresh();
});

document.getElementById('statusFilter').addEventListener('change', refresh);

document.getElementById('seedBtn').addEventListener('click', async () => {
  const btn = document.getElementById('seedBtn');
  btn.disabled = true;
  btn.textContent = 'Seeding…';
  try {
    await fetchJson('/api/demo/seed', { method: 'POST' });
    await refresh();
  } finally {
    btn.disabled = false;
    btn.textContent = 'Run attack scenario';
  }
});

refresh();
setInterval(refresh, 5000);