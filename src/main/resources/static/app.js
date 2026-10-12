const SEVERITY_ORDER = ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'];

async function fetchJson(url, options) {
  const res = await fetch(url, options);
  if (!res.ok) throw new Error(url + ' -> ' + res.status);
  return res.json();
}

function renderStatStrip(eventStats, alertStats) {
  const cells = [
    { label: 'Total events', value: eventStats.totalEvents, cls: '' },
    { label: 'Total alerts', value: alertStats.totalAlerts, cls: '' },
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
    <div class="timeline-blip sev-${a.severity}"
         title="${a.severity} · ${a.ruleTriggered} · ${a.ip} · ${new Date(a.createdAt).toLocaleTimeString()}">
    </div>`).join('');
}

function renderAlerts(alerts) {
  document.getElementById('alertCount').textContent = alerts.length + ' shown';
  const body = document.getElementById('alertsBody');

  if (alerts.length === 0) {
    body.innerHTML = `
      <tr><td colspan="6">
        <div class="empty-state">
          <strong>No signal yet.</strong> Click "Run attack scenario" above to seed a live attack
          and watch detection happen in real time.
        </div>
      </td></tr>`;
    return;
  }

  body.innerHTML = alerts.map(a => `
    <tr>
      <td>${new Date(a.createdAt).toLocaleTimeString()}</td>
      <td>${a.ip}</td>
      <td>${a.username}</td>
      <td>${a.ruleTriggered}</td>
      <td>${a.riskScore}</td>
      <td><span class="badge badge-${a.severity}">${a.severity}</span></td>
    </tr>`).join('');
}

function renderTopIps(alerts) {
  const el = document.getElementById('topIps');
  if (alerts.length === 0) {
    el.innerHTML = '<div class="ip-empty">Nothing to rank yet.</div>';
    return;
  }

  const counts = {};
  for (const a of alerts) counts[a.ip] = (counts[a.ip] || 0) + 1;
  const ranked = Object.entries(counts).sort((a, b) => b[1] - a[1]).slice(0, 6);
  const max = ranked[0][1];

  el.innerHTML = ranked.map(([ip, count]) => `
    <div class="ip-row">
      <div class="ip-row-top">
        <span class="ip-address">${ip}</span>
        <span class="ip-count">${count}</span>
      </div>
      <div class="ip-bar-track">
        <div class="ip-bar-fill" style="width:${(count / max) * 100}%"></div>
      </div>
    </div>`).join('');
}

async function refresh() {
  try {
    const [eventStats, alertStats, alerts] = await Promise.all([
      fetchJson('/api/events/stats'),
      fetchJson('/api/alerts/stats'),
      fetchJson('/api/alerts?limit=50')
    ]);
    renderStatStrip(eventStats, alertStats);
    renderTimeline(alerts);
    renderAlerts(alerts);
    renderTopIps(alerts);
    document.getElementById('lastUpdated').textContent =
      'Last updated ' + new Date().toLocaleTimeString();
  } catch (e) {
    document.getElementById('lastUpdated').textContent = 'Error refreshing: ' + e.message;
  }
}

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