const $ = (id) => document.getElementById(id);
const state = { csrf: null, installations: [], selected: null, shieldLocked: false };

async function api(path, options = {}) {
  const response = await fetch(path, { ...options, headers: { 'Content-Type': 'application/json', ...(state.csrf ? { 'X-Sentinel-CSRF': state.csrf } : {}), ...(options.headers || {}) } });
  const payload = await response.json().catch(() => ({}));
  if (!response.ok) throw Object.assign(new Error(payload.error || `HTTP ${response.status}`), { status: response.status });
  return payload;
}

function fmtDate(value) { if (!value) return 'Never'; const date = new Date(value); return Number.isNaN(date.valueOf()) ? 'Unknown' : date.toLocaleString(); }
function escapeText(value) { return String(value || ''); }

function item(title, detail, severity = 'info') {
  const node = document.createElement('article'); node.className = 'item';
  const head = document.createElement('div'); head.className = 'item-head';
  const heading = document.createElement('h4'); heading.textContent = escapeText(title);
  const badge = document.createElement('span'); badge.className = `severity ${severity}`; badge.textContent = severity;
  const text = document.createElement('p'); text.textContent = escapeText(detail);
  head.append(heading, badge); node.append(head, text); return node;
}

function shieldIncidentItem(incident) {
  const node = item(incident.title, `${fmtDate(incident.last_seen_at)} · ${incident.evidence} Recommended: ${incident.recommended_action}`, incident.severity);
  const action = document.createElement('button'); action.className = 'button secondary incident-action'; action.textContent = 'Mark reviewed';
  action.addEventListener('click', async () => {
    const confirmation = window.prompt('Type ACKNOWLEDGE to mark this incident reviewed. This does not change GitHub settings.');
    if (confirmation !== 'ACKNOWLEDGE') return;
    action.disabled = true;
    try { await api(`/api/installations/${state.selected}/shield/incidents/${incident.id}/acknowledge`, { method: 'POST', body: JSON.stringify({ confirm: confirmation }) }); await loadInstallation(state.selected); }
    catch (error) { alert(error.message); action.disabled = false; }
  });
  node.append(action); return node;
}

async function loadPublic() {
  const status = await api('/api/public/status');
  $('monitoring').textContent = status.monitoring ? 'Active' : 'Setup required';
  $('metric-installations').textContent = status.installations ?? 'Private';
  $('metric-repositories').textContent = status.repositories ?? 'Private';
  $('metric-urgent').textContent = status.urgent_findings ?? 'Private';
  $('last-event').textContent = status.last_event_at ? `Last event ${fmtDate(status.last_event_at)}` : 'Waiting for the first signed webhook.';
}

async function loadSession() {
  try {
    const me = await api('/api/me'); state.csrf = me.csrf;
    $('identity').textContent = `@${me.user.login}`; $('login').classList.add('hidden'); $('logout').classList.remove('hidden'); $('dashboard').classList.remove('hidden');
    await loadInstallations();
  } catch (error) { if (error.status !== 401) console.error(error.message); }
}

async function loadInstallations() {
  const payload = await api('/api/installations'); state.installations = payload.installations;
  const select = $('installation-select'); select.replaceChildren();
  for (const installation of state.installations) { const option = document.createElement('option'); option.value = installation.id; option.textContent = `${installation.account_login} (${installation.account_type})`; select.append(option); }
  if (!state.installations.length) { const option = document.createElement('option'); option.textContent = 'Install the GitHub App first'; select.append(option); return; }
  state.selected = Number(select.value || state.installations[0].id); await loadInstallation(state.selected);
}

async function loadInstallation(id) {
  const data = await api(`/api/installations/${id}`); state.selected = Number(id);
  state.shieldLocked = data.shield.locked;
  $('account-name').textContent = data.installation.account_login; $('pause').textContent = data.installation.paused ? 'Resume monitoring' : 'Pause monitoring';
  $('shield-state').textContent = data.shield.locked ? 'GUARDIAN LOCKED' : data.shield.level === 'clear' ? 'CLEAR' : data.shield.level.toUpperCase();
  $('shield-state').className = `shield-state ${data.shield.level}`;
  $('shield-meta').textContent = data.shield.locked ? 'Sentinel cannot write to GitHub. Monitoring and evidence collection remain active.' : `${data.shield.openIncidents} open incident${data.shield.openIncidents === 1 ? '' : 's'} · highest score ${data.shield.highestScore}/100`;
  $('shield-lock').textContent = data.shield.locked ? 'Release Guardian Lock' : 'Engage Guardian Lock';
  $('scan-meta').textContent = `Last scan: ${fmtDate(data.installation.last_scan_at)} · ${data.repositories.length} repositories`;
  $('summary').textContent = data.summary?.summary || 'No completed scan yet.'; $('finding-count').textContent = data.findings.length;
  const findings = $('findings'); findings.replaceChildren(); findings.classList.toggle('empty', !data.findings.length);
  if (!data.findings.length) findings.textContent = 'No open findings.'; else for (const finding of data.findings) findings.append(item(finding.title, `${finding.full_name || 'Installation'} · ${finding.evidence}`, finding.severity));
  const events = $('events'); events.replaceChildren(); events.classList.toggle('empty', !data.events.length);
  if (!data.events.length) events.textContent = 'No events received.'; else for (const event of data.events.slice(0, 50)) events.append(item(event.title, `${fmtDate(event.received_at)} · ${event.detail}`, event.risk));
  const incidents = $('shield-incidents'); incidents.replaceChildren(); incidents.classList.toggle('empty', !data.shield.incidents.length);
  if (!data.shield.incidents.length) incidents.textContent = 'No open Shield incidents.'; else for (const incident of data.shield.incidents) incidents.append(shieldIncidentItem(incident));
}

$('installation-select').addEventListener('change', (event) => loadInstallation(Number(event.target.value)).catch((error) => alert(error.message)));
$('scan').addEventListener('click', async () => { if (!state.selected) return; $('scan').disabled = true; try { await api(`/api/installations/${state.selected}/scan`, { method: 'POST', body: '{}' }); $('scan-meta').textContent = 'Scan queued. New results will appear shortly.'; setTimeout(() => loadInstallation(state.selected), 4000); } catch (error) { alert(error.message); } finally { $('scan').disabled = false; } });
$('pause').addEventListener('click', async () => { if (!state.selected) return; const selected = state.installations.find((item) => item.id === state.selected); const action = selected?.paused ? 'resume' : 'pause'; try { await api(`/api/installations/${state.selected}/${action}`, { method: 'POST', body: '{}' }); selected.paused = action === 'pause' ? 1 : 0; await loadInstallation(state.selected); } catch (error) { alert(error.message); } });
$('shield-lock').addEventListener('click', async () => {
  if (!state.selected) return;
  const action = state.shieldLocked ? 'unlock' : 'lock'; const expected = action === 'lock' ? 'LOCK' : 'UNLOCK';
  const confirmation = window.prompt(`Type ${expected} to ${action === 'lock' ? 'block Sentinel outbound GitHub writes' : 'release Guardian Lock'}. Monitoring continues either way.`);
  if (confirmation !== expected) return;
  $('shield-lock').disabled = true;
  try { await api(`/api/installations/${state.selected}/shield/${action}`, { method: 'POST', body: JSON.stringify({ confirm: confirmation }) }); await loadInstallation(state.selected); }
  catch (error) { alert(error.message); } finally { $('shield-lock').disabled = false; }
});
$('logout').addEventListener('click', async () => { try { await api('/api/logout', { method: 'POST', body: '{}' }); location.reload(); } catch (error) { alert(error.message); } });

loadPublic().catch((error) => { $('monitoring').textContent = 'Unavailable'; console.error(error.message); });
loadSession();
if ('serviceWorker' in navigator) navigator.serviceWorker.register('/sw.js').catch(() => {});
