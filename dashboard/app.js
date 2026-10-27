/**
 * AIDDS Mission Control Dashboard
 * Enterprise Security Gateway — Mission Control Application Logic
 * Real-time SSE telemetry, interactive simulation & forensic analysis.
 */

// Application State
const state = {
  agents: {},
  events: [],
  alerts: [],
  selectedAlertId: null,
  evalMetrics: null,
  activeTab: 'live-monitor',
  sseConnected: false,
};


// ---------------------------------------------------------------------------
// Authenticated fetch (analyst key kept in sessionStorage; prompted on 401)
// ---------------------------------------------------------------------------

function getKey() {
  try { return sessionStorage.getItem('aidds_key') || ''; } catch (e) { return ''; }
}

async function api(url, opts = {}) {
  const headers = Object.assign({}, opts.headers || {});
  const k = getKey();
  if (k) { headers['X-API-Key'] = k; headers['X-Gateway-Key'] = k; }
  let res = await fetch(url, Object.assign({}, opts, { headers }));
  if (res.status === 401) {
    const entered = window.prompt('This gateway requires an analyst API key (AIDDS_ANALYST_API_KEY):');
    if (entered) {
      try { sessionStorage.setItem('aidds_key', entered); } catch (e) { /* ignore */ }
      headers['X-API-Key'] = entered;
      res = await fetch(url, Object.assign({}, opts, { headers }));
    }
  }
  return res;
}

// ---------------------------------------------------------------------------
// Initialization
// ---------------------------------------------------------------------------

document.addEventListener('DOMContentLoaded', () => {
  setupNavigation();
  setupDemoButtons();
  setupEventSearch();
  setupModal();
  setupForensicFilters();

  // Initial Data Load
  refreshAll();

  // Start Real-Time SSE Stream
  connectSSE();

  // Polling fallback every 3.5s if SSE drops
  setInterval(() => {
    if (!state.sseConnected) {
      refreshAll();
    }
  }, 3500);
});

// ---------------------------------------------------------------------------
// Tab Navigation
// ---------------------------------------------------------------------------

function setupNavigation() {
  const tabs = document.querySelectorAll('.nav-tab-btn');
  tabs.forEach(tab => {
    tab.addEventListener('click', () => {
      const tabId = tab.dataset.tab;
      switchTab(tabId);
    });
  });
}

function switchTab(tabId) {
  state.activeTab = tabId;
  document.querySelectorAll('.nav-tab-btn').forEach(t => {
    t.classList.toggle('active', t.dataset.tab === tabId);
  });
  document.querySelectorAll('.tab-pane').forEach(p => {
    p.classList.toggle('active', p.id === `pane-${tabId}`);
  });

  if (tabId === 'quality-gates' && !state.evalMetrics) {
    fetchMetrics();
  } else if (tabId === 'alerts-view') {
    renderForensicList();
  }
}

// ---------------------------------------------------------------------------
// API Calls & Data Fetching
// ---------------------------------------------------------------------------

async function refreshAll() {
  await Promise.all([
    fetchAgents(),
    fetchAlerts(),
    fetchEvents(),
    fetchMetrics(),
    fetchLatency(),
  ]);
}

async function fetchAgents() {
  try {
    const res = await api('/v1/agents');
    if (!res.ok) return;
    const data = await res.json();
    data.forEach(a => {
      state.agents[a.agent_id] = a;
    });
    renderAgentCards();
    updateTelemetry();
  } catch (err) {
    console.error('fetchAgents error:', err);
  }
}

async function fetchAlerts() {
  try {
    const res = await api('/v1/alerts');
    if (!res.ok) return;
    state.alerts = await res.json();
    renderAlertsList();
    renderForensicList();
    updateTelemetry();
  } catch (err) {
    console.error('fetchAlerts error:', err);
  }
}

async function fetchEvents() {
  try {
    const res = await api('/v1/events?limit=50');
    if (!res.ok) return;
    const data = await res.json();
    state.events = data.events || [];
    renderEventTable();
    updateTelemetry();
  } catch (err) {
    console.error('fetchEvents error:', err);
  }
}

async function fetchLatency() {
  try {
    const res = await api('/v1/metrics/latency');
    if (!res.ok) return;
    const m = await res.json();
    const el = document.getElementById('stat-latency');
    if (el) el.textContent = m.count ? `${m.total_p95_ms.toFixed(1)} ms` : '—';
    const st = document.getElementById('stream-status-text');
    if (st && state.sseConnected && m.count) st.textContent = `Gateway Online (p95 ${m.total_p95_ms.toFixed(1)} ms, n=${m.count})`;
  } catch (err) { console.error('fetchLatency error:', err); }
}

async function fetchMetrics() {
  try {
    const res = await api('/v1/eval/metrics');
    if (!res.ok) return;
    state.evalMetrics = await res.json();
    renderQualityGates();
  } catch (err) {
    console.error('fetchMetrics error:', err);
  }
}

// ---------------------------------------------------------------------------
// Real-Time Server-Sent Events (SSE)
// ---------------------------------------------------------------------------

function connectSSE() {
  const statusEl = document.getElementById('stream-status-text');
  try {
    const es = new EventSource('/v1/events/stream' + (getKey() ? '?key=' + encodeURIComponent(getKey()) : ''));

    es.onopen = () => {
      state.sseConnected = true;
      if (statusEl) statusEl.textContent = 'Gateway Online';
      fetchLatency();
    };

    es.addEventListener('update', (e) => {
      try {
        const payload = JSON.parse(e.data);
        handleStreamUpdate(payload);
      } catch (err) {
        console.error('Error parsing SSE event:', err);
      }
    });

    es.onerror = () => {
      state.sseConnected = false;
      if (statusEl) statusEl.textContent = 'Reconnecting Stream...';
    };
  } catch (err) {
    console.warn('SSE not supported or failed to connect:', err);
  }
}

function handleStreamUpdate(payload) {
  if (payload.type === 'event') {
    const evt = payload.event;
    const dec = payload.decision;

    // Add event to table
    const item = {
      event_id: evt.event_id,
      ts: evt.ts,
      agent_id: evt.agent_id,
      role: evt.role,
      session_id: evt.session_id,
      tool: evt.tool,
      action: evt.action,
      resource: evt.resource,
      data_class: evt.data_class,
      sensitivity: evt.sensitivity,
      destination: evt.destination,
      bytes_out: evt.bytes_out,
      decision: dec.decision,
      score: dec.score,
      tier: dec.tier,
      payload: evt,
      alert_id: dec.alert_id,
    };
    state.events.unshift(item);
    if (state.events.length > 100) state.events.pop();
    renderEventTable();

    // Update agent state
    if (!state.agents[evt.agent_id]) {
      state.agents[evt.agent_id] = {
        agent_id: evt.agent_id,
        role: evt.role,
        score: dec.score,
        tier: dec.tier,
        status: dec.tier === 'isolate' ? 'isolated' : dec.tier === 'restrict' ? 'restricted' : 'healthy',
        event_count: 1,
        is_tainted: evt.taint && evt.taint.length > 0,
      };
    } else {
      const a = state.agents[evt.agent_id];
      a.event_count = (a.event_count || 0) + 1;
      if (evt.taint && evt.taint.length > 0) a.is_tainted = true;
      if (a.status !== 'isolated') {
        a.score = dec.score;
        a.tier = dec.tier;
        if (dec.tier === 'isolate') a.status = 'isolated';
        else if (dec.tier === 'restrict') a.status = 'restricted';
        else if (dec.tier === 'step_up') a.status = 'step_up';
      } else {
        a.score = Math.max(a.score, dec.score);
      }
    }
    renderAgentCards();

    // Trigger toast for high-risk containment events
    if (dec.score >= 90) {
      showToast(`🚨 KILL CHAIN DETECTED: Agent ${evt.agent_id} isolated (${dec.score}/100)`, 'danger');
    } else if (dec.score >= 70) {
      showToast(`⚠️ DRIFT DETECTED: ${evt.agent_id} restricted. Role scope violation.`, 'warning');
    } else if (evt.taint && evt.taint.length > 0 && evt.resource && evt.resource.includes('invoice.pdf')) {
      showToast(`🔍 Context Taint Attached: Untrusted PDF read by ${evt.agent_id}`, 'info');
    }

    fetchAlerts();
    updateTelemetry();
  } else if (payload.type === 'demo_reset') {
    showToast('Demo state reset. Agents restored to baseline.', 'info');
    refreshAll();
  } else if (payload.type === 'agent_released') {
    showToast(`Agent ${payload.agent_id} released from quarantine.`, 'success');
    refreshAll();
  } else if (payload.type === 'alert_feedback') {
    showToast(`Analyst feedback recorded for ${payload.alert_id}`, 'info');
    fetchAlerts();
  }
}

// ---------------------------------------------------------------------------
// Render Agent Cards & Risk Meters
// ---------------------------------------------------------------------------

function renderAgentCards() {
  renderAgent('procurement-bot-04', 'procurement');
  renderAgent('support-bot-02', 'support');
}

function renderAgent(agentId, prefix) {
  const agent = state.agents[agentId] || {
    agent_id: agentId,
    score: 0,
    tier: 'observe',
    status: 'healthy',
    event_count: 0,
    is_tainted: false,
  };

  const scoreEl = document.getElementById(`score-${prefix}`);
  const fillEl = document.getElementById(`meter-fill-${prefix}`);
  const tierEl = document.getElementById(`tier-${prefix}`);
  const statusBadge = document.getElementById(`status-badge-${prefix}`);
  const taintEl = document.getElementById(`taint-${prefix}`);
  const eventsEl = document.getElementById(`events-${prefix}`);
  const enforceEl = document.getElementById(`enforce-${prefix}`);
  const releaseBtn = document.getElementById(`btn-release-${prefix}`);

  const score = agent.score || 0;
  if (scoreEl) scoreEl.textContent = score;

  // Horizontal Meter Bar Width & Color
  if (fillEl) {
    fillEl.style.width = `${Math.min(100, score)}%`;

    if (score >= 90) {
      fillEl.style.backgroundColor = 'var(--rose-600)';
      if (scoreEl) scoreEl.style.color = 'var(--rose-600)';
    } else if (score >= 70) {
      fillEl.style.backgroundColor = 'var(--orange-600)';
      if (scoreEl) scoreEl.style.color = 'var(--orange-600)';
    } else if (score >= 40) {
      fillEl.style.backgroundColor = 'var(--amber-600)';
      if (scoreEl) scoreEl.style.color = 'var(--amber-600)';
    } else {
      fillEl.style.backgroundColor = 'var(--emerald-600)';
      if (scoreEl) scoreEl.style.color = 'var(--text-main)';
    }
  }

  // Tier Badge
  if (tierEl) {
    const tier = (agent.tier || 'observe').toLowerCase().replace('tier.', '');
    tierEl.textContent = tier.charAt(0).toUpperCase() + tier.slice(1);
    tierEl.className = `tier-pill tier-${tier}`;
  }

  // Status Badge
  if (statusBadge) {
    if (agent.status === 'isolated') {
      statusBadge.textContent = 'Quarantined';
      statusBadge.className = 'status-pill status-isolated';
    } else if (agent.status === 'restricted') {
      statusBadge.textContent = 'Restricted';
      statusBadge.className = 'status-pill status-restricted';
    } else {
      statusBadge.textContent = 'Healthy';
      statusBadge.className = 'status-pill status-healthy';
    }
  }

  // Taint Tag
  if (taintEl) {
    if (agent.is_tainted) {
      taintEl.innerHTML = '<span class="badge-tainted">Tainted (PDF)</span>';
    } else {
      taintEl.innerHTML = '<span class="taint-tag-clean">Clean</span>';
    }
  }

  // Total Events
  if (eventsEl) {
    eventsEl.textContent = agent.event_count || 0;
  }

  // Enforcement text & release button
  if (enforceEl) {
    if (agent.status === 'isolated') {
      enforceEl.textContent = 'Quarantined — All tool calls blocked';
      enforceEl.style.color = 'var(--rose-600)';
      if (releaseBtn) {
        releaseBtn.style.display = 'inline-flex';
        releaseBtn.onclick = () => releaseAgent(agentId);
      }
    } else if (agent.status === 'restricted') {
      enforceEl.textContent = 'Restricted — Sensitive scopes revoked';
      enforceEl.style.color = 'var(--orange-600)';
      if (releaseBtn) {
        releaseBtn.style.display = 'inline-flex';
        releaseBtn.onclick = () => releaseAgent(agentId);
      }
    } else {
      enforceEl.textContent = prefix === 'procurement' ? 'Standard Role Scopes Active' : 'Workflows Operating Normally (Zero Impact)';
      enforceEl.style.color = prefix === 'support' ? 'var(--emerald-600)' : 'var(--text-secondary)';
      if (releaseBtn) releaseBtn.style.display = 'none';
    }
  }
}

// ---------------------------------------------------------------------------
// Render Live Event Table
// ---------------------------------------------------------------------------

function renderEventTable() {
  const tbody = document.getElementById('events-table-body');
  if (!tbody) return;

  const filterText = (document.getElementById('event-search-input')?.value || '').toLowerCase();

  const filtered = state.events.filter(e => {
    if (!filterText) return true;
    return (
      (e.tool || '').toLowerCase().includes(filterText) ||
      (e.agent_id || '').toLowerCase().includes(filterText) ||
      (e.resource || '').toLowerCase().includes(filterText) ||
      (e.data_class || '').toLowerCase().includes(filterText)
    );
  });

  if (filtered.length === 0) {
    tbody.innerHTML = `
      <tr class="empty-row">
        <td colspan="10">No tool call events matching filter. Run a scenario above.</td>
      </tr>
    `;
    return;
  }

  tbody.innerHTML = filtered.slice(0, 35).map(e => {
    const isTainted = (e.payload && e.payload.taint && e.payload.taint.length > 0);
    const score = e.score !== null && e.score !== undefined ? e.score : 0;
    const tier = (e.tier || 'observe').toLowerCase().replace('tier.', '');
    const decision = (e.decision || 'allow').toUpperCase();

    let rowClass = '';
    if (tier === 'isolate') rowClass = 'event-row-isolate';
    else if (tier === 'restrict') rowClass = 'event-row-restrict';
    else if (tier === 'step_up') rowClass = 'event-row-stepup';

    let decisionBadge = 'badge-healthy';
    if (decision === 'DENY') decisionBadge = 'badge-danger';
    else if (decision === 'RESTRICT') decisionBadge = 'badge-restricted';
    else if (decision === 'STEP_UP') decisionBadge = 'badge-warning';

    const timeStr = e.ts ? new Date(e.ts).toLocaleTimeString() : '--:--:--';

    return `
      <tr class="${rowClass}">
        <td class="mono text-muted">${timeStr}</td>
        <td class="mono"><strong>${escapeHtml(e.agent_id)}</strong></td>
        <td>
          <span class="mono text-main font-600">${escapeHtml(e.tool)}</span>
          <span class="badge-outline" style="margin-left:4px;">${escapeHtml(e.action || 'read')}</span>
        </td>
        <td class="mono text-secondary" style="max-width:180px; overflow:hidden; text-overflow:ellipsis; white-space:nowrap;" title="${escapeHtml(e.resource)}">
          ${escapeHtml(e.resource)}
        </td>
        <td><span class="badge-neutral">${escapeHtml(e.data_class)}</span></td>
        <td>${isTainted ? '<span class="badge-tainted">Tainted</span>' : '<span class="text-muted">—</span>'}</td>
        <td class="mono"><strong>${score}</strong></td>
        <td><span class="tier-pill tier-${tier}">${tier.charAt(0).toUpperCase() + tier.slice(1)}</span></td>
        <td><span class="${decisionBadge}">${decision}</span></td>
        <td>
          <button class="btn btn-xs btn-secondary" onclick="inspectEvent('${e.event_id}')">
            Inspect
          </button>
        </td>
      </tr>
    `;
  }).join('');
}

// ---------------------------------------------------------------------------
// Render Alerts Feed
// ---------------------------------------------------------------------------

function renderAlertsList() {
  const container = document.getElementById('alerts-container');
  const countBadge = document.getElementById('active-alerts-badge');
  const navBadge = document.getElementById('nav-alert-count');
  if (!container) return;

  const count = state.alerts.length;
  if (countBadge) countBadge.textContent = `${count} Open`;
  if (navBadge) navBadge.textContent = count;

  if (count === 0) {
    container.innerHTML = `
      <div class="empty-alerts">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5">
          <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
        </svg>
        <p>No active drift incidents detected. All running agents comply strictly with signed role manifests.</p>
      </div>
    `;
    return;
  }

  container.innerHTML = state.alerts.slice(0, 10).map(a => {
    const reasons = a.reasons || [];
    const topReason = reasons[0] ? reasons[0].text || reasons[0].signal : 'Role or Manifest violation';
    const tier = (a.tier || 'isolate').toLowerCase().replace('tier.', '');

    let tierClass = 'alert-item-isolate';
    if (tier === 'restrict') tierClass = 'alert-item-restrict';
    else if (tier === 'step_up') tierClass = 'alert-item-stepup';

    return `
      <div class="alert-item-card ${tierClass}" onclick="selectAlert('${a.alert_id}')">
        <div class="alert-top">
          <span class="alert-id">${a.alert_id}</span>
          <span class="tier-pill tier-${tier}">${tier.toUpperCase()} (${a.score}/100)</span>
        </div>
        <div class="alert-agent-line">${escapeHtml(a.agent_id)} &bull; ${escapeHtml(a.tool)}</div>
        <div class="alert-summary">${escapeHtml(topReason)}</div>
        <div class="alert-actions-row">
          <button class="btn btn-xs btn-danger" onclick="event.stopPropagation(); alertFeedback('${a.alert_id}', 'confirmed')">
            Confirm Threat
          </button>
          <button class="btn btn-xs btn-secondary" onclick="event.stopPropagation(); alertFeedback('${a.alert_id}', 'false_alarm')">
            False Alarm
          </button>
        </div>
      </div>
    `;
  }).join('');
}

// ---------------------------------------------------------------------------
// Forensics View
// ---------------------------------------------------------------------------

function renderForensicList() {
  const container = document.getElementById('forensic-alerts-list');
  if (!container) return;

  const tierFilter = document.getElementById('alert-filter-tier')?.value;
  const filtered = state.alerts.filter(a => {
    if (!tierFilter) return true;
    const t = (a.tier || '').toLowerCase().replace('tier.', '');
    return t === tierFilter;
  });

  if (filtered.length === 0) {
    container.innerHTML = '<p class="text-muted" style="padding:20px;">No incidents match the selected criteria.</p>';
    return;
  }

  container.innerHTML = filtered.map(a => {
    const tier = (a.tier || '').toLowerCase().replace('tier.', '');
    return `
      <div class="alert-item-card ${state.selectedAlertId === a.alert_id ? 'active' : ''}" onclick="selectAlert('${a.alert_id}')">
        <div class="alert-top">
          <span class="alert-id">${a.alert_id}</span>
          <span class="tier-pill tier-${tier}">${tier.toUpperCase()}</span>
        </div>
        <div class="alert-agent-line">${escapeHtml(a.agent_id)} &bull; ${escapeHtml(a.resource)}</div>
        <div class="meta-row" style="margin-top:4px;">
          <span class="text-muted">${a.ts ? new Date(a.ts).toLocaleTimeString() : ''}</span>
          <span class="${a.feedback === 'confirmed' ? 'badge-danger' : a.feedback === 'false_alarm' ? 'badge-healthy' : 'badge-outline'}">
            ${a.feedback || 'unreviewed'}
          </span>
        </div>
      </div>
    `;
  }).join('');

  if (!state.selectedAlertId && filtered.length > 0) {
    selectAlert(filtered[0].alert_id);
  }
}

function selectAlert(alertId) {
  state.selectedAlertId = alertId;
  const alertObj = state.alerts.find(a => a.alert_id === alertId);
  const detailEl = document.getElementById('forensic-detail-view');
  if (!detailEl || !alertObj) return;

  const reasons = alertObj.reasons || [];
  const tier = (alertObj.tier || '').toLowerCase().replace('tier.', '');

  detailEl.innerHTML = `
    <div style="display:flex; justify-content:space-between; align-items:flex-start; margin-bottom:14px; padding-bottom:12px; border-bottom:1px solid var(--border-light);">
      <div>
        <h3 style="font-size:16px; font-weight:600; margin-bottom:2px;">Incident ${alertObj.alert_id}</h3>
        <span class="text-secondary" style="font-size:12px;">Agent: <strong>${escapeHtml(alertObj.agent_id)}</strong> (${escapeHtml(alertObj.role)})</span>
      </div>
      <div style="text-align:right;">
        <div class="tele-val text-rose" style="font-size:26px;">${alertObj.score}/100</div>
        <span class="tier-pill tier-${tier}">${tier.toUpperCase()}</span>
      </div>
    </div>

    <div style="background:var(--bg-subtle); padding:12px 14px; border-radius:6px; border:1px solid var(--border-light); display:flex; flex-direction:column; gap:6px; font-size:12.5px;">
      <div class="meta-row"><strong>Resource Touched:</strong> <span class="mono text-main font-600">${escapeHtml(alertObj.resource)}</span></div>
      <div class="meta-row"><strong>Tool Invoked:</strong> <span class="mono">${escapeHtml(alertObj.tool)}</span></div>
      <div class="meta-row"><strong>Gateway Action:</strong> <span class="badge-danger">${alertObj.decision || 'DENY'}</span></div>
      <div class="meta-row"><strong>Timestamp:</strong> <span class="text-secondary">${alertObj.ts || ''}</span></div>
    </div>

    <div>
      <h4 style="font-size:13px; font-weight:600; margin: 16px 0 8px 0;">Contributing Signals Breakdown</h4>
      ${reasons.length > 0 ? reasons.map(r => `
        <div class="signal-breakdown-card">
          <div class="signal-header">
            <span class="signal-name">${escapeHtml(r.signal)}</span>
            <span class="signal-points">+${r.points || 0} pts</span>
          </div>
          <div class="signal-desc">${escapeHtml(r.text || '')}</div>
        </div>
      `).join('') : '<p class="text-muted">No individual signal breakdown available.</p>'}
    </div>

    <div style="display:flex; gap:8px; margin-top:auto; padding-top:16px; border-top:1px solid var(--border-light); flex-wrap:wrap;">
      <button class="btn btn-danger" onclick="alertFeedback('${alertObj.alert_id}', 'confirmed')">
        ✓ Confirm Malicious Threat
      </button>
      <button class="btn btn-secondary" onclick="alertFeedback('${alertObj.alert_id}', 'false_alarm')">
        ✗ Mark False Positive
      </button>
      <button class="btn btn-primary" onclick="releaseAgent('${alertObj.agent_id}')">
        Lift Agent Containment
      </button>
    </div>
  `;
}

// ---------------------------------------------------------------------------
// Quality Gates Table
// ---------------------------------------------------------------------------

function renderQualityGates() {
  if (!state.evalMetrics) return;

  if (state.evalMetrics.status && state.evalMetrics.status !== 'ok') {
    const msg = state.evalMetrics.hint || 'Evaluation report not available';
    ['gate-recall', 'gate-fpr', 'gate-ttd'].forEach(id => { const e = document.getElementById(id); if (e) e.textContent = '—'; });
    const t = document.getElementById('scenarios-matrix-body');
    if (t) t.innerHTML = `<tr><td colspan="8">${escapeHtml(msg)}</td></tr>`;
    return;
  }
  const results = state.evalMetrics.results || {};
  renderHeldout(state.evalMetrics.heldout);
  const recallEl = document.getElementById('gate-recall');
  const fprEl = document.getElementById('gate-fpr');
  const ttdEl = document.getElementById('gate-ttd');
  const tbody = document.getElementById('scenarios-matrix-body');

  if (recallEl && results.recall !== undefined) {
    recallEl.textContent = `${results.recall.toFixed(3)} (${(results.recall * 100).toFixed(1)}%)`;
  }
  if (fprEl && results.false_positive_rate !== undefined) {
    fprEl.textContent = `${results.false_positive_rate.toFixed(3)} (${(results.false_positive_rate * 100).toFixed(1)}%)`;
  }
  if (ttdEl && results.avg_time_to_detect_events !== undefined) {
    ttdEl.textContent = `${results.avg_time_to_detect_events.toFixed(2)} events`;
  }

  const scenarios = state.evalMetrics.scenarios || [];
  if (tbody && scenarios.length > 0) {
    tbody.innerHTML = scenarios.map(s => {
      const isAttack = s.label === 'attack';
      const verdict = s.passed ? '<span class="badge-healthy">PASS</span>' : '<span class="badge-danger">FAIL</span>';
      return `
        <tr>
          <td class="mono"><strong>${escapeHtml(s.scenario_id || '')}</strong></td>
          <td>${escapeHtml(s.scenario_name || '')}</td>
          <td><span class="${isAttack ? 'badge-danger' : 'badge-neutral'}">${escapeHtml(s.label || '')}</span></td>
          <td class="mono">${escapeHtml(s.expected_tier || '')}</td>
          <td class="mono font-600">${s.max_score}</td>
          <td class="mono">${escapeHtml(s.max_tier || '')}</td>
          <td class="mono">${s.time_to_detect_events !== null ? s.time_to_detect_events : '—'}</td>
          <td>${verdict}</td>
        </tr>
      `;
    }).join('');
  }
}

// ---------------------------------------------------------------------------
// Telemetry Counter Updates
// ---------------------------------------------------------------------------

function renderHeldout(h) {
  const el = document.getElementById('heldout-body');
  if (!el) return;
  if (!h || !h.methods) { el.innerHTML = '<tr><td colspan="4">Run python -m eval.heldout to generate.</td></tr>'; return; }
  const rows = Object.entries(h.methods).map(([name, v]) =>
    `<tr><td class="mono">${escapeHtml(name)}</td><td class="mono">${v.recall.toFixed(3)} <span class="text-muted">(${v.recall_ci95[0]}–${v.recall_ci95[1]})</span></td><td class="mono">${v.session_fpr.toFixed(3)}</td><td class="mono">${v.mean_ttd_events ?? '—'}</td></tr>`);
  const per = Object.entries(h.methods.aidds.per_attack || {}).map(([k, v]) =>
    `<tr><td class="mono">&nbsp;&nbsp;↳ ${escapeHtml(k)}</td><td class="mono">${v.recall.toFixed(3)}</td><td></td><td></td></tr>`);
  el.innerHTML = rows.concat(per).join('');
}

function updateTelemetry() {
  const totalEventsEl = document.getElementById('stat-total-events');
  const alertsEl = document.getElementById('stat-active-alerts');
  const quarantinedEl = document.getElementById('stat-quarantined-agents');

  if (totalEventsEl) {
    const totalCalls = Object.values(state.agents).reduce((acc, a) => acc + (a.event_count || 0), 0);
    totalEventsEl.textContent = totalCalls || state.events.length;
  }
  if (alertsEl) {
    alertsEl.textContent = state.alerts.length;
  }
  if (quarantinedEl) {
    const quarantined = Object.values(state.agents).filter(a => a.status === 'isolated').length;
    quarantinedEl.textContent = quarantined;
  }
}

// ---------------------------------------------------------------------------
// Demo Simulation & Orchestrator
// ---------------------------------------------------------------------------

function setupDemoButtons() {
  document.getElementById('btn-run-injection')?.addEventListener('click', () => {
    runScenario('procurement_injection');
  });

  document.getElementById('btn-run-normal-proc')?.addEventListener('click', () => {
    runScenario('normal_procurement');
  });

  document.getElementById('btn-run-normal-sup')?.addEventListener('click', () => {
    runScenario('normal_support');
  });

  document.getElementById('btn-run-honeypot')?.addEventListener('click', () => {
    runScenario('honeypot');
  });

  document.getElementById('btn-run-slow-drift')?.addEventListener('click', () => {
    runScenario('slow_drift');
  });

  document.getElementById('btn-reset-demo')?.addEventListener('click', async () => {
    try {
      const res = await api('/v1/demo/reset', { method: 'POST' });
      if (res.ok) {
        showToast('Demo state reset to clean baseline.', 'info');
        refreshAll();
      }
    } catch (err) {
      console.error('Reset demo error:', err);
    }
  });
}

async function runScenario(scenarioName) {
  showToast(`Simulating scenario: ${scenarioName}...`, 'info');
  try {
    const res = await api('/v1/demo/simulate', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ scenario: scenarioName, delay_ms: 180 }),
    });
    if (!res.ok) {
      const err = await res.json();
      showToast(`Scenario error: ${err.detail || 'failed'}`, 'danger');
      return;
    }
    const data = await res.json();
    showToast(`Scenario complete: ${scenarioName} (${data.count} calls)`, 'success');
    refreshAll();
  } catch (err) {
    console.error('Error running scenario:', err);
    showToast('Failed to trigger scenario execution.', 'danger');
  }
}

window.demoStep = async function(stepType) {
  if (stepType === 'normal_proc') {
    await runScenario('normal_procurement');
  } else if (stepType === 'normal_sup') {
    await runScenario('normal_support');
  } else if (stepType === 'step_taint') {
    await sendSingleEvent({
      tool: 'supplier_price_api', action: 'read',
      resource: 'supplier_invoice.pdf', data_class: 'supplier', sensitivity: 1,
      taint: [{ source: 'supplier_invoice.pdf', ts: new Date().toISOString(), kind: 'document' }],
    });
  } else if (stepType === 'step_hr') {
    await sendSingleEvent({
      tool: 'hr_export_db', action: 'read',
      resource: 'hr/salaries.xlsx', data_class: 'hr', sensitivity: 3,
      taint: [{ source: 'supplier_invoice.pdf', ts: new Date().toISOString(), kind: 'document' }],
    });
  } else if (stepType === 'step_exfil') {
    await sendSingleEvent({
      tool: 'http_post', action: 'send',
      resource: 'exfil_payload', data_class: 'hr', sensitivity: 3,
      destination: 'unknown-host.example.com', bytes_out: 48200,
      taint: [{ source: 'supplier_invoice.pdf', ts: new Date().toISOString(), kind: 'document' }],
    });
  }
};

async function sendSingleEvent(params) {
  const payload = {
    event_id: crypto.randomUUID(),
    ts: new Date().toISOString(),
    agent_id: 'procurement-bot-04',
    role: 'procurement-agent',
    session_id: 's-demo-live',
    manifest_version: 3,
    token_id: 'tok-5521',
    chain: [],
    bytes_out: params.bytes_out || 0,
    destination: params.destination || null,
    taint: params.taint || [],
    ...params,
  };

  try {
    const res = await api('/v1/tool-calls', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
    });
    if (res.ok) {
      refreshAll();
    }
  } catch (err) {
    console.error('Failed to send single event:', err);
  }
}

// ---------------------------------------------------------------------------
// Analyst Actions (Feedback & Release)
// ---------------------------------------------------------------------------

window.alertFeedback = async function(alertId, feedback) {
  try {
    const res = await api(`/v1/alerts/${alertId}/feedback`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ feedback }),
    });
    if (res.ok) {
      showToast(`Analyst feedback recorded: ${feedback}`, 'success');
      fetchAlerts();
    }
  } catch (err) {
    console.error('Error submitting feedback:', err);
  }
};

window.releaseAgent = async function(agentId) {
  try {
    const res = await api(`/v1/agents/${agentId}/release`, {
      method: 'POST',
    });
    if (res.ok) {
      showToast(`Isolation lifted for ${agentId}. Baseline restored.`, 'success');
      refreshAll();
    }
  } catch (err) {
    console.error('Error releasing agent:', err);
  }
};

// ---------------------------------------------------------------------------
// Modal & Search Utilities
// ---------------------------------------------------------------------------

function setupModal() {
  const modal = document.getElementById('event-modal');
  const closeBtn = document.getElementById('modal-close-btn');

  if (closeBtn) {
    closeBtn.onclick = () => modal.classList.remove('active');
  }
  if (modal) {
    modal.onclick = (e) => {
      if (e.target === modal) modal.classList.remove('active');
    };
  }
}

window.inspectEvent = async function(eventId) {
  try {
    const res = await api(`/v1/events/${eventId}`);
    if (!res.ok) return;
    const data = await res.json();
    const modal = document.getElementById('event-modal');
    const content = document.getElementById('modal-json-content');
    const title = document.getElementById('modal-event-title');

    if (title) title.textContent = `Event Inspector: ${eventId}`;
    if (content) content.textContent = JSON.stringify(data, null, 2);
    if (modal) modal.classList.add('active');
  } catch (err) {
    console.error('Failed to inspect event:', err);
  }
};

function setupEventSearch() {
  const search = document.getElementById('event-search-input');
  if (search) {
    search.addEventListener('input', () => {
      renderEventTable();
    });
  }
}

function setupForensicFilters() {
  const tierSelect = document.getElementById('alert-filter-tier');
  if (tierSelect) {
    tierSelect.addEventListener('change', () => {
      renderForensicList();
    });
  }
}

// ---------------------------------------------------------------------------
// Toast Helper
// ---------------------------------------------------------------------------

function showToast(message, type = 'info') {
  const container = document.getElementById('toast-container');
  if (!container) return;

  const toast = document.createElement('div');
  let typeClass = '';
  if (type === 'danger') typeClass = 'toast-danger';
  else if (type === 'warning') typeClass = 'toast-warning';
  else if (type === 'success') typeClass = 'toast-success';

  toast.className = `toast ${typeClass}`;
  toast.innerHTML = `<span>${escapeHtml(message)}</span>`;

  container.appendChild(toast);
  setTimeout(() => {
    toast.style.opacity = '0';
    toast.style.transform = 'translateY(10px)';
    setTimeout(() => toast.remove(), 250);
  }, 4000);
}

function escapeHtml(str) {
  if (str === null || str === undefined) return '';
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}
