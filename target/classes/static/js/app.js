// ===== GLOBAL STATE =====
const API = 'http://localhost:8080/api';
let refreshInterval = null;
let allLogs = [];
let allAlerts = [];
let allCases = [];
let charts = {};
let currentCaseDetail = null;

// ===== THEME SYSTEM =====
function initTheme() {
  const saved = localStorage.getItem('soc-theme') || 'dark';
  document.documentElement.setAttribute('data-theme', saved);
  updateThemeIcon(saved);
}
function toggleTheme() {
  const current = document.documentElement.getAttribute('data-theme');
  const next = current === 'dark' ? 'light' : 'dark';
  document.documentElement.setAttribute('data-theme', next);
  localStorage.setItem('soc-theme', next);
  updateThemeIcon(next);
  // Rebuild charts with new theme colors
  if (allAlerts.length || allLogs.length) rebuildCharts();
}
function updateThemeIcon(theme) {
  const btn = document.getElementById('themeToggleBtn');
  if (btn) btn.innerHTML = theme === 'dark'
    ? '<i class="fa-solid fa-sun"></i>'
    : '<i class="fa-solid fa-moon"></i>';
}

// ===== NAVIGATION =====
function nav(pageId, element) {
  document.querySelectorAll('.page').forEach(p => p.classList.remove('active'));
  const page = document.getElementById(pageId);
  if (page) { page.classList.add('active'); page.classList.add('fade-in'); }
  document.querySelectorAll('.nav-item').forEach(n => n.classList.remove('active'));
  if (element) element.classList.add('active');
  const iconEl = element ? element.querySelector('i') : null;
  const titleText = element ? element.textContent.trim() : pageId;
  const iconHTML = iconEl ? iconEl.outerHTML : '';
  document.getElementById('pageTitle').innerHTML = `${iconHTML} ${titleText}`;
  // Hide case detail if navigating away
  if (pageId !== 'caseDetail') {
    const cd = document.getElementById('caseDetail');
    if (cd) cd.classList.remove('active');
  }
}

// ===== TOAST NOTIFICATIONS =====
function showToast(message, type = 'info') {
  const container = document.getElementById('toastContainer');
  const icons = { success: 'fa-circle-check', error: 'fa-circle-xmark', warning: 'fa-triangle-exclamation', info: 'fa-circle-info' };
  const toast = document.createElement('div');
  toast.className = `toast ${type}`;
  toast.innerHTML = `<i class="fa-solid ${icons[type]}"></i><span>${message}</span>`;
  container.appendChild(toast);
  setTimeout(() => { toast.style.opacity = '0'; toast.style.transform = 'translateX(60px)'; toast.style.transition = 'all 0.3s'; setTimeout(() => toast.remove(), 300); }, 3500);
}

// ===== SEVERITY HELPERS =====
function getBadgeClass(severity) {
  if (!severity) return 'low';
  const s = severity.toString().toLowerCase();
  if (s.includes('critical')) return 'critical';
  if (s.includes('high')) return 'high';
  if (s.includes('medium') || s.includes('warn')) return 'medium';
  return 'low';
}
function getAlertIcon(eventType) {
  const icons = {
    'ConsoleLogin': 'fa-right-to-bracket',
    'AttachUserPolicy': 'fa-user-shield',
    'ListBuckets': 'fa-bucket',
    'GetObject': 'fa-download',
    'DescribeInstances': 'fa-server',
    'ListUsers': 'fa-users',
    'DeleteBucket': 'fa-trash-can',
    'StopInstances': 'fa-power-off',
    'CreateUser': 'fa-user-plus'
  };
  return icons[eventType] || 'fa-circle-exclamation';
}

// ===== ANIMATED COUNTER =====
function animateCounter(elementId, targetValue) {
  const el = document.getElementById(elementId);
  if (!el) return;
  const start = parseInt(el.textContent) || 0;
  const duration = 800;
  const startTime = performance.now();
  function update(currentTime) {
    const elapsed = currentTime - startTime;
    const progress = Math.min(elapsed / duration, 1);
    const eased = 1 - Math.pow(1 - progress, 3);
    el.textContent = Math.round(start + (targetValue - start) * eased);
    if (progress < 1) requestAnimationFrame(update);
  }
  requestAnimationFrame(update);
}

// ===== LOADING SKELETONS =====
function showSkeleton(containerId, count = 3) {
  const el = document.getElementById(containerId);
  if (!el) return;
  el.innerHTML = Array(count).fill('<div class="skeleton skeleton-row"></div>').join('');
}

// ===== DATA FETCHING =====
async function fetchData() {
  const dot = document.getElementById('statusDot');
  const text = document.getElementById('statusText');
  dot.className = 'dot refreshing';
  text.innerText = 'Syncing...';
  try {
    await Promise.all([fetchLogs(), fetchAlerts(), fetchCases()]);
    dot.className = 'dot';
    text.innerText = 'Live — Connected';
    showToast('Data synced successfully', 'success');
  } catch (err) {
    console.error('API Error', err);
    dot.className = 'dot error';
    text.innerText = 'Disconnected';
    showToast('Failed to connect to API', 'error');
  }
  updateDashboardStats();
  rebuildCharts();
  buildTimeline();
}

// ===== FETCH LOGS =====
async function fetchLogs() {
  const res = await fetch(`${API}/logs`);
  if (!res.ok) throw new Error('API status ' + res.status);
  allLogs = await res.json();
  renderLogs(allLogs);
}

function renderLogs(logs) {
  const tbody = document.getElementById('logsTableBody');
  if (!tbody) return;
  if (logs.length === 0) {
    tbody.innerHTML = '<tr><td colspan="6" style="text-align:center;color:var(--text-muted);padding:40px;">No logs match your filters</td></tr>';
    return;
  }
  tbody.innerHTML = logs.map((l, i) => {
    const sevClass = getBadgeClass(l.severity);
    return `<tr class="log-row" onclick="openLogModal(${i})" style="animation: fadeIn 0.3s ease ${i * 0.02}s both">
      <td class="mono" style="font-size:0.8rem;color:var(--text-secondary)">${l.timestamp || 'N/A'}</td>
      <td class="mono" style="color:var(--accent-blue)">${l.user || 'Unknown'}</td>
      <td><span style="display:inline-flex;align-items:center;gap:6px"><i class="fa-solid ${getAlertIcon(l.eventType)}" style="color:var(--text-muted);font-size:0.8rem"></i>${l.eventType || 'N/A'}</span></td>
      <td><span class="badge ${sevClass}">${l.severity || 'INFO'}</span></td>
      <td class="mono" style="font-size:0.8rem">${l.ip || '0.0.0.0'}</td>
      <td>${l.status ? `<span class="badge ${l.status === 'FAILURE' ? 'high' : 'low'}">${l.status}</span>` : '—'}</td>
    </tr>`;
  }).join('');
}

// ===== LOG FILTERING =====
function filterLogs() {
  const search = (document.getElementById('logSearch')?.value || '').toLowerCase();
  const sevFilter = document.getElementById('logSevFilter')?.value || 'all';
  const userFilter = document.getElementById('logUserFilter')?.value || 'all';
  const typeFilter = document.getElementById('logTypeFilter')?.value || 'all';
  let filtered = allLogs.filter(l => {
    const matchSearch = !search || [l.timestamp, l.user, l.eventType, l.ip, l.severity, l.resource].some(f => (f || '').toLowerCase().includes(search));
    const matchSev = sevFilter === 'all' || getBadgeClass(l.severity) === sevFilter;
    const matchUser = userFilter === 'all' || l.user === userFilter;
    const matchType = typeFilter === 'all' || l.eventType === typeFilter;
    return matchSearch && matchSev && matchUser && matchType;
  });
  renderLogs(filtered);
}

function populateLogFilters() {
  const users = [...new Set(allLogs.map(l => l.user).filter(Boolean))];
  const types = [...new Set(allLogs.map(l => l.eventType).filter(Boolean))];
  const userSel = document.getElementById('logUserFilter');
  const typeSel = document.getElementById('logTypeFilter');
  if (userSel) userSel.innerHTML = '<option value="all">All Users</option>' + users.map(u => `<option value="${u}">${u}</option>`).join('');
  if (typeSel) typeSel.innerHTML = '<option value="all">All Events</option>' + types.map(t => `<option value="${t}">${t}</option>`).join('');
}

// ===== LOG MODAL =====
function openLogModal(index) {
  const log = allLogs[index];
  if (!log) return;
  const body = document.getElementById('logModalBody');
  body.innerHTML = [
    { label: 'Timestamp', value: log.timestamp, mono: true },
    { label: 'User Identity', value: log.user, mono: true },
    { label: 'Event Type', value: log.eventType },
    { label: 'Severity', value: `<span class="badge ${getBadgeClass(log.severity)}">${log.severity || 'INFO'}</span>`, html: true },
    { label: 'Source IP', value: log.ip, mono: true },
    { label: 'Resource', value: log.resource || 'N/A' },
    { label: 'Status', value: log.status || 'N/A' },
    { label: 'Detection', value: log.detectionReason || 'No detection rule triggered' }
  ].map(r => `<div class="detail-row"><div class="detail-label">${r.label}</div><div class="detail-value ${r.mono ? 'mono' : ''}">${r.html ? r.value : escapeHtml(r.value || 'N/A')}</div></div>`).join('');
  document.getElementById('logModalTitle').textContent = `Log Event — ${log.eventType || 'Unknown'}`;
  document.getElementById('logModal').classList.add('active');
}
function closeLogModal() { document.getElementById('logModal').classList.remove('active'); }

// ===== FETCH ALERTS =====
async function fetchAlerts() {
  const res = await fetch(`${API}/alerts`);
  if (!res.ok) throw new Error('API status ' + res.status);
  allAlerts = await res.json();
  renderAlerts(allAlerts);
}

function renderAlerts(alerts) {
  const grid = document.getElementById('alertsGrid');
  if (!grid) return;
  if (alerts.length === 0) { grid.innerHTML = '<div style="color:var(--text-muted);padding:40px;text-align:center">No alerts detected</div>'; return; }
  grid.innerHTML = alerts.map((a, i) => {
    const sc = getBadgeClass(a.severity);
    return `<div class="alert-card ${sc}" style="animation:slideUp 0.3s ease ${i * 0.05}s both" onclick="toggleExpand(this)">
      <div class="alert-header">
        <div class="alert-title"><i class="fa-solid ${getAlertIcon(a.eventType)}"></i>${a.ruleName || 'Suspicious Activity'}</div>
        <span class="badge ${sc}">${a.severity || 'HIGH'}</span>
      </div>
      <div class="alert-meta">
        <span><i class="fa-regular fa-clock"></i>${a.timestamp || 'N/A'}</span>
        <span><i class="fa-regular fa-user"></i>${a.user || 'N/A'}</span>
        <span class="mono"><i class="fa-solid fa-network-wired"></i>${a.ip || 'N/A'}</span>
      </div>
      <div class="alert-desc">${a.description || 'No details available'}</div>
      <div class="alert-expand">
        <div class="detail-row"><div class="detail-label">Alert ID</div><div class="detail-value mono">${a.id || 'N/A'}</div></div>
        <div class="detail-row"><div class="detail-label">Event Type</div><div class="detail-value">${a.eventType || 'N/A'}</div></div>
        <div class="alert-actions">
          <button class="btn btn-sm" onclick="event.stopPropagation();findRelatedCase('${a.user}')"><i class="fa-solid fa-link"></i>View Related Case</button>
        </div>
      </div>
    </div>`;
  }).join('');
}

function toggleExpand(el) { el.classList.toggle('expanded'); }

function findRelatedCase(user) {
  const c = allCases.find(c => c.user === user);
  if (c) {
    openCaseDetail(c);
  } else {
    showToast('No correlated case found for this user', 'warning');
  }
}

// ===== FETCH CASES =====
async function fetchCases() {
  const res = await fetch(`${API}/cases`);
  if (!res.ok) throw new Error('API status ' + res.status);
  allCases = await res.json();
  renderCases(allCases);
}

function renderCases(cases) {
  const grid = document.getElementById('casesGrid');
  if (!grid) return;
  if (cases.length === 0) { grid.innerHTML = '<div style="color:var(--text-muted);padding:40px;text-align:center">No correlated cases</div>'; return; }
  grid.innerHTML = cases.map((c, i) => {
    const sc = getBadgeClass(c.severity);
    const riskScore = c.severity?.toLowerCase().includes('high') ? 85 : c.severity?.toLowerCase().includes('medium') ? 55 : 25;
    const attackStage = getAttackStage(c);
    return `<div class="case-card ${sc}" style="animation:slideUp 0.3s ease ${i * 0.05}s both" onclick='openCaseDetail(${JSON.stringify(c).replace(/'/g, "\\'")})'>
      <div class="case-header">
        <span class="case-id">${c.caseId || 'CASE-000'}</span>
        <div style="display:flex;gap:8px;align-items:center">
          <span class="risk-score ${sc}"><i class="fa-solid fa-gauge-high"></i>${riskScore}/100</span>
          <span class="badge ${sc}">${c.severity || 'HIGH'}</span>
        </div>
      </div>
      <div class="case-reason">${c.correlationReason || 'Pattern Match'}</div>
      <div class="case-meta-row">
        <span><i class="fa-regular fa-user"></i>${c.user || 'N/A'}</span>
        <span class="mono"><i class="fa-solid fa-network-wired"></i>${c.ip || 'N/A'}</span>
        <span><i class="fa-solid fa-link"></i>${c.linkedEventCount || 0} linked events</span>
      </div>
      <div class="case-tags">
        ${attackStage.map(s => `<span class="badge purple">${s}</span>`).join('')}
      </div>
    </div>`;
  }).join('');
}

function getAttackStage(c) {
  const stages = [];
  if (!c.relatedEvents) return ['Reconnaissance'];
  const types = c.relatedEvents.map(e => e.eventType);
  if (types.some(t => t?.includes('Login'))) stages.push('Initial Access');
  if (types.some(t => t?.includes('Policy') || t?.includes('Attach'))) stages.push('Privilege Escalation');
  if (types.some(t => t?.includes('List') || t?.includes('Describe'))) stages.push('Discovery');
  if (types.some(t => t?.includes('Get') || t?.includes('Download'))) stages.push('Exfiltration');
  return stages.length ? stages : ['Reconnaissance'];
}

// ===== CASE DETAIL VIEW =====
function openCaseDetail(caseData) {
  currentCaseDetail = caseData;
  document.querySelectorAll('.page').forEach(p => p.classList.remove('active'));
  const cd = document.getElementById('caseDetail');
  cd.classList.add('active');
  document.getElementById('pageTitle').innerHTML = `<i class="fa-solid fa-folder-open"></i> Case: ${caseData.caseId || 'CASE-000'}`;
  const sc = getBadgeClass(caseData.severity);
  const riskScore = caseData.severity?.toLowerCase().includes('high') ? 85 : caseData.severity?.toLowerCase().includes('medium') ? 55 : 25;
  const content = document.getElementById('caseDetailContent');
  const events = caseData.relatedEvents || [];
  content.innerHTML = `
    <div class="case-detail-back" onclick="backToCases()"><i class="fa-solid fa-arrow-left"></i>Back to Cases</div>
    <div class="case-detail-header">
      <div>
        <div class="case-detail-title"><i class="fa-solid fa-folder-open" style="color:var(--accent-blue);margin-right:8px"></i>${caseData.caseId || 'CASE-000'}</div>
        <div style="color:var(--text-secondary);margin-top:4px">${caseData.correlationReason || 'Pattern Match'}</div>
      </div>
      <div style="display:flex;gap:10px;align-items:center">
        <span class="risk-score ${sc}" style="font-size:0.85rem;padding:6px 14px"><i class="fa-solid fa-gauge-high"></i>Risk: ${riskScore}/100</span>
        <span class="badge ${sc}" style="font-size:0.8rem;padding:5px 14px">${caseData.severity || 'HIGH'}</span>
      </div>
    </div>
    <div class="detail-info-grid">
      <div class="detail-info-item"><div class="detail-info-label">Primary Actor</div><div class="detail-info-value" style="font-family:'JetBrains Mono',monospace">${caseData.user || 'N/A'}</div></div>
      <div class="detail-info-item"><div class="detail-info-label">Source IP</div><div class="detail-info-value" style="font-family:'JetBrains Mono',monospace">${caseData.ip || 'N/A'}</div></div>
      <div class="detail-info-item"><div class="detail-info-label">Linked Events</div><div class="detail-info-value">${caseData.linkedEventCount || 0}</div></div>
      <div class="detail-info-item"><div class="detail-info-label">Attack Stages</div><div class="detail-info-value">${getAttackStage(caseData).join(' → ')}</div></div>
    </div>
    <div class="panel"><div class="panel-header"><span><i class="fa-solid fa-clock-rotate-left"></i>Attack Timeline</span></div>
      <div class="timeline-container">${events.map((e, i) => {
        const esc = getBadgeClass(e.severity);
        return `<div class="timeline-event ${esc}" style="animation:slideUp 0.3s ease ${i * 0.08}s both">
          <div class="timeline-time">${e.timestamp || 'N/A'}</div>
          <div class="timeline-title"><i class="fa-solid ${getAlertIcon(e.eventType)}" style="margin-right:6px;color:var(--text-muted)"></i>${e.eventType || 'Unknown Event'}</div>
          <div class="timeline-desc">${e.resource ? `Resource: ${e.resource}` : ''} ${e.status ? `| Status: ${e.status}` : ''} ${e.detectionReason ? `| ${e.detectionReason}` : ''}</div>
        </div>`;
      }).join('')}</div>
    </div>
    <div class="panel"><div class="panel-header"><span><i class="fa-solid fa-list"></i>Linked Log Events</span></div>
    <div class="table-wrapper"><table>
      <thead><tr><th>Time</th><th>Event</th><th>Resource</th><th>Severity</th><th>Status</th></tr></thead>
      <tbody>${events.map(e => {
        const esc = getBadgeClass(e.severity);
        return `<tr><td class="mono" style="font-size:0.8rem">${e.timestamp||'N/A'}</td><td>${e.eventType||'N/A'}</td><td>${e.resource||'N/A'}</td><td><span class="badge ${esc}">${e.severity||'INFO'}</span></td><td>${e.status||'—'}</td></tr>`;
      }).join('')}</tbody>
    </table></div></div>
    <div class="panel"><div class="panel-header"><span><i class="fa-solid fa-shield-halved"></i>Detection Rules Triggered</span></div>
      <div>${getDetectionRules(caseData).map(r => `<div style="padding:10px 0;border-bottom:1px solid var(--border-subtle);display:flex;align-items:center;gap:10px"><i class="fa-solid fa-bolt" style="color:var(--accent-yellow)"></i><span style="font-weight:600">${r}</span></div>`).join('')}</div>
    </div>`;
}

function getDetectionRules(c) {
  const rules = [];
  const events = c.relatedEvents || [];
  const types = events.map(e => e.eventType);
  if (types.filter(t => t?.includes('Login')).length >= 3) rules.push('Brute Force Detection — Multiple failed logins detected');
  if (types.some(t => t?.includes('Policy'))) rules.push('Privilege Escalation — IAM policy modification detected');
  if (types.filter(t => t?.includes('Get')).length >= 2) rules.push('Data Exfiltration — Bulk data access pattern detected');
  if (types.some(t => t?.includes('List'))) rules.push('Reconnaissance — Resource enumeration detected');
  if (!rules.length) rules.push('Anomaly Correlation — Behavioral pattern match');
  return rules;
}

function backToCases() {
  document.getElementById('caseDetail').classList.remove('active');
  const casesPage = document.getElementById('cases');
  casesPage.classList.add('active');
  const navItem = document.querySelector('.nav-item[onclick*="cases"]');
  document.querySelectorAll('.nav-item').forEach(n => n.classList.remove('active'));
  if (navItem) navItem.classList.add('active');
  document.getElementById('pageTitle').innerHTML = '<i class="fa-solid fa-folder-tree"></i> Correlated Cases';
}

// ===== DASHBOARD STATS =====
function updateDashboardStats() {
  animateCounter('dashLogCount', allLogs.length);
  animateCounter('dashAlertCount', allAlerts.length);
  animateCounter('dashCaseCount', allCases.length);
  const highAlerts = allAlerts.filter(a => getBadgeClass(a.severity) === 'high').length;
  animateCounter('dashHighAlerts', highAlerts);
  // Update alert badge in sidebar
  const badge = document.getElementById('alertNavBadge');
  if (badge) badge.textContent = allAlerts.length;
  populateLogFilters();
}

// ===== CHARTS =====
function getChartColors() {
  const isDark = document.documentElement.getAttribute('data-theme') !== 'light';
  return {
    text: isDark ? '#9ca3af' : '#64748b',
    grid: isDark ? 'rgba(255,255,255,0.06)' : 'rgba(0,0,0,0.06)',
    bg: isDark ? '#111827' : '#ffffff'
  };
}

function rebuildCharts() {
  Object.values(charts).forEach(c => c.destroy());
  charts = {};
  buildSeverityChart();
  buildLogsTimeChart();
  buildTopUsersChart();
}

function buildSeverityChart() {
  const ctx = document.getElementById('severityChart');
  if (!ctx) return;
  const counts = { HIGH: 0, MEDIUM: 0, LOW: 0 };
  allAlerts.forEach(a => {
    const c = getBadgeClass(a.severity);
    if (c === 'high' || c === 'critical') counts.HIGH++;
    else if (c === 'medium') counts.MEDIUM++;
    else counts.LOW++;
  });
  const colors = getChartColors();
  charts.severity = new Chart(ctx, {
    type: 'doughnut',
    data: {
      labels: ['High / Critical', 'Medium', 'Low / Info'],
      datasets: [{ data: [counts.HIGH, counts.MEDIUM, counts.LOW], backgroundColor: ['#ef4444', '#f59e0b', '#10b981'], borderWidth: 0, hoverOffset: 8 }]
    },
    options: {
      responsive: true, maintainAspectRatio: false,
      cutout: '65%',
      plugins: {
        legend: { position: 'bottom', labels: { color: colors.text, padding: 16, usePointStyle: true, pointStyleWidth: 10, font: { family: 'Inter', size: 12 } } }
      }
    }
  });
}

function buildLogsTimeChart() {
  const ctx = document.getElementById('logsTimeChart');
  if (!ctx) return;
  const timeMap = {};
  allLogs.forEach(l => {
    const ts = l.timestamp || '';
    const hour = ts.includes('T') ? ts.split('T')[1]?.substring(0, 5) : ts;
    if (hour) timeMap[hour] = (timeMap[hour] || 0) + 1;
  });
  const labels = Object.keys(timeMap).sort();
  const data = labels.map(l => timeMap[l]);
  const colors = getChartColors();
  charts.logsTime = new Chart(ctx, {
    type: 'line',
    data: {
      labels,
      datasets: [{
        label: 'Events',
        data,
        borderColor: '#3b82f6',
        backgroundColor: 'rgba(59,130,246,0.1)',
        fill: true,
        tension: 0.4,
        pointRadius: 4,
        pointBackgroundColor: '#3b82f6',
        pointBorderColor: '#3b82f6',
        pointHoverRadius: 6
      }]
    },
    options: {
      responsive: true, maintainAspectRatio: false,
      scales: {
        x: { grid: { color: colors.grid }, ticks: { color: colors.text, font: { family: 'JetBrains Mono', size: 10 } } },
        y: { beginAtZero: true, grid: { color: colors.grid }, ticks: { color: colors.text, stepSize: 1 } }
      },
      plugins: { legend: { display: false } }
    }
  });
}

function buildTopUsersChart() {
  const ctx = document.getElementById('topUsersChart');
  if (!ctx) return;
  const userMap = {};
  allLogs.forEach(l => { if (l.user) userMap[l.user] = (userMap[l.user] || 0) + 1; });
  const sorted = Object.entries(userMap).sort((a, b) => b[1] - a[1]).slice(0, 6);
  const colors = getChartColors();
  charts.topUsers = new Chart(ctx, {
    type: 'bar',
    data: {
      labels: sorted.map(s => s[0]),
      datasets: [{ label: 'Events', data: sorted.map(s => s[1]), backgroundColor: ['#3b82f6', '#8b5cf6', '#06b6d4', '#10b981', '#f59e0b', '#ef4444'], borderRadius: 6, borderSkipped: false, maxBarThickness: 40 }]
    },
    options: {
      responsive: true, maintainAspectRatio: false, indexAxis: 'y',
      scales: {
        x: { beginAtZero: true, grid: { color: colors.grid }, ticks: { color: colors.text, stepSize: 1 } },
        y: { grid: { display: false }, ticks: { color: colors.text, font: { family: 'JetBrains Mono', size: 11 } } }
      },
      plugins: { legend: { display: false } }
    }
  });
}

// ===== ATTACK TIMELINE =====
function buildTimeline() {
  const container = document.getElementById('timelineContent');
  if (!container) return;
  const events = [];
  allLogs.forEach(l => {
    events.push({ timestamp: l.timestamp, title: l.eventType, user: l.user, ip: l.ip, resource: l.resource, status: l.status, severity: l.severity || 'INFO', type: 'log' });
  });
  events.sort((a, b) => (a.timestamp || '').localeCompare(b.timestamp || ''));
  if (events.length === 0) {
    container.innerHTML = '<div class="placeholder-content"><i class="fa-solid fa-clock-rotate-left"></i><h3>No timeline data</h3><p>Timeline will appear when log events are loaded.</p></div>';
    return;
  }
  container.innerHTML = `<div class="timeline-container">${events.map((e, i) => {
    const sc = getBadgeClass(e.severity);
    const statusBadge = e.status === 'FAILURE' ? '<span class="badge high" style="font-size:0.68rem">FAILED</span>' : e.status === 'SUCCESS' ? '<span class="badge low" style="font-size:0.68rem">OK</span>' : '';
    return `<div class="timeline-event ${sc}" onclick="toggleExpand(this)" style="animation:slideUp 0.4s ease ${i * 0.06}s both">
      <div class="timeline-time">${e.timestamp || 'N/A'}</div>
      <div class="timeline-title">${e.title || 'Unknown'} ${statusBadge}</div>
      <div class="timeline-desc"><span style="color:var(--accent-blue)">${e.user || ''}</span> ${e.resource ? '→ ' + e.resource : ''}</div>
      <div class="timeline-tags"><span class="badge ${sc}" style="font-size:0.68rem">${e.severity}</span></div>
      <div class="timeline-expand">
        <div class="detail-row"><div class="detail-label">IP Address</div><div class="detail-value mono">${e.ip || 'N/A'}</div></div>
        <div class="detail-row"><div class="detail-label">Resource</div><div class="detail-value">${e.resource || 'N/A'}</div></div>
      </div>
    </div>`;
  }).join('')}</div>`;
}

// ===== MITRE ATT&CK MATRIX =====
function buildMitreMatrix() {
  const tactics = [
    { name: 'Initial Access', techniques: [
      { id: 'T1078', name: 'Valid Accounts', desc: 'Adversaries use credentials of existing accounts to gain access.' },
      { id: 'T1110', name: 'Brute Force', desc: 'Adversaries use brute force attacks to gain access to accounts.' },
      { id: 'T1133', name: 'External Remote Services', desc: 'Adversaries exploit external-facing services for initial access.' }
    ]},
    { name: 'Persistence', techniques: [
      { id: 'T1098', name: 'Account Manipulation', desc: 'Adversaries manipulate accounts to maintain persistent access.' },
      { id: 'T1136', name: 'Create Account', desc: 'Adversaries create accounts to maintain access.' }
    ]},
    { name: 'Privilege Escalation', techniques: [
      { id: 'T1078.004', name: 'Cloud Accounts', desc: 'Adversaries use cloud account credentials for privilege escalation.' },
      { id: 'T1484', name: 'Domain Policy Modification', desc: 'Adversaries modify domain policies to escalate privileges.' }
    ]},
    { name: 'Discovery', techniques: [
      { id: 'T1087', name: 'Account Discovery', desc: 'Adversaries enumerate accounts to understand the environment.' },
      { id: 'T1580', name: 'Cloud Infrastructure Discovery', desc: 'Adversaries discover cloud infrastructure to plan next steps.' },
      { id: 'T1526', name: 'Cloud Service Discovery', desc: 'Adversaries enumerate cloud services for lateral movement.' }
    ]},
    { name: 'Collection', techniques: [
      { id: 'T1530', name: 'Data from Cloud Storage', desc: 'Adversaries access data in cloud storage objects like S3 buckets.' }
    ]},
    { name: 'Exfiltration', techniques: [
      { id: 'T1537', name: 'Transfer to Cloud Account', desc: 'Adversaries exfiltrate data to another cloud account.' },
      { id: 'T1567', name: 'Exfil Over Web Service', desc: 'Adversaries exfiltrate data using legitimate web services.' }
    ]}
  ];
  // Determine detected techniques
  const detectedIds = new Set();
  const eventTypes = allLogs.map(l => l.eventType);
  if (eventTypes.some(t => t?.includes('Login'))) { detectedIds.add('T1078'); detectedIds.add('T1110'); }
  if (eventTypes.some(t => t?.includes('Policy') || t?.includes('Attach'))) { detectedIds.add('T1098'); detectedIds.add('T1078.004'); detectedIds.add('T1484'); }
  if (eventTypes.some(t => t?.includes('List') || t?.includes('Describe'))) { detectedIds.add('T1087'); detectedIds.add('T1580'); detectedIds.add('T1526'); }
  if (eventTypes.some(t => t?.includes('Get'))) { detectedIds.add('T1530'); }
  const container = document.getElementById('mitreMatrix');
  if (!container) return;
  container.innerHTML = tactics.map(tactic => `
    <div class="mitre-tactic">
      <div class="mitre-tactic-header">${tactic.name}</div>
      ${tactic.techniques.map(t => `<div class="mitre-technique ${detectedIds.has(t.id) ? 'detected' : ''}" title="${t.desc}">
        <span style="font-family:'JetBrains Mono',monospace;font-size:0.72rem;color:var(--text-muted);margin-right:6px">${t.id}</span>${t.name}
      </div>`).join('')}
    </div>
  `).join('');
}

// ===== EVIDENCE LOCKER =====
function buildEvidenceLocker() {
  const container = document.getElementById('evidenceList');
  if (!container) return;
  const evidenceItems = [
    { name: 'cloudtrail-logs-2026-03-25.json', hash: sha256Fake('cloudtrail-logs'), type: 'Log Bundle', icon: 'fa-file-code', verified: true },
    { name: 'iam-policy-snapshot.json', hash: sha256Fake('iam-policy'), type: 'Config Snapshot', icon: 'fa-shield-halved', verified: true },
    { name: 's3-access-audit.csv', hash: sha256Fake('s3-access'), type: 'Audit Trail', icon: 'fa-table', verified: true },
    { name: 'network-flow-capture.pcap', hash: sha256Fake('network-flow'), type: 'Network Capture', icon: 'fa-network-wired', verified: false }
  ];
  container.innerHTML = evidenceItems.map((e, i) => `
    <div class="evidence-item" style="animation:slideUp 0.3s ease ${i * 0.08}s both">
      <div class="evidence-icon"><i class="fa-solid ${e.icon}"></i></div>
      <div class="evidence-info">
        <div class="evidence-name">${e.name}</div>
        <div class="evidence-hash">SHA-256: ${e.hash}</div>
      </div>
      <div class="evidence-actions">
        <span class="integrity-badge ${e.verified ? 'verified' : 'unverified'}">
          <i class="fa-solid ${e.verified ? 'fa-check-circle' : 'fa-question-circle'}"></i>${e.verified ? 'Verified' : 'Pending'}
        </span>
        <button class="btn btn-sm" onclick="showToast('Download started: ${e.name}','info')"><i class="fa-solid fa-download"></i></button>
      </div>
    </div>
  `).join('');
}

function sha256Fake(input) {
  let hash = 0;
  for (let i = 0; i < input.length; i++) { hash = ((hash << 5) - hash) + input.charCodeAt(i); hash |= 0; }
  const hex = Math.abs(hash).toString(16).padStart(8, '0');
  return (hex.repeat(8)).substring(0, 64);
}

// ===== REPORT BUILDER =====
function initReportBuilder() {
  const container = document.getElementById('reportCaseList');
  if (!container) return;
  if (allCases.length === 0) {
    container.innerHTML = '<div style="color:var(--text-muted)">No cases available for report generation.</div>';
    return;
  }
  container.innerHTML = allCases.map(c => `
    <div class="report-case-option" onclick="this.classList.toggle('selected')" data-case-id="${c.caseId}">
      <div style="font-weight:600;font-family:'JetBrains Mono',monospace;margin-bottom:4px">${c.caseId || 'CASE-000'}</div>
      <div style="font-size:0.78rem;color:var(--text-secondary)">${c.correlationReason || 'Pattern Match'}</div>
    </div>
  `).join('');
}

function generateReport() {
  const selected = document.querySelectorAll('.report-case-option.selected');
  if (selected.length === 0) { showToast('Please select at least one case', 'warning'); return; }
  showToast(`Generating report for ${selected.length} case(s)...`, 'info');
  setTimeout(() => showToast('Report generated successfully!', 'success'), 2000);
}

function downloadReport() {
  showToast('Preparing PDF download...', 'info');
  setTimeout(() => showToast('Report downloaded', 'success'), 1500);
}

// ===== AUTO REFRESH =====
function toggleAutoRefresh() {
  const isAuto = document.getElementById('autoRefresh')?.checked;
  clearInterval(refreshInterval);
  if (isAuto) refreshInterval = setInterval(fetchData, 15000);
}

// ===== UTILS =====
function escapeHtml(str) {
  const div = document.createElement('div');
  div.textContent = str;
  return div.innerHTML;
}

// ===== INIT =====
document.addEventListener('DOMContentLoaded', () => {
  initTheme();
  fetchData().then(() => {
    buildMitreMatrix();
    buildEvidenceLocker();
    initReportBuilder();
  });
  toggleAutoRefresh();
  // Close modal on overlay click
  document.getElementById('logModal')?.addEventListener('click', (e) => {
    if (e.target.classList.contains('modal-overlay')) closeLogModal();
  });
  // Close modal on Escape
  document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape') closeLogModal();
  });
});
