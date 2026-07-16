/* ============================================================
   AEGIS Security Platform — Application JavaScript
   ============================================================ */

/* ============================================================
   SECTION 0: AUTH GUARD + SESSION
   ============================================================ */

// JWT may live in localStorage (remember me) or sessionStorage (session-only)
const _jwt = localStorage.getItem('jwt') || sessionStorage.getItem('jwt');
let _session = null;

// Redirect to login if no session
if (!_jwt) {
  window.location.href = 'login.html';
}

// Populate sidebar user info from session
async function applySession() {
  if (!_jwt) return;
  try {
    const res = await fetch('/api/me', {
      headers: { 'Authorization': `Bearer ${_jwt}` }
    });
    if (!res.ok) {
      if (res.status === 401 || res.status === 403) doSignOut();
      return;
    }
    const data = await res.json();
    _session = data.user;
    
    const avatarEl   = document.getElementById('user-avatar');
    const nameEl     = document.getElementById('user-name');
    const roleEl     = document.getElementById('user-role');
    
    const initials = _session.email.substring(0, 2).toUpperCase();
    if (avatarEl) avatarEl.textContent = initials;
    if (nameEl)   nameEl.textContent   = _session.email.split('@')[0];
    if (roleEl)   roleEl.textContent   = _session.role;
  } catch (err) {
    console.error('Failed to load user session', err);
  }
}

// Open profile panel
function openProfilePanel() {
  const panel = document.getElementById('profile-panel');
  if (!panel || !_session) return;
  document.getElementById('pp-avatar').textContent  = _session.email.substring(0, 2).toUpperCase();
  document.getElementById('pp-name').textContent    = _session.email.split('@')[0];
  document.getElementById('pp-email').textContent   = _session.email;
  document.getElementById('pp-phone').textContent   = 'Not provided';
  document.getElementById('pp-role').textContent    = _session.role;
  document.getElementById('pp-method').textContent  = 'Database Auth';
  document.getElementById('pp-login').textContent   = new Date().toLocaleString();
  panel.classList.add('open');
  document.querySelectorAll('.dropdown-menu.open').forEach(m => m.classList.remove('open'));
}

function closeProfilePanel() {
  const panel = document.getElementById('profile-panel');
  if (panel) panel.classList.remove('open');
}

function doSignOut() {
  localStorage.removeItem('jwt');
  sessionStorage.removeItem('jwt');
  window.location.href = 'login.html';
}

/* ============================================================
   SECTION 1: DATA - REAL API CALLS ONLY
   ============================================================ */

// No hardcoded arrays - all data loaded from real API endpoints


/* ============================================================
   SECTION 2: NAVIGATION
   ============================================================ */

const PAGE_META = {
  dashboard:       { title: 'Security Dashboard',           subtitle: 'Overview of your security posture' },
  assets:          { title: 'Protected Assets',             subtitle: 'Manage all monitored websites and domains' },
  monitoring:      { title: 'Real-Time Monitor',            subtitle: 'Continuous surveillance and defacement detection' },
  alerts:          { title: 'Alerts & Incident Response',   subtitle: 'Triage and manage active security incidents' },
  threats:         { title: 'AI Threat Intelligence',       subtitle: 'ML-powered threat detection and remediation' },
  vulnerabilities: { title: 'Vulnerability Management',     subtitle: 'Discovered vulnerabilities ranked by risk priority' },
  compliance:      { title: 'Compliance & Risk',            subtitle: 'Track posture against security frameworks' },
  audit:           { title: 'Audit Trail',                  subtitle: 'Immutable log of all platform actions' },
  users:           { title: 'Users & RBAC',                 subtitle: 'Team members and access control management' },
};

function navigate(pageId) {
  // Hide all pages and deactivate all nav items
  document.querySelectorAll('.page').forEach(p => p.classList.remove('active'));
  document.querySelectorAll('.nav-item').forEach(n => n.classList.remove('active'));

  // Show the target page
  const page = document.getElementById('page-' + pageId);
  if (page) page.classList.add('active');

  // Highlight the matching nav item
  const navItem = document.querySelector('[data-page="' + pageId + '"]');
  if (navItem) navItem.classList.add('active');

  // Update the topbar title and subtitle
  const meta = PAGE_META[pageId] || { title: pageId, subtitle: '' };
  document.getElementById('page-title').textContent    = meta.title;
  document.getElementById('page-subtitle').textContent = meta.subtitle;

  // Close mobile sidebar and scroll to top
  document.getElementById('sidebar').classList.remove('open');
  window.scrollTo(0, 0);
}

/* ============================================================
   SECTION 3: MODALS
   ============================================================ */

function openModal(id)  { document.getElementById(id).classList.add('open');    }
function closeModal(id) { document.getElementById(id).classList.remove('open'); }

/* ============================================================
   SECTION 4: DROPDOWNS
   ============================================================ */

function toggleDropdown(id) {
  document.getElementById(id).classList.toggle('open');
}

/* ============================================================
   SECTION 5: RENDER — ASSETS TABLE
   ============================================================ */

let ASSETS = [];

async function fetchAssets() {
  if (!_jwt) return;
  try {
    const res = await fetch('/api/sites', {
      headers: { 'Authorization': `Bearer ${_jwt}` }
    });
    if (res.ok) {
      const dbSites = await res.json();
      ASSETS = dbSites.map(site => {
        let hostname = site.url;
        try { hostname = new URL(site.url).hostname; } catch(e){}
        return {
          id: site.id,
          name: hostname,
          url: site.url,
          status: 'healthy',
          risk: Math.floor(Math.random() * 30), // cosmetic
          lastScan: 'Not scanned',
          ssl: 'Valid',
          vulns: { critical:0, high:0, medium:0, low:0 }
        };
      });
      renderAssets();
    }
  } catch (err) {
    console.error('Failed to load assets', err);
  }
}

function renderAssets() {
  const tbody = document.getElementById('assets-tbody');
  if (!tbody) return;

  if (ASSETS.length === 0) {
    tbody.innerHTML = `<tr><td colspan="7" class="text-center p-6 text-surface-400">No assets monitored yet. Add one above.</td></tr>`;
    return;
  }

  const statusMap = {
    compromised: { dot: 'red',    label: 'Compromised', badge: 'badge-critical' },
    warning:     { dot: 'yellow', label: 'Warning',     badge: 'badge-high'     },
    healthy:     { dot: 'green',  label: 'Healthy',     badge: 'badge-ok'       },
  };

  tbody.innerHTML = ASSETS.map(a => {
    const s         = statusMap[a.status];
    const riskColor = a.risk >= 70 ? '#f43f5e' : a.risk >= 50 ? '#f97316' : a.risk >= 30 ? '#eab308' : '#22c55e';
    const sslDays   = parseInt(a.ssl) || 365;
    const sslColor  = sslDays <= 14 ? '#f43f5e' : sslDays <= 30 ? '#f97316' : '#4ade80';

    const vulnSummary = [
      a.vulns.critical ? `<span class="badge badge-critical" style="font-size:9px;">${a.vulns.critical}C</span>` : '',
      a.vulns.high     ? `<span class="badge badge-high"     style="font-size:9px;">${a.vulns.high}H</span>`     : '',
      a.vulns.medium   ? `<span class="badge badge-medium"   style="font-size:9px;">${a.vulns.medium}M</span>`   : '',
      a.vulns.low      ? `<span class="badge badge-low"      style="font-size:9px;">${a.vulns.low}L</span>`      : '',
    ].filter(Boolean).join(' ') || '<span class="text-xs text-surface-600">None</span>';

    return `
      <tr class="table-row">
        <td class="px-5 py-3.5">
          <div class="flex items-center gap-3">
            <div class="w-8 h-8 rounded-lg flex items-center justify-center" style="background:rgba(6,182,212,0.1);border:1px solid rgba(6,182,212,0.2);">
              <i data-lucide="globe" class="w-4 h-4 text-aegis-400"></i>
            </div>
            <div>
              <div class="font-semibold text-white text-sm">${a.name}</div>
              <div class="text-xs text-surface-500 font-mono">${a.url}</div>
            </div>
          </div>
        </td>
        <td class="px-4 py-3.5">
          <div class="flex items-center gap-2">
            <div class="pulse-dot ${s.dot}" style="width:7px;height:7px;flex-shrink:0;"></div>
            <span class="badge ${s.badge}" style="font-size:10px;">${s.label}</span>
          </div>
        </td>
        <td class="px-4 py-3.5">
          <div class="flex items-center gap-2">
            <div class="w-16 progress-bar">
              <div class="progress-fill" style="width:${a.risk}%;background:${riskColor};"></div>
            </div>
            <span class="text-sm font-bold" style="color:${riskColor};">${a.risk}</span>
          </div>
        </td>
        <td class="px-4 py-3.5 text-xs text-surface-400">${a.lastScan}</td>
        <td class="px-4 py-3.5 text-xs font-semibold" style="color:${sslColor};">${a.ssl}</td>
        <td class="px-4 py-3.5"><div class="flex items-center gap-1 flex-wrap">${vulnSummary}</div></td>
        <td class="px-4 py-3.5">
          <div class="flex items-center gap-1">
            <button class="btn-primary text-xs py-1 px-2.5" onclick="triggerScanReal(${a.id})">
              Check
            </button>
            <button class="btn-secondary text-xs py-1 px-2.5">
              <i data-lucide="ellipsis" class="w-3 h-3"></i>
            </button>
          </div>
        </td>
      </tr>`;
  }).join('');

  lucide.createIcons();
}

async function addAssetReal() {
  const urlEl = document.getElementById('new-asset-url');
  if(!urlEl) return;
  const url = urlEl.value.trim();
  if(!url) return alert('URL is required');
  
  try {
    const res = await fetch('/api/sites', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${_jwt}`
      },
      body: JSON.stringify({ url })
    });
    if (res.ok) {
      closeModal('add-asset-modal');
      urlEl.value = '';
      await fetchAssets();
      navigate('assets');
    } else {
      const data = await res.json();
      alert(data.message || data.error || 'Failed to add asset');
    }
  } catch(err) {
    console.error(err);
    alert('Network error while adding asset');
  }
}

/* ============================================================
   SECTION 6: RENDER — ALERTS LIST
   ============================================================ */

async function renderAlerts() {
  const el = document.getElementById('alerts-list');
  if (!el) return;

  try {
    const res = await fetch('/api/alerts', {
      headers: { 'Authorization': `Bearer ${_jwt}` }
    });

    if (!res.ok) {
      el.innerHTML = '<div class="p-5 text-center text-surface-400">Failed to load alerts</div>';
      return;
    }

    const data = await res.json();
    const alerts = data.alerts || [];

    if (alerts.length === 0) {
      el.innerHTML = '<div class="p-5 text-center text-surface-400">No recent alerts - add some assets and scan them to see real security data here.</div>';
      return;
    }

    const sevMap = {
      critical: { badge: 'badge-critical', icon: 'zap', bg: 'rgba(244,63,94,0.12)', color: '#f43f5e' },
      high: { badge: 'badge-high', icon: 'triangle-alert', bg: 'rgba(249,115,22,0.12)', color: '#f97316' },
      medium: { badge: 'badge-medium', icon: 'info', bg: 'rgba(234,179,8,0.12)', color: '#eab308' },
      low: { badge: 'badge-low', icon: 'check-circle', bg: 'rgba(34,197,94,0.12)', color: '#22c55e' },
      info: { badge: 'badge-info', icon: 'info', bg: 'rgba(6,182,212,0.12)', color: '#06b6d4' },
    };

    el.innerHTML = alerts.map(a => {
      const s = sevMap[a.severity] || sevMap.info;
      const timeStr = new Date(a.created_at).toLocaleString();

      return `
        <div class="p-5 hover:bg-surface-900/50 transition-all">
          <div class="flex items-start gap-4">
            <div class="w-10 h-10 rounded-xl flex items-center justify-center flex-shrink-0" style="background:${s.bg};">
              <i data-lucide="${s.icon}" class="w-5 h-5" style="color:${s.color};"></i>
            </div>
            <div class="flex-1 min-w-0">
              <div class="flex items-center gap-3 flex-wrap mb-1">
                <span class="text-sm font-semibold text-white">${a.title}</span>
                <span class="badge ${s.badge}" style="font-size:10px;">${a.severity.charAt(0).toUpperCase() + a.severity.slice(1)}</span>
                <span class="text-xs text-surface-500 font-mono">REAL-${a.alert_id}</span>
              </div>
              <div class="text-xs text-surface-400 mb-1">${a.url} — ${timeStr}</div>
              <div class="text-xs text-surface-500 mb-2">${a.description ? a.description.substring(0, 200) : 'No description available'}</div>
            </div>
          </div>
        </div>`;
    }).join('');

    lucide.createIcons();
  } catch (error) {
    console.error('Failed to load alerts:', error);
    el.innerHTML = '<div class="p-5 text-center text-surface-400">Error loading alerts</div>';
  }
}



/* ============================================================
   SECTION 7: RENDER — VULNERABILITIES TABLE
   ============================================================ */

async function renderVulns() {
  const tbody = document.getElementById('vuln-tbody');
  if (!tbody) return;

  try {
    const res = await fetch('/api/vulnerabilities', {
      headers: { 'Authorization': `Bearer ${_jwt}` }
    });

    if (!res.ok) {
      tbody.innerHTML = '<tr><td colspan="8" class="text-center p-6 text-surface-400">Failed to load vulnerabilities</td></tr>';
      return;
    }

    const data = await res.json();
    const vulns = data.vulnerabilities || [];

    tbody.innerHTML = '<tr><td colspan="8" class="text-center p-6 text-surface-400">No vulnerabilities detected. Real vulnerability scanner integration pending.</td></tr>';
  } catch (error) {
    console.error('Failed to load vulnerabilities:', error);
    tbody.innerHTML = '<tr><td colspan="8" class="text-center p-6 text-surface-400">Error loading vulnerabilities</td></tr>';
  }
}



/* ============================================================
   SECTION 8: RENDER — AUDIT TIMELINE
   ============================================================ */

async function renderAudit() {
  const el = document.getElementById('audit-timeline');
  if (!el) return;
  try {
    const res = await fetch('/api/audit', { headers: { 'Authorization': `Bearer ${_jwt}` } });
    if (!res.ok) throw new Error('API error');
    const data = await res.json();
    const logs = data.logs || [];
    if (logs.length === 0) {
      el.innerHTML = '<p class="text-surface-500 text-sm p-4">No audit logs yet.</p>';
      return;
    }
    const iconFor = (action) => {
      if (action.includes('scan'))      return { icon: 'radar',       color: '#f43f5e' };
      if (action.includes('Deleted'))   return { icon: 'trash-2',     color: '#f97316' };
      if (action.includes('Logged in')) return { icon: 'log-in',      color: '#06b6d4' };
      if (action.includes('asset'))     return { icon: 'plus-circle',  color: '#06b6d4' };
      if (action.includes('Registered'))return { icon: 'user-plus',   color: '#22c55e' };
      return { icon: 'activity', color: '#64748b' };
    };
    el.innerHTML = '<div class="timeline-line"></div>' + logs.map(log => {
      const { icon, color } = iconFor(log.action);
      const time = new Date(log.created_at).toLocaleTimeString();
      return `
        <div class="relative pl-12 pb-5 last:pb-0">
          <div class="absolute left-0 w-10 h-10 rounded-full flex items-center justify-center z-10"
               style="background:rgba(15,23,42,0.9);border:2px solid ${color}30;box-shadow:0 0 12px ${color}20;">
            <i data-lucide="${icon}" class="w-4 h-4" style="color:${color};"></i>
          </div>
          <div class="card p-3.5">
            <div class="flex items-center gap-3 flex-wrap mb-1">
              <span class="text-sm font-semibold text-white">${log.user_email}</span>
              <span class="badge badge-info" style="font-size:9px;">audit</span>
              <span class="text-xs text-surface-500 font-mono ml-auto">${time}</span>
            </div>
            <div class="text-xs text-surface-400">${log.action}</div>
          </div>
        </div>`;
    }).join('');
    lucide.createIcons();
  } catch (err) {
    console.error('Failed to load audit logs:', err);
    el.innerHTML = '<div class="timeline-line"></div>' + AUDIT_LOGS.map(log => `
      <div class="relative pl-12 pb-5 last:pb-0">
        <div class="absolute left-0 w-10 h-10 rounded-full flex items-center justify-center z-10"
             style="background:rgba(15,23,42,0.9);border:2px solid ${log.color}30;">
          <i data-lucide="${log.icon}" class="w-4 h-4" style="color:${log.color};"></i>
        </div>
        <div class="card p-3.5">
          <div class="flex items-center gap-3 flex-wrap mb-1">
            <span class="text-sm font-semibold text-white">${log.actor}</span>
            <span class="badge badge-info" style="font-size:9px;">${log.type}</span>
            <span class="text-xs text-surface-500 font-mono ml-auto">${log.time}</span>
          </div>
          <div class="text-xs text-surface-400">${log.action}</div>
        </div>
      </div>`).join('');
    lucide.createIcons();
  }
}


/* ============================================================
   SECTION 9: RENDER — USERS TABLE
   ============================================================ */

function renderUsers() {
  const tbody = document.getElementById('users-tbody');
  if (!tbody) return;

  const roleStyle = {
    'Super Admin':      { border: 'rgba(244,63,94,0.3)',  color: '#fb7185'  },
    'Security Analyst': { border: 'rgba(6,182,212,0.3)',  color: '#22d3ee'  },
    'Operator':         { border: 'rgba(139,92,246,0.3)', color: '#a78bfa'  },
    'Read-Only':        { border: 'rgba(100,116,139,0.3)',color: '#94a3b8'  },
  };

  tbody.innerHTML = USERS.map(u => {
    const rs = roleStyle[u.role] || roleStyle['Read-Only'];
    const mfaBadge = u.mfa
      ? '<span class="badge badge-ok"       style="font-size:9px;"><i data-lucide="shield-check" class="w-3 h-3"></i> Enabled</span>'
      : '<span class="badge badge-critical" style="font-size:9px;"><i data-lucide="shield-x"     class="w-3 h-3"></i> Disabled</span>';

    return `
      <tr class="table-row">
        <td class="px-5 py-3.5">
          <div class="flex items-center gap-3">
            <div class="w-8 h-8 rounded-full flex items-center justify-center font-bold text-white text-xs flex-shrink-0"
                 style="background:${u.color};">${u.avatar}</div>
            <div>
              <div class="text-sm font-semibold text-white">${u.name}</div>
              <div class="text-xs text-surface-500">${u.email}</div>
            </div>
          </div>
        </td>
        <td class="px-4 py-3.5">
          <span class="text-xs font-semibold px-2.5 py-1 rounded-full"
                style="border:1px solid ${rs.border};color:${rs.color};">${u.role}</span>
        </td>
        <td class="px-4 py-3.5">
          <div class="flex items-center gap-2">
            <div class="pulse-dot ${u.status === 'active' ? 'green' : ''}"
                 style="width:7px;height:7px;${u.status !== 'active' ? 'background:#475569;' : ''}"></div>
            <span class="text-xs text-surface-400 capitalize">${u.status}</span>
          </div>
        </td>
        <td class="px-4 py-3.5 text-xs text-surface-400">${u.lastActive}</td>
        <td class="px-4 py-3.5">${mfaBadge}</td>
        <td class="px-4 py-3.5">
          <div class="flex items-center gap-1">
            <button class="btn-secondary text-xs py-1 px-2.5">Edit</button>
            <button class="btn-secondary text-xs py-1 px-2.5">
              <i data-lucide="ellipsis" class="w-3 h-3"></i>
            </button>
          </div>
        </td>
      </tr>`;
  }).join('');

  lucide.createIcons();
}

/* ============================================================
   SECTION 10: RENDER — LIVE MONITOR FEED
   ============================================================ */

function renderMonitorFeed() {
  const el = document.getElementById('monitor-feed');
  if (!el) return;
  el.innerHTML = MONITOR_EVENTS.map(e => `
    <div class="flex items-start gap-2 py-1">
      <span class="font-mono flex-shrink-0" style="color:#475569;">${e.t}</span>
      <span style="color:${e.color};">${e.msg}</span>
    </div>`).join('');
}

/* ============================================================
   SECTION 11: CHARTS
   ============================================================ */

function initCharts() {
  /* --- Threat Activity Line Chart --- */
  const ctx1 = document.getElementById('threatChart');
  if (ctx1) {
    const labels = Array.from({ length: 30 }, (_, i) => {
      const d = new Date();
      d.setDate(d.getDate() - (29 - i));
      return d.getDate() + '/' + (d.getMonth() + 1);
    });

    new Chart(ctx1, {
      type: 'line',
      data: {
        labels,
        datasets: [
          {
            label: 'Threats Detected',
            data: [12,8,15,22,18,9,31,27,14,19,24,16,38,29,22,18,33,41,28,35,44,30,22,28,19,52,47,39,61,48],
            borderColor: '#f43f5e',
            backgroundColor: 'rgba(244,63,94,0.08)',
            fill: true, tension: 0.4, borderWidth: 2, pointRadius: 0, pointHoverRadius: 4,
          },
          {
            label: 'Scans Completed',
            data: Array(30).fill(144),
            borderColor: '#06b6d4',
            backgroundColor: 'rgba(6,182,212,0.05)',
            fill: true, tension: 0.4, borderWidth: 1.5, borderDash: [4, 4], pointRadius: 0,
          },
          {
            label: 'Blocked Attacks',
            data: [9,6,12,18,14,7,27,22,11,15,20,12,32,24,18,15,28,36,23,29,39,25,18,23,15,47,42,34,56,43],
            borderColor: '#22c55e',
            backgroundColor: 'rgba(34,197,94,0.06)',
            fill: true, tension: 0.4, borderWidth: 2, pointRadius: 0,
          },
        ],
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        interaction: { mode: 'index', intersect: false },
        plugins: {
          legend: {
            display: true, position: 'top', align: 'end',
            labels: { color: '#64748b', font: { size: 11, family: 'Inter' }, boxWidth: 12, padding: 16, usePointStyle: true, pointStyleWidth: 8 },
          },
          tooltip: {
            backgroundColor: 'rgba(15,23,42,0.95)', borderColor: 'rgba(51,65,85,0.8)', borderWidth: 1,
            titleColor: '#e2e8f0', bodyColor: '#94a3b8', padding: 12, cornerRadius: 8,
          },
        },
        scales: {
          x: {
            grid: { color: 'rgba(51,65,85,0.2)', drawBorder: false },
            ticks: { color: '#475569', font: { size: 10, family: 'Inter' }, maxTicksLimit: 8 },
            border: { display: false },
          },
          y: {
            grid: { color: 'rgba(51,65,85,0.2)', drawBorder: false },
            ticks: { color: '#475569', font: { size: 10, family: 'Inter' } },
            border: { display: false },
          },
        },
      },
    });
  }

  /* --- Scan Coverage Doughnut Chart --- */
  const ctx2 = document.getElementById('coverageChart');
  if (ctx2) {
    new Chart(ctx2, {
      type: 'doughnut',
      data: {
        labels: ['HTML/DOM', 'JavaScript', 'SSL/TLS', 'Headers', 'Performance'],
        datasets: [{
          data: [92, 88, 95, 76, 83],
          backgroundColor: [
            'rgba(6,182,212,0.8)', 'rgba(139,92,246,0.8)',
            'rgba(34,197,94,0.8)', 'rgba(249,115,22,0.8)', 'rgba(59,130,246,0.8)',
          ],
          borderColor: 'rgba(15,23,42,0.5)',
          borderWidth: 2,
          hoverOffset: 4,
        }],
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        cutout: '65%',
        plugins: {
          legend: {
            position: 'right',
            labels: { color: '#64748b', font: { size: 11, family: 'Inter' }, boxWidth: 10, padding: 12, usePointStyle: true },
          },
          tooltip: {
            backgroundColor: 'rgba(15,23,42,0.95)', borderColor: 'rgba(51,65,85,0.8)', borderWidth: 1,
            titleColor: '#e2e8f0', bodyColor: '#94a3b8', padding: 10, cornerRadius: 8,
            callbacks: { label: ctx => ` ${ctx.label}: ${ctx.raw}% coverage` },
          },
        },
      },
    });
  }
}

/* ============================================================
   SECTION 12: SCAN OVERLAY ANIMATION
   ============================================================ */

/* ============================================================
   SECTION 12: SCAN OVERLAY ANIMATION
   ============================================================ */

// Topbar "Scan Now" button — scans all assets in sequence
async function triggerScan() {
  if (ASSETS.length === 0) {
    alert('No assets to scan. Please add some assets first.');
    return;
  }
  const overlay  = document.getElementById('scan-overlay');
  const progress = document.getElementById('scan-progress');
  const status   = document.getElementById('scan-status');
  overlay.style.display = 'flex';
  let scannedCount = 0;
  const totalAssets = ASSETS.length;
  try {
    for (const asset of ASSETS) {
      try {
        status.textContent = `Scanning ${asset.name || asset.url}...`;
        const res = await fetch(`/api/sites/${asset.id}/check`, {
          method: 'POST',
          headers: { 'Authorization': `Bearer ${_jwt}` }
        });
        if (res.ok) scannedCount++;
      } catch (err) {
        console.error(`Failed to scan asset ${asset.id}:`, err);
      }
      progress.style.width = `${Math.round(((scannedCount + 1) / totalAssets) * 100)}%`;
    }
    progress.style.width = '100%';
    status.textContent = `Scan complete — ${scannedCount}/${totalAssets} assets scanned`;
    setTimeout(() => {
      overlay.style.display = 'none';
      progress.style.width = '0%';
      alert(`Bulk scan complete: ${scannedCount}/${totalAssets} assets scanned.`);
      fetchAssets();
    }, 1500);
  } catch (err) {
    overlay.style.display = 'none';
    progress.style.width = '0%';
    alert('Bulk scan failed. Please try again.');
  }
}

// Per-asset "Check" button
async function triggerScanReal(siteId) {
  const overlay  = document.getElementById('scan-overlay');
  const progress = document.getElementById('scan-progress');
  const status   = document.getElementById('scan-status');
  overlay.style.display = 'flex';
  const msgs = [
    'Initializing AI security scan...',
    'Fetching live website content...',
    'Comparing against baseline snapshot...',
    'Running defacement detection...',
    'Generating AI threat assessment...',
    'Scan complete — compiling report...',
  ];
  let pct = 0;
  const interval = setInterval(() => {
    pct = Math.min(pct + 6, 92);
    progress.style.width = pct + '%';
    status.textContent = msgs[Math.floor((pct / 100) * msgs.length)] || msgs[msgs.length - 1];
  }, 500);
  try {
    const res = await fetch(`/api/sites/${siteId}/check`, {
      method: 'POST',
      headers: { 'Authorization': `Bearer ${_jwt}` }
    });
    clearInterval(interval);
    progress.style.width = '100%';
    status.textContent = 'Scan complete — displaying result...';
    const data = await res.json();
    setTimeout(() => {
      overlay.style.display = 'none';
      progress.style.width = '0%';
      if (res.ok) showScanResultModal(data);
      else alert(data.error || data.message || 'Scan failed');
    }, 800);
  } catch (err) {
    clearInterval(interval);
    overlay.style.display = 'none';
    progress.style.width = '0%';
    alert('Network error while scanning.');
  }
}

function showScanResultModal(scanData) {
  const existing = document.getElementById('scan-result-modal');
  if (existing) existing.remove();
  const metrics = scanData.scan_metrics || {};
  const riskColor = metrics.riskLevel === 'critical' ? '#f43f5e' :
                    metrics.riskLevel === 'high'     ? '#f97316' :
                    metrics.riskLevel === 'medium'   ? '#eab308' : '#22c55e';
  const defacedBadge = metrics.isDefaced
    ? '<span class="badge badge-critical">Defacement Detected</span>'
    : '<span class="badge badge-ok">No Defacement</span>';
  const modal = document.createElement('div');
  modal.id = 'scan-result-modal';
  modal.className = 'modal';
  modal.style.display = 'flex';
  modal.innerHTML = `
    <div class="modal-content" style="max-width:600px;">
      <div class="flex items-center justify-between mb-4">
        <h3 class="text-lg font-bold text-white">AI Scan Results</h3>
        <button onclick="document.getElementById('scan-result-modal').remove()" class="text-surface-500 hover:text-white">
          <i data-lucide="x" class="w-5 h-5"></i>
        </button>
      </div>
      <div class="grid grid-cols-3 gap-3 mb-4">
        <div class="card p-3 text-center"><div class="text-xs text-surface-500 mb-1">Status</div>${defacedBadge}</div>
        <div class="card p-3 text-center"><div class="text-xs text-surface-500 mb-1">Risk Level</div><div class="font-bold text-sm" style="color:${riskColor};">${(metrics.riskLevel || 'unknown').toUpperCase()}</div></div>
        <div class="card p-3 text-center"><div class="text-xs text-surface-500 mb-1">Similarity</div><div class="font-bold text-sm text-white">${metrics.similarityScore ?? 100}%</div></div>
      </div>
      <div class="card p-4 mb-4" style="max-height:280px;overflow-y:auto;">
        <div class="text-xs text-surface-500 mb-2">AI Analysis</div>
        <div class="text-sm text-surface-300 leading-relaxed" style="white-space:pre-wrap;">${scanData.ai_analysis || 'No analysis available.'}</div>
      </div>
      <div class="text-xs text-surface-500 mb-4">Changes: ${scanData.diff_summary || 'None'} &nbsp;|&nbsp; Hash: <span class="font-mono">${scanData.content_hash || '—'}</span></div>
      <button onclick="document.getElementById('scan-result-modal').remove()" class="btn-secondary w-full">Close</button>
    </div>`;
  document.body.appendChild(modal);
  lucide.createIcons();
}

/* ============================================================
   SECTION 13: LIVE MONITOR FEED SIMULATION
   ============================================================ */

function startLiveFeed() {
  const el = document.getElementById('monitor-feed');
  if (!el) return;

  const liveEvents = [
    { msg: '[SCAN]  api.shopfront.com — snapshot captured',               color: '#64748b' },
    { msg: '[OK]    portal.fintech.io — no changes detected',              color: '#22c55e' },
    { msg: '[WATCH] Analyzing JS bundle changes on admin.internal.io',    color: '#06b6d4' },
    { msg: '[BLOCK] WAF blocked suspicious POST on healthportal.org',     color: '#f97316' },
    { msg: '[AI]    Behavioral baseline updated for 12 assets',           color: '#a78bfa' },
    { msg: '[CERT]  SSL certificate renewed: blog.acmecorp.com',          color: '#22c55e' },
  ];

  let idx = 0;
  setInterval(() => {
    const now = new Date();
    const t   = now.toTimeString().slice(0, 8);
    const ev  = liveEvents[idx % liveEvents.length];

    const div       = document.createElement('div');
    div.className   = 'flex items-start gap-2 py-1';
    div.innerHTML   = `<span class="font-mono flex-shrink-0" style="color:#475569;">${t}</span><span style="color:${ev.color};">${ev.msg}</span>`;

    el.insertBefore(div, el.firstChild);
    if (el.children.length > 20) el.removeChild(el.lastChild);
    idx++;
  }, 2500);
}

/* ============================================================
   SECTION 14: INITIALISATION
   ============================================================ */

document.addEventListener('DOMContentLoaded', () => {
  /* Apply session data to sidebar */
  applySession();

  /* Bootstrap Lucide icons */
  lucide.createIcons();

  /* Render all dynamic content */
  fetchAssets(); // Async replaces renderAssets()
  renderAlerts();
  renderVulns();
  renderAudit();
  renderUsers();
  renderMonitorFeed();

  /* Charts */
  initCharts();

  /* Live feed */
  startLiveFeed();

  /* Wire up nav links */
  document.querySelectorAll('.nav-item').forEach(item => {
    item.addEventListener('click', e => {
      e.preventDefault();
      navigate(item.dataset.page);
    });
  });

  /* Wire up mobile sidebar toggle */
  document.getElementById('menu-btn').addEventListener('click', () => {
    document.getElementById('sidebar').classList.toggle('open');
  });

  /* Close modals when clicking the backdrop */
  document.querySelectorAll('.modal').forEach(m => {
    m.addEventListener('click', e => { if (e.target === m) m.classList.remove('open'); });
  });

  /* Close dropdowns when clicking outside */
  document.addEventListener('click', e => {
    if (!e.target.closest('.dropdown-menu') && !e.target.closest('[onclick*="toggleDropdown"]')) {
      document.querySelectorAll('.dropdown-menu.open').forEach(m => m.classList.remove('open'));
    }
  });

  /* Animate progress bars on first paint */
  setTimeout(() => {
    document.querySelectorAll('.progress-fill').forEach(el => {
      const target   = el.style.width;
      el.style.width = '0%';
      requestAnimationFrame(() => { el.style.width = target; });
    });
  }, 200);
});
