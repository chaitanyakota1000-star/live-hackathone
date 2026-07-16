/* ============================================================
   AEGIS Security Platform — Application JavaScript
   ============================================================ */

/* ============================================================
   SECTION 0: AUTH GUARD + SESSION
   ============================================================ */

// Configuration
window.API_BASE_URL = 'https://system-siege-backend.onrender.com';

const _jwt = localStorage.getItem('jwt');
let _session = null;

// Redirect to login if no session
if (!_jwt) {
  window.location.href = 'login.html';
}

// Populate sidebar user info from session
async function applySession() {
  if (!_jwt) return;
  try {
    const res = await fetch(`${window.API_BASE_URL}/api/me`, {
      headers: { 'Authorization': `Bearer ${_jwt}` }
    });
    if (!res.ok) {
      if (res.status === 401 || res.status === 403) doSignOut();
      throw new Error('API missing');
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
  window.location.href = 'login.html';
}

/* ============================================================
   SECTION 1: DATA
   ============================================================ */

let ALERTS = [];

async function fetchAlerts() {
  try {
    const res = await fetch(`${window.API_BASE_URL}/api/alerts`, {
      headers: { 'Authorization': `Bearer ${_jwt}` }
    });
    if (res.ok) {
      ALERTS = await res.json();
      renderAlerts();
    } else {
      throw new Error('API missing');
    }
  } catch (err) {
    console.error('Failed to fetch alerts', err);
  }
}

// Call on load
if (_jwt) {
  fetchAlerts();
  fetchStats();
  fetchAuditLogs();
}

async function fetchStats() {
  try {
    const res = await fetch(`${window.API_BASE_URL}/api/stats`, {
      headers: { 'Authorization': `Bearer ${_jwt}` }
    });
    if (res.ok) {
      const stats = await res.json();
      
      const elSites = document.getElementById('stat-total-sites');
      const elCritical = document.getElementById('stat-critical-alerts');
      const elWarning = document.getElementById('stat-warning-alerts');
      const elScans = document.getElementById('stat-total-scans');
      const badgeLastScan = document.getElementById('badge-last-scan');

      if (elSites) elSites.textContent = stats.totalSites;
      if (elCritical) elCritical.textContent = stats.criticalAlerts;
      if (elWarning) elWarning.textContent = stats.warningAlerts;
      if (elScans) elScans.textContent = stats.totalScans;
      
      if (badgeLastScan) {
        if (stats.lastScanTime) {
          const date = new Date(stats.lastScanTime);
          const now = new Date();
          const diffMs = now - date;
          const diffMins = Math.floor(diffMs / 60000);
          if (diffMins < 60) {
            badgeLastScan.textContent = diffMins === 0 ? 'Just now' : `${diffMins}m ago`;
          } else if (diffMins < 1440) {
            badgeLastScan.textContent = `${Math.floor(diffMins / 60)}h ago`;
          } else {
            badgeLastScan.textContent = `${Math.floor(diffMins / 1440)}d ago`;
          }
        } else {
          badgeLastScan.textContent = 'N/A';
        }
      }
    } else {
      throw new Error('API missing');
    }
  } catch (err) {
    console.error('Failed to fetch stats', err);
  }
}

const VULNS = [
  { id: 'CVE-2025-3841',  name: 'Cross-Site Scripting (XSS)', asset: 'api.shopfront.com',    cvss: 9.1, severity: 'critical', priority: 'P0', status: 'open' },
  { id: 'CVE-2025-4190',  name: 'SQL Injection',               asset: 'portal.fintech.io',    cvss: 7.8, severity: 'high',     priority: 'P1', status: 'open' },
  { id: 'CVE-2024-8821',  name: 'Path Traversal',              asset: 'admin.internal.io',    cvss: 7.2, severity: 'high',     priority: 'P1', status: 'investigating' },
  { id: 'CVE-2025-1122',  name: 'Remote Code Execution',       asset: 'api.mobileapp.dev',    cvss: 9.8, severity: 'critical', priority: 'P0', status: 'open' },
  { id: 'CVE-2024-9934',  name: 'SSRF Vulnerability',          asset: 'portal.fintech.io',    cvss: 8.1, severity: 'high',     priority: 'P1', status: 'open' },
  { id: 'MISCONFIG-022',  name: 'Missing Security Headers',    asset: 'staging.devteam.app',  cvss: 5.8, severity: 'medium',   priority: 'P2', status: 'resolved' },
  { id: 'TLS-WEAK-001',   name: 'Weak TLS Configuration',      asset: 'legacy.govdata.net',   cvss: 5.5, severity: 'medium',   priority: 'P2', status: 'open' },
  { id: 'INFO-LEAK-008',  name: 'Server Version Disclosure',   asset: 'Multiple',             cvss: 3.1, severity: 'low',      priority: 'P3', status: 'open' },
];

let AUDIT_LOGS = [];

const USERS = [
  { name: 'Abhijith Kasyap',     email: 'a.kasyap@company.com',    role: 'Super Admin',       status: 'active',   lastActive: 'Now',        mfa: true,  avatar: 'AK', color: 'linear-gradient(135deg, #0891b2, #7c3aed)' },
  { name: 'Priya Sharma',        email: 'p.sharma@company.com',    role: 'Super Admin',       status: 'active',   lastActive: '5 min ago',  mfa: true,  avatar: 'PS', color: 'linear-gradient(135deg, #7c3aed, #ec4899)' },
  { name: 'James Wilson',        email: 'j.wilson@company.com',    role: 'Security Analyst',  status: 'active',   lastActive: '1 hr ago',   mfa: true,  avatar: 'JW', color: 'linear-gradient(135deg, #0891b2, #06b6d4)' },
  { name: 'Sarah Chen',          email: 's.chen@company.com',      role: 'Security Analyst',  status: 'active',   lastActive: '2 hr ago',   mfa: false, avatar: 'SC', color: 'linear-gradient(135deg, #059669, #06b6d4)' },
  { name: 'Mohammed Al-Rashid',  email: 'm.alrashid@company.com',  role: 'Security Analyst',  status: 'active',   lastActive: '4 hr ago',   mfa: true,  avatar: 'MA', color: 'linear-gradient(135deg, #d97706, #dc2626)' },
  { name: 'Lisa Park',           email: 'l.park@company.com',      role: 'Operator',          status: 'active',   lastActive: '1 day ago',  mfa: true,  avatar: 'LP', color: 'linear-gradient(135deg, #7c3aed, #06b6d4)' },
  { name: 'Tom Bradley',         email: 't.bradley@company.com',   role: 'Read-Only',         status: 'inactive', lastActive: '5 days ago', mfa: false, avatar: 'TB', color: 'linear-gradient(135deg, #475569, #334155)' },
];

const MONITOR_EVENTS = [
  { t: '14:04:33', msg: '[ALERT] Defacement confirmed on api.shopfront.com',         color: '#f43f5e' },
  { t: '14:04:12', msg: '[SCAN]  Snapshot diff analysis complete — 34% change',      color: '#f97316' },
  { t: '14:03:55', msg: '[AI]    Content injection pattern detected (confidence: 96%)', color: '#a78bfa' },
  { t: '14:02:14', msg: '[DETECT] Unauthorized DOM modification detected',            color: '#f43f5e' },
  { t: '14:02:01', msg: '[SCAN]  Snapshot taken: api.shopfront.com/index.html',      color: '#94a3b8' },
  { t: '14:00:01', msg: '[SCAN]  Scheduled scan started — 12 assets queued',         color: '#06b6d4' },
  { t: '13:59:44', msg: '[OK]    portal.fintech.io — No changes detected',            color: '#22c55e' },
  { t: '13:59:31', msg: '[OK]    www.healthportal.org — No changes detected',         color: '#22c55e' },
  { t: '13:55:22', msg: '[OK]    legacy.govdata.net — No changes detected',           color: '#22c55e' },
  { t: '13:50:11', msg: '[BLOCK] 47 SQLi attempts blocked from 185.220.101.45',      color: '#f97316' },
  { t: '13:45:00', msg: '[OK]    admin.internal.io — No changes detected',            color: '#22c55e' },
  { t: '13:40:00', msg: '[OK]    shop.retailhub.net — No changes detected',           color: '#22c55e' },
];

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
    const res = await fetch(`${window.API_BASE_URL}/api/sites`, {
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
    } else {
      throw new Error('API missing');
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
            <button class="btn-secondary text-xs py-1 px-2.5" onclick="openHistory(${a.id}, '${a.name}')" title="View History">
              <i data-lucide="history" class="w-3 h-3"></i>
            </button>
            <button class="btn-secondary text-xs py-1 px-2.5 text-critical-400 hover:text-critical-300" onclick="deleteSite(${a.id}, '${a.name}')" title="Delete Site">
              <i data-lucide="trash-2" class="w-3 h-3"></i>
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
    const res = await fetch(`${window.API_BASE_URL}/api/sites`, {
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

async function deleteSite(siteId, siteName) {
  if (!confirm(`Are you sure you want to permanently delete the site "${siteName}" and all its history?`)) {
    return;
  }
  
  try {
    const res = await fetch(`${window.API_BASE_URL}/api/sites/${siteId}`, {
      method: 'DELETE',
      headers: { 'Authorization': `Bearer ${_jwt}` }
    });
    
    if (res.ok) {
      await fetchAssets();
    } else {
      const data = await res.json().catch(() => ({}));
      if (res.status === 401 || res.status === 403) {
        alert('Unauthorized: You do not have permission to delete this site.');
      } else if (res.status === 404) {
        alert('Site not found. It may have already been deleted.');
        await fetchAssets();
      } else {
        alert(data.message || data.error || 'Server error while deleting site.');
      }
    }
  } catch (err) {
    console.error(err);
    alert('Network error while deleting site.');
  }
}

/* ============================================================
   SECTION 6: RENDER — ALERTS LIST
   ============================================================ */

function renderAlerts() {
  const el = document.getElementById('alerts-list');
  if (!el) return;

  const sevMap = {
    critical: { badge: 'badge-critical', icon: 'zap',           bg: 'rgba(244,63,94,0.12)',  color: '#f43f5e' },
    high:     { badge: 'badge-high',     icon: 'triangle-alert', bg: 'rgba(249,115,22,0.12)', color: '#f97316' },
    medium:   { badge: 'badge-medium',   icon: 'info',           bg: 'rgba(234,179,8,0.12)',  color: '#eab308' },
    low:      { badge: 'badge-low',      icon: 'check-circle',   bg: 'rgba(34,197,94,0.12)',  color: '#22c55e' },
  };

  const statusBadge = {
    open:          '<span class="badge badge-critical"  style="font-size:10px;">Open</span>',
    investigating: '<span class="badge badge-medium"    style="font-size:10px;">Investigating</span>',
    resolved:      '<span class="badge badge-ok"        style="font-size:10px;">Resolved</span>',
  };

  if (ALERTS.length === 0) {
    el.innerHTML = '<div class="p-5 text-center text-sm text-surface-500">No active alerts.</div>';
    return;
  }

  el.innerHTML = ALERTS.map(a => {
    // Determine severity, defaulting to low if not mapped
    const severity = (a.severity || 'low').toLowerCase();
    const s = sevMap[severity] || sevMap['low'];
    const title = 'Security Scan Anomaly';
    const timeStr = new Date(a.created_at).toLocaleString();
    const status = 'open'; // DB schema does not have status yet
    const actionBtn = `<button class="btn-primary text-xs py-1.5 px-3">Investigate</button>`;

    return `
      <div class="p-5 hover:bg-surface-900/50 transition-all">
        <div class="flex items-start gap-4">
          <div class="w-10 h-10 rounded-xl flex items-center justify-center flex-shrink-0" style="background:${s.bg};">
            <i data-lucide="${s.icon}" class="w-5 h-5" style="color:${s.color};"></i>
          </div>
          <div class="flex-1 min-w-0">
            <div class="flex items-center gap-3 flex-wrap mb-1">
              <span class="text-sm font-semibold text-white">${title}</span>
              <span class="badge ${s.badge}" style="font-size:10px;">${severity.charAt(0).toUpperCase() + severity.slice(1)}</span>
              ${statusBadge[status]}
              <span class="text-xs text-surface-500 font-mono">ID: ${a.id}</span>
            </div>
            <div class="text-xs text-surface-400 mb-1">${a.asset_name} — ${timeStr}</div>
            <div class="flex items-start gap-2 p-2.5 rounded-lg mt-2" style="background:rgba(139,92,246,0.08);border:1px solid rgba(139,92,246,0.2);">
              <i data-lucide="brain-circuit" class="w-3.5 h-3.5 flex-shrink-0 mt-0.5" style="color:#a78bfa;"></i>
              <span class="text-xs" style="color:#c4b5fd;">
                <strong style="color:#a78bfa;">AI:</strong> ${a.message}
              </span>
            </div>
          </div>
          <div class="flex items-center gap-2 flex-shrink-0">${actionBtn}</div>
        </div>
      </div>`;
  }).join('');

  lucide.createIcons();
}

/* ============================================================
   SECTION 7: RENDER — VULNERABILITIES TABLE
   ============================================================ */

function renderVulns() {
  const tbody = document.getElementById('vuln-tbody');
  if (!tbody) return;

  const sevBadge     = { critical: 'badge-critical', high: 'badge-high', medium: 'badge-medium', low: 'badge-low' };
  const priorityColor = { P0: '#f43f5e', P1: '#f97316', P2: '#eab308', P3: '#22c55e' };
  const statusBadge  = {
    open:          '<span class="badge badge-critical" style="font-size:9px;">Open</span>',
    investigating: '<span class="badge badge-medium"   style="font-size:9px;">Investigating</span>',
    resolved:      '<span class="badge badge-ok"       style="font-size:9px;">Resolved</span>',
  };

  tbody.innerHTML = VULNS.map(v => {
    const cvssColor = v.cvss >= 9 ? '#f43f5e' : v.cvss >= 7 ? '#f97316' : v.cvss >= 4 ? '#eab308' : '#22c55e';
    return `
      <tr class="table-row">
        <td class="px-5 py-3.5 font-mono text-xs text-aegis-400">${v.id}</td>
        <td class="px-4 py-3.5 text-sm font-medium text-white">${v.name}</td>
        <td class="px-4 py-3.5 text-xs text-surface-400">${v.asset}</td>
        <td class="px-4 py-3.5"><span class="text-sm font-bold" style="color:${cvssColor};">${v.cvss}</span></td>
        <td class="px-4 py-3.5">
          <span class="badge ${sevBadge[v.severity]}" style="font-size:10px;">
            ${v.severity.charAt(0).toUpperCase() + v.severity.slice(1)}
          </span>
        </td>
        <td class="px-4 py-3.5">
          <span class="font-mono text-xs font-bold" style="color:${priorityColor[v.priority]};">${v.priority}</span>
        </td>
        <td class="px-4 py-3.5">${statusBadge[v.status]}</td>
        <td class="px-4 py-3.5"><button class="btn-secondary text-xs py-1 px-2.5">Details</button></td>
      </tr>`;
  }).join('');

  lucide.createIcons();
}

/* ============================================================
   SECTION 8: RENDER — AUDIT TIMELINE
   ============================================================ */

async function fetchAuditLogs() {
  const loading = document.getElementById('audit-loading');
  const error = document.getElementById('audit-error');
  const empty = document.getElementById('audit-empty');
  const table = document.getElementById('audit-table-container');

  if (loading) {
    loading.classList.remove('hidden');
    if(error) error.classList.add('hidden');
    if(empty) empty.classList.add('hidden');
    if(table) table.style.display = 'none';
  }

  try {
    const res = await fetch(`${window.API_BASE_URL}/api/audit-logs`, {
      headers: { 'Authorization': `Bearer ${_jwt}` }
    });
    if (res.ok) {
      AUDIT_LOGS = await res.json();
      renderAudit();
    } else {
      throw new Error('API missing');
    }
  } catch (err) {
    console.error('Failed to fetch audit logs', err);
    if(loading) loading.classList.add('hidden');
    if(error) error.classList.remove('hidden');
  }
}

function renderAudit() {
  const tbody = document.getElementById('audit-tbody');
  const loading = document.getElementById('audit-loading');
  const error = document.getElementById('audit-error');
  const empty = document.getElementById('audit-empty');
  const table = document.getElementById('audit-table-container');

  if (!tbody) return;
  if(loading) loading.classList.add('hidden');
  if(error) error.classList.add('hidden');

  if (AUDIT_LOGS.length === 0) {
    if(empty) empty.classList.remove('hidden');
    if(table) table.style.display = 'none';
    return;
  }

  if(empty) empty.classList.add('hidden');
  if(table) table.style.display = 'table';

  tbody.innerHTML = AUDIT_LOGS.map(log => {
    // Parse Resource from Action
    let resource = '-';
    if (log.action.includes('site ID')) {
      const match = log.action.match(/site ID (\d+)/);
      if (match) resource = `Site ${match[1]}`;
    } else if (log.action.includes('website:')) {
      const match = log.action.match(/website:\s*"(.+?)"/);
      if (match) resource = match[1];
    } else {
      resource = 'System';
    }

    const timeStr = new Date(log.created_at).toLocaleString();
    const userDisplay = log.user_email || 'System';
    const initial = userDisplay.substring(0, 1).toUpperCase();

    return `
      <tr class="table-row hover:bg-surface-800 transition-colors">
        <td class="px-5 py-3.5">
          <div class="flex items-center gap-2">
            <div class="w-6 h-6 rounded bg-surface-700 flex items-center justify-center text-xs text-white font-bold flex-shrink-0">${initial}</div>
            <span class="text-sm font-semibold text-white truncate max-w-[150px]" title="${userDisplay}">${userDisplay}</span>
          </div>
        </td>
        <td class="px-4 py-3.5 text-xs text-surface-300 max-w-[250px] truncate" title="${log.action}">${log.action}</td>
        <td class="px-4 py-3.5 text-xs text-surface-500 font-mono whitespace-nowrap">${timeStr}</td>
        <td class="px-4 py-3.5"><span class="badge badge-info truncate max-w-[150px]" title="${resource}">${resource}</span></td>
        <td class="px-4 py-3.5"><span class="badge badge-ok"><i data-lucide="check-circle" class="w-3 h-3"></i> Success</span></td>
      </tr>
    `;
  }).join('');

  lucide.createIcons();
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

async function triggerScanReal(siteId) {
  const overlay  = document.getElementById('scan-overlay');
  const progress = document.getElementById('scan-progress');
  const status   = document.getElementById('scan-status');

  overlay.style.display = 'flex';
  
  const msgs = [
    'Initializing AI security scan...',
    'Authenticating with asset endpoints...',
    'Capturing DOM snapshots...',
    'Running defacement detection algorithms...',
    'Analyzing SSL/TLS configurations...',
    'Checking security headers...',
    'Cross-referencing CVE database...',
    'Running behavioral analysis...',
    'Generating AI threat assessment...',
    'Scan complete — compiling report...',
  ];

  let pct = 0;
  const interval = setInterval(() => {
    pct = Math.min(pct + 5, 95); // wait for API
    progress.style.width = pct + '%';
    status.textContent   = msgs[Math.floor((pct/100) * msgs.length)] || msgs[msgs.length - 1];
  }, 500);

  try {
    const res = await fetch(`${window.API_BASE_URL}/api/sites/${siteId}/check`, {
      method: 'POST',
      headers: { 'Authorization': `Bearer ${_jwt}` }
    });
    
    clearInterval(interval);
    progress.style.width = '100%';
    status.textContent = 'Scan complete — displaying result...';
    
    const data = await res.json();
    
    setTimeout(() => {
      overlay.style.display = 'none';
      if (res.ok) {
        document.getElementById('scan-result-text').textContent = data.ai_analysis;
        openModal('scan-result-modal');
        
        // Refresh history if the modal is currently open for this site
        if (document.getElementById('history-modal').classList.contains('open') && window.currentHistorySiteId === siteId) {
          openHistory(siteId, document.getElementById('history-site-name').textContent);
        }
        fetchAlerts(); // Refresh alerts list
        fetchStats();  // Refresh KPIs
      } else {
        alert(data.message || data.error || 'Scan failed');
      }
    }, 1000);
    
  } catch(err) {
    console.error("Scan Network Error:", err);
    clearInterval(interval);
    overlay.style.display = 'none';
    progress.style.width  = '0%';
    alert('Network error while scanning. Check console for details.');
  }
}

/* ============================================================
   SECTION 12.5: HISTORY
   ============================================================ */

window.currentHistorySiteId = null;

async function openHistory(siteId, siteName) {
  window.currentHistorySiteId = siteId;
  const modal = document.getElementById('history-modal');
  const title = document.getElementById('history-site-name');
  const loading = document.getElementById('history-loading');
  const error = document.getElementById('history-error');
  const empty = document.getElementById('history-empty');
  const list = document.getElementById('history-list');

  // Reset states
  title.textContent = siteName;
  loading.classList.remove('hidden');
  error.classList.add('hidden');
  empty.classList.add('hidden');
  list.classList.add('hidden');
  list.innerHTML = '';
  modal.classList.add('open');

  try {
    const res = await fetch(`${window.API_BASE_URL}/api/sites/${siteId}/history`, {
      headers: { 'Authorization': `Bearer ${_jwt}` }
    });
    
    loading.classList.add('hidden');

    if (!res.ok) {
      error.classList.remove('hidden');
      document.getElementById('history-error-msg').textContent = `Failed to load history (HTTP ${res.status})`;
      return;
    }

    const data = await res.json();
    
    if (!data || data.length === 0) {
      empty.classList.remove('hidden');
      return;
    }

    renderHistory(data, list);
    list.classList.remove('hidden');
  } catch (err) {
    console.error(err);
    loading.classList.add('hidden');
    error.classList.remove('hidden');
    document.getElementById('history-error-msg').textContent = 'Network error while loading history.';
  }
}

function renderHistory(historyData, container) {
  const sevBadge = { 
    critical: 'badge-critical', 
    high: 'badge-high', 
    medium: 'badge-medium', 
    low: 'badge-low' 
  };
  
  const sevColors = {
    critical: '#f43f5e',
    high: '#f97316',
    medium: '#eab308',
    low: '#22c55e'
  };

  container.innerHTML = historyData.map(h => {
    // Determine severity from flags if available, else default to 'low'
    const flag = h.flags && h.flags.length > 0 ? h.flags[0] : null;
    const severity = flag ? flag.severity : 'low';
    const aiSummary = flag ? flag.description : 'No anomalies detected.';
    const sBadge = sevBadge[severity] || 'badge-low';
    const sColor = sevColors[severity] || '#22c55e';
    const timestamp = new Date(h.created_at).toLocaleString();
    const hashShort = h.dom_hash ? h.dom_hash.substring(0, 8) + '...' : 'N/A';

    return `
      <div class="card p-4 hover:bg-surface-900/50 transition-colors" style="border-left: 3px solid ${sColor};">
        <div class="flex items-start justify-between mb-2">
          <div class="flex items-center gap-3">
            <span class="badge ${sBadge} text-xs uppercase tracking-wider px-2 py-0.5">${severity}</span>
            <span class="text-xs text-surface-500 font-mono"><i data-lucide="clock" class="inline w-3 h-3 mr-1"></i>${timestamp}</span>
          </div>
          <span class="text-xs text-surface-600 font-mono bg-surface-900 px-2 py-0.5 rounded" title="Snapshot Hash: ${h.dom_hash}">Snap: ${hashShort}</span>
        </div>
        <div class="mt-2 text-sm text-surface-300 leading-relaxed">
          <strong class="text-white">AI Analysis:</strong> ${aiSummary}
        </div>
      </div>
    `;
  }).join('');
  
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
