/* ============================================================
   AEGIS Security Platform — Application JavaScript
   ============================================================ */

/* ============================================================
   SECTION 0: AUTH GUARD + SESSION
   ============================================================ */

const _session = JSON.parse(sessionStorage.getItem('aegis_user') || 'null');

// Redirect to login if no session
if (!_session) {
  window.location.href = 'login.html';
}

// Populate sidebar user info from session
function applySession() {
  if (!_session) return;
  const avatarEl   = document.getElementById('user-avatar');
  const nameEl     = document.getElementById('user-name');
  const roleEl     = document.getElementById('user-role');
  if (avatarEl) avatarEl.textContent = _session.avatar || '??';
  if (nameEl)   nameEl.textContent   = _session.name   || 'User';
  if (roleEl)   roleEl.textContent   = _session.role   || 'Member';
}

// Open profile panel
function openProfilePanel() {
  const panel = document.getElementById('profile-panel');
  if (!panel || !_session) return;
  document.getElementById('pp-avatar').textContent  = _session.avatar   || '??';
  document.getElementById('pp-name').textContent    = _session.name     || '—';
  document.getElementById('pp-email').textContent   = _session.email    || '—';
  document.getElementById('pp-phone').textContent   = _session.phone    || 'Not provided';
  document.getElementById('pp-role').textContent    = _session.role     || '—';
  document.getElementById('pp-method').textContent  = _session.method   === 'google' ? 'Google OAuth' : 'Email & Password';
  const d = new Date(_session.loginTime);
  document.getElementById('pp-login').textContent   = isNaN(d) ? '—' : d.toLocaleString();
  panel.classList.add('open');
  document.querySelectorAll('.dropdown-menu.open').forEach(m => m.classList.remove('open'));
}

function closeProfilePanel() {
  const panel = document.getElementById('profile-panel');
  if (panel) panel.classList.remove('open');
}

function doSignOut() {
  sessionStorage.removeItem('aegis_user');
  window.location.href = 'login.html';
}

/* ============================================================
   SECTION 1: DATA
   ============================================================ */

const ASSETS = [
  { name: 'ShopFront API',       url: 'api.shopfront.com',        status: 'compromised', risk: 94, lastScan: '2 min ago',  ssl: '142 days', vulns: { critical:1, high:2, medium:1, low:0 } },
  { name: 'FinTech Portal',      url: 'portal.fintech.io',        status: 'warning',     risk: 72, lastScan: '18 min ago', ssl: '67 days',  vulns: { critical:0, high:1, medium:3, low:1 } },
  { name: 'Health Portal',       url: 'www.healthportal.org',     status: 'warning',     risk: 61, lastScan: '1 hr ago',   ssl: '89 days',  vulns: { critical:0, high:1, medium:2, low:2 } },
  { name: 'Gov Data Legacy',     url: 'legacy.govdata.net',       status: 'healthy',     risk: 38, lastScan: '2 hr ago',   ssl: '8 days',   vulns: { critical:0, high:0, medium:1, low:3 } },
  { name: 'Corporate Blog',      url: 'blog.acmecorp.com',        status: 'healthy',     risk: 18, lastScan: '3 hr ago',   ssl: '201 days', vulns: { critical:0, high:0, medium:0, low:1 } },
  { name: 'E-Commerce Main',     url: 'shop.retailhub.net',       status: 'healthy',     risk: 24, lastScan: '4 hr ago',   ssl: '115 days', vulns: { critical:0, high:0, medium:1, low:0 } },
  { name: 'Admin Dashboard',     url: 'admin.internal.io',        status: 'healthy',     risk: 31, lastScan: '5 hr ago',   ssl: '78 days',  vulns: { critical:0, high:1, medium:0, low:0 } },
  { name: 'Mobile API',          url: 'api.mobileapp.dev',        status: 'healthy',     risk: 22, lastScan: '6 hr ago',   ssl: '290 days', vulns: { critical:0, high:0, medium:1, low:1 } },
  { name: 'Auth Service',        url: 'auth.services.io',         status: 'healthy',     risk: 19, lastScan: '7 hr ago',   ssl: '44 days',  vulns: { critical:0, high:0, medium:0, low:2 } },
  { name: 'Analytics Platform',  url: 'analytics.biztools.com',   status: 'healthy',     risk: 15, lastScan: '8 hr ago',   ssl: '156 days', vulns: { critical:0, high:0, medium:0, low:0 } },
  { name: 'CDN Edge Node',       url: 'cdn.globalassets.net',     status: 'healthy',     risk: 12, lastScan: '9 hr ago',   ssl: '320 days', vulns: { critical:0, high:0, medium:0, low:0 } },
  { name: 'Staging Env',         url: 'staging.devteam.app',      status: 'healthy',     risk: 28, lastScan: '12 hr ago',  ssl: '55 days',  vulns: { critical:0, high:0, medium:1, low:2 } },
];

const ALERTS = [
  {
    id: 'INC-2847', title: 'Website Defacement Detected',
    asset: 'api.shopfront.com', severity: 'critical', status: 'open', time: '2 min ago',
    desc: 'Homepage HTML structure changed by 34%. Possible content injection attack.',
    ai: 'Attacker injected script tags and modified visible content. Recommend immediate rollback and forensic analysis.'
  },
  {
    id: 'INC-2846', title: 'SQL Injection Attack Blocked',
    asset: 'portal.fintech.io', severity: 'high', status: 'investigating', time: '18 min ago',
    desc: '47 SQL injection attempts blocked in 5 minutes from IP 185.220.101.45.',
    ai: 'Coordinated automated attack. IP belongs to known Tor exit node. Recommend permanent block.'
  },
  {
    id: 'INC-2845', title: 'Unusual Bot Traffic Spike',
    asset: 'www.healthportal.org', severity: 'medium', status: 'open', time: '1 hr ago',
    desc: 'Request rate 340% above baseline. Possible DDoS reconnaissance.',
    ai: 'Traffic pattern consistent with credential stuffing preparation. Enable rate limiting.'
  },
  {
    id: 'INC-2844', title: 'SSL Certificate Near Expiry',
    asset: 'legacy.govdata.net', severity: 'medium', status: 'open', time: '3 hr ago',
    desc: 'SSL certificate expires in 8 days. Service disruption imminent if not renewed.',
    ai: "Auto-renewal appears disabled. Contact certificate authority or enable Let's Encrypt."
  },
  {
    id: 'INC-2843', title: 'Admin Panel Bruteforce Attempt',
    asset: 'admin.internal.io', severity: 'high', status: 'open', time: '4 hr ago',
    desc: '230 failed login attempts from 3 IPs in 10 minutes.',
    ai: 'Brute force pattern detected. Implement account lockout, enable MFA, geo-block suspicious IPs.'
  },
  {
    id: 'INC-2842', title: 'New Vulnerability: CVE-2025-3841',
    asset: 'Multiple (3 assets)', severity: 'critical', status: 'open', time: '6 hr ago',
    desc: 'Critical XSS vulnerability in login form affecting 3 monitored assets.',
    ai: 'Patch available. Upgrade frontend validation library to v3.2.1 or later.'
  },
  {
    id: 'INC-2841', title: 'Security Header Misconfiguration',
    asset: 'staging.devteam.app', severity: 'low', status: 'resolved', time: '1 day ago',
    desc: 'Missing HSTS, CSP, and X-Frame-Options headers on staging environment.',
    ai: 'Fixed by adding headers to nginx.conf. Verify across all environments.'
  },
];

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

const AUDIT_LOGS = [
  { actor: 'Abhijith Kasyap', action: 'Triggered emergency scan on all assets',                             type: 'security',    time: '14:04:33', icon: 'radar',         color: '#f43f5e' },
  { actor: 'AI Engine',       action: 'Defacement detected on api.shopfront.com — Alert INC-2847 created',  type: 'security',    time: '14:02:14', icon: 'zap',           color: '#f43f5e' },
  { actor: 'System',          action: 'Scheduled scan completed — 12/12 assets scanned',                    type: 'system',      time: '14:00:01', icon: 'check-circle',  color: '#22c55e' },
  { actor: 'Priya Sharma',    action: 'Updated role: James Wilson → Security Analyst',                      type: 'access',      time: '13:45:22', icon: 'user-check',    color: '#06b6d4' },
  { actor: 'AI Engine',       action: 'CVE-2025-3841 matched against 3 monitored assets',                   type: 'security',    time: '13:30:11', icon: 'brain-circuit', color: '#a78bfa' },
  { actor: 'Abhijith Kasyap', action: 'Added asset: cdn.globalassets.net to monitoring',                    type: 'config',      time: '12:55:04', icon: 'plus-circle',   color: '#06b6d4' },
  { actor: 'System',          action: 'SOC 2 compliance report auto-generated',                              type: 'compliance',  time: '12:00:00', icon: 'file-check-2',  color: '#7c3aed' },
  { actor: 'James Wilson',    action: 'Exported vulnerability report (PDF)',                                 type: 'access',      time: '11:34:17', icon: 'download',      color: '#64748b' },
  { actor: 'Priya Sharma',    action: 'Dismissed alert INC-2839 as false positive',                         type: 'security',    time: '11:10:09', icon: 'x-circle',      color: '#f59e0b' },
  { actor: 'System',          action: 'INC-2841 auto-resolved: headers now present after deploy',           type: 'system',      time: '10:45:00', icon: 'shield-check',  color: '#22c55e' },
];

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

function renderAssets() {
  const tbody = document.getElementById('assets-tbody');
  if (!tbody) return;

  const statusMap = {
    compromised: { dot: 'red',    label: 'Compromised', badge: 'badge-critical' },
    warning:     { dot: 'yellow', label: 'Warning',     badge: 'badge-high'     },
    healthy:     { dot: 'green',  label: 'Healthy',     badge: 'badge-ok'       },
  };

  tbody.innerHTML = ASSETS.map(a => {
    const s         = statusMap[a.status];
    const riskColor = a.risk >= 70 ? '#f43f5e' : a.risk >= 50 ? '#f97316' : a.risk >= 30 ? '#eab308' : '#22c55e';
    const sslDays   = parseInt(a.ssl);
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
            <button class="btn-secondary text-xs py-1 px-2.5" onclick="navigate('monitoring')">
              <i data-lucide="activity" class="w-3 h-3"></i>
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

function addAssetDemo() {
  closeModal('add-asset-modal');
  ASSETS.push({ name: 'New Asset', url: 'example.com', status: 'healthy', risk: 10, lastScan: 'Just added', ssl: '365 days', vulns: { critical:0, high:0, medium:0, low:0 } });
  renderAssets();
  navigate('assets');
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

  el.innerHTML = ALERTS.map(a => {
    const s = sevMap[a.severity];
    const actionBtn = a.status !== 'resolved'
      ? `<button class="btn-primary  text-xs py-1.5 px-3">Investigate</button>`
      : `<button class="btn-secondary text-xs py-1.5 px-3">View</button>`;

    return `
      <div class="p-5 hover:bg-surface-900/50 transition-all" style="${a.status === 'resolved' ? 'opacity:0.65;' : ''}">
        <div class="flex items-start gap-4">
          <div class="w-10 h-10 rounded-xl flex items-center justify-center flex-shrink-0" style="background:${s.bg};">
            <i data-lucide="${s.icon}" class="w-5 h-5" style="color:${s.color};"></i>
          </div>
          <div class="flex-1 min-w-0">
            <div class="flex items-center gap-3 flex-wrap mb-1">
              <span class="text-sm font-semibold text-white">${a.title}</span>
              <span class="badge ${s.badge}" style="font-size:10px;">${a.severity.charAt(0).toUpperCase() + a.severity.slice(1)}</span>
              ${statusBadge[a.status]}
              <span class="text-xs text-surface-500 font-mono">${a.id}</span>
            </div>
            <div class="text-xs text-surface-400 mb-1">${a.asset} — ${a.time}</div>
            <div class="text-xs text-surface-500 mb-2">${a.desc}</div>
            <div class="flex items-start gap-2 p-2.5 rounded-lg" style="background:rgba(139,92,246,0.08);border:1px solid rgba(139,92,246,0.2);">
              <i data-lucide="brain-circuit" class="w-3.5 h-3.5 flex-shrink-0 mt-0.5" style="color:#a78bfa;"></i>
              <span class="text-xs" style="color:#c4b5fd;">
                <strong style="color:#a78bfa;">AI:</strong> ${a.ai}
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

function renderAudit() {
  const el = document.getElementById('audit-timeline');
  if (!el) return;

  el.innerHTML = `<div class="timeline-line"></div>` + AUDIT_LOGS.map(log => `
    <div class="relative pl-12 pb-5 last:pb-0">
      <div class="absolute left-0 w-10 h-10 rounded-full flex items-center justify-center z-10"
           style="background:rgba(15,23,42,0.9);border:2px solid ${log.color}30;box-shadow:0 0 12px ${log.color}20;">
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

function triggerScan() {
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
    pct += 10;
    progress.style.width = pct + '%';
    status.textContent   = msgs[Math.floor(pct / 10) - 1] || msgs[msgs.length - 1];

    if (pct >= 100) {
      clearInterval(interval);
      setTimeout(() => {
        overlay.style.display = 'none';
        progress.style.width  = '0%';
      }, 1200);
    }
  }, 280);
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
  renderAssets();
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
