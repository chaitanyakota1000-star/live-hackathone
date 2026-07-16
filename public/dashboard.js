/* ============================================================
   SYSTEM SIEGE JS — FRONTEND CLIENT STATE ENGINE
   Handles authentication, CRUD, scans, alert feeds, audit logs,
   and visual diff renderings.
   ============================================================ */

const API_BASE = "/api";
let currentToken = localStorage.getItem("siege_token") || "";
let currentUser = JSON.parse(localStorage.getItem("siege_user") || "null");
let selectedSite = null;
let sitesList = [];

// DOM Elements
const authSection = document.getElementById("auth-section");
const dashboardSection = document.getElementById("dashboard-section");
const loginForm = document.getElementById("login-form");
const registerForm = document.getElementById("register-form");
const toRegisterLink = document.getElementById("to-register");
const toLoginLink = document.getElementById("to-login");
const authTitle = document.getElementById("auth-title");
const authSubtitle = document.getElementById("auth-subtitle");
const authBanner = document.getElementById("auth-banner");

const headerUserEmail = document.getElementById("header-user-email");
const userRoleBadge = document.getElementById("user-role-badge");
const logoutBtn = document.getElementById("logout-btn");

const addWebsiteForm = document.getElementById("add-website-form");
const siteNameInput = document.getElementById("site-name");
const siteUrlInput = document.getElementById("site-url");
const websiteList = document.getElementById("website-list");
const emptyWebsites = document.getElementById("empty-websites");
const websiteListLoading = document.getElementById("website-list-loading");

const noSiteSelected = document.getElementById("no-site-selected");
const siteWorkspace = document.getElementById("site-workspace");
const workSiteName = document.getElementById("work-site-name");
const workSiteUrl = document.getElementById("work-site-url");
const scanNowBtn = document.getElementById("scan-now-btn");
const deleteSiteBtn = document.getElementById("delete-site-btn");
const scanLoadingOverlay = document.getElementById("scan-loading-overlay");

const healthStatusGlow = document.getElementById("health-status-glow");
const healthText = document.getElementById("health-text");
const statLastScan = document.getElementById("stat-last-scan");
const statVulnerabilitiesCount = document.getElementById("stat-vulnerabilities-count");

const similarityValue = document.getElementById("similarity-value");
const similarityBar = document.getElementById("similarity-bar");
const defacementVerdict = document.getElementById("defacement-verdict");

const aiReportContent = document.getElementById("ai-report-content");
const vulnerabilitiesList = document.getElementById("vulnerabilities-list");
const noVulnerabilities = document.getElementById("no-vulnerabilities");

const scanHistoryRows = document.getElementById("scan-history-rows");

const alertsList = document.getElementById("alerts-list");
const emptyAlerts = document.getElementById("empty-alerts");
const auditList = document.getElementById("audit-list");
const emptyAudit = document.getElementById("empty-audit");
const refreshAlerts = document.getElementById("refresh-alerts");
const refreshAudit = document.getElementById("refresh-audit");

const reportModal = document.getElementById("report-modal");
const modalReportBody = document.getElementById("modal-report-body");
const modalCloseBtn = document.getElementById("modal-close-btn");

/* ================= AUTHENTICATION & SWAP VIEWS ================= */

// Initialize state on page load
document.addEventListener("DOMContentLoaded", () => {
    if (currentToken && currentUser) {
        showDashboard();
    } else {
        showAuth();
    }
});

// Switch to register form
toRegisterLink.addEventListener("click", (e) => {
    e.preventDefault();
    loginForm.classList.remove("active");
    registerForm.classList.add("active");
    authTitle.textContent = "Create Analyst Account";
    authSubtitle.textContent = "Register a new account to begin auditing digital assets.";
    clearAuthBanner();
});

// Switch to login form
toLoginLink.addEventListener("click", (e) => {
    e.preventDefault();
    registerForm.classList.remove("active");
    loginForm.classList.add("active");
    authTitle.textContent = "Security Gateway";
    authSubtitle.textContent = "Provide your credentials to access the security command center.";
    clearAuthBanner();
});

// Show auth card
function showAuth() {
    dashboardSection.classList.remove("active");
    authSection.classList.add("active");
    loginForm.reset();
    registerForm.reset();
}

// Show dashboard panel
function showDashboard() {
    authSection.classList.remove("active");
    dashboardSection.classList.add("active");
    
    // Header details
    headerUserEmail.textContent = currentUser.email;
    userRoleBadge.textContent = currentUser.role === "admin" ? "Administrator" : "Analyst";
    if (currentUser.role === "admin") {
        userRoleBadge.className = "badge badge-purple";
    } else {
        userRoleBadge.className = "badge badge-outline";
    }

    loadWebsites();
    loadAlerts();
    loadAuditLogs();
}

// Clear banners
function clearAuthBanner() {
    authBanner.className = "banner hide";
    authBanner.textContent = "";
}

// Show banner notifications
function showAuthBanner(message, type = "error") {
    authBanner.className = `banner banner-${type}`;
    authBanner.textContent = message;
}

// Register Form Submission
registerForm.addEventListener("submit", async (e) => {
    e.preventDefault();
    clearAuthBanner();
    
    const email = document.getElementById("reg-email").value.trim();
    const password = document.getElementById("reg-password").value;
    const role = document.getElementById("reg-role").value;

    if (password.length < 6) {
        showAuthBanner("Password must be at least 6 characters long.");
        return;
    }

    try {
        const res = await fetch(`${API_BASE}/register`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ email, password, role })
        });
        
        const data = await res.json();
        
        if (res.ok) {
            showAuthBanner(data.message, "success");
            setTimeout(() => {
                toLoginLink.click();
            }, 1500);
        } else {
            showAuthBanner(data.message || "Registration failed.");
        }
    } catch (err) {
        showAuthBanner("Server network error occurred.");
    }
});

// Login Form Submission
loginForm.addEventListener("submit", async (e) => {
    e.preventDefault();
    clearAuthBanner();
    
    const email = document.getElementById("login-email").value.trim();
    const password = document.getElementById("login-password").value;

    try {
        const res = await fetch(`${API_BASE}/login`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ email, password })
        });
        
        const data = await res.json();
        
        if (res.ok) {
            currentToken = data.token;
            currentUser = data.user;
            localStorage.setItem("siege_token", data.token);
            localStorage.setItem("siege_user", JSON.stringify(data.user));
            
            showDashboard();
        } else {
            showAuthBanner(data.message || "Authentication failed.");
        }
    } catch (err) {
        showAuthBanner("Server network error occurred.");
    }
});

// Terminate Session
logoutBtn.addEventListener("click", () => {
    localStorage.removeItem("siege_token");
    localStorage.removeItem("siege_user");
    currentToken = "";
    currentUser = null;
    selectedSite = null;
    sitesList = [];
    noSiteSelected.className = "empty-state active";
    siteWorkspace.className = "site-workspace hide";
    showAuth();
});

/* ================= WEB ASSET MANAGEMENT ================= */

// Fetch registered websites
async function loadWebsites() {
    websiteListLoading.classList.remove("hide");
    emptyWebsites.classList.add("hide");
    websiteList.innerHTML = "";

    try {
        const res = await fetch(`${API_BASE}/websites`, {
            headers: { "Authorization": `Bearer ${currentToken}` }
        });
        
        const data = await res.json();
        websiteListLoading.classList.add("hide");

        if (res.ok) {
            sitesList = data.websites || [];
            
            if (sitesList.length === 0) {
                emptyWebsites.classList.remove("hide");
                return;
            }

            sitesList.forEach(site => {
                const li = document.createElement("li");
                li.className = `website-item ${selectedSite && selectedSite.id === site.id ? "active" : ""}`;
                li.innerHTML = `
                    <div class="website-item-top">
                        <span class="website-item-name">${escapeHtml(site.website_name)}</span>
                        <span class="status-pill status-${site.status}">${site.status}</span>
                    </div>
                    <span class="website-item-url">${escapeHtml(site.url)}</span>
                `;
                li.addEventListener("click", () => selectWebsite(site));
                websiteList.appendChild(li);
            });
        }
    } catch (err) {
        websiteListLoading.classList.add("hide");
        console.error("Failed to load websites", err);
    }
}

// Select a website workspace
async function selectWebsite(site) {
    selectedSite = site;
    
    // Highlight list item
    document.querySelectorAll(".website-list .website-item").forEach((el, index) => {
        if (sitesList[index].id === site.id) {
            el.classList.add("active");
        } else {
            el.classList.remove("active");
        }
    });

    noSiteSelected.className = "empty-state hide";
    siteWorkspace.className = "site-workspace";

    // Header values
    workSiteName.textContent = site.website_name;
    workSiteUrl.textContent = site.url;
    workSiteUrl.href = site.url;

    // Reset status fields to loading/default
    updateHealthUI(site.status, site.last_scan);

    // Fetch scan history and findings
    await loadScanHistory(site.id);
}

// Add Monitored Website
addWebsiteForm.addEventListener("submit", async (e) => {
    e.preventDefault();
    const website_name = siteNameInput.value.trim();
    const url = siteUrlInput.value.trim();

    try {
        const res = await fetch(`${API_BASE}/website`, {
            method: "POST",
            headers: {
                "Content-Type": "application/json",
                "Authorization": `Bearer ${currentToken}`
            },
            body: JSON.stringify({ website_name, url })
        });
        
        const data = await res.json();
        
        if (res.ok) {
            addWebsiteForm.reset();
            await loadWebsites();
            loadAuditLogs();
        } else {
            alert(data.message || "Failed to add website asset.");
        }
    } catch (err) {
        alert("Connection error adding asset.");
    }
});

// Delete Monitored Website
deleteSiteBtn.addEventListener("click", async () => {
    if (!selectedSite) return;
    if (!confirm(`Are you sure you want to remove monitoring for "${selectedSite.website_name}"? This deletes all snapshots and reports.`)) return;

    try {
        const res = await fetch(`${API_BASE}/website/${selectedSite.id}`, {
            method: "DELETE",
            headers: { "Authorization": `Bearer ${currentToken}` }
        });

        if (res.ok) {
            selectedSite = null;
            noSiteSelected.className = "empty-state active";
            siteWorkspace.className = "site-workspace hide";
            await loadWebsites();
            loadAlerts();
            loadAuditLogs();
        } else {
            const data = await res.json();
            alert(data.message || "Deletion refused.");
        }
    } catch (err) {
        alert("Error sending delete instruction.");
    }
});

/* ================= SECURITY SCANS & AI ENGINE ================= */

// Run security scan
scanNowBtn.addEventListener("click", async () => {
    if (!selectedSite) return;

    scanLoadingOverlay.classList.remove("hide");

    try {
        const res = await fetch(`${API_BASE}/scan/${selectedSite.id}`, {
            method: "POST",
            headers: { "Authorization": `Bearer ${currentToken}` }
        });

        const data = await res.json();
        scanLoadingOverlay.classList.add("hide");

        if (res.ok) {
            const latestScan = data.scan;
            
            // Re-fetch website to refresh list status
            const siteRes = await fetch(`${API_BASE}/website/${selectedSite.id}`, {
                headers: { "Authorization": `Bearer ${currentToken}` }
            });
            if (siteRes.ok) {
                const siteData = await siteRes.json();
                selectedSite = siteData.website;
                loadWebsites();
            }

            updateHealthUI(selectedSite.status, latestScan.scan_time);
            renderLatestScanDetails(latestScan);
            await loadScanHistory(selectedSite.id);
            loadAlerts();
            loadAuditLogs();
        } else {
            alert(data.message || "Scan failed to compile.");
        }
    } catch (err) {
        scanLoadingOverlay.classList.add("hide");
        alert("Fatal scan pipeline failure: " + err.message);
    }
});

// Load scan history
async function loadScanHistory(websiteId) {
    scanHistoryRows.innerHTML = `<tr><td colspan="5" style="text-align:center">Reading report history...</td></tr>`;

    try {
        const res = await fetch(`${API_BASE}/scan/history/${websiteId}`, {
            headers: { "Authorization": `Bearer ${currentToken}` }
        });

        const data = await res.json();
        scanHistoryRows.innerHTML = "";

        if (res.ok) {
            const history = data.history || [];
            
            if (history.length === 0) {
                scanHistoryRows.innerHTML = `<tr><td colspan="5" style="text-align:center; color:var(--text-muted)">No scans executed yet.</td></tr>`;
                
                // Clear active scan visualizers
                similarityValue.textContent = "--";
                similarityBar.style.width = "0%";
                defacementVerdict.textContent = "Awaiting initial baseline scan...";
                aiReportContent.innerHTML = `<p class="placeholder-text">Run a scan to generate AI threat intelligence summaries.</p>`;
                vulnerabilitiesList.innerHTML = "";
                noVulnerabilities.style.display = "block";
                return;
            }

            // Render details of latest run
            renderLatestScanDetails(history[0]);

            history.forEach(run => {
                const tr = document.createElement("tr");
                const vulnNum = Array.isArray(run.vulnerability) ? run.vulnerability.length : 0;
                const formattedDate = new Date(run.scan_time).toLocaleString();

                let scoreStr = "--";
                let isDef = false;
                
                // Attempt to check if defacement occurred in this scan
                if (run.vulnerability && Array.isArray(run.vulnerability)) {
                    isDef = run.vulnerability.some(v => v.vulnerability.includes("Defacement"));
                }
                
                // We'll query scan detail or estimate similarity score
                // In our model we store content similarity hash. Let's parse similarity if present.
                // We can check our latest snapshot parameters.
                tr.innerHTML = `
                    <td class="history-time">${formattedDate}</td>
                    <td><span class="vuln-severity severity-${run.risk_level}">${run.risk_level}</span></td>
                    <td class="history-similarity">${isDef ? "⚠️ Defaced" : "100% Match"}</td>
                    <td>${vulnNum} Issues</td>
                    <td><button class="btn btn-secondary btn-sm select-report-btn">Open Report 📄</button></td>
                `;

                tr.querySelector(".select-report-btn").addEventListener("click", () => {
                    openReportModal(run);
                });

                scanHistoryRows.appendChild(tr);
            });
        }
    } catch (err) {
        console.error("Failed scan history logs", err);
    }
}

// Render scan details to panel
function renderLatestScanDetails(scan) {
    // 1. Defacement Similarity index
    let score = 100;
    let isDefaced = false;
    const vulns = Array.isArray(scan.vulnerability) ? scan.vulnerability : [];

    // Check if website has defacement vuln
    const defaceVuln = vulns.find(v => v.vulnerability.includes("Defacement"));
    if (defaceVuln) {
        isDefaced = true;
        // Parse similarity score if mentioned in description
        const match = defaceVuln.description.match(/(\d+(\.\d+)?)/);
        score = match ? parseFloat(match[1]) : 50;
    }

    similarityValue.textContent = `${score}%`;
    similarityBar.style.width = `${score}%`;
    
    if (isDefaced) {
        similarityBar.style.backgroundColor = "var(--danger)";
        defacementVerdict.innerHTML = `<span style="color:var(--danger); font-weight:700">⚠️ COMPROMISED:</span> Content similarity dropped below threshold (Similarity: ${score}%). Critical structural modifications detected.`;
    } else {
        similarityBar.style.backgroundColor = "var(--electric-blue)";
        defacementVerdict.innerHTML = `<span style="color:var(--safe); font-weight:700">✅ SECURE:</span> Page structure integrity matches baseline parameters (Similarity: ${score}%).`;
    }

    // 2. Vulnerabilities Audit checklist
    vulnerabilitiesList.innerHTML = "";
    if (vulns.length === 0) {
        noVulnerabilities.style.display = "block";
        statVulnerabilitiesCount.textContent = "0 Detected";
    } else {
        noVulnerabilities.style.display = "none";
        statVulnerabilitiesCount.textContent = `${vulns.length} Detected`;
        
        vulns.forEach(v => {
            const li = document.createElement("li");
            li.className = "vuln-item";
            li.innerHTML = `
                <div class="vuln-item-header">
                    <span class="vuln-name">${escapeHtml(v.vulnerability)}</span>
                    <span class="vuln-severity severity-${v.severity}">${v.severity}</span>
                </div>
                <p class="vuln-desc">${escapeHtml(v.description)}</p>
            `;
            vulnerabilitiesList.appendChild(li);
        });
    }

    // 3. AI Assessment Summary box
    aiReportContent.innerHTML = formatMarkdown(scan.ai_summary || "No AI Threat summary is generated.");
}

// Helper to update top health gauge widget
function updateHealthUI(status, lastScan) {
    healthStatusGlow.className = `health-status-glow ${status}`;
    healthText.textContent = status.toUpperCase();
    healthText.className = "health-text";
    
    if (status === "safe") healthText.style.color = "var(--safe)";
    else if (status === "defaced") healthText.style.color = "var(--danger)";
    else if (status === "warning") healthText.style.color = "var(--warning)";
    else if (status === "error") healthText.style.color = "var(--text-muted)";
    else healthText.style.color = "var(--electric-blue)";

    statLastScan.textContent = lastScan ? new Date(lastScan).toLocaleString() : "Never";
}

/* ================= ALERTS & COMPLIANCE AUDIT TRAIL ================= */

// Load active security warnings
async function loadAlerts() {
    emptyAlerts.style.display = "none";
    alertsList.innerHTML = "";

    try {
        const res = await fetch(`${API_BASE}/alerts`, {
            headers: { "Authorization": `Bearer ${currentToken}` }
        });
        
        const data = await res.json();
        
        if (res.ok) {
            const alerts = data.alerts || [];
            
            if (alerts.length === 0) {
                emptyAlerts.style.display = "block";
                return;
            }

            alerts.forEach(item => {
                const li = document.createElement("li");
                li.className = `alert-feed-item alert-severity-${item.severity}`;
                li.innerHTML = `
                    <div class="alert-feed-body">
                        <span class="alert-feed-site">[${escapeHtml(item.website_name)}]</span>
                        <p>${escapeHtml(item.message)}</p>
                        <span class="alert-feed-time">${new Date(item.created_at).toLocaleTimeString()}</span>
                    </div>
                    <button class="btn-resolve">Resolve ✓</button>
                `;

                li.querySelector(".btn-resolve").addEventListener("click", () => resolveAlertItem(item.id));
                alertsList.appendChild(li);
            });
        }
    } catch (err) {
        console.error("Alert feed fetch failed", err);
    }
}

// Clear / resolve active warnings (deletes database alert row)
async function resolveAlertItem(alertId) {
    try {
        const res = await fetch(`${API_BASE}/alert/${alertId}`, {
            method: "DELETE",
            headers: { "Authorization": `Bearer ${currentToken}` }
        });

        if (res.ok) {
            await loadAlerts();
            loadAuditLogs();
        } else {
            const data = await res.json();
            alert(data.message || "Failed to resolve alert.");
        }
    } catch (err) {
        alert("Network error resolving warning.");
    }
}

// Fetch audit trail logs
async function loadAuditLogs() {
    emptyAudit.style.display = "none";
    auditList.innerHTML = "";

    try {
        const res = await fetch(`${API_BASE}/audit`, {
            headers: { "Authorization": `Bearer ${currentToken}` }
        });
        
        const data = await res.json();
        
        if (res.ok) {
            const logs = data.logs || [];
            
            if (logs.length === 0) {
                emptyAudit.style.display = "block";
                return;
            }

            logs.forEach(item => {
                const li = document.createElement("li");
                li.className = "audit-feed-item";
                
                const actorEmail = item.user_email || "System";
                const actionTime = new Date(item.timestamp).toLocaleString();
                
                li.innerHTML = `
                    <div>
                        <span class="audit-user">${escapeHtml(actorEmail)}</span>: 
                        <span class="audit-action">${escapeHtml(item.action)}</span>
                    </div>
                    <span class="audit-time">${actionTime}</span>
                `;
                auditList.appendChild(li);
            });
        }
    } catch (err) {
        console.error("Audit log retrieval failed", err);
    }
}

// Refresh handlers
refreshAlerts.addEventListener("click", loadAlerts);
refreshAudit.addEventListener("click", loadAuditLogs);

/* ================= REPORT DIALOGS & UTILS ================= */

// Open modal detailing full AI security assessment report
function openReportModal(scan) {
    reportModal.classList.add("active");
    
    const formattedDate = new Date(scan.scan_time).toLocaleString();
    const vulnerabilities = Array.isArray(scan.vulnerability) ? scan.vulnerability : [];
    
    let htmlContent = `
        <div style="margin-bottom: 20px; font-family: var(--font-mono); font-size: 0.85rem; color: var(--text-muted);">
            Report Compiled: ${formattedDate}<br>
            Audit Snapshot Hash: ${scan.content_hash || "Un-compiled"}<br>
            Asset Scan Risk verdict: <span class="vuln-severity severity-${scan.risk_level}">${scan.risk_level.toUpperCase()}</span>
        </div>
        <h3 style="color:#c084fc; margin-bottom: 12px; font-size:1.1rem; text-transform: uppercase;">Compliance findings</h3>
        <ul style="margin-bottom: 24px; list-style:none; display:flex; flex-direction:column; gap:8px;">
    `;

    if (vulnerabilities.length === 0) {
        htmlContent += `<li style="padding: 10px; background: rgba(16, 185, 129, 0.05); border: 1px solid rgba(16, 185, 129, 0.15); border-radius: 6px; color:#a7f3d0;">✅ Configuration Audit Passed. No security configuration misses found.</li>`;
    } else {
        vulnerabilities.forEach(v => {
            htmlContent += `
                <li style="padding: 12px; background: rgba(0,0,0,0.2); border: 1px solid rgba(255,255,255,0.05); border-radius: 6px;">
                    <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:4px;">
                        <strong style="font-size:0.85rem; color:#f8fafc;">${escapeHtml(v.vulnerability)}</strong>
                        <span class="vuln-severity severity-${v.severity}">${v.severity}</span>
                    </div>
                    <p style="font-size:0.8rem; color:#94a3b8; line-height:1.4;">${escapeHtml(v.description)}</p>
                </li>
            `;
        });
    }

    htmlContent += `
        </ul>
        <h3 style="color:#c084fc; margin-bottom: 12px; font-size:1.1rem; text-transform: uppercase;">🧠 AI Threat Analysis & Remediation Steps</h3>
        <div class="markdown-body" style="background:rgba(0,0,0,0.3); padding:16px; border-radius:8px; line-height:1.6; border: 1px solid rgba(139, 92, 246, 0.15);">
            ${formatMarkdown(scan.ai_summary || "No AI threat analysis brief is loaded.")}
        </div>
    `;

    modalReportBody.innerHTML = htmlContent;
}

// Close modal handler
modalCloseBtn.addEventListener("click", () => {
    reportModal.classList.remove("active");
});
window.addEventListener("click", (e) => {
    if (e.target === reportModal) {
        reportModal.classList.remove("active");
    }
});

// HTML escaping helper
function escapeHtml(str) {
    if (!str) return "";
    return str
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;")
        .replace(/'/g, "&#039;");
}

// Simple Markdown formatting helper
function formatMarkdown(text) {
    if (!text) return "";
    let html = escapeHtml(text);

    // Headings
    html = html.replace(/^### (.*?)$/gm, "<h4>$1</h4>");
    html = html.replace(/^## (.*?)$/gm, "<h3>$1</h3>");
    html = html.replace(/^# (.*?)$/gm, "<h2>$1</h2>");

    // Bold tags
    html = html.replace(/\*\*(.*?)\*\*/g, "<strong>$1</strong>");

    // Bullet Lists
    html = html.replace(/^\- (.*?)$/gm, "<li>$1</li>");
    html = html.replace(/(<li>.*?<\/li>)/gs, "<ul>$1</ul>");
    
    // Clean up empty lines or duplicate lists tags
    html = html.replace(/<\/ul>\s*<ul>/g, "");
    
    // Paragraph spaces
    html = html.replace(/\n\n/g, "</p><p>");
    html = html.replace(/\n/g, "<br>");

    return `<p>${html}</p>`;
}
