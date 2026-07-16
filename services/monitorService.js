const websiteModel = require("../models/websiteModel");
const scanModel = require("../models/scanModel");
const alertModel = require("../models/alertModel");
const vulnerabilityService = require("./vulnerabilityService");
const aiService = require("./aiService");

let monitorInterval = null;

// Perform a scan for a single site in the background, creating alerts if changes or critical issues are found
async function checkWebsiteBackground(website) {
    try {
        console.log(`[Monitor] Scanning ${website.url} (ID: ${website.id})...`);
        
        // Fetch previous snapshot
        const latestSnapshot = await scanModel.getLatestSnapshot(website.id);

        // Perform scan
        const scanResult = await vulnerabilityService.performScan(website.url, latestSnapshot);

        // Format vulnerabilities as string for DB
        const vulnerabilitiesJson = JSON.stringify(scanResult.vulnerabilities);

        // Determine if alert is needed (Defaced or new critical issues)
        if (scanResult.isDefaced) {
            await alertModel.createAlert(
                website.id,
                `Defacement alert! HTML content similarity with baseline dropped to ${scanResult.similarityScore}%.`,
                "critical"
            );
            await websiteModel.updateStatus(website.id, "defaced");
        } else if (scanResult.riskLevel === "critical" || scanResult.riskLevel === "high") {
            await alertModel.createAlert(
                website.id,
                `Vulnerability alert! Scan identified multiple compliance and security issues (Risk: ${scanResult.riskLevel.toUpperCase()}).`,
                scanResult.riskLevel
            );
            await websiteModel.updateStatus(website.id, "warning");
        } else {
            await websiteModel.updateStatus(website.id, "safe");
        }

        // Call AI analysis (optional background threat summarization)
        let aiSummary = "Background analysis completed.";
        try {
            aiSummary = await aiService.analyzeScanReport(
                website.url,
                scanResult.vulnerabilities,
                scanResult.isDefaced,
                scanResult.similarityScore,
                scanResult.riskLevel
            );
        } catch (aiErr) {
            console.warn(`[Monitor] AI Analysis skipped for ${website.url}:`, aiErr.message);
            aiSummary = `Vulnerability scan completed. Detected ${scanResult.vulnerabilities.length} issues. AI Summary is unavailable.`;
        }

        // Save report snapshot
        await scanModel.createReport(
            website.id,
            vulnerabilitiesJson,
            scanResult.riskLevel,
            aiSummary,
            scanResult.contentHash,
            scanResult.rawContent
        );

        console.log(`[Monitor] Finished scan for ${website.url}. Status: ${scanResult.isDefaced ? "DEFACED" : "SAFE"}`);
    } catch (err) {
        console.error(`[Monitor] Scan failed for ${website.url}:`, err.message);
        await websiteModel.updateStatus(website.id, "error");
        await alertModel.createAlert(
            website.id,
            `Monitoring failure: Failed to reach host. Error: ${err.message}`,
            "medium"
        );
    }
}

// Check all registered sites
async function scanAllWebsites() {
    try {
        console.log("[Monitor] Initiating background monitoring sweep...");
        const websites = await websiteModel.listAllWebsites();
        for (const website of websites) {
            await checkWebsiteBackground(website);
        }
        console.log("[Monitor] Background sweep completed.");
    } catch (err) {
        console.error("[Monitor] Error listing websites during sweep:", err);
    }
}

// Start the continuous background monitoring interval (e.g. check every 30 minutes)
function startMonitoring(intervalMs = 30 * 60 * 1000) {
    if (monitorInterval) {
        clearInterval(monitorInterval);
    }

    console.log(`[Monitor] Starting background web monitor service (Interval: ${intervalMs / 1000}s)`);
    // Run initial scan
    setTimeout(scanAllWebsites, 2000);

    monitorInterval = setInterval(scanAllWebsites, intervalMs);
}

// Stop background monitoring
function stopMonitoring() {
    if (monitorInterval) {
        clearInterval(monitorInterval);
        monitorInterval = null;
        console.log("[Monitor] Background web monitor service stopped.");
    }
}

module.exports = {
    startMonitoring,
    stopMonitoring,
    checkWebsiteBackground,
    scanAllWebsites
};
