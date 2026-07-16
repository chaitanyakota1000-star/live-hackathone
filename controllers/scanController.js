const scanModel = require("../models/scanModel");
const websiteModel = require("../models/websiteModel");
const userModel = require("../models/userModel");
const alertModel = require("../models/alertModel");
const vulnerabilityService = require("../services/vulnerabilityService");
const aiService = require("../services/aiService");

// Trigger manual security scan & defacement assessment
exports.triggerScan = async (req, res) => {
    const websiteId = req.params.websiteId;
    const userId = req.user.id;
    const userRole = req.user.role;

    try {
        // 1. Verify website existence
        const website = await websiteModel.findById(websiteId);
        if (!website) {
            return res.status(404).json({
                message: "Website not found."
            });
        }

        // 2. IDOR check
        if (userRole !== "admin" && website.owner_id !== userId) {
            return res.status(403).json({
                message: "Access Denied: You do not own this resource."
            });
        }

        // 3. Log start audit log
        await userModel.logAuditTrail(userId, `Triggered manual security scan for "${website.website_name}"`);

        // 4. Retrieve the latest baseline snapshot (if any)
        const previousSnapshot = await scanModel.getLatestSnapshot(websiteId);

        // 5. Run the scanner
        const scanResult = await vulnerabilityService.performScan(website.url, previousSnapshot);

        // 6. Alert Creation and status updates
        let newStatus = "safe";
        if (scanResult.isDefaced) {
            newStatus = "defaced";
            await alertModel.createAlert(
                websiteId,
                `Website Defacement Alert: similarity index dropped to ${scanResult.similarityScore}%.`,
                "critical"
            );
        } else if (scanResult.riskLevel === "critical" || scanResult.riskLevel === "high") {
            newStatus = "warning";
            await alertModel.createAlert(
                websiteId,
                `High Risk Detected: Security configuration lacks proper encryption headers. Risk Level: ${scanResult.riskLevel.toUpperCase()}`,
                scanResult.riskLevel
            );
        } else if (scanResult.responseCode >= 400) {
            newStatus = "error";
            await alertModel.createAlert(
                websiteId,
                `Scanning Error: Target URL returned HTTP status code ${scanResult.responseCode}.`,
                "medium"
            );
        }

        // Update the website status in DB
        await websiteModel.updateStatus(websiteId, newStatus);

        // 7. Request LLM Vulnerability and Defacement Analysis (BYOK)
        let aiSummaryText = "";
        try {
            aiSummaryText = await aiService.analyzeScanReport(
                website.url,
                scanResult.vulnerabilities,
                scanResult.isDefaced,
                scanResult.similarityScore,
                scanResult.riskLevel
            );
        } catch (aiErr) {
            console.error("AI Analysis connector failed:", aiErr.message);
            aiSummaryText = `Vulnerability scan completed. Found ${scanResult.vulnerabilities.length} issues. AI Summary is unavailable due to an API error: ${aiErr.message}`;
        }

        // 8. Save scan report to Database
        const vulnerabilitiesString = JSON.stringify(scanResult.vulnerabilities);
        const reportId = await scanModel.createReport(
            websiteId,
            vulnerabilitiesString,
            scanResult.riskLevel,
            aiSummaryText,
            scanResult.contentHash,
            scanResult.rawContent
        );

        // 9. Return result
        return res.status(200).json({
            message: "Scan completed successfully.",
            scan: {
                id: reportId,
                website_id: websiteId,
                scan_time: new Date(),
                vulnerability: scanResult.vulnerabilities,
                risk_level: scanResult.riskLevel,
                ai_summary: aiSummaryText,
                is_defaced: scanResult.isDefaced,
                similarity_score: scanResult.similarityScore,
                response_code: scanResult.responseCode
            }
        });
    } catch (err) {
        console.error("❌ Scan triggering failed:", err);
        return res.status(500).json({
            message: `Scan execution failed: ${err.message}`
        });
    }
};

// Retrieve scan history (Strict IDOR checks)
exports.getHistory = async (req, res) => {
    const websiteId = req.params.websiteId;
    const userId = req.user.id;
    const userRole = req.user.role;

    try {
        // Verify website ownership
        const website = await websiteModel.findById(websiteId);
        if (!website) {
            return res.status(404).json({
                message: "Website not found."
            });
        }

        if (userRole !== "admin" && website.owner_id !== userId) {
            return res.status(403).json({
                message: "Access Denied: You do not have permission to view history for this site."
            });
        }

        const history = await scanModel.getScanHistory(websiteId);
        
        // Parse vulnerabilities back from JSON string for front-end rendering
        const parsedHistory = history.map(h => {
            try {
                h.vulnerability = JSON.parse(h.vulnerability || "[]");
            } catch (e) {
                h.vulnerability = [];
            }
            return h;
        });

        return res.status(200).json({ history: parsedHistory });
    } catch (err) {
        return res.status(500).json({
            message: "Failed to retrieve scan history."
        });
    }
};
