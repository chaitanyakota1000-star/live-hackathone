const aiService = require("../services/aiService");
const scanModel = require("../models/scanModel");
const websiteModel = require("../models/websiteModel");

// Endpoint for manual / ad-hoc AI analysis requests
exports.analyzeScan = async (req, res) => {
    const { scanId } = req.body;
    const userId = req.user.id;
    const userRole = req.user.role;

    if (!scanId) {
        return res.status(400).json({
            message: "Scan ID is required."
        });
    }

    try {
        // Fetch scan report details
        const scan = await scanModel.getScanById(scanId);
        if (!scan) {
            return res.status(404).json({
                message: "Scan report not found."
            });
        }

        // Fetch associated website for IDOR check
        const website = await websiteModel.findById(scan.website_id);
        if (!website) {
            return res.status(404).json({
                message: "Monitored website associated with this scan was not found."
            });
        }

        // Check ownership
        if (userRole !== "admin" && website.owner_id !== userId) {
            return res.status(403).json({
                message: "Access Denied: You do not own the website associated with this scan."
            });
        }

        let vulnerabilities = [];
        try {
            vulnerabilities = JSON.parse(scan.vulnerability || "[]");
        } catch (e) {
            vulnerabilities = [];
        }

        // Determine if defaced from vulnerability list or historical hashes
        const isDefaced = scan.risk_level === "critical" && vulnerabilities.some(v => v.vulnerability.includes("Defacement"));
        const similarityScore = isDefaced ? 50 : 100; // Simulated overlap indicator if baseline details aren't stored

        console.log(`[AI Controller] Invoking AI analysis for Scan ID: ${scanId}...`);
        const summary = await aiService.analyzeScanReport(
            website.url,
            vulnerabilities,
            isDefaced,
            similarityScore,
            scan.risk_level
        );

        return res.status(200).json({
            message: "AI analysis completed.",
            summary
        });
    } catch (err) {
        console.error("❌ AI controller execution failed:", err);
        return res.status(500).json({
            message: `AI analysis failed: ${err.message}`
        });
    }
};
