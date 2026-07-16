const websiteModel = require("../models/websiteModel");
const userModel = require("../models/userModel");
const vulnerabilityService = require("../services/vulnerabilityService");

// Add a website to monitor
exports.addWebsite = async (req, res) => {
    const { website_name, url } = req.body;
    const ownerId = req.user.id;

    if (!website_name || !url) {
        return res.status(400).json({
            message: "Website name and URL are required."
        });
    }

    try {
        // 1. SSRF prevention check
        await vulnerabilityService.validateUrlForSSRF(url);

        // 2. Save website to DB
        const websiteId = await websiteModel.createWebsite(ownerId, website_name, url);

        // 3. Log Audit Trail
        await userModel.logAuditTrail(ownerId, `Added monitored website: "${website_name}" (URL: ${url})`);

        return res.status(201).json({
            message: "Website added to monitoring list successfully.",
            websiteId
        });
    } catch (err) {
        // Handle SSRF validation error or connection error specifically
        if (err.message.includes("SSRF") || err.message.includes("scheme")) {
            return res.status(400).json({
                message: `Security validation failed: ${err.message}`
            });
        }
        return res.status(500).json({
            message: "Internal server error occurred while adding the asset."
        });
    }
};

// List monitored websites (Admin: all, User: only owned)
exports.listWebsites = async (req, res) => {
    const userId = req.user.id;
    const userRole = req.user.role;

    try {
        let websites;
        if (userRole === "admin") {
            websites = await websiteModel.listAllWebsites();
        } else {
            websites = await websiteModel.listWebsitesByOwner(userId);
        }

        return res.status(200).json({ websites });
    } catch (err) {
        return res.status(500).json({
            message: "Internal server error while listing digital assets."
        });
    }
};

// Delete website monitoring asset (Strict IDOR checks)
exports.deleteWebsite = async (req, res) => {
    const websiteId = req.params.id;
    const userId = req.user.id;
    const userRole = req.user.role;

    try {
        const website = await websiteModel.findById(websiteId);
        if (!website) {
            return res.status(404).json({
                message: "Monitored website not found."
            });
        }

        // 1. Strict IDOR protection
        if (userRole !== "admin" && website.owner_id !== userId) {
            return res.status(403).json({
                message: "Access Denied: You do not own this resource."
            });
        }

        // 2. Perform delete
        await websiteModel.deleteWebsite(websiteId);

        // 3. Log Audit Trail
        await userModel.logAuditTrail(userId, `Deleted monitored website: "${website.website_name}" (URL: ${website.url})`);

        return res.status(200).json({
            message: "Website removed from monitoring list successfully."
        });
    } catch (err) {
        return res.status(500).json({
            message: "Internal server error while removing the website."
        });
    }
};

// Retrieve a single website (Strict IDOR checks)
exports.getWebsiteById = async (req, res) => {
    const websiteId = req.params.id;
    const userId = req.user.id;
    const userRole = req.user.role;

    try {
        const website = await websiteModel.findById(websiteId);
        if (!website) {
            return res.status(404).json({
                message: "Monitored website not found."
            });
        }

        // Strict IDOR Check
        if (userRole !== "admin" && website.owner_id !== userId) {
            return res.status(403).json({
                message: "Access Denied: You do not have permission to view this resource."
            });
        }

        return res.status(200).json({ website });
    } catch (err) {
        return res.status(500).json({
            message: "Internal server error while retrieving website details."
        });
    }
};
