const alertModel = require("../models/alertModel");
const websiteModel = require("../models/websiteModel");
const userModel = require("../models/userModel");

// Get alerts (Admin: all, User: only owned assets)
exports.getAlerts = async (req, res) => {
    const userId = req.user.id;
    const userRole = req.user.role;

    try {
        let alerts;
        if (userRole === "admin") {
            alerts = await alertModel.getAlerts();
        } else {
            alerts = await alertModel.getAlertsByOwner(userId);
        }

        return res.status(200).json({ alerts });
    } catch (err) {
        console.error("❌ Failed to fetch alerts:", err);
        return res.status(500).json({
            message: "Internal server error while fetching warnings."
        });
    }
};

// Resolve (delete) a warning alert (Strict ownership checking)
exports.resolveAlert = async (req, res) => {
    const alertId = req.params.id;
    const userId = req.user.id;
    const userRole = req.user.role;

    try {
        // Fetch all alerts to find the target alert details (or add single fetch to alertModel, getAlerts returns all joins)
        const allAlerts = await alertModel.getAlerts();
        const alert = allAlerts.find(a => a.id === parseInt(alertId, 10));

        if (!alert) {
            return res.status(404).json({
                message: "Alert not found."
            });
        }

        // Strict IDOR Check: User must own the website or be admin
        if (userRole !== "admin" && alert.owner_id !== userId) {
            return res.status(403).json({
                message: "Access Denied: You do not own the website associated with this alert."
            });
        }

        // Delete (Resolve) the alert
        await alertModel.deleteAlert(alertId);

        // Log audit trail
        await userModel.logAuditTrail(userId, `Resolved alert ID: ${alertId} (Message: "${alert.message}")`);

        return res.status(200).json({
            message: "Alert resolved and removed successfully."
        });
    } catch (err) {
        console.error("❌ Failed to resolve alert:", err);
        return res.status(500).json({
            message: "Internal server error while resolving alert."
        });
    }
};
