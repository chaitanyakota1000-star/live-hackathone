const express = require("express");
const router = express.Router();
const alertController = require("../controllers/alertController");
const authMiddleware = require("../middleware/authMiddleware");

// Alerts endpoints (JWT protected)
router.get("/alerts", authMiddleware, alertController.getAlerts);
router.delete("/alert/:id", authMiddleware, alertController.resolveAlert);

module.exports = router;
