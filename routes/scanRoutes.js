const express = require("express");
const router = express.Router();
const scanController = require("../controllers/scanController");
const authMiddleware = require("../middleware/authMiddleware");

// Trigger scanning and history (All protected by JWT auth with strict IDOR verification inside controller)
router.post("/scan/:websiteId", authMiddleware, scanController.triggerScan);
router.get("/scan/history/:websiteId", authMiddleware, scanController.getHistory);

module.exports = router;
