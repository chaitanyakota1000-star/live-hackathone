const express = require("express");
const router = express.Router();
const aiController = require("../controllers/aiController");
const authMiddleware = require("../middleware/authMiddleware");

// Manual AI Threat analysis endpoint (JWT authenticated)
router.post("/ai/analyze", authMiddleware, aiController.analyzeScan);

module.exports = router;
