const express = require("express");
const router = express.Router();
const authController = require("../controllers/authController");
const authMiddleware = require("../middleware/authMiddleware");

// Public endpoints
router.post("/register", authController.register);
router.post("/login", authController.login);

// Protected endpoints
router.get("/me", authMiddleware, authController.getCurrentUser);
router.get("/audit", authMiddleware, authController.getAuditLogs);

module.exports = router;
