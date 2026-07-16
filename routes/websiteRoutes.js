const express = require("express");
const router = express.Router();
const websiteController = require("../controllers/websiteController");
const authMiddleware = require("../middleware/authMiddleware");

// Monitored assets management (All protected by JWT auth)
router.post("/website", authMiddleware, websiteController.addWebsite);
router.get("/websites", authMiddleware, websiteController.listWebsites);
router.get("/website/:id", authMiddleware, websiteController.getWebsiteById);
router.delete("/website/:id", authMiddleware, websiteController.deleteWebsite);

module.exports = router;
