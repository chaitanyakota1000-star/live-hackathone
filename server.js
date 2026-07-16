require("dotenv").config();
const express = require("express");
const cors = require("cors");
const path = require("path");
const monitorService = require("./services/monitorService");

const app = express();
const PORT = process.env.PORT || 5000;

// Import Routes
const authRoutes = require("./routes/authRoutes");
const websiteRoutes = require("./routes/websiteRoutes");
const scanRoutes = require("./routes/scanRoutes");
const aiRoutes = require("./routes/aiRoutes");
const alertRoutes = require("./routes/alertRoutes");

// Setup Middlewares
app.use(cors());
app.use(express.json());

// Expose public folder for premium frontend client
app.use(express.static(path.join(__dirname, "public")));

// Register APIs
app.use("/api", authRoutes);
app.use("/api", websiteRoutes);
app.use("/api", scanRoutes);
app.use("/api", aiRoutes);
app.use("/api", alertRoutes);

// Health check endpoint
app.get("/api/ping", (req, res) => {
    res.status(200).json({
        status: "online",
        message: "System Siege Web Security Backend Running 🚀",
        timestamp: new Date()
    });
});

// Centralized error handler to hide details from clients (Security Requirement)
app.use((err, req, res, next) => {
    console.error("🔥 Internal Server Error:", err.stack || err.message || err);
    res.status(500).json({
        message: "An internal server error occurred. Please contact the system administrator."
    });
});

// Start the server
app.listen(PORT, () => {
    console.log(`✅ System Siege Server running on port ${PORT}`);
    
    // Optional: Start background website scanner (Interval: 15 minutes)
    // monitorService.startMonitoring(15 * 60 * 1000);
});
