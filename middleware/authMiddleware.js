const jwt = require("jsonwebtoken");
require("dotenv").config();

module.exports = (req, res, next) => {
    // 1. Get the Authorization header
    const authHeader = req.headers["authorization"];
    const token = authHeader && authHeader.split(" ")[1]; // Format: Bearer TOKEN

    if (!token) {
        return res.status(401).json({
            message: "Access Denied: Missing authentication token."
        });
    }

    try {
        // 2. Verify token
        const decoded = jwt.verify(token, process.env.JWT_SECRET || "super_secret_jwt_token_for_system_siege");
        
        // 3. Attach user context to request
        req.user = decoded;
        next();
    } catch (err) {
        return res.status(403).json({
            message: "Access Denied: Invalid or expired authentication token."
        });
    }
};
