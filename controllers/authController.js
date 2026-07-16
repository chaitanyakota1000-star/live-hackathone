const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const userModel = require("../models/userModel");
require("dotenv").config();

// Register a new user
exports.register = async (req, res) => {
    const { email, password, role } = req.body;

    if (!email || !password) {
        return res.status(400).json({
            message: "Email and password are required."
        });
    }

    try {
        // Check if user already exists
        const existingUser = await userModel.findByEmail(email);
        if (existingUser) {
            return res.status(400).json({
                message: "User with this email already exists."
            });
        }

        // Hash password
        const passwordHash = await bcrypt.hash(password, 10);

        // Determine role (ensure only valid roles are registered)
        const userRole = role === "admin" ? "admin" : "user";

        // Create user
        const newUserId = await userModel.createUser(email, passwordHash, userRole);

        // Log audit trail
        await userModel.logAuditTrail(newUserId, `Registered user account with role '${userRole}'`);

        return res.status(201).json({
            message: "Registration successful. You can now log in.",
            userId: newUserId
        });
    } catch (err) {
        return res.status(500).json({
            message: "Internal server error occurred during registration."
        });
    }
};

// Login user and return JWT
exports.login = async (req, res) => {
    const { email, password } = req.body;

    if (!email || !password) {
        return res.status(400).json({
            message: "Email and password are required."
        });
    }

    try {
        // Find user
        const user = await userModel.findByEmail(email);
        if (!user) {
            return res.status(401).json({
                message: "Invalid email or password."
            });
        }

        // Compare password
        const isMatch = await bcrypt.compare(password, user.password_hash);
        if (!isMatch) {
            return res.status(401).json({
                message: "Invalid email or password."
            });
        }

        // Generate JWT
        const token = jwt.sign(
            { id: user.id, email: user.email, role: user.role },
            process.env.JWT_SECRET || "super_secret_jwt_token_for_system_siege",
            { expiresIn: "12h" }
        );

        // Log audit trail
        await userModel.logAuditTrail(user.id, "Logged in successfully");

        return res.status(200).json({
            message: "Login successful.",
            token,
            user: {
                id: user.id,
                email: user.email,
                role: user.role
            }
        });
    } catch (err) {
        return res.status(500).json({
            message: "Internal server error occurred during login."
        });
    }
};

// Get current user context details
exports.getCurrentUser = async (req, res) => {
    try {
        const user = await userModel.findById(req.user.id);
        if (!user) {
            return res.status(404).json({
                message: "User not found."
            });
        }
        return res.status(200).json({ user });
    } catch (err) {
        return res.status(500).json({
            message: "Internal server error."
        });
    }
};

// Get Audit Logs (Admin only)
exports.getAuditLogs = async (req, res) => {
    try {
        let logs;
        if (req.user.role === "admin") {
            logs = await userModel.getAuditLogs();
        } else {
            logs = await userModel.getAuditLogsByUser(req.user.id);
        }
        return res.status(200).json({ logs });
    } catch (err) {
        return res.status(500).json({
            message: "Failed to retrieve audit logs."
        });
    }
};
