const db = require("../database/db");

// Find a user by email
async function findByEmail(email) {
    const [rows] = await db.query(
        "SELECT * FROM users WHERE email = ?",
        [email]
    );
    return rows[0];
}

// Find a user by ID
async function findById(id) {
    const [rows] = await db.query(
        "SELECT id, email, role, created_at FROM users WHERE id = ?",
        [id]
    );
    return rows[0];
}

// Create a new user
async function createUser(email, passwordHash, role = "user") {
    const [result] = await db.query(
        "INSERT INTO users (email, password_hash, role) VALUES (?, ?, ?)",
        [email, passwordHash, role]
    );
    return result.insertId;
}

// Log audit trails (Required for compliance & audit logs table)
async function logAuditTrail(userId, action) {
    try {
        await db.query(
            "INSERT INTO audit_logs (user_id, action) VALUES (?, ?)",
            [userId, action]
        );
    } catch (err) {
        console.error("❌ Failed to log audit trail:", err);
    }
}

// Fetch all audit logs (for Admin views)
async function getAuditLogs() {
    const [rows] = await db.query(
        `SELECT a.id, a.action, a.timestamp, u.email as user_email 
         FROM audit_logs a 
         LEFT JOIN users u ON a.user_id = u.id 
         ORDER BY a.timestamp DESC LIMIT 100`
    );
    return rows;
}

// Fetch user audit logs
async function getAuditLogsByUser(userId) {
    const [rows] = await db.query(
        `SELECT id, action, timestamp 
         FROM audit_logs 
         WHERE user_id = ? 
         ORDER BY timestamp DESC LIMIT 50`,
        [userId]
    );
    return rows;
}

module.exports = {
    findByEmail,
    findById,
    createUser,
    logAuditTrail,
    getAuditLogs,
    getAuditLogsByUser
};
