const db = require("../database/db");

// Log a new system/security warning alert
async function createAlert(websiteId, message, severity = "low") {
    const [result] = await db.query(
        "INSERT INTO alerts (website_id, message, severity) VALUES (?, ?, ?)",
        [websiteId, message, severity]
    );
    return result.insertId;
}

// Get all warnings with asset context (Admin org-wide view)
async function getAlerts() {
    const [rows] = await db.query(
        `SELECT a.*, w.website_name, w.url, w.owner_id 
         FROM alerts a 
         JOIN websites w ON a.website_id = w.id 
         ORDER BY a.created_at DESC`
    );
    return rows;
}

// Get alerts filtered by asset owner (Standard user scope - prevents IDOR)
async function getAlertsByOwner(ownerId) {
    const [rows] = await db.query(
        `SELECT a.*, w.website_name, w.url 
         FROM alerts a 
         JOIN websites w ON a.website_id = w.id 
         WHERE w.owner_id = ? 
         ORDER BY a.created_at DESC`,
        [ownerId]
    );
    return rows;
}

// Get alerts for a single asset
async function getAlertsByWebsite(websiteId) {
    const [rows] = await db.query(
        "SELECT * FROM alerts WHERE website_id = ? ORDER BY created_at DESC",
        [websiteId]
    );
    return rows;
}

// Clear/resolve an alert
async function deleteAlert(id) {
    const [result] = await db.query(
        "DELETE FROM alerts WHERE id = ?",
        [id]
    );
    return result.affectedRows > 0;
}

module.exports = {
    createAlert,
    getAlerts,
    getAlertsByOwner,
    getAlertsByWebsite,
    deleteAlert
};
