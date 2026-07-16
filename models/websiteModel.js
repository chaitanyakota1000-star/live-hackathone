const db = require("../database/db");

// Register a new website asset
async function createWebsite(ownerId, websiteName, url) {
    const [result] = await db.query(
        "INSERT INTO websites (owner_id, website_name, url, status) VALUES (?, ?, ?, 'pending')",
        [ownerId, websiteName, url]
    );
    return result.insertId;
}

// List all websites (For Admin)
async function listAllWebsites() {
    const [rows] = await db.query(
        `SELECT w.*, u.email as owner_email 
         FROM websites w 
         JOIN users u ON w.owner_id = u.id 
         ORDER BY w.id DESC`
    );
    return rows;
}

// List websites belonging to a specific user
async function listWebsitesByOwner(ownerId) {
    const [rows] = await db.query(
        "SELECT * FROM websites WHERE owner_id = ? ORDER BY id DESC",
        [ownerId]
    );
    return rows;
}

// Find website by ID
async function findById(id) {
    const [rows] = await db.query(
        "SELECT * FROM websites WHERE id = ?",
        [id]
    );
    return rows[0];
}

// Delete website asset
async function deleteWebsite(id) {
    const [result] = await db.query(
        "DELETE FROM websites WHERE id = ?",
        [id]
    );
    return result.affectedRows > 0;
}

// Update safety status and last scan timestamp
async function updateStatus(id, status, lastScanTime = new Date()) {
    const [result] = await db.query(
        "UPDATE websites SET status = ?, last_scan = ? WHERE id = ?",
        [status, lastScanTime, id]
    );
    return result.affectedRows > 0;
}

module.exports = {
    createWebsite,
    listAllWebsites,
    listWebsitesByOwner,
    findById,
    deleteWebsite,
    updateStatus
};
