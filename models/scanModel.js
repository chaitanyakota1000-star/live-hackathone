const db = require("../database/db");

// Save a new scan report snapshot
async function createReport(websiteId, vulnerability, riskLevel, aiSummary, contentHash, rawContent) {
    const [result] = await db.query(
        `INSERT INTO scan_reports 
         (website_id, vulnerability, risk_level, ai_summary, content_hash, raw_content) 
         VALUES (?, ?, ?, ?, ?, ?)`,
        [websiteId, vulnerability, riskLevel, aiSummary, contentHash, rawContent]
    );
    return result.insertId;
}

// Get the latest scan report snapshot (for defacement comparison baseline)
async function getLatestSnapshot(websiteId) {
    const [rows] = await db.query(
        `SELECT * FROM scan_reports 
         WHERE website_id = ? 
         ORDER BY scan_time DESC LIMIT 1`,
        [websiteId]
    );
    return rows[0];
}

// Get all scans for a specific website (User / Admin view scan history)
async function getScanHistory(websiteId) {
    const [rows] = await db.query(
        `SELECT id, website_id, scan_time, vulnerability, risk_level, ai_summary, content_hash
         FROM scan_reports 
         WHERE website_id = ? 
         ORDER BY scan_time DESC`,
        [websiteId]
    );
    return rows;
}

// Get scan report details by ID
async function getScanById(id) {
    const [rows] = await db.query(
        "SELECT * FROM scan_reports WHERE id = ?",
        [id]
    );
    return rows[0];
}

module.exports = {
    createReport,
    getLatestSnapshot,
    getScanHistory,
    getScanById
};
