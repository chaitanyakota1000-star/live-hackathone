import express from 'express';
import pkg from 'pg';
import { GoogleGenAI } from '@google/genai';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import { diffLines } from 'diff';

const { Pool } = pkg;
const router = express.Router();
const JWT_SECRET = process.env.JWT_SECRET;

// 1. Initialize the PostgreSQL Connection Pool
const db = new Pool({
  host: process.env.DB_HOST || 'db',
  user: process.env.DB_USER || 'postgres',
  password: process.env.DB_PASSWORD || 'secret_db_pass',
  database: process.env.DB_NAME || 'system_siege',
  port: 5432,
});

// Auto-migrate schema to support live diffs
db.query('ALTER TABLE snapshots ADD COLUMN IF NOT EXISTS diff TEXT')
  .catch(err => console.error("Auto-migration failed (this is usually safe to ignore):", err.message));

// 2. Initialize the Google Gen AI Client
const ai = new GoogleGenAI({ apiKey: process.env.GEMINI_API_KEY });

// ==========================================
// MIDDLEWARE: JWT Authentication
// ==========================================
const authMiddleware = (req, res, next) => {
  const authHeader = req.headers["authorization"];
  const token = authHeader && authHeader.split(" ")[1];
  if (!token) return res.status(401).json({ message: "Access Denied: Missing authentication token." });

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = decoded;
    next();
  } catch (err) {
    return res.status(403).json({ message: "Access Denied: Invalid or expired authentication token." });
  }
};

// ==========================================
// HELPER: Audit Logging
// ==========================================
const logAuditTrail = async (userId, action) => {
  try {
    await db.query('INSERT INTO audit_logs (user_id, action) VALUES ($1, $2)', [userId, action]);
  } catch (error) {
    console.error("Audit log failed:", error);
  }
};

// ==========================================
// PRIORITY 1: AUTHENTICATION ENDPOINTS
// ==========================================
router.post('/register', async (req, res, next) => {
  try {
    const { email, password, role } = req.body;
    if (!email || !password) return res.status(400).json({ message: "Email and password are required." });

    // Security: Basic Email Validation
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(email)) {
      return res.status(400).json({ message: "Invalid email format." });
    }

    // Security: Role Validation
    if (role && role !== 'admin' && role !== 'user') {
      return res.status(400).json({ message: "Invalid role specified." });
    }

    const existingUser = await db.query('SELECT * FROM users WHERE email = $1', [email]);
    if (existingUser.rows.length > 0) return res.status(400).json({ message: "User already exists." });

    const passwordHash = await bcrypt.hash(password, 10);
    const userRole = role === "admin" ? "admin" : "user";

    const result = await db.query(
      'INSERT INTO users (email, password_hash, role) VALUES ($1, $2, $3) RETURNING id',
      [email, passwordHash, userRole]
    );
    const newUserId = result.rows[0].id;
    
    await logAuditTrail(newUserId, `Registered user account with role '${userRole}'`);
    return res.status(201).json({ message: "Registration successful.", userId: newUserId });
  } catch (error) {
    next(error);
  }
});

router.post('/login', async (req, res, next) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) return res.status(400).json({ message: "Email and password are required." });

    const result = await db.query('SELECT * FROM users WHERE email = $1', [email]);
    if (result.rows.length === 0) return res.status(401).json({ message: "Invalid email or password." });

    const user = result.rows[0];
    const isMatch = await bcrypt.compare(password, user.password_hash);
    if (!isMatch) return res.status(401).json({ message: "Invalid email or password." });

    const token = jwt.sign({ id: user.id, email: user.email, role: user.role }, JWT_SECRET, { expiresIn: "12h" });
    await logAuditTrail(user.id, "Logged in successfully");

    return res.status(200).json({ message: "Login successful.", token, user: { id: user.id, email: user.email, role: user.role } });
  } catch (error) {
    next(error);
  }
});

router.get('/me', authMiddleware, async (req, res, next) => {
  try {
    const result = await db.query('SELECT id, email, role FROM users WHERE id = $1', [req.user.id]);
    if (result.rows.length === 0) return res.status(404).json({ message: "User not found." });
    return res.status(200).json({ user: result.rows[0] });
  } catch (error) {
    next(error);
  }
});

// ==========================================
// PROTECTED BUSINESS LOGIC ENDPOINTS
// ==========================================
router.post('/sites', authMiddleware, async (req, res, next) => {
  try {
    const { url } = req.body;
    
    // Security: Basic URL Input Validation
    if (!url || typeof url !== 'string' || (!url.startsWith('http://') && !url.startsWith('https://'))) {
      return res.status(400).json({ message: "Invalid URL format. Must begin with http:// or https://" });
    }

    const result = await db.query(
      'INSERT INTO sites (owner_id, url) VALUES ($1, $2) RETURNING *',
      [req.user.id, url]
    );
    await logAuditTrail(req.user.id, `Registered new monitored asset: ${url}`);
    return res.status(201).json(result.rows[0]);
  } catch (error) {
    next(error);
  }
});

router.get('/sites', authMiddleware, async (req, res, next) => {
  try {
    let result;
    if (req.user.role === 'admin') {
      result = await db.query('SELECT * FROM sites ORDER BY id DESC');
    } else {
      result = await db.query('SELECT * FROM sites WHERE owner_id = $1 ORDER BY id DESC', [req.user.id]);
    }
    return res.json(result.rows);
  } catch (error) {
    next(error);
  }
});

router.get('/sites/:id', authMiddleware, async (req, res, next) => {
  try {
    const siteId = req.params.id;
    const userId = req.user.id;
    const userRole = req.user.role;

    const siteLookup = await db.query('SELECT * FROM sites WHERE id = $1', [siteId]);
    if (siteLookup.rows.length === 0) {
      return res.status(404).json({ error: "Monitored website not found." });
    }
    const website = siteLookup.rows[0];

    // Strict IDOR Check
    if (userRole !== "admin" && website.owner_id !== userId) {
      return res.status(403).json({ message: "Access Denied: You do not have permission to view this resource." });
    }

    return res.status(200).json(website);
  } catch (error) {
    next(error);
  }
});

router.delete('/sites/:id', authMiddleware, async (req, res, next) => {
  try {
    const siteId = req.params.id;
    const userId = req.user.id;
    const userRole = req.user.role;

    const siteLookup = await db.query('SELECT * FROM sites WHERE id = $1', [siteId]);
    if (siteLookup.rows.length === 0) {
      return res.status(404).json({ error: "Monitored website not found." });
    }
    const website = siteLookup.rows[0];

    // Strict IDOR Check
    if (userRole !== "admin" && website.owner_id !== userId) {
      return res.status(403).json({ message: "Access Denied: You do not own this resource." });
    }

    await db.query('DELETE FROM sites WHERE id = $1', [siteId]);
    await logAuditTrail(userId, `Deleted monitored website: "${website.url}"`);

    return res.status(200).json({ message: "Website removed from monitoring list successfully." });
  } catch (error) {
    next(error);
  }
});

router.get('/sites/:id/history', authMiddleware, async (req, res, next) => {
  try {
    const siteId = req.params.id;
    const userId = req.user.id;
    const userRole = req.user.role;

    // Verify website ownership
    const siteLookup = await db.query('SELECT * FROM sites WHERE id = $1', [siteId]);
    if (siteLookup.rows.length === 0) {
      return res.status(404).json({ error: "Monitored website not found." });
    }
    const website = siteLookup.rows[0];

    if (userRole !== "admin" && website.owner_id !== userId) {
      return res.status(403).json({ message: "Access Denied: You do not have permission to view history for this site." });
    }

    // Dev 2 scan history is mapping to snapshots and flags
    // Get all snapshots for this site
    const historyLookup = await db.query('SELECT id, content_hash, raw_content FROM snapshots WHERE site_id = $1 ORDER BY id DESC', [siteId]);
    
    return res.status(200).json({ history: historyLookup.rows });
  } catch (error) {
    next(error);
  }
});

router.post('/sites/:id/check', authMiddleware, async (req, res, next) => {
  try {
    const siteId = req.params.id;
    const userId = req.user.id;
    const userRole = req.user.role;

    // A. Verify website existence and IDOR Protection
    const siteLookup = await db.query('SELECT * FROM sites WHERE id = $1', [siteId]);
    if (siteLookup.rows.length === 0) {
      return res.status(404).json({ error: "Monitored asset target not found." });
    }
    const website = siteLookup.rows[0];

    if (userRole !== "admin" && website.owner_id !== userId) {
      return res.status(403).json({ message: "Access Denied: You do not own this resource." });
    }

    await logAuditTrail(userId, `Triggered manual security scan for site ID ${siteId}`);

    const targetUrl = website.url;

    // B. Fetch live content
    let fetchRes;
    try {
      fetchRes = await fetch(targetUrl, { signal: AbortSignal.timeout(10000) });
    } catch (err) {
      if (err.name === 'AbortError' || err.message.includes('timeout')) {
        return res.status(504).json({ message: "HTTP timeout while fetching target URL." });
      }
      return res.status(400).json({ message: "DNS failure or Invalid URL." });
    }

    if (!fetchRes.ok) {
      return res.status(502).json({ message: `Target responded with Non-200 status: ${fetchRes.status}` });
    }

    const currentHtml = await fetchRes.text();
    if (!currentHtml || currentHtml.trim() === '') {
      return res.status(502).json({ message: "Target returned empty HTML." });
    }

    // C. Retrieve previous snapshot
    const prevSnapshotRes = await db.query('SELECT raw_content FROM snapshots WHERE site_id = $1 ORDER BY id DESC LIMIT 1', [siteId]);
    const prevHtml = prevSnapshotRes.rows.length > 0 ? prevSnapshotRes.rows[0].raw_content : "";

    // D. Generate real diff
    const diffParts = diffLines(prevHtml, currentHtml);
    let diffString = diffParts.filter(p => p.added || p.removed).map(part => {
      const prefix = part.added ? '+' : '-';
      return part.value.split('\n').filter(l => l).map(l => `${prefix}${l}`).join('\n');
    }).join('\n');
    
    if (!diffString) diffString = "No structural DOM mutations detected between scans.";

    // E. Dynamic Prompt Generation
    console.log(`[SYSTEM INTEGRATION] Running automated Gemini 2.5 Flash scan for: ${targetUrl}`);
    
    const systemInstruction = `You are an automated DevSecOps Incident Response Analyst integrated within a corporate Security Operations Center (SOC) framework. Your sole purpose is to audit raw code differences generated by a background web scanner application to identify active website defacements, security compromises, or hidden exploit payload code insertions.

    You must rigorously enforce these functional execution parameters:
    1. Complete Objectivity: Do not use any warm introductions, conversational pleasantries, greetings, or closure signatures. Do not say "Here is my evaluation". Start typing technical evaluations instantly.
    2. Threat Classification Matrix: Analyze both structural HTML layouts and syntax indicators pointing to code lines removed (-) or lines added (+). Identify hidden inline iframes, unverified external scripts, cryptojacking modules, phishing forms, text defacements, or unwanted image overrides.
    3. Contextual Synthesis: Evaluate the structured metadata (similarity score, risk level) alongside the raw DOM diffs to provide a highly accurate threat severity baseline.
    4. Clean Plain-Text Output Strategy: Do not under any circumstances output raw markdown styling parameters, bolding notation (**), text header hashtags (#), or backtick code gates (\`\`\`). Provide your structured output entirely using standard line breaks and plain paragraph spacing.`;

    const dynamicPrompt = `ALERT: Web server content integrity mutation mismatch captured on monitoring system.
    Target Inspected Endpoint URL: ${targetUrl}
    
    Examine the following text modification array showcasing lines removed (-) and lines added (+):

    ---
    ${diffString.substring(0, 5000)}
    ---

    Execute your security assessment guidelines. Map the details of the specific threat vector or text change, explain in simple terms what negative impacts it introduces to visitors, and provide a single concise plain-text action statement telling the site administrator how to address or remove the compromised lines.`;

    // F. Gemini AI Invocation
    let aiOutput;
    try {
      const response = await ai.models.generateContent({
        model: 'gemini-2.5-flash',
        contents: dynamicPrompt,
        config: {
          systemInstruction: systemInstruction,
          temperature: 0.1,
        },
      });
      aiOutput = response.text;
      
      if (!aiOutput || aiOutput.trim() === '') {
        return res.status(502).json({ message: "Empty response from Gemini API." });
      }
    } catch (err) {
      console.error("Gemini API failure:", err);
      return res.status(502).json({ message: "Gemini API failure. Please try again later." });
    }

    // Determine Risk Level dynamically
    let riskLevel = "low";
    const lowerOutput = aiOutput.toLowerCase();
    if (lowerOutput.includes("critical") || lowerOutput.includes("defacement") || lowerOutput.includes("injection")) riskLevel = "critical";
    else if (lowerOutput.includes("high") || lowerOutput.includes("exploit")) riskLevel = "high";
    else if (lowerOutput.includes("medium")) riskLevel = "medium";

    // G. Database Storage
    // Log snapshot and diff
    await db.query(
      'INSERT INTO snapshots (site_id, content_hash, raw_content, diff) VALUES ($1, $2, $3, $4)',
      [siteId, 'live_hash_generated', currentHtml, diffString]
    );

    // Insert alert
    await db.query(
      'INSERT INTO alerts (site_id, message, severity) VALUES ($1, $2, $3)',
      [siteId, aiOutput, riskLevel]
    );

    // H. Return assessment
    res.status(200).json({ ai_analysis: aiOutput });
  } catch (error) {
    next(error);
  }
});

router.get('/alerts', authMiddleware, async (req, res, next) => {
  try {
    const userId = req.user.id;
    const userRole = req.user.role;

    let query;
    let params;

    if (userRole === 'admin') {
      query = `
        SELECT a.id, a.message, a.severity, a.created_at, s.url as asset_name, s.id as site_id
        FROM alerts a
        JOIN sites s ON a.site_id = s.id
        ORDER BY a.created_at DESC
      `;
      params = [];
    } else {
      query = `
        SELECT a.id, a.message, a.severity, a.created_at, s.url as asset_name, s.id as site_id
        FROM alerts a
        JOIN sites s ON a.site_id = s.id
        WHERE s.owner_id = $1
        ORDER BY a.created_at DESC
      `;
      params = [userId];
    }

    const { rows } = await db.query(query, params);
    res.status(200).json(rows);
  } catch (error) {
    next(error);
  }
});

router.get('/audit-logs', authMiddleware, async (req, res, next) => {
  try {
    const userId = req.user.id;
    const userRole = req.user.role;

    let query;
    let params;

    if (userRole === 'admin') {
      query = `
        SELECT a.id, a.action, a.created_at, u.email as user_email
        FROM audit_logs a
        JOIN users u ON a.user_id = u.id
        ORDER BY a.created_at DESC
        LIMIT 100
      `;
      params = [];
    } else {
      query = `
        SELECT a.id, a.action, a.created_at, u.email as user_email
        FROM audit_logs a
        JOIN users u ON a.user_id = u.id
        WHERE a.user_id = $1
        ORDER BY a.created_at DESC
        LIMIT 100
      `;
      params = [userId];
    }

    const { rows } = await db.query(query, params);
    res.status(200).json(rows);
  } catch (error) {
    next(error);
  }
});

router.get('/stats', authMiddleware, async (req, res, next) => {
  try {
    const userId = req.user.id;
    const userRole = req.user.role;

    let stats = {
      totalSites: 0,
      criticalAlerts: 0,
      warningAlerts: 0,
      totalScans: 0,
      lastScanTime: null
    };

    if (userRole === 'admin') {
      const sitesResult = await db.query('SELECT COUNT(*) FROM sites');
      stats.totalSites = parseInt(sitesResult.rows[0].count, 10);

      const criticalAlertsResult = await db.query("SELECT COUNT(*) FROM alerts WHERE severity = 'critical'");
      stats.criticalAlerts = parseInt(criticalAlertsResult.rows[0].count, 10);

      const warningAlertsResult = await db.query("SELECT COUNT(*) FROM alerts WHERE severity IN ('high', 'medium')");
      stats.warningAlerts = parseInt(warningAlertsResult.rows[0].count, 10);

      const scansResult = await db.query('SELECT COUNT(*) FROM snapshots');
      stats.totalScans = parseInt(scansResult.rows[0].count, 10);

      const lastScanResult = await db.query('SELECT MAX(created_at) as last_scan FROM alerts');
      stats.lastScanTime = lastScanResult.rows[0].last_scan;
    } else {
      const sitesResult = await db.query('SELECT COUNT(*) FROM sites WHERE owner_id = $1', [userId]);
      stats.totalSites = parseInt(sitesResult.rows[0].count, 10);

      const criticalAlertsResult = await db.query("SELECT COUNT(*) FROM alerts a JOIN sites s ON a.site_id = s.id WHERE s.owner_id = $1 AND a.severity = 'critical'", [userId]);
      stats.criticalAlerts = parseInt(criticalAlertsResult.rows[0].count, 10);

      const warningAlertsResult = await db.query("SELECT COUNT(*) FROM alerts a JOIN sites s ON a.site_id = s.id WHERE s.owner_id = $1 AND a.severity IN ('high', 'medium')", [userId]);
      stats.warningAlerts = parseInt(warningAlertsResult.rows[0].count, 10);

      const scansResult = await db.query("SELECT COUNT(*) FROM snapshots sn JOIN sites s ON sn.site_id = s.id WHERE s.owner_id = $1", [userId]);
      stats.totalScans = parseInt(scansResult.rows[0].count, 10);

      const lastScanResult = await db.query("SELECT MAX(a.created_at) as last_scan FROM alerts a JOIN sites s ON a.site_id = s.id WHERE s.owner_id = $1", [userId]);
      stats.lastScanTime = lastScanResult.rows[0].last_scan;
    }

    res.status(200).json(stats);
  } catch (error) {
    next(error);
  }
});

export default router;
