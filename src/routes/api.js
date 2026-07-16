import express from 'express';
import pkg from 'pg';
import { GoogleGenAI } from '@google/genai';
import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';
import crypto from 'crypto';

const { Pool } = pkg;
const router = express.Router();
const JWT_SECRET = process.env.JWT_SECRET;

const db = new Pool({
  host: process.env.DB_HOST || 'db',
  user: process.env.DB_USER || 'postgres',
  password: process.env.DB_PASSWORD || 'secret_db_pass',
  database: process.env.DB_NAME || 'system_siege',
  port: 5432,
});

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
// HELPER: Input Validators
// ==========================================
const EMAIL_REGEX = /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/;
const isValidEmail = (e) => typeof e === 'string' && EMAIL_REGEX.test(e.trim());

// ==========================================
// AUTHENTICATION ENDPOINTS
// ==========================================
router.post('/register', async (req, res, next) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) return res.status(400).json({ message: "Email and password are required." });
    if (!isValidEmail(email)) return res.status(400).json({ message: "A valid email address is required." });
    if (typeof password !== 'string' || password.length < 8)
      return res.status(400).json({ message: "Password must be at least 8 characters." });
    const existingUser = await db.query('SELECT id FROM users WHERE email = $1', [email]);
    if (existingUser.rows.length > 0) return res.status(400).json({ message: "User already exists." });
    const passwordHash = await bcrypt.hash(password, 10);
    const userRole = "user";
    const result = await db.query(
      'INSERT INTO users (email, password_hash, role) VALUES ($1, $2, $3) RETURNING id',
      [email, passwordHash, userRole]
    );
    const newUserId = result.rows[0].id;
    await logAuditTrail(newUserId, `Registered user account with role '${userRole}'`);
    return res.status(201).json({ message: "Registration successful.", userId: newUserId });
  } catch (error) { next(error); }
});

router.post('/login', async (req, res, next) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) return res.status(400).json({ message: "Email and password are required." });
    if (!isValidEmail(email)) return res.status(400).json({ message: "A valid email address is required." });
    const result = await db.query('SELECT * FROM users WHERE email = $1', [email]);
    if (result.rows.length === 0) return res.status(401).json({ message: "Invalid email or password." });
    const user = result.rows[0];
    const isMatch = await bcrypt.compare(password, user.password_hash);
    if (!isMatch) return res.status(401).json({ message: "Invalid email or password." });
    const token = jwt.sign({ id: user.id, email: user.email, role: user.role }, JWT_SECRET, { expiresIn: "12h" });
    await logAuditTrail(user.id, "Logged in successfully");
    return res.status(200).json({ message: "Login successful.", token, user: { id: user.id, email: user.email, role: user.role } });
  } catch (error) { next(error); }
});

router.get('/me', authMiddleware, async (req, res, next) => {
  try {
    const result = await db.query('SELECT id, email, role FROM users WHERE id = $1', [req.user.id]);
    if (result.rows.length === 0) return res.status(404).json({ message: "User not found." });
    return res.status(200).json({ user: result.rows[0] });
  } catch (error) { next(error); }
});

// ==========================================
// SITES ENDPOINTS
// ==========================================
router.post('/sites', authMiddleware, async (req, res, next) => {
  try {
    const { url } = req.body;
    if (!url) return res.status(400).json({ message: "URL is required." });
    const result = await db.query(
      'INSERT INTO sites (owner_id, url) VALUES ($1, $2) RETURNING *',
      [req.user.id, url]
    );
    await logAuditTrail(req.user.id, `Registered new monitored asset: ${url}`);
    return res.status(201).json(result.rows[0]);
  } catch (error) { next(error); }
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
  } catch (error) { next(error); }
});

router.get('/sites/:id', authMiddleware, async (req, res, next) => {
  try {
    const siteId = req.params.id;
    const siteLookup = await db.query('SELECT * FROM sites WHERE id = $1', [siteId]);
    if (siteLookup.rows.length === 0) return res.status(404).json({ error: "Monitored website not found." });
    const website = siteLookup.rows[0];
    if (req.user.role !== "admin" && website.owner_id !== req.user.id)
      return res.status(403).json({ message: "Access Denied." });
    return res.status(200).json(website);
  } catch (error) { next(error); }
});

router.delete('/sites/:id', authMiddleware, async (req, res, next) => {
  try {
    const siteId = req.params.id;
    const siteLookup = await db.query('SELECT * FROM sites WHERE id = $1', [siteId]);
    if (siteLookup.rows.length === 0) return res.status(404).json({ error: "Monitored website not found." });
    const website = siteLookup.rows[0];
    if (req.user.role !== "admin" && website.owner_id !== req.user.id)
      return res.status(403).json({ message: "Access Denied: You do not own this resource." });
    await db.query('DELETE FROM sites WHERE id = $1', [siteId]);
    await logAuditTrail(req.user.id, `Deleted monitored website: "${website.url}"`);
    return res.status(200).json({ message: "Website removed from monitoring list successfully." });
  } catch (error) { next(error); }
});

router.get('/sites/:id/history', authMiddleware, async (req, res, next) => {
  try {
    const siteId = req.params.id;
    const siteLookup = await db.query('SELECT * FROM sites WHERE id = $1', [siteId]);
    if (siteLookup.rows.length === 0) return res.status(404).json({ error: "Monitored website not found." });
    const website = siteLookup.rows[0];
    if (req.user.role !== "admin" && website.owner_id !== req.user.id)
      return res.status(403).json({ message: "Access Denied." });
    const historyLookup = await db.query(
      `SELECT id, content_hash,
         CASE WHEN content_hash = 'fetch_error' THEN raw_content
              ELSE SUBSTRING(raw_content, 1, 200) || '...' END AS preview,
         created_at
       FROM snapshots WHERE site_id = $1 ORDER BY id DESC LIMIT 50`,
      [siteId]
    );
    return res.status(200).json({ history: historyLookup.rows, site: website });
  } catch (error) { next(error); }
});

// ==========================================
// CORE SCAN ENDPOINT — REAL IMPLEMENTATION
// ==========================================
router.post('/sites/:id/check', authMiddleware, async (req, res, next) => {
  try {
    const siteId = req.params.id;
    const siteLookup = await db.query('SELECT * FROM sites WHERE id = $1', [siteId]);
    if (siteLookup.rows.length === 0) return res.status(404).json({ error: "Monitored asset target not found." });
    const website = siteLookup.rows[0];
    if (req.user.role !== "admin" && website.owner_id !== req.user.id)
      return res.status(403).json({ message: "Access Denied: You do not own this resource." });

    await logAuditTrail(req.user.id, `Triggered manual security scan for site ID ${siteId}`);
    const targetUrl = website.url;

    try {
      console.log(`[SCAN] Fetching content from: ${targetUrl}`);
      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), 10000);

      const fetchResponse = await fetch(targetUrl, {
        headers: { 'User-Agent': 'AEGIS-Security-Scanner/1.0' },
        redirect: 'follow',
        signal: controller.signal
      });
      clearTimeout(timeoutId);

      if (!fetchResponse.ok)
        return res.status(400).json({ error: `Failed to fetch ${targetUrl}: HTTP ${fetchResponse.status}` });

      const currentContent = await fetchResponse.text();
      const contentHash = crypto.createHash('sha256').update(currentContent).digest('hex').substring(0, 16);

      // Check for previous baseline
      const previousSnapshot = await db.query(
        "SELECT content_hash, raw_content FROM snapshots WHERE site_id = $1 AND content_hash != 'fetch_error' ORDER BY id DESC LIMIT 1",
        [siteId]
      );

      let diffOutput = '';
      let scanMetrics = { isDefaced: false, similarityScore: 100, riskLevel: "low", responseCode: fetchResponse.status };

      if (previousSnapshot.rows.length > 0) {
        const lastSnapshot = previousSnapshot.rows[0];
        if (lastSnapshot.content_hash !== contentHash) {
          // Line-by-line diff
          const prevLines = lastSnapshot.raw_content.split('\n');
          const currLines = currentContent.split('\n');
          const diffLines = [];
          const maxLines = Math.max(prevLines.length, currLines.length);
          let changes = 0;
          for (let i = 0; i < maxLines; i++) {
            const p = prevLines[i] || '', c = currLines[i] || '';
            if (p !== c) {
              changes++;
              if (p && !c) diffLines.push(`- ${p}`);
              else if (!p && c) diffLines.push(`+ ${c}`);
              else { diffLines.push(`- ${p}`); diffLines.push(`+ ${c}`); }
            }
          }
          diffOutput = diffLines.join('\n');
          const similarity = Math.max(0, 100 - (changes / Math.max(prevLines.length, currLines.length)) * 100);
          scanMetrics.similarityScore = Math.round(similarity * 100) / 100;
          scanMetrics.isDefaced = similarity < 85;
          scanMetrics.riskLevel = similarity < 50 ? "critical" : similarity < 70 ? "high" : similarity < 85 ? "medium" : "low";
          console.log(`[SCAN] Content changed — similarity: ${scanMetrics.similarityScore}%`);
        } else {
          diffOutput = 'No changes detected since last scan.';
          console.log(`[SCAN] No changes detected`);
        }
      } else {
        diffOutput = 'Baseline established - first scan for this asset.';
        console.log(`[SCAN] Establishing baseline for ${targetUrl}`);
      }

      // AI Analysis — only when there are changes
      let aiOutput = 'No security analysis needed - content unchanged.';
      if (diffOutput !== 'No changes detected since last scan.') {
        const systemInstruction = `You are an automated DevSecOps Incident Response Analyst. Analyze code differences for website defacements, security compromises, or exploit payloads. Start immediately without greetings. Plain text output only, no markdown.`;
        const dynamicPrompt = `ALERT: Web content change detected on ${targetUrl}\n\n[SCAN METRICS]\n- Defacement Detected: ${scanMetrics.isDefaced}\n- Similarity Score: ${scanMetrics.similarityScore}%\n- Risk Level: ${scanMetrics.riskLevel.toUpperCase()}\n- HTTP Response: ${scanMetrics.responseCode}\n\nContent diff (first 100 lines):\n---\n${diffOutput.split('\n').slice(0, 100).join('\n')}\n---\n\nAnalyze the threat and provide remediation steps.`;
        try {
          const response = await ai.models.generateContent({
            model: 'gemini-2.0-flash',
            contents: dynamicPrompt,
            config: { systemInstruction, temperature: 0.1 }
          });
          aiOutput = response.text;
        } catch (aiError) {
          console.error('AI analysis failed:', aiError);
          aiOutput = `AI analysis unavailable. Manual review required. Similarity: ${scanMetrics.similarityScore}%, risk: ${scanMetrics.riskLevel}.`;
        }
      }

      // Store snapshot
      await db.query(
        'INSERT INTO snapshots (site_id, content_hash, raw_content) VALUES ($1, $2, $3)',
        [siteId, contentHash, currentContent]
      );

      return res.status(200).json({
        ai_analysis: aiOutput,
        scan_metrics: scanMetrics,
        content_hash: contentHash,
        diff_summary: diffOutput.split('\n').length > 1 ? `${diffOutput.split('\n').length} lines changed` : 'No changes'
      });

    } catch (fetchError) {
      console.error(`[SCAN] Failed to fetch ${targetUrl}:`, fetchError);
      await db.query(
        'INSERT INTO snapshots (site_id, content_hash, raw_content) VALUES ($1, $2, $3)',
        [siteId, 'fetch_error', `Fetch failed: ${fetchError.message}`]
      );
      return res.status(500).json({
        error: `Unable to scan ${targetUrl}: ${fetchError.message}`,
        scan_metrics: { isDefaced: false, similarityScore: 0, riskLevel: "unknown", responseCode: 0 }
      });
    }
  } catch (error) { next(error); }
});

// ==========================================
// AUDIT LOGS ENDPOINT
// ==========================================
router.get('/audit', authMiddleware, async (req, res, next) => {
  try {
    const result = await db.query(`
      SELECT a.id, a.action, a.created_at, u.email AS user_email
      FROM audit_logs a
      JOIN users u ON a.user_id = u.id
      ORDER BY a.created_at DESC
      LIMIT 100
    `);
    return res.json({ logs: result.rows });
  } catch (error) { next(error); }
});

// ==========================================
// ALERTS ENDPOINT - REAL DATA ONLY (IDOR PROTECTED)
// ==========================================
router.get('/alerts', authMiddleware, async (req, res, next) => {
  try {
    let query, params;
    if (req.user.role === 'admin') {
      query = `
        SELECT s.id as alert_id, s.site_id, si.url, s.content_hash, s.created_at,
               CASE
                 WHEN s.content_hash = 'fetch_error' THEN 'critical'
                 ELSE 'info'
               END as severity,
               CASE
                 WHEN s.content_hash = 'fetch_error' THEN 'Scan Failed'
                 ELSE 'Scan Completed'
               END as title,
               LEFT(s.raw_content, 200) as description
        FROM snapshots s
        JOIN sites si ON s.site_id = si.id
        WHERE s.created_at > NOW() - INTERVAL '24 HOURS'
        ORDER BY s.created_at DESC
        LIMIT 20
      `;
      params = [];
    } else {
      query = `
        SELECT s.id as alert_id, s.site_id, si.url, s.content_hash, s.created_at,
               CASE
                 WHEN s.content_hash = 'fetch_error' THEN 'critical'
                 ELSE 'info'
               END as severity,
               CASE
                 WHEN s.content_hash = 'fetch_error' THEN 'Scan Failed'
                 ELSE 'Scan Completed'
               END as title,
               LEFT(s.raw_content, 200) as description
        FROM snapshots s
        JOIN sites si ON s.site_id = si.id
        WHERE si.owner_id = $1 AND s.created_at > NOW() - INTERVAL '24 HOURS'
        ORDER BY s.created_at DESC
        LIMIT 20
      `;
      params = [req.user.id];
    }

    const result = await db.query(query, params);
    return res.json({ alerts: result.rows });
  } catch (error) { next(error); }
});

// ==========================================
// ALERTS ENDPOINT - REAL DATA ONLY (IDOR PROTECTED)
// ==========================================
router.get('/alerts', authMiddleware, async (req, res, next) => {
  try {
    let query, params;
    if (req.user.role === 'admin') {
      query = `
        SELECT s.id as alert_id, s.site_id, si.url, s.content_hash, s.created_at,
               CASE
                 WHEN s.content_hash = 'fetch_error' THEN 'critical'
                 ELSE 'info'
               END as severity,
               CASE
                 WHEN s.content_hash = 'fetch_error' THEN 'Scan Failed'
                 ELSE 'Scan Completed'
               END as title,
               LEFT(s.raw_content, 200) as description
        FROM snapshots s
        JOIN sites si ON s.site_id = si.id
        WHERE s.created_at > NOW() - INTERVAL '24 HOURS'
        ORDER BY s.created_at DESC
        LIMIT 20
      `;
      params = [];
    } else {
      query = `
        SELECT s.id as alert_id, s.site_id, si.url, s.content_hash, s.created_at,
               CASE
                 WHEN s.content_hash = 'fetch_error' THEN 'critical'
                 ELSE 'info'
               END as severity,
               CASE
                 WHEN s.content_hash = 'fetch_error' THEN 'Scan Failed'
                 ELSE 'Scan Completed'
               END as title,
               LEFT(s.raw_content, 200) as description
        FROM snapshots s
        JOIN sites si ON s.site_id = si.id
        WHERE si.owner_id = $1 AND s.created_at > NOW() - INTERVAL '24 HOURS'
        ORDER BY s.created_at DESC
        LIMIT 20
      `;
      params = [req.user.id];
    }

    const result = await db.query(query, params);
    return res.json({ alerts: result.rows });
  } catch (error) { next(error); }
});

// ==========================================
// VULNERABILITIES ENDPOINT - REAL DATA ONLY
// ==========================================
router.get('/vulnerabilities', authMiddleware, async (req, res, next) => {
  try {
    return res.json({ vulnerabilities: [] });
  } catch (error) { next(error); }
});


export default router;
