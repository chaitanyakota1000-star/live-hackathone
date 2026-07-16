import express from 'express';
import pkg from 'pg';
import { GoogleGenAI } from '@google/genai';
import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';

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

    // B. Simulating scan logic
    const simulatedHtmlDiff = `
    @@ -12,4 +12,6 @@
     <h1>Welcome Internal Corporate Portal</h1>
    +<!-- Malicious unauthorized crypto mining payload injected -->
    +<script src='http://coinhive-miner-network.xyz/processor.js'></script>
     </body>
    `;
    
    // Simulating structured metadata from a scanner engine (Ported from dev2 logic)
    const scanMetrics = {
      isDefaced: true,
      similarityScore: 84.5,
      riskLevel: "critical",
      responseCode: 200
    };

    console.log(`[SYSTEM INTEGRATION] Running automated Gemini 2.5 Flash scan for: ${targetUrl}`);
    
    // ----------------------------------------------------------------
    // PROMPT 1: SYSTEM INSTRUCTIONS
    // ----------------------------------------------------------------
    const systemInstruction = `You are an automated DevSecOps Incident Response Analyst integrated within a corporate Security Operations Center (SOC) framework. Your sole purpose is to audit raw code differences generated by a background web scanner application to identify active website defacements, security compromises, or hidden exploit payload code insertions.

    You must rigorously enforce these functional execution parameters:
    1. Complete Objectivity: Do not use any warm introductions, conversational pleasantries, greetings, or closure signatures. Do not say "Here is my evaluation". Start typing technical evaluations instantly.
    2. Threat Classification Matrix: Analyze both structural HTML layouts and syntax indicators pointing to code lines removed (-) or lines added (+). Identify hidden inline iframes, unverified external scripts, cryptojacking modules, phishing forms, text defacements, or unwanted image overrides.
    3. Contextual Synthesis: Evaluate the structured metadata (similarity score, risk level) alongside the raw DOM diffs to provide a highly accurate threat severity baseline.
    4. Clean Plain-Text Output Strategy: Do not under any circumstances output raw markdown styling parameters, bolding notation (**), text header hashtags (#), or backtick code gates (\`\`\`). Provide your structured output entirely using standard line breaks and plain paragraph spacing.`;

    // ----------------------------------------------------------------
    // PROMPT 2: THE DYNAMIC CONTENT PACKET (Now with structured metadata!)
    // ----------------------------------------------------------------
    const dynamicPrompt = `ALERT: Web server content integrity mutation mismatch captured on monitoring system.
    Target Inspected Endpoint URL: ${targetUrl}
    
    [SCAN METRICS]
    - Defacement Detected by Scanner: ${scanMetrics.isDefaced}
    - HTML Similarity Score vs Baseline: ${scanMetrics.similarityScore}%
    - Initial Scanner Risk Level: ${scanMetrics.riskLevel.toUpperCase()}

    Examine the following text modification array showcasing lines removed (-) and lines added (+):

    ---
    ${simulatedHtmlDiff}
    ---

    Execute your security assessment guidelines. Map the details of the specific threat vector or text change, explain in simple terms what negative impacts it introduces to visitors, and provide a single concise plain-text action statement telling the site administrator how to address or remove the compromised lines.`;

    // C. LIVE INVOCATION: Stream the variables directly over to the Google API
    const response = await ai.models.generateContent({
      model: 'gemini-2.5-flash',
      contents: dynamicPrompt,
      config: {
        systemInstruction: systemInstruction,
        temperature: 0.1,
      },
    });

    const aiOutput = response.text;

    // Log snapshot (history) to DB for the GET /history endpoint
    await db.query(
      'INSERT INTO snapshots (site_id, content_hash, raw_content) VALUES ($1, $2, $3)',
      [siteId, 'simulated_hash_123', aiOutput]
    );

    // D. Return the assessment to the user
    res.status(200).json({ ai_analysis: aiOutput });
  } catch (error) {
    next(error);
  }
});

export default router;
