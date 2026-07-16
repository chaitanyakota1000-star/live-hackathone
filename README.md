# System Siege — Website Defacement Detection & Vulnerability Assessment Platform

Built for the **System Siege** hackathon — problem statement **PS-005**.

An AI-powered monitor that lets organizations register web assets, trigger integrity scans, track vulnerability configuration assessments, inspect active warning feeds, review compliance audit trails, and receive threat intelligence recommendations.

---

## 1. Features & Capabilities

1. **Integrity Monitoring (Defacement Check)**: Pulls HTML snapshots of targets. On sequential checks, computes a similarity percentage using a custom word-level difference checker. Below a 90% match, flags a potential defacement warning.
2. **Vulnerability Audit Checklist**: Audits target response headers. Checks for security configs:
   - HTTPS encryption presence.
   - Clickjacking prevention (`X-Frame-Options` or `Content-Security-Policy` with `frame-ancestors`).
   - Content Security Policy presence (`Content-Security-Policy`).
   - MIME Sniffing protection (`X-Content-Type-Options: nosniff`).
   - HSTS force-HTTPS configuration (`Strict-Transport-Security`).
   - Technology exposures (e.g. `Server` or `X-Powered-By` version headers).
3. **AI Threat Intelligence (BYOK)**: Connects to **Google Gemini API** (`gemini-2.5-flash`) or **OpenAI** to generate plain-language risk breakdowns, structural impact explanations, and specific remediation config blocks (nginx/Apache headers, etc.).
4. **Secure Org-level Dashboard**: A glassmorphic front-end client providing a multi-functional security command center.
5. **Access Authorization Scoping**: Fully implements role permissions:
   - `admin` role: Observes and audits all websites, alerts, and system-wide actions.
   - `user` role: Standard security analyst. Observes and triggers actions only for assets they own.
6. **Centralized Compliance Logs**: Stores comprehensive logs of analyst activities in an `audit_logs` table.

---

## 2. Security Configuration Checklist

- **SQL Injection Prevention**: Built entirely with `mysql2` parameterized queries, fully preventing SQL injection vectors.
- **SSRF Prevention**: All added URLs resolve DNS coordinates through Node's `dns` module first. System explicitly blocks resolving to loopback (`127.0.0.1`), link-local (`169.254.169.254`), or private IP subnets (`10.x.x.x`, `172.16.x.x` to `172.31.x.x`, `192.168.x.x`).
- **IDOR Protections**: All records are query-scoped. User roles are validated against `owner_id` for websites, scans, and alert resolutions.
- **Centralized Error Routing**: Restricts internal system stack trace leaks to the client console. Returns sanitized generic responses.

---

## 3. Generative AI BYOK Disclosure

This application supports and incorporates Generative AI capabilities under the **Bring Your Own Key (BYOK)** framework.

| Provider | Model Version | Environment Variable | Setup Requirement |
|---|---|---|---|
| **Google Gemini** | `gemini-2.5-flash` | `GEMINI_API_KEY` | Recommended. Primary model used for security briefings. |
| **OpenAI** | `gpt-4-turbo` | `OPENAI_API_KEY` | Optional fallback. Used if Gemini key is absent. |

---

## 4. Folder Structure

```
backend/
├── controllers/
│     authController.js       - Registration, Login, JWT issuing, Audit trails
│     websiteController.js    - CRUD operations for websites
│     scanController.js       - Triggers scan, snapshot checks, views history
│     aiController.js         - Calls AI threat analysis on scan results
│     alertController.js      - Retrieve active alerts and resolve warnings
│
├── routes/
│     authRoutes.js           - User signups, login, me context, audit logs
│     websiteRoutes.js        - Website management endpoints
│     scanRoutes.js           - Active scanning and history log endpoints
│     aiRoutes.js             - Manual threat analysis triggers
│     alertRoutes.js          - Alerts retrieval and deletion
│
├── middleware/
│     authMiddleware.js       - JWT token validation
│     roleMiddleware.js       - Role authorization
│
├── models/
│     userModel.js            - MySQL queries for users and audits
│     websiteModel.js         - MySQL queries for assets
│     scanModel.js            - MySQL queries for snapshots
│     alertModel.js           - MySQL queries for warnings
│
├── services/
│     monitorService.js       - Background monitoring interval tasks
│     aiService.js            - Gemini/OpenAI connection wrapper
│     vulnerabilityService.js - HTTP request fetching, SSRF checks, header audits
│
├── database/
│     db.js                   - SSL-enabled Aiven MySQL pool setup
│     schema.sql              - DDL SQL statements to setup tables
│
├── public/                   - Premium Glassmorphic Frontend Client Dashboard
│
├── .env                      - Environment configurations
├── server.js                 - Main server startup entry point
└── package.json              - npm dependencies list
```

---

## 5. Local Setup & Running Instructions

### Prerequisites
- Node.js installed (version 16 or later recommended)
- A running MySQL instance (local or remote on Aiven)

### Step 1: Initialize Database tables
Execute the DDL script in [schema.sql](file:///C:/Users/Maha%20Deep/Desktop/backend/database/schema.sql) inside your MySQL environment:
```sql
-- Connect to your database command line and run:
SOURCE database/schema.sql;
```

### Step 2: Configure Environment variables
Copy the `.env.example` file to `.env`:
```bash
cp .env.example .env
```
Open `.env` and fill in your connection credentials:
- Set `DB_HOST`, `DB_PORT`, `DB_USER`, `DB_PASSWORD`, and `DB_NAME` to your MySQL configurations (e.g., Aiven MySQL details).
- Provide a `GEMINI_API_KEY` or `OPENAI_API_KEY` for AI threat analyses.
- Set a strong `JWT_SECRET`.

### Step 3: Install dependencies
Navigate to the backend directory and run:
```bash
npm install
```

### Step 4: Start the application
```bash
npm start
```

Open your browser and navigate to `http://localhost:5000` to access the Command Dashboard!
