-- Database schema for Website Defacement Detection & Vulnerability Assessment Platform (System Siege)
-- Built for Aiven MySQL

CREATE TABLE IF NOT EXISTS users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    email VARCHAR(100) NOT NULL UNIQUE,
    password_hash VARCHAR(255) NOT NULL,
    role VARCHAR(50) DEFAULT 'user', -- 'user' or 'admin'
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS websites (
    id INT AUTO_INCREMENT PRIMARY KEY,
    owner_id INT NOT NULL,
    website_name VARCHAR(100) NOT NULL,
    url VARCHAR(255) NOT NULL,
    status VARCHAR(50) DEFAULT 'pending', -- 'safe', 'defaced', 'warning', 'error', 'pending'
    last_scan TIMESTAMP NULL,
    FOREIGN KEY (owner_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS scan_reports (
    id INT AUTO_INCREMENT PRIMARY KEY,
    website_id INT NOT NULL,
    scan_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    vulnerability TEXT, -- JSON or string list of vulnerabilities detected
    risk_level VARCHAR(50) DEFAULT 'low', -- 'low', 'medium', 'high', 'critical'
    ai_summary TEXT, -- LLM vulnerability summary and recommendations
    content_hash VARCHAR(64), -- SHA-256 hash of the page HTML content
    raw_content LONGTEXT, -- Full content snapshot for diffing
    FOREIGN KEY (website_id) REFERENCES websites(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS alerts (
    id INT AUTO_INCREMENT PRIMARY KEY,
    website_id INT NOT NULL,
    message TEXT NOT NULL,
    severity VARCHAR(50) DEFAULT 'low', -- 'low', 'medium', 'high', 'critical'
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (website_id) REFERENCES websites(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS audit_logs (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NULL,
    action VARCHAR(255) NOT NULL,
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL
);
