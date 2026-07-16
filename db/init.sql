DROP TABLE IF EXISTS flags CASCADE;
DROP TABLE IF EXISTS snapshots CASCADE;
DROP TABLE IF EXISTS sites CASCADE;
DROP TABLE IF EXISTS users CASCADE;
DROP TABLE IF EXISTS audit_logs CASCADE;
DROP TABLE IF EXISTS alerts CASCADE;

CREATE TABLE users (
    id SERIAL PRIMARY KEY,
    email VARCHAR(255) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    role VARCHAR(50) NOT NULL DEFAULT 'user' CHECK (role IN ('user', 'admin'))
);

CREATE TABLE sites (
    id SERIAL PRIMARY KEY,
    owner_id INTEGER REFERENCES users(id) ON DELETE CASCADE NOT NULL,
    url TEXT NOT NULL
);

CREATE TABLE snapshots (
    id SERIAL PRIMARY KEY,
    site_id INTEGER REFERENCES sites(id) ON DELETE CASCADE NOT NULL,
    content_hash VARCHAR(64) NOT NULL,
    raw_content TEXT NOT NULL
);

CREATE TABLE flags (
    id SERIAL PRIMARY KEY,
    site_id INTEGER REFERENCES sites(id) ON DELETE CASCADE NOT NULL,
    snapshot_id INTEGER REFERENCES snapshots(id) ON DELETE CASCADE NOT NULL,
    severity VARCHAR(50) NOT NULL,
    summary TEXT NOT NULL
);

CREATE TABLE audit_logs (
    id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES users(id) ON DELETE CASCADE NOT NULL,
    action TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE alerts (
    id SERIAL PRIMARY KEY,
    site_id INTEGER REFERENCES sites(id) ON DELETE CASCADE NOT NULL,
    message TEXT NOT NULL,
    severity VARCHAR(50) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Seed an operational admin user. Password: Admin@Siege1 (bcrypt, cost 12).
-- Change this password immediately after first login in any non-development environment.
INSERT INTO users (email, password_hash, role) VALUES ('admin@siege.local', '$2b$12$5ppnY0l1uyacpiYgI8DTTe1KOSjDaBOu8JgTgZKck15wrux/NQiGq', 'admin');
INSERT INTO sites (owner_id, url) VALUES (1, 'https://enterprise-panel.net');
