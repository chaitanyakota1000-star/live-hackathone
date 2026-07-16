-- Runs automatically on the *first* container start (Postgres only executes
-- files in /docker-entrypoint-initdb.d when the data volume is empty).
-- If you change this after the first run, you'll need to
-- `docker-compose down -v` to wipe the volume and re-trigger it.
--
-- This is a starting point - Dev 3 should refine columns/constraints as the
-- API takes shape.

CREATE TABLE IF NOT EXISTS users (
    id SERIAL PRIMARY KEY,
    email TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    role TEXT NOT NULL DEFAULT 'user' CHECK (role IN ('user', 'admin')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS sites (
    id SERIAL PRIMARY KEY,
    owner_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    url TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS snapshots (
    id SERIAL PRIMARY KEY,
    site_id INTEGER NOT NULL REFERENCES sites(id) ON DELETE CASCADE,
    content_hash TEXT NOT NULL,
    raw_content TEXT NOT NULL,
    checked_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS flags (
    id SERIAL PRIMARY KEY,
    site_id INTEGER NOT NULL REFERENCES sites(id) ON DELETE CASCADE,
    snapshot_id INTEGER NOT NULL REFERENCES snapshots(id) ON DELETE CASCADE,
    severity TEXT NOT NULL,
    summary TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Every "list my sites" / "get site by id" query should filter on owner_id
-- (or allow-all for admins) - that filter IS your IDOR defense, and this
-- index is what keeps it fast once there's real data.
CREATE INDEX IF NOT EXISTS idx_sites_owner_id ON sites(owner_id);
