-- Dynamically reserved usernames (managed by admins via API)
CREATE TABLE IF NOT EXISTS reserved_usernames (
    name       TEXT PRIMARY KEY,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
