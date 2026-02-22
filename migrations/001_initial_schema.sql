-- riley_auth v1 schema
-- Requires PostgreSQL 18 (native uuidv7)

-- Users
CREATE TABLE users (
    id uuid PRIMARY KEY DEFAULT uuidv7(),
    username text UNIQUE NOT NULL,
    display_name text,
    avatar_url text,
    role text NOT NULL DEFAULT 'user',
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    deleted_at timestamptz
);

CREATE UNIQUE INDEX idx_users_username_lower ON users(lower(username))
    WHERE deleted_at IS NULL;

-- OAuth links (one user can have multiple providers)
CREATE TABLE oauth_links (
    id uuid PRIMARY KEY DEFAULT uuidv7(),
    user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    provider text NOT NULL,
    provider_id text NOT NULL,
    provider_email text,
    created_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (provider, provider_id)
);

CREATE INDEX idx_oauth_links_user_id ON oauth_links(user_id);
CREATE INDEX idx_oauth_links_provider_email ON oauth_links(lower(provider_email))
    WHERE provider_email IS NOT NULL;

-- OAuth clients (for cross-domain "Sign in with Riley")
CREATE TABLE oauth_clients (
    id uuid PRIMARY KEY DEFAULT uuidv7(),
    name text NOT NULL,
    client_id text UNIQUE NOT NULL,
    client_secret_hash text NOT NULL,
    redirect_uris text[] NOT NULL,
    auto_approve boolean NOT NULL DEFAULT false,
    created_at timestamptz NOT NULL DEFAULT now()
);

-- Refresh tokens
CREATE TABLE refresh_tokens (
    id uuid PRIMARY KEY DEFAULT uuidv7(),
    user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    client_id uuid REFERENCES oauth_clients(id) ON DELETE CASCADE,
    token_hash text NOT NULL UNIQUE,
    expires_at timestamptz NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    last_used_at timestamptz
);

CREATE INDEX idx_refresh_tokens_user_id ON refresh_tokens(user_id);
CREATE INDEX idx_refresh_tokens_expires_at ON refresh_tokens(expires_at);

-- Username history (tracks changes, holds old names)
CREATE TABLE username_history (
    id uuid PRIMARY KEY DEFAULT uuidv7(),
    user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    old_username text NOT NULL,
    changed_at timestamptz NOT NULL DEFAULT now(),
    held_until timestamptz NOT NULL
);

CREATE INDEX idx_username_history_old_lower ON username_history(lower(old_username));

-- Authorization codes (OAuth provider flow)
CREATE TABLE authorization_codes (
    id uuid PRIMARY KEY DEFAULT uuidv7(),
    code_hash text UNIQUE NOT NULL,
    user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    client_id uuid NOT NULL REFERENCES oauth_clients(id) ON DELETE CASCADE,
    redirect_uri text NOT NULL,
    scopes text[] NOT NULL DEFAULT '{}',
    code_challenge text,
    code_challenge_method text,
    expires_at timestamptz NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    used boolean NOT NULL DEFAULT false
);

CREATE INDEX idx_authorization_codes_expires ON authorization_codes(expires_at);
