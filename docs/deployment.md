# Deployment Guide

## Requirements

- **PostgreSQL 14+** — UUIDs are generated application-side, no PG18 features required
- **Rust 1.88+** — if building from source
- **Docker** — if using container deployment

## Docker

### Build

```bash
docker build -t riley-auth .
```

### Run

```bash
docker run -d \
  --name riley-auth \
  -e DATABASE_URL=postgres://riley_auth:password@db:5432/riley_auth \
  -v ./config:/config:ro \
  -v ./keys:/keys:ro \
  -p 8081:8081 \
  riley-auth
```

Set `RILEY_AUTH_CONFIG=/config/riley_auth.toml` to point to your config file, or mount it at the default search path.

## Docker Compose

A production-ready `docker-compose.yml` is included in the repo root. To use it:

1. Create a `.env` file:
   ```
   DB_PASSWORD=your-secure-password
   GOOGLE_CLIENT_ID=...
   GOOGLE_CLIENT_SECRET=...
   GITHUB_CLIENT_ID=...
   GITHUB_CLIENT_SECRET=...
   ```

2. Create `config/riley_auth.toml` (use `riley_auth.example.toml` as a starting point).

3. Generate signing keys:
   ```bash
   mkdir -p keys
   docker run --rm -v ./keys:/keys riley-auth riley-auth generate-keys --output /keys
   ```

4. Start the stack:
   ```bash
   docker compose up -d
   ```

Migrations run automatically when the server starts. No separate migration step is needed.

The stack includes:
- **riley-auth** — the identity server on port 8081
- **PostgreSQL 17** — database with persistent volume

### Adding a reverse proxy

For production, add a reverse proxy (Caddy, nginx, Traefik) in front of riley-auth for TLS termination. Example Caddy configuration:

```
auth.example.com {
    reverse_proxy riley-auth:8081
}
```

If using a reverse proxy, set `behind_proxy = true` in your config and ensure the proxy sets `X-Forwarded-For` to the real client IP (not append).

## VPS (Build from Source)

### Build

```bash
git clone https://github.com/rileyleff/riley_auth
cd riley_auth
cargo build --release
```

The binary is at `target/release/riley-auth`.

### systemd service

Create `/etc/systemd/system/riley-auth.service`:

```ini
[Unit]
Description=riley_auth identity server
After=network.target postgresql.service

[Service]
Type=simple
User=riley-auth
Group=riley-auth
WorkingDirectory=/opt/riley-auth
ExecStart=/opt/riley-auth/riley-auth serve
Restart=on-failure
RestartSec=5
Environment=RILEY_AUTH_CONFIG=/etc/riley-auth/riley_auth.toml
Environment=DATABASE_URL=postgres://riley_auth:password@localhost/riley_auth

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now riley-auth
```

### nginx reverse proxy

```nginx
server {
    listen 443 ssl http2;
    server_name auth.example.com;

    ssl_certificate /etc/letsencrypt/live/auth.example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/auth.example.com/privkey.pem;

    location / {
        proxy_pass http://127.0.0.1:8081;
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-For $remote_addr;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

Set `behind_proxy = true` in your riley_auth config when behind a reverse proxy.

## First-Time Setup

1. **Create config** — Copy `riley_auth.example.toml`, set `issuer`, database URL, and at least one OAuth provider.

2. **Generate signing keys:**
   ```bash
   riley-auth generate-keys --algorithm es256 --output /path/to/keys
   ```

3. **Run migrations:**
   ```bash
   riley-auth migrate
   ```

4. **Start the server:**
   ```bash
   riley-auth serve
   ```

5. **Log in** — Visit `/auth/google` (or your provider) to create your account.

6. **Promote yourself to admin:**
   ```bash
   riley-auth promote your-username
   ```

7. **Register OAuth clients** for your apps:
   ```bash
   riley-auth register-client "My App" https://app.example.com/callback
   ```

## Key Rotation

riley_auth supports zero-downtime key rotation via multi-key JWKS.

1. **Generate a new keypair:**
   ```bash
   riley-auth generate-keys --algorithm es256 --output /path/to/new-keys
   ```

2. **Add the new key to your config** (as the first `[[jwt.keys]]` entry — the first key is the active signing key):
   ```toml
   [[jwt.keys]]
   algorithm = "ES256"
   private_key_path = "/path/to/new-keys/private.pem"
   public_key_path = "/path/to/new-keys/public.pem"

   [[jwt.keys]]
   algorithm = "ES256"
   private_key_path = "/path/to/old-keys/private.pem"
   public_key_path = "/path/to/old-keys/public.pem"
   ```

3. **Restart riley-auth.** New tokens are signed with the new key. Old tokens verify against the old key via JWKS.

4. **Wait for cache expiry.** The `/.well-known/jwks.json` endpoint sets `Cache-Control: max-age=<jwks_cache_max_age_secs>` (default: 1 hour). Wait at least that long for downstream apps to pick up the new key.

5. **Remove the old key** from config and restart. Tokens signed with the old key will fail verification — but access tokens have a short TTL (default: 15 minutes), and refresh tokens will be rotated on next use.

## Backup

Back up these three things:

1. **PostgreSQL database** — `pg_dump riley_auth > backup.sql`
2. **Signing keys** — the PEM files referenced in `[[jwt.keys]]`
3. **Config file** — `riley_auth.toml`

The signing keys are the most critical item. If lost, all existing tokens become unverifiable and all users must re-authenticate. The database can be reconstructed (users re-login via OAuth), but losing keys means immediate service disruption.
