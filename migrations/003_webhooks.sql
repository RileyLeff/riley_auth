-- v2: webhook registration and delivery log

CREATE TABLE webhooks (
    id uuid PRIMARY KEY DEFAULT uuidv7(),
    client_id uuid REFERENCES oauth_clients(id) ON DELETE CASCADE,  -- NULL = global
    url text NOT NULL,
    events text[] NOT NULL,
    secret text NOT NULL,  -- HMAC signing key
    active boolean NOT NULL DEFAULT true,
    created_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX idx_webhooks_client_id ON webhooks(client_id);
CREATE INDEX idx_webhooks_active ON webhooks(active) WHERE active = true;

CREATE TABLE webhook_deliveries (
    id uuid PRIMARY KEY DEFAULT uuidv7(),
    webhook_id uuid NOT NULL REFERENCES webhooks(id) ON DELETE CASCADE,
    event_type text NOT NULL,
    payload jsonb NOT NULL,
    status_code smallint,
    error text,
    attempted_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX idx_webhook_deliveries_webhook_id ON webhook_deliveries(webhook_id);
CREATE INDEX idx_webhook_deliveries_attempted_at ON webhook_deliveries(attempted_at);
