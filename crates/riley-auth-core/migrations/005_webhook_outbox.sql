-- v3: persistent webhook outbox for reliable delivery

CREATE TABLE webhook_outbox (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    webhook_id uuid NOT NULL REFERENCES webhooks(id) ON DELETE CASCADE,
    event_type text NOT NULL,
    payload jsonb NOT NULL,
    attempts int NOT NULL DEFAULT 0,
    max_attempts int NOT NULL DEFAULT 5,
    next_attempt_at timestamptz NOT NULL DEFAULT now(),
    last_error text,
    status text NOT NULL DEFAULT 'pending',  -- pending, delivered, failed
    created_at timestamptz NOT NULL DEFAULT now()
);

-- The delivery worker polls for pending items due for a retry
CREATE INDEX idx_webhook_outbox_pending
    ON webhook_outbox(next_attempt_at) WHERE status = 'pending';
