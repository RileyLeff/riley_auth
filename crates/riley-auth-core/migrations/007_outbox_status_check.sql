-- Add CHECK constraint to webhook_outbox.status column
ALTER TABLE webhook_outbox ADD CONSTRAINT webhook_outbox_status_check
    CHECK (status IN ('pending', 'processing', 'delivered', 'failed'));
