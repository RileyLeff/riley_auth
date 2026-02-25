-- Phase 11: Multi-Provider Account Merging
-- Track email verification status from OAuth providers.
ALTER TABLE oauth_links ADD COLUMN email_verified boolean NOT NULL DEFAULT false;
