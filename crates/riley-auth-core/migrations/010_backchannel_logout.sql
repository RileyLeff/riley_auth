-- Add back-channel logout support to OAuth clients (OIDC Back-Channel Logout 1.0)
ALTER TABLE oauth_clients
    ADD COLUMN backchannel_logout_uri text,
    ADD COLUMN backchannel_logout_session_required boolean NOT NULL DEFAULT false;
