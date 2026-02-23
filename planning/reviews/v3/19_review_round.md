# Phase 6 Review — Standard Review

**Models**: Claude subagent (Gemini rate-limited)
**Context**: ~100k tokens
**Scope**: Phase 6 SSRF hardening — is_private_ip, SsrfSafeResolver, check_url_ip_literal, build_webhook_client, deliver_outbox_entry block_private_ips

## Findings

### Major

1. **[claude-only] IPv4-mapped IPv6 bypass** — `::ffff:127.0.0.1` bypassed `is_private_ip()` because IPv6 branch didn't check mapped addresses. **Fixed in 6d36916** — added `to_ipv4_mapped()` check.

### Minor

1. **[claude-only] Missing multicast range blocks** — Neither IPv4 224.0.0.0/4 nor IPv6 ff00::/8 were blocked. **Fixed in 6d36916** — added `is_multicast()` checks.
2. **[claude-only] HTTP redirect to private IP literal bypasses SSRF** — A 302 from public server to `http://127.0.0.1/` bypasses both defenses. **Fixed in 6d36916** — disabled redirect following on webhook client.
3. **[claude-only] SSRF block errors trigger retries** — `check_url_ip_literal` errors were retryable. **Fixed in 6d36916** — prefixed with "permanent:".
4. **[claude-only] `check_url_ip_literal()` silently succeeds on URL parse failure** — Low risk since reqwest would also fail. Accepted as note.

### Notes

1. **TOCTOU in DNS resolver** — Inherent to the DNS-check-then-connect pattern. Acceptable.
2. **Webhook URL validation at registration is scheme-only** — Acceptable for admin-only endpoint.
3. **Documentation/benchmarking IP ranges not blocked** — Very low risk, non-routable.
