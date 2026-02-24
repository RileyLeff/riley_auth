# Fixes for Review Round 20 (Phase 10 R2)

**Commit:** 3008bf9

## M1 + m1 Fix: Add backchannel logout to delete_account and CLI

**Problem:** Self-service `DELETE /auth/me` (`delete_account`) called `soft_delete_user` without first dispatching backchannel logout. `soft_delete_user` deletes all refresh tokens in a transaction, so the subsequent backchannel logout query would find no matching clients. Same issue existed in CLI `delete` and `revoke` commands.

**Fix:**
1. `routes/auth.rs` (`delete_account`): Added `webhooks::dispatch_backchannel_logout(...)` call before `db::soft_delete_user(...)`, matching the pattern in admin `delete_user`
2. `cli/main.rs`: Added `dispatch_backchannel_logout_cli` helper that loads JWT keys and builds webhook client, with graceful degradation (warns and continues if keys unavailable). Called from both `Command::Delete` and `Command::Revoke` before destructive operations.

**Tests:** 106 integration + 22 unit — all passing.
