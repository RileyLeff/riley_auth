# Soul

riley_auth is an identity sovereignty layer.

OAuth providers have spent billions making authentication secure — password hashing, MFA, brute force protection, recovery flows, breach response. riley_auth doesn't compete with that. It delegates the hard, dangerous parts entirely, managing state and calling out to trusted parties for validation. You get identity without liability — if your database leaks, there are no passwords, no MFA secrets, no security questions. Just usernames and avatar URLs. The focus is on what OAuth providers don't give you: **a unified identity that you own and control across your own ecosystem of apps**.

A user signs in with Google or GitHub. They pick a username. That's their identity now — not a Google identity, not a GitHub identity, but *yours*. Your server issued the token. Your database holds the account. The user sees "Sign in with [your brand]," not "Sign in with Google." You're the identity provider; Google and GitHub are just how people prove they're human.

riley_auth is both an OAuth **consumer** (it talks to Google/GitHub to authenticate users) and an OAuth **provider** (downstream apps in your ecosystem authenticate against *it*). This is what makes the "cinematic universe" work: you run one riley_auth instance, register each of your apps as OAuth clients, and users get a single account across all of them. Same username, same avatar, same identity — whether they're on your blog, your game, your SaaS tool, or something you haven't built yet. Adding a new app means registering a client and trusting a public key, not integrating an auth system.

## Principles

**Store nothing dangerous.** Authentication is someone else's problem. riley_auth stores only what it needs to manage identity — usernames, avatars, provider links — and nothing that would be catastrophic to lose.

**Configuration over code.** Username rules, cookie domains, token lifetimes, reserved words, OAuth providers — these are deployment decisions, not library decisions. Two people running riley_auth should be able to have completely different policies without forking the code.

**The library is the product.** riley_auth is not "the auth for Riley's website." It's an auth service that Riley's website happens to use. The API, the CLI, the config format — these should make sense to someone who has never heard of rileyleff.com. If Bob deploys it for bob.com, his users should never encounter the word "Riley."

**Portable identity.** A user's riley_auth account should feel like *theirs*, not like a row in someone else's database. They chose their username, they uploaded their avatar, they linked their providers. If they want to delete it, it's gone cleanly. If they want to change their name, they can, with guardrails that protect the namespace.

**Invisible when working.** The best auth UX is one the user forgets exists. Sign in once, stay signed in for a month, never see an expiry screen. Tokens refresh silently. Cookies cross subdomains automatically. Cross-domain apps redirect through the auth server so fast the user barely notices. The auth service does its job and gets out of the way.

**Identity, not entitlements.** riley_auth answers "who is this person?" Everything else — subscriptions, permissions, feature flags, billing — layers on top using that identity. riley_auth gives you the foundation; what you build on it is your business.
