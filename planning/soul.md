# Soul

riley_auth creates identity without liability.

OAuth providers have spent billions making authentication secure — password hashing, MFA, brute force protection, recovery flows, breach response. riley_auth doesn't compete with that. It delegates the hard, dangerous parts entirely and focuses on what OAuth providers don't give you: **a unified identity that you own and control across your own ecosystem of apps**.

A user signs in with Google or GitHub. They pick a username. That's their identity now — across your blog, your games, your tools, whatever you build next. One sign-in, one avatar, one name. The auth service is the only thing that issues tokens; everything else just verifies them. Adding a new app to the ecosystem means trusting a public key, not integrating an auth system.

## Principles

**Store nothing dangerous.** No passwords, no MFA secrets, no security questions. If riley_auth's database leaks, the attacker gets usernames and avatar URLs. That's it.

**Configuration over code.** Username rules, cookie domains, token lifetimes, reserved words, OAuth providers — these are deployment decisions, not library decisions. Two people running riley_auth should be able to have completely different policies without forking the code.

**The library is the product.** riley_auth is not "the auth for Riley's website." It's an auth service that Riley's website happens to use. The API, the CLI, the config format — these should make sense to someone who has never heard of rileyleff.com.

**Portable identity.** A user's riley_auth account should feel like *theirs*, not like a row in someone else's database. They chose their username, they uploaded their avatar, they linked their providers. If they want to delete it, it's gone cleanly. If they want to change their name, they can, with guardrails that protect the namespace.

**Invisible when working.** The best auth UX is one the user forgets exists. Sign in once, stay signed in for a month, never see an expiry screen. Tokens refresh silently. Cookies cross subdomains automatically. The auth service does its job and gets out of the way.
