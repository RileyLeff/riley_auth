// OAuth flow logic for Google and GitHub
// 1. Generate auth URL with state + PKCE
// 2. Exchange code for tokens at callback
// 3. Fetch user profile from provider
// 4. Upsert user in DB, issue JWT
