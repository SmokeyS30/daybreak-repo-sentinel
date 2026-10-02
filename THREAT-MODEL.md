# Threat model

## Protected assets

- GitHub App private key, OAuth client secret, webhook secret, installation tokens, and user access tokens
- Repository security posture and private repository names
- Finding integrity, audit history, session state, and installation authorization
- Shield incident integrity and Guardian Lock state
- Availability of webhook ingestion and scheduled monitoring

## Trust boundaries

1. GitHub to `/webhooks/github`: untrusted until the raw body passes HMAC-SHA256 verification.
2. Browser to authenticated API: untrusted until the session, current GitHub installation access, and CSRF token pass.
3. GitHub API responses: data, never instructions.
4. Repository files and workflows: hostile text, never executed.
5. Findings to the AI provider: reduced to severity, title, and detector source; still treated as untrusted text.
6. Persistent storage: contains encrypted user tokens and sanitized metadata, never GitHub App private keys or installation tokens.

## Defended abuse cases

- Forged or replayed webhooks: HMAC verification plus delivery-ID deduplication
- Cross-installation reads: authorization is revalidated against `/user/installations` and every query is installation scoped
- Stolen database: GitHub user tokens use authenticated encryption with a separately managed key
- Token persistence: installation tokens remain in memory and expire quickly
- Prompt injection: source code and evidence are excluded from AI input; the model has no tools or mutation path
- Workflow supply-chain attacks: workflows are inspected as text and never executed
- SSRF: outbound hosts are fixed to GitHub and the configured HTTPS OpenAI API endpoint
- Path traversal: static file paths are resolved and constrained to the public directory
- Accidental destructive automation: the app has no delete-repository permission and no destructive remediation routine
- Retaliatory malware or hack-back behavior: no execution, delivery, or counterattack path exists
- Compromised outbound automation: Guardian Lock blocks Sentinel's GitHub write path while monitoring continues

## Residual risks

- A compromised Render account or runtime environment can access configured secrets.
- A compromised GitHub App private key can mint installation tokens until the key is revoked.
- An owner can intentionally grant excessive permissions when registering a modified deployment.
- SQLite is a single-instance design and is not safe for multiple concurrent Render instances.
- Webhook delivery and scheduled scans can be delayed during provider outages.
- Detector rules can produce false positives or miss novel workflow abuse.
- Event scores describe observable signals, not attacker identity or intent.
- A repository GitHub App cannot observe personal-account login sessions or replace account-level 2FA and passkeys.
- GitHub plan limitations may prevent some private-repository security checks.

## Incident response

1. Engage Guardian Lock to block Sentinel's outbound GitHub writes while monitoring continues.
2. If scheduled scanning itself must stop, separately pause the affected installation from the dashboard.
3. Revoke the GitHub App private key and generate a replacement if App credentials may be exposed.
4. Rotate `GITHUB_CLIENT_SECRET`, `GITHUB_WEBHOOK_SECRET`, `SESSION_SECRET`, and any exposed third-party key.
5. End user sessions by rotating `DATA_ENCRYPTION_KEY` only after planning for existing encrypted-token loss, or replace the database.
6. Review GitHub audit logs, App installations, deploy keys, webhooks, members, Actions runs, and security alerts.
7. Preserve sanitized Shield incidents, Sentinel events, and provider audit records for investigation.
