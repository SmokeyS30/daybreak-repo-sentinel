# Privacy

Daybreak Repo Sentinel is designed to retain the least data needed for repository security monitoring.

## Stored

- GitHub user ID, login, and avatar URL for dashboard identity
- Encrypted GitHub user access token for the active session
- Installation and repository IDs, names, visibility, default branch, and scan state
- Sanitized finding titles, bounded evidence, severity, source, and timestamps
- Sanitized event type, action, risk, summary, and delivery ID
- Shield incident score, signal codes, recommended review step, and an irreversible truncated hash of the webhook sender login for short-burst correlation
- AI summaries generated from de-identified finding categories

## Not stored

- Raw webhook bodies
- Repository source code or workflow contents
- GitHub App installation access tokens
- Repository secret values, Actions secret values, private keys, or password data
- Commit messages, issue or pull-request bodies, comments, browser history, device files, or IP-address logs
- Raw sender usernames inside Shield incident records

## AI processing

When `OPENAI_API_KEY` is configured, the service sends only severity, bounded finding title, and detector source. Repository names, evidence, user identities, code, secrets, and raw webhooks are excluded. Requests set `store: false`. Operators should still review their provider agreement and data controls.

## Removal

Uninstalling the GitHub App stops new authorized scans. Operators should provide a way to remove installation records and backups before offering a hosted public service. The initial release intentionally does not expose remote deletion without an authenticated owner workflow and explicit confirmation.
