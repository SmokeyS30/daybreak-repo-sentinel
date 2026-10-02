# Daybreak Shield

Daybreak Shield is the defensive evolution of Daybreak Repo Sentinel: an open-source, always-on GitHub App for continuous repository security monitoring. It receives signed GitHub webhooks when something new happens, performs scheduled full rescans for configuration drift, correlates native GitHub security alerts, and presents sanitized findings and incident signals in a mobile-friendly dashboard.

Monitoring is automatic. Consequential repository changes are approval-gated.

## Guardian Mode

Shield uses deterministic evidence—not guesses about a person's intent—to score dangerous changes. It opens privacy-minimized incidents for signals such as:

- A repository becoming public, being deleted, or being transferred
- A writable deploy key or administrator collaborator being added
- Branch protection being deleted, a force push, or a default-branch change
- GitHub Actions workflow changes
- Secret-scanning alerts and push-protection bypasses
- Multiple urgent changes arriving within ten minutes

Incident records contain bounded metadata, signal codes, an irreversible actor hash for correlation, and a recommended review step. They do not contain raw webhook payloads, secret values, commit messages, source code, or sender usernames.

Guardian Lock is an owner-controlled emergency brake. After the owner types `LOCK`, Sentinel blocks its own outbound GitHub writes while signed-webhook collection and scheduled monitoring continue. Releasing the lock requires typing `UNLOCK`. Shield never infects, attacks, or retaliates against another device or account.

## What it monitors

- New, removed, transferred, archived, privatized, and publicized repositories
- Installation and repository-access changes
- New members, deploy keys, branch-protection changes, pushes, and workflow runs
- Code-scanning, secret-scanning, push-protection bypass, and Dependabot alerts
- Default-branch protection, required reviews, and required checks
- Default GitHub Actions token permissions
- Missing `SECURITY.md`, `CODEOWNERS`, and Dependabot configuration
- Workflow use of `write-all`, `pull_request_target`, mutable action references, download-to-shell patterns, and direct interpolation of untrusted event data

Every accepted webhook schedules a fresh scan. A background worker also rescans active installations every 15 minutes by default, so missed webhook deliveries do not silently disable monitoring.

## Safety model

- Uses a GitHub App instead of personal access tokens.
- Verifies `X-Hub-Signature-256` before parsing webhook JSON.
- Deduplicates webhook delivery IDs.
- Never stores raw webhook bodies, source code, repository secrets, or private keys.
- Stores GitHub user tokens with AES-256-GCM encryption.
- Uses short-lived installation access tokens and keeps them only in memory.
- Uses `HttpOnly`, `Secure`, `SameSite=Lax` sessions and CSRF protection.
- Sends only finding severity, title, and detector source to OpenAI; repository names, code, evidence, usernames, secrets, and raw payloads are excluded.
- Sends AI requests with `store: false`. Monitoring and scoring continue without an AI key.
- Does not execute repository code, clone repositories, run scanners from pull requests, or accept arbitrary URLs.
- Does not automatically delete, lock, dismiss, or rewrite repository data.
- Does not label a person as a hacker; signals describe observable risk and always require human confirmation.
- Guardian Lock blocks Sentinel's outbound GitHub writes without disabling monitoring.

See [THREAT-MODEL.md](THREAT-MODEL.md) and [PRIVACY.md](PRIVACY.md).

## Architecture

```text
GitHub App webhooks ──HMAC──> Sentinel event gate ──> sanitized event log
                                          │
GitHub installation API <──short token────┼──> deterministic repository auditor
                                          │
                                          ├──> SQLite encrypted-token store
                                          ├──> optional stateless AI summary
                                          └──> owner dashboard / emergency pause
```

The included Render Blueprint uses one Starter web service and a 1 GB persistent disk. SQLite is appropriate for the initial single-instance deployment; larger public installations should move persistence and work queues to managed PostgreSQL before horizontal scaling.

## GitHub App registration

Create a GitHub App under **Settings → Developer settings → GitHub Apps**.

Use these URLs after deployment:

- Homepage: `https://YOUR-SERVICE.onrender.com`
- Callback: `https://YOUR-SERVICE.onrender.com/auth/github/callback`
- Setup: `https://YOUR-SERVICE.onrender.com/`
- Webhook: `https://YOUR-SERVICE.onrender.com/webhooks/github`

Enable **Request user authorization during installation** and generate a private key.

Repository permissions:

| Permission | Access | Why |
|---|---:|---|
| Actions | Read | Workflow runs and default token posture |
| Administration | Read | Branch protection and repository security configuration |
| Code scanning alerts | Read | Open CodeQL and compatible scanner alerts |
| Contents | Read | Inspect security files and workflow configuration only |
| Dependabot alerts | Read | Open dependency vulnerabilities |
| Issues | Write | Optional owner-approved posture report publishing |
| Members | Read | Membership-change monitoring |
| Metadata | Read | Required repository metadata |
| Secret scanning alerts | Read | Secret and push-protection alerts |

Do **not** grant Contents write, Workflows write, Secrets, Deployments, or repository deletion permissions.

Subscribe to these events:

`branch_protection_rule`, `code_scanning_alert`, `dependabot_alert`, `deploy_key`, `installation`, `installation_repositories`, `member`, `membership`, `public`, `push`, `repository`, `repository_vulnerability_alert`, `secret_scanning_alert`, `team`, and `workflow_run`.

## Deploy to Render

1. Fork or clone this repository.
2. In Render, create a Blueprint from `render.yaml`.
3. Set the GitHub App values requested by the Blueprint:
   - `GITHUB_APP_ID`
   - `GITHUB_APP_SLUG`
   - `GITHUB_CLIENT_ID`
   - `GITHUB_CLIENT_SECRET`
   - `GITHUB_PRIVATE_KEY_FILE=/etc/secrets/github-app.pem`
   - `GITHUB_WEBHOOK_SECRET`
4. Optionally set `OPENAI_API_KEY` for sanitized AI summaries.
5. Confirm the service reports `configured: true` at `/healthz`.
6. Install the GitHub App only on repositories you authorize.

Add the GitHub App private key as a Render **Secret File** named
`github-app.pem`. Render mounts it at `/etc/secrets/github-app.pem`, so the PEM
never needs to be pasted into an environment variable. Inline
`GITHUB_PRIVATE_KEY` remains supported for local development.

Never commit `.env`, a GitHub App private key, webhook secret, OAuth client secret, OpenAI key, or Render-generated encryption key.

## Run locally

Requires Node.js 24 or newer.

```bash
cp .env.example .env
npm install
npm run check
npm start
```

Local development starts in setup-required mode when GitHub credentials are absent. Health checks, the public landing page, deterministic unit tests, and static UI remain available.

## Owner-approved publishing

The server contains an authenticated endpoint that can create or update a single posture issue in a repository. It requires current installation access, CSRF validation, and the exact confirmation word `PUBLISH`. Automatic issue publishing is disabled by default with `AUTO_PUBLISH_ISSUES=false`.

## Limits

Daybreak Shield reduces risk; it cannot guarantee that an account will not be compromised or determine a person's intent. A repository GitHub App cannot monitor personal-account sign-in sessions, replace GitHub account passkeys or 2FA, inspect secret values, or monitor repositories where it is not installed. Organization audit-log visibility depends on the owner's GitHub plan and permissions.

## License

MIT
