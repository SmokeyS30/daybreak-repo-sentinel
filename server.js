import http from 'node:http';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { loadConfig } from './src/config.js';
import { openDatabase } from './src/database.js';
import { GitHubClient } from './src/github.js';
import { createAiTriage } from './src/ai.js';
import { scanInstallation } from './src/audit.js';
import { processGitHubWebhook } from './src/webhooks.js';
import { clearSessionCookie, decryptString, encryptString, parseCookies, randomToken, sessionCookie, sha256, verifyWebhookSignature, safeText } from './src/security.js';

const root = path.dirname(fileURLToPath(import.meta.url));
const publicRoot = path.join(root, 'public');
const mime = { '.html': 'text/html; charset=utf-8', '.css': 'text/css; charset=utf-8', '.js': 'text/javascript; charset=utf-8', '.svg': 'image/svg+xml', '.webmanifest': 'application/manifest+json' };

function json(response, status, body, headers = {}) {
  response.writeHead(status, { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store', ...headers });
  response.end(JSON.stringify(body));
}

function redirect(response, location, headers = {}) { response.writeHead(302, { Location: location, ...headers }); response.end(); }

async function readBody(request, limit = 2 * 1024 * 1024) {
  const chunks = []; let size = 0;
  for await (const chunk of request) {
    size += chunk.length;
    if (size > limit) throw Object.assign(new Error('Request body is too large.'), { status: 413 });
    chunks.push(chunk);
  }
  return Buffer.concat(chunks);
}

function csrfRequired(request, session) {
  if (['GET', 'HEAD', 'OPTIONS'].includes(request.method)) return;
  if (request.headers['x-sentinel-csrf'] !== session.csrf_token) throw Object.assign(new Error('Security token is missing or expired.'), { status: 403 });
}

function shieldSnapshot(installation, incidents) {
  const highest = incidents[0] || null;
  return {
    locked: Boolean(installation.shield_locked),
    level: installation.shield_locked ? 'locked' : highest?.severity || 'clear',
    openIncidents: incidents.length,
    highestScore: highest?.score || 0,
    incidents
  };
}

export function createSentinelServer(options = {}) {
  const config = options.config || loadConfig(options.env || process.env, options.overrides || {});
  const db = options.db || openDatabase(config.databasePath);
  // Cumulative API-usage counters for the public stats endpoint. In-memory is
  // enough: the external watchdog samples hourly and tracks deltas itself.
  const startedAt = new Date().toISOString();
  const stats = { inboundRequests: 0, outboundGithubCalls: 0, githubRateLimitedHits: 0, openaiCalls: 0, byRepo: {} };
  const github = options.github || new GitHubClient(config.github, { ...(options.githubOptions || {}), stats });
  const ai = options.ai || createAiTriage(config.openai, { ...(options.aiOptions || {}), stats });
  const requestLog = new Map();
  const accessCache = new Map();
  let workerBusy = false;
  let workerTimer;

  function rateLimited(request, limit = 240) {
    const key = request.socket.remoteAddress || 'unknown';
    const cutoff = Date.now() - 60_000;
    const current = (requestLog.get(key) || []).filter((stamp) => stamp > cutoff);
    current.push(Date.now()); requestLog.set(key, current);
    if (requestLog.size > 10_000) for (const [address, stamps] of requestLog) if (!stamps.some((stamp) => stamp > cutoff)) requestLog.delete(address);
    return current.length > limit;
  }

  function sessionFor(request) {
    const token = parseCookies(request.headers.cookie).sentinel_session;
    if (!token) return null;
    const session = db.getSession(sha256(token));
    if (!session) return null;
    try { return { ...session, githubToken: decryptString(session.github_token_encrypted, config.encryptionSecret) }; }
    catch { return null; }
  }

  async function refreshAccess(session, force = false) {
    const cached = accessCache.get(session.user_id);
    if (!force && cached && cached.expiresAt > Date.now()) return cached.ids;
    const installations = await github.userInstallations(session.githubToken);
    const ids = installations.map((item) => Number(item.id));
    db.replaceInstallationAccess(session.user_id, ids);
    for (const item of installations) db.upsertInstallation({ id: item.id, accountLogin: item.account?.login || 'unknown', accountType: item.account?.type || 'Unknown', targetType: item.target_type || null, suspended: Boolean(item.suspended_at) });
    accessCache.set(session.user_id, { ids, expiresAt: Date.now() + 60_000 });
    return ids;
  }

  async function requireInstallationAccess(session, installationId, force = false) {
    const ids = await refreshAccess(session, force);
    if (!ids.includes(Number(installationId)) || !db.userHasAccess(session.user_id, Number(installationId))) {
      throw Object.assign(new Error('Installation access is not available.'), { status: 403 });
    }
    const installation = db.getInstallation(Number(installationId));
    if (!installation) throw Object.assign(new Error('Installation not found.'), { status: 404 });
    return installation;
  }

  async function runDueScans() {
    if (workerBusy || !config.configured) return;
    workerBusy = true;
    try {
      for (const installation of db.dueInstallations(3)) {
        try { await scanInstallation({ installation, github, db, ai, config }); }
        catch (error) {
          db.scheduleInstallation(installation.id, new Date(Date.now() + 10 * 60_000));
          db.addEvent({ deliveryId: `scan-${randomToken(18)}`, installationId: installation.id, event: 'scheduled_scan', action: 'failed', risk: 'medium', title: 'Installation scan failed safely', detail: safeText(error.message, 240) });
        }
      }
    } finally { workerBusy = false; }
  }

  const server = http.createServer(async (request, response) => {
    stats.inboundRequests++;
    response.setHeader('X-Content-Type-Options', 'nosniff');
    response.setHeader('X-Frame-Options', 'DENY');
    response.setHeader('Referrer-Policy', 'no-referrer');
    response.setHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=(), payment=(), usb=()');
    response.setHeader('Content-Security-Policy', "default-src 'self'; img-src 'self' https://avatars.githubusercontent.com data:; style-src 'self'; script-src 'self'; connect-src 'self'; base-uri 'none'; frame-ancestors 'none'; form-action 'self' https://github.com");
    if (config.production) response.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
    if (rateLimited(request)) return json(response, 429, { error: 'Too many requests. Try again shortly.' });

    const url = new URL(request.url, config.baseUrl);
    try {
      if (request.method === 'GET' && url.pathname === '/healthz') return json(response, 200, { ok: true, service: 'daybreak-repo-sentinel', shield: true, configured: config.configured, workerBusy });
      if (request.method === 'GET' && url.pathname === '/api/public/status') {
        const counts = config.publicMetrics ? db.publicCounts() : { installations: null, repositories: null, open_findings: null, urgent_findings: null, last_event_at: null };
        return json(response, 200, { configured: config.configured, aiConfigured: ai.configured, monitoring: config.configured, ...counts });
      }
      // Aggregate API-usage counters plus a per-repository breakdown of the
      // app's own outbound GitHub API use (repo names are public; no per-user,
      // token, or secret data is exposed here), so this stays public like
      // /api/public/status.
      if (request.method === 'GET' && url.pathname === '/api/public/stats') {
        return json(response, 200, { ok: true, startedAt, ...stats });
      }
      if (request.method === 'GET' && url.pathname === '/github/install') {
        const target = github.installUrl();
        if (!target) throw Object.assign(new Error('GitHub App installation is not configured yet.'), { status: 503 });
        return redirect(response, target);
      }
      if (request.method === 'GET' && url.pathname === '/auth/github') {
        if (!config.configured) throw Object.assign(new Error('GitHub authentication is not configured yet.'), { status: 503 });
        const state = randomToken(32);
        db.createOauthState(sha256(state), new Date(Date.now() + 10 * 60_000).toISOString());
        return redirect(response, github.loginUrl(state, `${config.baseUrl}/auth/github/callback`));
      }
      if (request.method === 'GET' && url.pathname === '/auth/github/callback') {
        const code = url.searchParams.get('code'); const state = url.searchParams.get('state');
        if (!code || !state || !db.consumeOauthState(sha256(state))) throw Object.assign(new Error('GitHub login state was not accepted.'), { status: 400 });
        const githubToken = await github.exchangeCode(code, `${config.baseUrl}/auth/github/callback`);
        const profile = await github.user(githubToken);
        const user = db.upsertUser(profile);
        const token = randomToken(32); const csrf = randomToken(24); const expiresAt = new Date(Date.now() + 7 * 24 * 60 * 60_000).toISOString();
        db.createSession({ tokenHash: sha256(token), userId: user.github_id, githubTokenEncrypted: encryptString(githubToken, config.encryptionSecret), csrfToken: csrf, expiresAt });
        const session = { user_id: user.github_id, githubToken };
        await refreshAccess(session, true);
        return redirect(response, '/', { 'Set-Cookie': sessionCookie(token, { secure: config.production }) });
      }
      if (request.method === 'POST' && url.pathname === '/webhooks/github') {
        if (!config.configured) throw Object.assign(new Error('Webhook receiver is not configured.'), { status: 503 });
        const raw = await readBody(request);
        if (!verifyWebhookSignature(raw, request.headers['x-hub-signature-256'], config.github.webhookSecret)) throw Object.assign(new Error('Webhook signature was not accepted.'), { status: 401 });
        const eventName = safeText(request.headers['x-github-event'], 80);
        const deliveryId = safeText(request.headers['x-github-delivery'], 100);
        let payload; try { payload = JSON.parse(raw.toString('utf8')); } catch { throw Object.assign(new Error('Webhook body must be valid JSON.'), { status: 400 }); }
        const result = processGitHubWebhook({ eventName, deliveryId, payload, db });
        setImmediate(runDueScans);
        return json(response, result.duplicate ? 200 : 202, result);
      }

      if (url.pathname.startsWith('/api/')) {
        const session = sessionFor(request);
        if (!session) return json(response, 401, { error: 'Sign in with GitHub to continue.' });
        csrfRequired(request, session);
        if (request.method === 'GET' && url.pathname === '/api/me') return json(response, 200, { user: { id: session.user_id, login: session.login, avatarUrl: session.avatar_url }, csrf: session.csrf_token, installUrl: github.installUrl() });
        if (request.method === 'POST' && url.pathname === '/api/logout') {
          const token = parseCookies(request.headers.cookie).sentinel_session; if (token) db.deleteSession(sha256(token));
          return json(response, 200, { ok: true }, { 'Set-Cookie': clearSessionCookie({ secure: config.production }) });
        }
        if (request.method === 'GET' && url.pathname === '/api/installations') {
          const ids = await refreshAccess(session);
          return json(response, 200, { installations: db.listInstallations().filter((item) => ids.includes(item.id)) });
        }
        const installationMatch = url.pathname.match(/^\/api\/installations\/(\d+)$/);
        if (request.method === 'GET' && installationMatch) {
          const installation = await requireInstallationAccess(session, Number(installationMatch[1]));
          const incidents = db.listOpenShieldIncidents(installation.id);
          return json(response, 200, { installation, shield: shieldSnapshot(installation, incidents), repositories: db.listRepositories(installation.id), findings: db.listOpenFindings(installation.id), events: db.recentEvents(installation.id), summary: db.latestSummary(installation.id) || null });
        }
        const scanMatch = url.pathname.match(/^\/api\/installations\/(\d+)\/scan$/);
        if (request.method === 'POST' && scanMatch) {
          const installation = await requireInstallationAccess(session, Number(scanMatch[1]), true);
          if (installation.paused) throw Object.assign(new Error('Monitoring is paused for this installation.'), { status: 423 });
          db.scheduleInstallation(installation.id, new Date()); setImmediate(runDueScans);
          return json(response, 202, { accepted: true });
        }
        const pauseMatch = url.pathname.match(/^\/api\/installations\/(\d+)\/(pause|resume)$/);
        if (request.method === 'POST' && pauseMatch) {
          const installation = await requireInstallationAccess(session, Number(pauseMatch[1]), true);
          db.setInstallationPaused(installation.id, pauseMatch[2] === 'pause');
          return json(response, 200, { paused: pauseMatch[2] === 'pause' });
        }
        const shieldLockMatch = url.pathname.match(/^\/api\/installations\/(\d+)\/shield\/(lock|unlock)$/);
        if (request.method === 'POST' && shieldLockMatch) {
          const installation = await requireInstallationAccess(session, Number(shieldLockMatch[1]), true);
          const action = shieldLockMatch[2];
          const body = JSON.parse((await readBody(request, 8_000)).toString('utf8') || '{}');
          const expected = action === 'lock' ? 'LOCK' : 'UNLOCK';
          if (body.confirm !== expected) throw Object.assign(new Error(`Type ${expected} to confirm this Guardian Lock change.`), { status: 400 });
          db.setShieldLocked(installation.id, action === 'lock');
          db.addEvent({ deliveryId: `shield-${randomToken(18)}`, installationId: installation.id, event: 'shield_control', action, risk: action === 'lock' ? 'high' : 'medium',
            title: action === 'lock' ? 'Guardian Lock engaged' : 'Guardian Lock released',
            detail: action === 'lock' ? 'Outbound GitHub writes from Sentinel are blocked. Monitoring and signed-webhook evidence collection continue.' : 'Outbound GitHub writes may proceed only through their existing explicit approval gates.' });
          return json(response, 200, { locked: action === 'lock' });
        }
        const shieldAcknowledgeMatch = url.pathname.match(/^\/api\/installations\/(\d+)\/shield\/incidents\/([0-9a-f-]+)\/acknowledge$/);
        if (request.method === 'POST' && shieldAcknowledgeMatch) {
          const installation = await requireInstallationAccess(session, Number(shieldAcknowledgeMatch[1]), true);
          const body = JSON.parse((await readBody(request, 8_000)).toString('utf8') || '{}');
          if (body.confirm !== 'ACKNOWLEDGE') throw Object.assign(new Error('Type ACKNOWLEDGE to confirm that you reviewed this incident.'), { status: 400 });
          if (!db.acknowledgeShieldIncident(shieldAcknowledgeMatch[2], installation.id)) throw Object.assign(new Error('Open Shield incident not found.'), { status: 404 });
          db.addEvent({ deliveryId: `shield-${randomToken(18)}`, installationId: installation.id, event: 'shield_incident', action: 'acknowledged', risk: 'info', title: 'Shield incident acknowledged', detail: 'An authorized owner marked a Shield incident reviewed. No GitHub setting was changed.' });
          return json(response, 200, { acknowledged: true });
        }
        const acceptMatch = url.pathname.match(/^\/api\/installations\/(\d+)\/findings\/([0-9a-f-]+)\/accept$/);
        if (request.method === 'POST' && acceptMatch) {
          const installation = await requireInstallationAccess(session, Number(acceptMatch[1]), true);
          db.acceptFinding(acceptMatch[2], installation.id);
          return json(response, 200, { accepted: true });
        }
        const publishMatch = url.pathname.match(/^\/api\/installations\/(\d+)\/repositories\/(\d+)\/publish$/);
        if (request.method === 'POST' && publishMatch) {
          const installation = await requireInstallationAccess(session, Number(publishMatch[1]), true);
          if (installation.shield_locked) throw Object.assign(new Error('Guardian Lock is engaged. Release it before publishing to GitHub.'), { status: 423 });
          const body = JSON.parse((await readBody(request, 32_000)).toString('utf8') || '{}');
          if (body.confirm !== 'PUBLISH') throw Object.assign(new Error('Type PUBLISH to confirm creating or updating the GitHub issue.'), { status: 400 });
          const repo = db.getRepositoryById(installation.id, Number(publishMatch[2]));
          if (!repo) throw Object.assign(new Error('Repository not found.'), { status: 404 });
          const findings = db.listOpenFindings(installation.id).filter((item) => item.repo_id === repo.id);
          const report = ['## Daybreak Repo Sentinel report', '', ...findings.slice(0, 30).map((item) => `- **${item.severity.toUpperCase()}** — ${item.title}`), '', '> Review evidence in the Sentinel dashboard before changing settings.'].join('\n');
          const issue = await github.publishSecurityIssue(installation.id, repo.owner, repo.name, report);
          return json(response, 201, { issueUrl: issue.html_url });
        }
        return json(response, 404, { error: 'API route not found.' });
      }

      if (!['GET', 'HEAD'].includes(request.method)) return json(response, 405, { error: 'Method not allowed.' });
      const requestPath = url.pathname === '/' ? '/index.html' : url.pathname;
      let resolved; try { resolved = path.resolve(publicRoot, `.${decodeURIComponent(requestPath)}`); } catch { return json(response, 404, { error: 'Not found.' }); }
      if (!resolved.startsWith(`${publicRoot}${path.sep}`)) return json(response, 404, { error: 'Not found.' });
      try {
        const stat = fs.statSync(resolved); if (!stat.isFile()) throw new Error();
        response.writeHead(200, { 'Content-Type': mime[path.extname(resolved)] || 'application/octet-stream', 'Cache-Control': path.basename(resolved) === 'index.html' ? 'no-cache' : 'public, max-age=3600' });
        if (request.method === 'HEAD') return response.end();
        return fs.createReadStream(resolved).pipe(response);
      } catch { return json(response, 404, { error: 'Not found.' }); }
    } catch (error) {
      const status = error.status || (error.github && error.status) || 500;
      const message = status < 500 ? error.message : 'Request failed safely.';
      return json(response, status, { error: safeText(message, 240) });
    }
  });

  return {
    server, db, config, github, ai, runDueScans,
    startWorker() { db.pruneSessions(); workerTimer = setInterval(runDueScans, 60_000); workerTimer.unref(); setImmediate(runDueScans); },
    async close() { if (workerTimer) clearInterval(workerTimer); if (server.listening) await new Promise((resolve) => server.close(resolve)); db.close(); }
  };
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const app = createSentinelServer();
  app.server.listen(app.config.port, app.config.host, () => {
    app.startWorker();
    console.log(`Daybreak Repo Sentinel is ready at ${app.config.baseUrl} (${app.config.configured ? 'configured' : 'setup required'}).`);
  });
  const shutdown = async () => { await app.close(); process.exit(0); };
  process.on('SIGTERM', shutdown); process.on('SIGINT', shutdown);
}
