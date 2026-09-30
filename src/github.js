import { createSign } from 'node:crypto';
import { safeText } from './security.js';

const API = 'https://api.github.com';
const WEB = 'https://github.com';

function base64url(value) {
  return Buffer.from(typeof value === 'string' ? value : JSON.stringify(value)).toString('base64url');
}

function errorDetail(payload, status) {
  return safeText(payload?.message || `GitHub API returned HTTP ${status}.`, 300);
}

export class GitHubClient {
  constructor(config, { fetchImpl = fetch } = {}) {
    this.config = config;
    this.fetch = fetchImpl;
    this.installationTokens = new Map();
  }

  appJwt() {
    const now = Math.floor(Date.now() / 1000);
    const header = base64url({ alg: 'RS256', typ: 'JWT' });
    const payload = base64url({ iat: now - 60, exp: now + 540, iss: this.config.appId });
    const input = `${header}.${payload}`;
    const signature = createSign('RSA-SHA256').update(input).end().sign(this.config.privateKey, 'base64url');
    return `${input}.${signature}`;
  }

  async request(url, { token, method = 'GET', body, headers = {} } = {}) {
    const target = new URL(url);
    const allowedApi = target.origin === API;
    const allowedOauth = target.origin === WEB && target.pathname === '/login/oauth/access_token';
    if (!allowedApi && !allowedOauth) {
      throw new Error('Refused a request outside the fixed GitHub API hosts.');
    }
    const response = await this.fetch(url, {
      method,
      headers: {
        Accept: 'application/vnd.github+json',
        'Content-Type': 'application/json',
        'User-Agent': 'daybreak-repo-sentinel/0.1',
        'X-GitHub-Api-Version': '2022-11-28',
        ...(token ? { Authorization: `Bearer ${token}` } : {}),
        ...headers
      },
      body: body === undefined ? undefined : JSON.stringify(body),
      signal: AbortSignal.timeout(30_000)
    });
    if (response.status === 204) return null;
    const payload = await response.json().catch(() => ({}));
    if (!response.ok) {
      const error = new Error(errorDetail(payload, response.status));
      error.status = response.status;
      error.github = true;
      throw error;
    }
    return payload;
  }

  loginUrl(state, redirectUri) {
    const url = new URL(`${WEB}/login/oauth/authorize`);
    url.searchParams.set('client_id', this.config.clientId);
    url.searchParams.set('state', state);
    url.searchParams.set('redirect_uri', redirectUri);
    return url.toString();
  }

  installUrl() {
    if (!this.config.appSlug) return null;
    return `${WEB}/apps/${encodeURIComponent(this.config.appSlug)}/installations/new`;
  }

  async exchangeCode(code, redirectUri) {
    const payload = await this.request(`${WEB}/login/oauth/access_token`, {
      method: 'POST',
      body: { client_id: this.config.clientId, client_secret: this.config.clientSecret, code, redirect_uri: redirectUri }
    });
    if (!payload.access_token) throw new Error('GitHub did not return a user access token.');
    return payload.access_token;
  }

  user(token) {
    return this.request(`${API}/user`, { token });
  }

  async userInstallations(token) {
    const installations = [];
    for (let page = 1; page <= 10; page += 1) {
      const payload = await this.request(`${API}/user/installations?per_page=100&page=${page}`, { token });
      installations.push(...(payload.installations || []));
      if ((payload.installations || []).length < 100) break;
    }
    return installations;
  }

  async installationToken(installationId) {
    const cached = this.installationTokens.get(Number(installationId));
    if (cached && cached.expiresAt > Date.now() + 60_000) return cached.token;
    const payload = await this.request(`${API}/app/installations/${Number(installationId)}/access_tokens`, {
      method: 'POST', token: this.appJwt(), body: {}
    });
    const expiresAt = new Date(payload.expires_at).valueOf();
    this.installationTokens.set(Number(installationId), { token: payload.token, expiresAt });
    return payload.token;
  }

  async installationRequest(installationId, apiPath, options = {}) {
    if (!String(apiPath).startsWith('/')) throw new Error('GitHub API path must start with /.');
    const token = await this.installationToken(installationId);
    return this.request(`${API}${apiPath}`, { ...options, token });
  }

  async listRepositories(installationId, maximum = 250) {
    const repositories = [];
    for (let page = 1; page <= 10 && repositories.length < maximum; page += 1) {
      const payload = await this.installationRequest(installationId, `/installation/repositories?per_page=100&page=${page}`);
      repositories.push(...(payload.repositories || []));
      if ((payload.repositories || []).length < 100) break;
    }
    return repositories.slice(0, maximum);
  }

  async optional(installationId, apiPath) {
    try { return await this.installationRequest(installationId, apiPath); }
    catch (error) { if ([403, 404, 422].includes(error.status)) return null; throw error; }
  }

  async content(installationId, owner, repo, filePath, ref) {
    const suffix = ref ? `?ref=${encodeURIComponent(ref)}` : '';
    const payload = await this.optional(installationId, `/repos/${encodeURIComponent(owner)}/${encodeURIComponent(repo)}/contents/${filePath.split('/').map(encodeURIComponent).join('/')}${suffix}`);
    if (!payload || Array.isArray(payload) || payload.type !== 'file' || payload.encoding !== 'base64') return null;
    if (payload.size > 256_000) return null;
    return Buffer.from(payload.content.replace(/\n/g, ''), 'base64').toString('utf8');
  }

  async directory(installationId, owner, repo, directoryPath, ref) {
    const suffix = ref ? `?ref=${encodeURIComponent(ref)}` : '';
    const payload = await this.optional(installationId, `/repos/${encodeURIComponent(owner)}/${encodeURIComponent(repo)}/contents/${directoryPath.split('/').map(encodeURIComponent).join('/')}${suffix}`);
    return Array.isArray(payload) ? payload : [];
  }

  async publishSecurityIssue(installationId, owner, repo, body) {
    const title = '[Daybreak Repo Sentinel] Security posture report';
    const existing = await this.installationRequest(installationId, `/repos/${encodeURIComponent(owner)}/${encodeURIComponent(repo)}/issues?state=open&per_page=100`);
    const issue = existing.find((item) => item.title === title && !item.pull_request);
    if (issue) return this.installationRequest(installationId, `/repos/${encodeURIComponent(owner)}/${encodeURIComponent(repo)}/issues/${issue.number}`, { method: 'PATCH', body: { body } });
    return this.installationRequest(installationId, `/repos/${encodeURIComponent(owner)}/${encodeURIComponent(repo)}/issues`, { method: 'POST', body: { title, body } });
  }
}
