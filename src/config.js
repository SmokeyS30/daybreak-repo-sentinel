import path from 'node:path';

function positiveInteger(value, fallback, minimum, maximum) {
  const parsed = Number.parseInt(value || '', 10);
  if (!Number.isFinite(parsed)) return fallback;
  return Math.min(Math.max(parsed, minimum), maximum);
}

function normalizePrivateKey(value = '') {
  return value.trim().replace(/^"|"$/g, '').replace(/\\n/g, '\n');
}

function safeBaseUrl(value, production) {
  const fallback = production ? 'https://daybreak-repo-sentinel.onrender.com' : 'http://127.0.0.1:3000';
  const url = new URL(value || fallback);
  const local = ['127.0.0.1', 'localhost', '::1'].includes(url.hostname);
  if (production && url.protocol !== 'https:') throw new Error('PUBLIC_BASE_URL must use HTTPS in production.');
  if (!production && url.protocol !== 'https:' && !(local && url.protocol === 'http:')) {
    throw new Error('Development PUBLIC_BASE_URL must use HTTPS or local HTTP.');
  }
  return url.toString().replace(/\/$/, '');
}

export function loadConfig(env = process.env, overrides = {}) {
  const production = (overrides.nodeEnv || env.NODE_ENV) === 'production';
  const dataDir = path.resolve(overrides.dataDir || env.DATA_DIR || './data');
  const config = {
    production,
    host: overrides.host || env.HOST || '127.0.0.1',
    port: positiveInteger(overrides.port || env.PORT, 3000, 1, 65535),
    baseUrl: safeBaseUrl(overrides.baseUrl || env.PUBLIC_BASE_URL, production),
    dataDir,
    databasePath: path.resolve(overrides.databasePath || path.join(dataDir, 'sentinel.sqlite')),
    github: {
      appId: String(overrides.github?.appId || env.GITHUB_APP_ID || '').trim(),
      appSlug: String(overrides.github?.appSlug || env.GITHUB_APP_SLUG || '').trim(),
      clientId: String(overrides.github?.clientId || env.GITHUB_CLIENT_ID || '').trim(),
      clientSecret: String(overrides.github?.clientSecret || env.GITHUB_CLIENT_SECRET || '').trim(),
      privateKey: normalizePrivateKey(overrides.github?.privateKey || env.GITHUB_PRIVATE_KEY),
      webhookSecret: String(overrides.github?.webhookSecret || env.GITHUB_WEBHOOK_SECRET || '').trim()
    },
    sessionSecret: String(overrides.sessionSecret || env.SESSION_SECRET || '').trim(),
    encryptionSecret: String(overrides.encryptionSecret || env.DATA_ENCRYPTION_KEY || '').trim(),
    openai: {
      apiKey: String(overrides.openai?.apiKey || env.OPENAI_API_KEY || '').trim(),
      model: String(overrides.openai?.model || env.OPENAI_MODEL || 'gpt-5.4-mini').trim(),
      baseUrl: String(overrides.openai?.baseUrl || env.OPENAI_BASE_URL || 'https://api.openai.com/v1').replace(/\/$/, '')
    },
    scanIntervalMinutes: positiveInteger(overrides.scanIntervalMinutes || env.SCAN_INTERVAL_MINUTES, 15, 5, 1440),
    maxRepositoriesPerScan: positiveInteger(overrides.maxRepositoriesPerScan || env.MAX_REPOSITORIES_PER_SCAN, 250, 1, 1000),
    publicMetrics: String(overrides.publicMetrics ?? env.PUBLIC_METRICS ?? 'true') === 'true',
    autoPublishIssues: String(overrides.autoPublishIssues ?? env.AUTO_PUBLISH_ISSUES ?? 'false') === 'true'
  };

  const required = [config.github.appId, config.github.appSlug, config.github.clientId, config.github.clientSecret,
    config.github.privateKey, config.github.webhookSecret, config.sessionSecret, config.encryptionSecret];
  config.configured = required.every(Boolean);
  if (production && config.configured && (config.sessionSecret.length < 24 || config.encryptionSecret.length < 24)) {
    throw new Error('SESSION_SECRET and DATA_ENCRYPTION_KEY must each contain at least 24 characters.');
  }
  return config;
}
