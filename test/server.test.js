import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { createSentinelServer } from '../server.js';
import { encryptString, sha256 } from '../src/security.js';

test('serves health and privacy-safe public status before GitHub setup', async () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'repo-sentinel-server-'));
  const app = createSentinelServer({ env: { NODE_ENV: 'development', DATA_DIR: directory, PUBLIC_BASE_URL: 'http://127.0.0.1:3000' }, overrides: { databasePath: path.join(directory, 'test.sqlite') } });
  await new Promise((resolve) => app.server.listen(0, '127.0.0.1', resolve));
  try {
    const address = app.server.address();
    const health = await fetch(`http://127.0.0.1:${address.port}/healthz`).then((response) => response.json());
    const status = await fetch(`http://127.0.0.1:${address.port}/api/public/status`).then((response) => response.json());
    const dashboardScript = await fetch(`http://127.0.0.1:${address.port}/app.js?v=3`);
    assert.equal(health.ok, true);
    assert.equal(health.configured, false);
    assert.equal(status.monitoring, false);
    assert.equal('githubToken' in status, false);
    assert.equal(dashboardScript.status, 200);
    assert.equal(dashboardScript.headers.get('cache-control'), 'no-cache');
  } finally { await app.close(); fs.rmSync(directory, { recursive: true }); }
});

test('Guardian Lock requires an authorized session, CSRF, and exact confirmation', async () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'repo-shield-server-'));
  const github = {
    installUrl: () => null,
    userInstallations: async () => [{ id: 91, account: { login: 'octo', type: 'User' }, target_type: 'User' }]
  };
  const app = createSentinelServer({ env: { NODE_ENV: 'development', DATA_DIR: directory, PUBLIC_BASE_URL: 'http://127.0.0.1:3000', DATA_ENCRYPTION_KEY: 'test-encryption-key' }, overrides: { databasePath: path.join(directory, 'test.sqlite') }, github });
  const token = 'session-token'; const csrf = 'csrf-token';
  app.db.upsertUser({ id: 7, login: 'owner' });
  app.db.createSession({ tokenHash: sha256(token), userId: 7, githubTokenEncrypted: encryptString('github-token', app.config.encryptionSecret), csrfToken: csrf, expiresAt: new Date(Date.now() + 60_000).toISOString() });
  await new Promise((resolve) => app.server.listen(0, '127.0.0.1', resolve));
  try {
    const address = app.server.address(); const base = `http://127.0.0.1:${address.port}`;
    await fetch(`${base}/api/installations`, { headers: { Cookie: `sentinel_session=${token}` } });
    const rejected = await fetch(`${base}/api/installations/91/shield/lock`, { method: 'POST', headers: { Cookie: `sentinel_session=${token}`, 'X-Sentinel-CSRF': csrf, 'Content-Type': 'application/json' }, body: JSON.stringify({ confirm: 'lock' }) });
    assert.equal(rejected.status, 400);
    const locked = await fetch(`${base}/api/installations/91/shield/lock`, { method: 'POST', headers: { Cookie: `sentinel_session=${token}`, 'X-Sentinel-CSRF': csrf, 'Content-Type': 'application/json' }, body: JSON.stringify({ confirm: 'LOCK' }) });
    assert.equal(locked.status, 200);
    assert.equal((await locked.json()).locked, true);
    assert.equal(app.db.getInstallation(91).shield_locked, 1);
    assert.equal(app.db.getInstallation(91).paused, 0);
  } finally { await app.close(); fs.rmSync(directory, { recursive: true }); }
});
