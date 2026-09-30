import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { createSentinelServer } from '../server.js';

test('serves health and privacy-safe public status before GitHub setup', async () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'repo-sentinel-server-'));
  const app = createSentinelServer({ env: { NODE_ENV: 'development', DATA_DIR: directory, PUBLIC_BASE_URL: 'http://127.0.0.1:3000' }, overrides: { databasePath: path.join(directory, 'test.sqlite') } });
  await new Promise((resolve) => app.server.listen(0, '127.0.0.1', resolve));
  try {
    const address = app.server.address();
    const health = await fetch(`http://127.0.0.1:${address.port}/healthz`).then((response) => response.json());
    const status = await fetch(`http://127.0.0.1:${address.port}/api/public/status`).then((response) => response.json());
    assert.equal(health.ok, true);
    assert.equal(health.configured, false);
    assert.equal(status.monitoring, false);
    assert.equal('githubToken' in status, false);
  } finally { await app.close(); fs.rmSync(directory, { recursive: true }); }
});
