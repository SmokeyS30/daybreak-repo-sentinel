import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { loadConfig } from '../src/config.js';

test('loads a GitHub App private key from a mounted secret file', () => {
  const directory = mkdtempSync(join(tmpdir(), 'sentinel-config-'));
  const keyPath = join(directory, 'github-app.pem');
  const key = '-----BEGIN PRIVATE KEY-----\nexample\n-----END PRIVATE KEY-----';
  writeFileSync(keyPath, key, { mode: 0o600 });

  const config = loadConfig({ GITHUB_PRIVATE_KEY_FILE: keyPath });
  assert.equal(config.github.privateKey, key);
});

test('prefers an inline private key when both sources are configured', () => {
  const config = loadConfig({
    GITHUB_PRIVATE_KEY: 'inline\\nkey',
    GITHUB_PRIVATE_KEY_FILE: '/does/not/exist'
  });
  assert.equal(config.github.privateKey, 'inline\nkey');
});
