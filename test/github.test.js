import test from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPairSync } from 'node:crypto';
import { GitHubClient } from '../src/github.js';

test('creates a short-lived GitHub App JWT', () => {
  const { privateKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });
  const client = new GitHubClient({ appId: '123', privateKey: privateKey.export({ type: 'pkcs8', format: 'pem' }) });
  const token = client.appJwt();
  const parts = token.split('.');
  assert.equal(parts.length, 3);
  const payload = JSON.parse(Buffer.from(parts[1], 'base64url').toString('utf8'));
  assert.equal(payload.iss, '123');
  assert.ok(payload.exp - payload.iat <= 600);
});

test('refuses arbitrary outbound hosts', async () => {
  const client = new GitHubClient({}, { fetchImpl: async () => { throw new Error('must not fetch'); } });
  await assert.rejects(() => client.request('https://attacker.invalid/'), /fixed GitHub API hosts/);
  await assert.rejects(() => client.request('https://api.github.com.attacker.invalid/'), /fixed GitHub API hosts/);
});
