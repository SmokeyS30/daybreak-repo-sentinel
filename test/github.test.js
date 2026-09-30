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

test('rate-limited responses stay distinguishable and are not swallowed as null', async () => {
  const rateLimitedFetch = async () => ({
    status: 403,
    ok: false,
    headers: { get: (name) => (String(name).toLowerCase() === 'x-ratelimit-remaining' ? '0' : null) },
    json: async () => ({ message: 'API rate limit exceeded for installation.' })
  });
  const client = new GitHubClient({}, { fetchImpl: rateLimitedFetch });
  client.installationTokens.set(1, { token: 'test-token', expiresAt: Date.now() + 3_600_000 });
  const error = await client.optional(1, '/repos/o/r').catch((e) => e);
  assert.equal(error.rateLimited, true);
  assert.equal(error.status, 403);
});

test('plain 404 responses are still treated as absent', async () => {
  const notFoundFetch = async () => ({
    status: 404,
    ok: false,
    headers: { get: () => null },
    json: async () => ({ message: 'Not Found' })
  });
  const client = new GitHubClient({}, { fetchImpl: notFoundFetch });
  client.installationTokens.set(1, { token: 'test-token', expiresAt: Date.now() + 3_600_000 });
  assert.equal(await client.optional(1, '/repos/o/r'), null);
});
