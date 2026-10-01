import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { createSentinelServer } from '../server.js';
import { GitHubClient } from '../src/github.js';
import { createAiTriage } from '../src/ai.js';

test('public stats endpoint exposes aggregate counters and nothing sensitive', async () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'repo-sentinel-stats-'));
  const app = createSentinelServer({ env: { NODE_ENV: 'development', DATA_DIR: directory, PUBLIC_BASE_URL: 'http://127.0.0.1:3000' }, overrides: { databasePath: path.join(directory, 'test.sqlite') } });
  await new Promise((resolve) => app.server.listen(0, '127.0.0.1', resolve));
  try {
    const address = app.server.address();
    const stats = await fetch(`http://127.0.0.1:${address.port}/api/public/stats`).then((response) => response.json());
    assert.equal(stats.ok, true);
    assert.ok(typeof stats.startedAt === 'string');
    for (const key of ['inboundRequests', 'outboundGithubCalls', 'githubRateLimitedHits', 'openaiCalls']) {
      assert.ok(Number.isInteger(stats[key]), `${key} should be an integer`);
    }
    assert.ok(stats.byRepo && typeof stats.byRepo === 'object', 'byRepo should be an object');
    assert.ok(stats.inboundRequests >= 1, 'the stats request itself counts as inbound');
    const blob = JSON.stringify(stats).toLowerCase();
    for (const leak of ['token', 'secret', 'privatekey', 'apikey']) assert.ok(!blob.includes(leak), `stats must not leak ${leak}`);
    const again = await fetch(`http://127.0.0.1:${address.port}/api/public/stats`).then((response) => response.json());
    assert.equal(again.inboundRequests, stats.inboundRequests + 1);
  } finally { await app.close(); fs.rmSync(directory, { recursive: true }); }
});

test('GitHub client counts outbound calls and rate-limit hits', async () => {
  const stats = { outboundGithubCalls: 0, githubRateLimitedHits: 0 };
  const okFetch = async () => ({ status: 200, ok: true, headers: { get: () => null }, json: async () => ({}) });
  const client = new GitHubClient({}, { fetchImpl: okFetch, stats });
  await client.request('https://api.github.com/rate_limit');
  assert.equal(stats.outboundGithubCalls, 1);
  assert.equal(stats.githubRateLimitedHits, 0);

  const limitedFetch = async () => ({ status: 429, ok: false, headers: { get: () => null }, json: async () => ({ message: 'slow down' }) });
  const limited = new GitHubClient({}, { fetchImpl: limitedFetch, stats });
  await assert.rejects(() => limited.request('https://api.github.com/rate_limit'), /slow down/);
  assert.equal(stats.outboundGithubCalls, 2);
  assert.equal(stats.githubRateLimitedHits, 1);
});

test('GitHub client attributes calls per repository', async () => {
  const stats = { outboundGithubCalls: 0, githubRateLimitedHits: 0 };
  const okFetch = async () => ({ status: 200, ok: true, headers: { get: () => null }, json: async () => ({}) });
  const client = new GitHubClient({}, { fetchImpl: okFetch, stats });
  await client.request('https://api.github.com/repos/SmokeyS30/daybreak-repo-sentinel/actions/runs');
  await client.request('https://api.github.com/repos/SmokeyS30/orbit-buddy');
  await client.request('https://api.github.com/rate_limit');
  assert.equal(stats.outboundGithubCalls, 3);
  assert.deepEqual(stats.byRepo['SmokeyS30/daybreak-repo-sentinel'], { outboundGithubCalls: 1, githubRateLimitedHits: 0 });
  assert.deepEqual(stats.byRepo['SmokeyS30/orbit-buddy'], { outboundGithubCalls: 1, githubRateLimitedHits: 0 });
  assert.deepEqual(stats.byRepo._other, { outboundGithubCalls: 1, githubRateLimitedHits: 0 });

  const limitedFetch = async () => ({ status: 429, ok: false, headers: { get: () => null }, json: async () => ({ message: 'slow down' }) });
  const limited = new GitHubClient({}, { fetchImpl: limitedFetch, stats });
  await assert.rejects(() => limited.request('https://api.github.com/repos/SmokeyS30/orbit-buddy/issues'), /slow down/);
  assert.equal(stats.outboundGithubCalls, 4);
  assert.equal(stats.githubRateLimitedHits, 1);
  assert.deepEqual(stats.byRepo['SmokeyS30/orbit-buddy'], { outboundGithubCalls: 2, githubRateLimitedHits: 1 });
});

test('AI triage counts OpenAI calls', async () => {
  const stats = { openaiCalls: 0 };
  const fetchImpl = async () => ({ ok: true, json: async () => ({ output_text: JSON.stringify({ summary: 'fine', priorities: [] }) }) });
  const ai = createAiTriage({ apiKey: 'sk-test' }, { fetchImpl, stats });
  await ai.summarize({ findings: [], deterministic: 'deterministic summary' });
  assert.equal(stats.openaiCalls, 1);
});
