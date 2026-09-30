import test from 'node:test';
import assert from 'node:assert/strict';
import { createAiTriage } from '../src/ai.js';

test('AI triage is stateless and excludes repository names and evidence', async () => {
  let request;
  const ai = createAiTriage({ apiKey: 'test-key', model: 'test-model', baseUrl: 'https://api.openai.com/v1' }, { fetchImpl: async (url, options) => {
    request = { url, options, body: JSON.parse(options.body) };
    return { ok: true, json: async () => ({ output_text: JSON.stringify({ summary: 'Review urgent findings.', priorities: ['Rotate exposed credentials.'] }) }) };
  } });
  const result = await ai.summarize({ deterministic: 'Score 60.', findings: [{ severity: 'critical', title: 'Secret alert', source: 'scheduled-secret-scanning', full_name: 'private/hidden', evidence: 'private/hidden contains details' }] });
  assert.equal(request.body.store, false);
  assert.equal(request.options.body.includes('private/hidden'), false);
  assert.equal(request.options.body.includes('contains details'), false);
  assert.match(result, /Review urgent findings/);
});
