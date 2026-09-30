import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { openDatabase } from '../src/database.js';
import { processGitHubWebhook } from '../src/webhooks.js';

function setup() {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'repo-sentinel-webhook-'));
  return { db: openDatabase(path.join(directory, 'test.sqlite')), directory };
}

const base = {
  installation: { id: 91, account: { login: 'octo', type: 'User' }, target_type: 'User' },
  repository: { id: 55, name: 'demo', full_name: 'octo/demo', owner: { login: 'octo' }, private: true, default_branch: 'main' }
};

test('records a sanitized critical finding for a new secret alert', () => {
  const { db, directory } = setup();
  try {
    const result = processGitHubWebhook({ eventName: 'secret_scanning_alert', deliveryId: 'delivery-123456', payload: { ...base, action: 'created', alert: { number: 7, secret: 'sk-do-not-store-this-value' } }, db });
    assert.equal(result.risk, 'critical');
    const findings = db.listOpenFindings(91);
    assert.equal(findings.length, 1);
    assert.equal(findings[0].severity, 'critical');
    assert.equal(JSON.stringify(findings).includes('do-not-store'), false);
    assert.equal(processGitHubWebhook({ eventName: 'secret_scanning_alert', deliveryId: 'delivery-123456', payload: base, db }).duplicate, true);
  } finally { db.close(); fs.rmSync(directory, { recursive: true }); }
});

test('new workflow files schedule a scan and create a bounded finding', () => {
  const { db, directory } = setup();
  try {
    processGitHubWebhook({ eventName: 'push', deliveryId: 'delivery-987654', payload: { ...base, after: 'abc123', commits: [{ modified: ['.github/workflows/release.yml'] }] }, db });
    assert.equal(db.listOpenFindings(91)[0].title, 'GitHub Actions workflow changed');
    assert.equal(db.dueInstallations(5)[0].id, 91);
  } finally { db.close(); fs.rmSync(directory, { recursive: true }); }
});
