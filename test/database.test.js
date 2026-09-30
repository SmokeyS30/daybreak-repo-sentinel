import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { openDatabase } from '../src/database.js';

function database() {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'repo-sentinel-'));
  return { db: openDatabase(path.join(directory, 'test.sqlite')), directory };
}

test('isolates repositories and findings by installation', () => {
  const { db, directory } = database();
  try {
    db.upsertInstallation({ id: 1, accountLogin: 'one', accountType: 'User' });
    db.upsertInstallation({ id: 2, accountLogin: 'two', accountType: 'User' });
    const first = db.upsertRepository(1, { id: 11, full_name: 'one/repo', name: 'repo', owner: { login: 'one' } });
    db.upsertRepository(2, { id: 22, full_name: 'two/repo', name: 'repo', owner: { login: 'two' } });
    db.upsertFinding({ installationId: 1, repoId: first.id, fingerprint: 'one', severity: 'high', title: 'Test', evidence: 'Safe evidence', source: 'scheduled-posture' });
    assert.equal(db.listRepositories(1).length, 1);
    assert.equal(db.listRepositories(1)[0].full_name, 'one/repo');
    assert.equal(db.listOpenFindings(1).length, 1);
    assert.equal(db.listOpenFindings(2).length, 0);
  } finally { db.close(); fs.rmSync(directory, { recursive: true }); }
});

test('resolves scanner findings that disappear on a later scan', () => {
  const { db, directory } = database();
  try {
    db.upsertInstallation({ id: 1, accountLogin: 'one', accountType: 'User' });
    const repo = db.upsertRepository(1, { id: 11, full_name: 'one/repo', name: 'repo', owner: { login: 'one' } });
    db.upsertFinding({ installationId: 1, repoId: repo.id, fingerprint: 'scan:11:old', severity: 'medium', title: 'Old', evidence: 'Old', source: 'scheduled-posture' });
    db.resolveStaleScannerFindings(repo.id, []);
    assert.equal(db.listOpenFindings(1).length, 0);
  } finally { db.close(); fs.rmSync(directory, { recursive: true }); }
});
