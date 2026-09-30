import test from 'node:test';
import assert from 'node:assert/strict';
import { createHmac } from 'node:crypto';
import { decryptString, encryptString, redactSecrets, verifyWebhookSignature } from '../src/security.js';

test('encrypts stored user tokens with authenticated encryption', () => {
  const secret = 'a-very-long-test-encryption-secret';
  const encrypted = encryptString('ghu_sensitive-token', secret);
  assert.equal(encrypted.includes('ghu_sensitive-token'), false);
  assert.equal(decryptString(encrypted, secret), 'ghu_sensitive-token');
  assert.throws(() => decryptString(encrypted, 'wrong-secret'));
});

test('accepts only a valid GitHub webhook signature', () => {
  const raw = Buffer.from('{"action":"created"}');
  const secret = 'webhook-secret';
  const signature = `sha256=${createHmac('sha256', secret).update(raw).digest('hex')}`;
  assert.equal(verifyWebhookSignature(raw, signature, secret), true);
  assert.equal(verifyWebhookSignature(Buffer.from('{}'), signature, secret), false);
  assert.equal(verifyWebhookSignature(raw, 'sha256=bad', secret), false);
});

test('redacts common credential forms from bounded evidence', () => {
  const value = redactSecrets('token github_pat_abcdefghijklmnopqrstuvwxyz123456 and sk-exampleSECRET123456789');
  assert.equal(value.includes('github_pat_'), false);
  assert.equal(value.includes('sk-example'), false);
});
