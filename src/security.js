import { createCipheriv, createDecipheriv, createHash, createHmac, randomBytes, timingSafeEqual } from 'node:crypto';

export const sha256 = (value) => createHash('sha256').update(String(value)).digest('hex');
export const randomToken = (bytes = 32) => randomBytes(bytes).toString('base64url');

function derivedKey(secret) {
  if (!secret) throw new Error('Encryption secret is not configured.');
  return createHash('sha256').update(secret).digest();
}

export function encryptString(plaintext, secret) {
  const iv = randomBytes(12);
  const cipher = createCipheriv('aes-256-gcm', derivedKey(secret), iv);
  const encrypted = Buffer.concat([cipher.update(String(plaintext), 'utf8'), cipher.final()]);
  return ['v1', iv.toString('base64url'), cipher.getAuthTag().toString('base64url'), encrypted.toString('base64url')].join('.');
}

export function decryptString(bundle, secret) {
  const [version, ivText, tagText, payloadText] = String(bundle || '').split('.');
  if (version !== 'v1' || !ivText || !tagText || !payloadText) throw new Error('Encrypted value is malformed.');
  const decipher = createDecipheriv('aes-256-gcm', derivedKey(secret), Buffer.from(ivText, 'base64url'));
  decipher.setAuthTag(Buffer.from(tagText, 'base64url'));
  return Buffer.concat([decipher.update(Buffer.from(payloadText, 'base64url')), decipher.final()]).toString('utf8');
}

export function verifyWebhookSignature(rawBody, signature, secret) {
  if (!secret || !signature?.startsWith('sha256=')) return false;
  const expected = Buffer.from(`sha256=${createHmac('sha256', secret).update(rawBody).digest('hex')}`);
  const actual = Buffer.from(signature);
  return actual.length === expected.length && timingSafeEqual(actual, expected);
}

export function parseCookies(header = '') {
  const result = {};
  for (const part of header.split(';')) {
    const index = part.indexOf('=');
    if (index < 1) continue;
    const key = part.slice(0, index).trim();
    try { result[key] = decodeURIComponent(part.slice(index + 1).trim()); } catch { result[key] = ''; }
  }
  return result;
}

export function sessionCookie(token, { secure = true, maxAge = 60 * 60 * 24 * 7 } = {}) {
  return `sentinel_session=${encodeURIComponent(token)}; Path=/; HttpOnly; SameSite=Lax; Max-Age=${maxAge}${secure ? '; Secure' : ''}`;
}

export function clearSessionCookie({ secure = true } = {}) {
  return `sentinel_session=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0${secure ? '; Secure' : ''}`;
}

export function safeText(value, maximum = 500) {
  return String(value || '').replace(/[\u0000-\u001f\u007f]/g, ' ').replace(/\s+/g, ' ').trim().slice(0, maximum);
}

export function redactSecrets(value) {
  return safeText(value, 4000)
    .replace(/(?:gh[pousr]_|github_pat_|sk-|AKIA)[A-Za-z0-9_-]{8,}/gi, '[REDACTED]')
    .replace(/-----BEGIN [^-]+-----[\s\S]*?-----END [^-]+-----/g, '[REDACTED KEY]')
    .replace(/\b[A-Fa-f0-9]{40,}\b/g, '[REDACTED HASH]');
}

export function secureEqual(left, right) {
  const a = Buffer.from(String(left || ''));
  const b = Buffer.from(String(right || ''));
  return a.length === b.length && timingSafeEqual(a, b);
}
