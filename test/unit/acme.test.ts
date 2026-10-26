import { describe, expect, test } from 'bun:test';
import { join } from 'node:path';
import { ariCertId, hexToBytes } from '../../src/certificate';
import { loadOrCreateAccountKey, signJws, thumbprint } from '../../src/acme/jws';
import { tempDir } from '../helpers';

describe('ARI certificate identifier', () => {
  test('RFC 9773 §4.1 example', () => {
    const aki = hexToBytes('69:88:5B:6B:87:46:40:41:E1:B3:7B:84:7B:A0:AE:2C:DE:01:C8:D4');
    expect(ariCertId(aki, hexToBytes('00:87:65:43:21'))).toBe('aYhba4dGQEHhs3uEe6CuLN4ByNQ.AIdlQyE');
    // The same serial without its sign byte, and with a redundant extra zero.
    expect(ariCertId(aki, hexToBytes('87:65:43:21'))).toBe('aYhba4dGQEHhs3uEe6CuLN4ByNQ.AIdlQyE');
    expect(ariCertId(aki, hexToBytes('00:00:87:65:43:21'))).toBe('aYhba4dGQEHhs3uEe6CuLN4ByNQ.AIdlQyE');
  });
});

describe('JWS', () => {
  test('thumbprint hashes the RFC 7638 canonical form', async () => {
    // RFC 7638's worked example is RSA. This pins the EC canonical form:
    // crv, kty, x, y in that order, no whitespace. The independent check is the
    // Pebble end-to-end test, where a wrong thumbprint fails every DNS-01 challenge.
    const jwk = {
      kty: 'EC' as const,
      crv: 'P-256' as const,
      x: 'f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU',
      y: 'x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0',
    };
    const canonical = `{"crv":"P-256","kty":"EC","x":"${jwk.x}","y":"${jwk.y}"}`;
    expect(await thumbprint(jwk)).toBe(new Bun.CryptoHasher('sha256').update(canonical).digest('base64url'));
  });

  test('account key persists, and signatures verify', async () => {
    const file = join(tempDir(), 'account.json');
    const a = await loadOrCreateAccountKey(file);
    const b = await loadOrCreateAccountKey(file);
    expect(b.thumbprint).toBe(a.thumbprint);

    const jws = await signJws(a, { nonce: 'n', url: 'https://x/y', kid: 'https://x/acct/1' }, { hello: 1 });
    const pub = await crypto.subtle.importKey('jwk', a.jwk, { name: 'ECDSA', namedCurve: 'P-256' }, false, ['verify']);
    const ok = await crypto.subtle.verify(
      { name: 'ECDSA', hash: 'SHA-256' },
      pub,
      Buffer.from(jws.signature, 'base64url'),
      new TextEncoder().encode(`${jws.protected}.${jws.payload}`),
    );
    expect(ok).toBe(true);
    expect(JSON.parse(Buffer.from(jws.protected, 'base64url').toString())).toEqual({
      alg: 'ES256',
      nonce: 'n',
      url: 'https://x/y',
      kid: 'https://x/acct/1',
    });
    const asGet = await signJws(a, { nonce: 'n', url: 'https://x/y', kid: 'k' }, null);
    expect(asGet.payload).toBe('');
  });
});
