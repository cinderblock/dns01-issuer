import { describe, expect, test } from 'bun:test';
import { writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { parseCsr } from '../../src/csr';
import { ecdsaDerToRaw, keyKind, verifySignature } from '../../src/keys';
import { ecKey, makeCsr, openssl, opensslKeyAndCsr } from '../helpers';

describe('CSR parsing', () => {
  test('names, pin and proof of possession from a WebCrypto CSR', async () => {
    const key = await ecKey();
    const csr = await parseCsr(await makeCsr(key, ['a.example.com', 'B.example.com']));
    expect(csr.names).toEqual(['a.example.com', 'b.example.com']);
    expect(csr.pin).toBe(key.pin);
  });

  test('an OpenSSL CSR gives the same pin openssl prints', () => {
    const { csrPem, pin } = opensslKeyAndCsr(['robot-1.fleet.example.com']);
    return parseCsr(csrPem).then(csr => {
      expect(csr.names).toEqual(['robot-1.fleet.example.com']);
      expect(csr.pin).toBe(pin);
    });
  });

  test('a CN must be one of the DNS names', async () => {
    const key = await ecKey();
    await expect(parseCsr(await makeCsr(key, ['a.example.com'], { cn: 'other.example.com' }))).rejects.toThrow(
      'not among its DNS names',
    );
    expect((await parseCsr(await makeCsr(key, ['a.example.com'], { cn: 'a.example.com' }))).names).toEqual([
      'a.example.com',
    ]);
  });

  test('rejects no names, wildcards, garbage and a tampered signature', async () => {
    const key = await ecKey();
    await expect(parseCsr(await makeCsr(key, []))).rejects.toThrow('no DNS names');
    await expect(parseCsr(await makeCsr(key, ['*.example.com']))).rejects.toThrow('wildcard');
    await expect(parseCsr('hello')).rejects.toThrow('not a PEM');

    const pem = await makeCsr(key, ['a.example.com']);
    const body = pem.split('\n').filter(l => !l.startsWith('-----'));
    const der = Buffer.from(body.join(''), 'base64');
    der[der.length - 5] = der[der.length - 5]! ^ 0xff; // inside the signature
    const tampered = `-----BEGIN CERTIFICATE REQUEST-----\n${der.toString('base64')}\n-----END CERTIFICATE REQUEST-----`;
    await expect(parseCsr(tampered)).rejects.toThrow();
  });
});

describe('keys', () => {
  test('key kinds', async () => {
    expect(keyKind((await ecKey('P-256')).spkiDer)).toEqual({ kind: 'ec', curve: 'P-256' });
    expect(keyKind((await ecKey('P-384')).spkiDer)).toEqual({ kind: 'ec', curve: 'P-384' });
    const rsa = (await crypto.subtle.generateKey(
      { name: 'RSASSA-PKCS1-v1_5', modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: 'SHA-256' },
      true,
      ['sign', 'verify'],
    )) as CryptoKeyPair;
    expect(keyKind(await crypto.subtle.exportKey('spki', rsa.publicKey))).toEqual({ kind: 'rsa', bits: 2048 });
  });

  test('verifies an OpenSSL DER ECDSA signature, and refuses a wrong one', async () => {
    const { dir, keyFile } = opensslKeyAndCsr(['x.example.com']);
    const data = new TextEncoder().encode('{"name":"x.example.com","time":1}');
    const dataFile = join(dir, 'data');
    writeFileSync(dataFile, data);
    const sig = openssl(['dgst', '-sha256', '-sign', keyFile, dataFile]);
    const spki = openssl(['pkey', '-in', keyFile, '-pubout', '-outform', 'DER']);
    const spkiBuf = spki.buffer.slice(spki.byteOffset, spki.byteOffset + spki.byteLength) as ArrayBuffer;
    expect(await verifySignature(spkiBuf, sig, data)).toBe(true);
    expect(await verifySignature(spkiBuf, sig, new TextEncoder().encode('something else'))).toBe(false);
    expect(await verifySignature(spkiBuf, new Uint8Array([1, 2, 3]), data)).toBe(false);
  });

  test('DER to raw ECDSA handles short and padded integers', () => {
    // r = 0x01 (short), s = 0x00 0x80.. (leading zero for a high bit)
    const s = new Uint8Array(32).fill(0x80);
    const der = new Uint8Array([0x30, 3 + 2 + 33, 0x02, 0x01, 0x01, 0x02, 33, 0x00, ...s]);
    const raw = ecdsaDerToRaw(der, 32);
    expect(raw[31]).toBe(1);
    expect(raw.subarray(32)).toEqual(s);
  });
});
