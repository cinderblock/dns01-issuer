/**
 * Public keys: the fingerprint a config entry binds, and verifying a device's
 * signature with its key.
 *
 * The fingerprint is `sha256/` + base64 of SHA-256 over the DER
 * SubjectPublicKeyInfo: the same value as an HPKP pin, and what
 *   openssl pkey -in key.pem -pubout -outform DER | openssl dgst -sha256 -binary | base64
 * prints for the device's key.
 */

import { x509 } from './x509';

/** WebCrypto's byte-input type (lib has no DOM, so it isn't global). */
type BufferSource = Parameters<SubtleCrypto['digest']>[1];

export async function spkiPin(spkiDer: ArrayBuffer | Uint8Array): Promise<string> {
  const digest = await crypto.subtle.digest('SHA-256', spkiDer as BufferSource);
  return `sha256/${Buffer.from(digest).toString('base64')}`;
}

export type KeyKind = { kind: 'ec'; curve: 'P-256' | 'P-384' } | { kind: 'rsa'; bits: number };

const EC_CURVES: Record<string, 'P-256' | 'P-384'> = {
  '1.2.840.10045.3.1.7': 'P-256',
  '1.3.132.0.34': 'P-384',
};

/** The algorithm of a SubjectPublicKeyInfo, limited to what public CAs issue for. */
export function keyKind(spkiDer: ArrayBuffer): KeyKind {
  const info = new x509.PublicKey(spkiDer);
  const algorithm = info.algorithm as { name: string; namedCurve?: string; modulusLength?: number };
  // @peculiar/x509 reports the parameters it parsed; fall back to the raw OID map
  // for curves it names by OID.
  if (algorithm.name === 'ECDSA' || algorithm.name === 'EC') {
    const curve = algorithm.namedCurve && (EC_CURVES[algorithm.namedCurve] ?? algorithm.namedCurve);
    if (curve === 'P-256' || curve === 'P-384') return { kind: 'ec', curve };
    throw new Error(`unsupported EC curve ${algorithm.namedCurve ?? '(unknown)'}; use P-256 or P-384`);
  }
  if (algorithm.name === 'RSASSA-PKCS1-v1_5' || algorithm.name === 'RSA') {
    const bits = algorithm.modulusLength ?? 0;
    if (bits < 2048) throw new Error(`RSA key of ${bits} bits; use at least 2048`);
    return { kind: 'rsa', bits };
  }
  throw new Error(`unsupported key algorithm ${algorithm.name}; use ECDSA P-256/P-384 or RSA`);
}

/** Convert an ASN.1 DER ECDSA signature (what OpenSSL writes) to the raw r||s WebCrypto verifies. */
export function ecdsaDerToRaw(der: Uint8Array, size: number): Uint8Array {
  let i = 0;
  const expect = (byte: number) => {
    if (der[i++] !== byte) throw new Error('not a DER ECDSA signature');
  };
  const length = () => {
    let len = der[i++]!;
    if (len & 0x80) {
      const n = len & 0x7f;
      len = 0;
      for (let k = 0; k < n; k++) len = (len << 8) | der[i++]!;
    }
    return len;
  };
  expect(0x30);
  const total = length();
  if (i + total !== der.length) throw new Error('not a DER ECDSA signature');
  const out = new Uint8Array(size * 2);
  for (const offset of [0, size]) {
    expect(0x02);
    let len = length();
    let start = i;
    i += len;
    while (len > size && der[start] === 0) {
      start++;
      len--;
    }
    if (len > size) throw new Error('ECDSA signature integer too long');
    out.set(der.subarray(start, start + len), offset + size - len);
  }
  if (i !== der.length) throw new Error('trailing bytes after ECDSA signature');
  return out;
}

/**
 * Verify `signature` over `data` with the key in `spkiDer`, SHA-256 throughout.
 * ECDSA signatures may be DER (OpenSSL) or raw r||s; RSA is PKCS#1 v1.5.
 */
export async function verifySignature(spkiDer: ArrayBuffer, signature: Uint8Array, data: Uint8Array): Promise<boolean> {
  const kind = keyKind(spkiDer);
  if (kind.kind === 'ec') {
    const size = kind.curve === 'P-256' ? 32 : 48;
    let raw: Uint8Array;
    if (signature.length === size * 2 && signature[0] !== 0x30) raw = signature;
    else {
      try {
        raw = ecdsaDerToRaw(signature, size);
      } catch {
        return false;
      }
    }
    const key = await crypto.subtle.importKey('spki', spkiDer, { name: 'ECDSA', namedCurve: kind.curve }, false, [
      'verify',
    ]);
    return crypto.subtle.verify({ name: 'ECDSA', hash: 'SHA-256' }, key, raw as BufferSource, data as BufferSource);
  }
  const key = await crypto.subtle.importKey('spki', spkiDer, { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' }, false, [
    'verify',
  ]);
  return crypto.subtle.verify('RSASSA-PKCS1-v1_5', key, signature as BufferSource, data as BufferSource);
}
