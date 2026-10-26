/**
 * JOSE pieces ACME needs: an ES256 account key, its JWK and RFC 7638
 * thumbprint, and flattened JWS signing (RFC 8555 §6.2).
 */

import { chmodSync, existsSync, readFileSync, writeFileSync } from 'node:fs';

/** The private JWK members this file reads and writes (lib has no DOM, so `JsonWebKey` isn't global). */
type JsonWebKey = { kty?: string; crv?: string; x?: string; y?: string; d?: string; ext?: boolean; key_ops?: string[] };

export type EcJwk = { kty: 'EC'; crv: 'P-256'; x: string; y: string };

export type AccountKey = { privateKey: CryptoKey; jwk: EcJwk; thumbprint: string };

export const b64url = (bytes: ArrayBuffer | Uint8Array | string): string =>
  Buffer.from(typeof bytes === 'string' ? new TextEncoder().encode(bytes) : new Uint8Array(bytes)).toString(
    'base64url',
  );

export async function thumbprint(jwk: EcJwk): Promise<string> {
  // RFC 7638: required members only, lexicographic order, no whitespace.
  const canonical = JSON.stringify({ crv: jwk.crv, kty: jwk.kty, x: jwk.x, y: jwk.y });
  return b64url(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(canonical)));
}

async function fromPrivateJwk(privateJwk: JsonWebKey): Promise<AccountKey> {
  const privateKey = await crypto.subtle.importKey('jwk', privateJwk, { name: 'ECDSA', namedCurve: 'P-256' }, false, [
    'sign',
  ]);
  const jwk: EcJwk = { kty: 'EC', crv: 'P-256', x: privateJwk.x!, y: privateJwk.y! };
  return { privateKey, jwk, thumbprint: await thumbprint(jwk) };
}

/**
 * The ACME account key, created on first start and kept in the data
 * directory. It is the issuer's identity at the CA, not a deploy secret.
 */
export async function loadOrCreateAccountKey(file: string): Promise<AccountKey> {
  if (existsSync(file)) {
    const stored = JSON.parse(readFileSync(file, 'utf8')) as JsonWebKey;
    if (stored.kty !== 'EC' || stored.crv !== 'P-256' || !stored.d) throw new Error(`${file}: not a P-256 private JWK`);
    return fromPrivateJwk(stored);
  }
  const pair = (await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, [
    'sign',
    'verify',
  ])) as CryptoKeyPair;
  const privateJwk = await crypto.subtle.exportKey('jwk', pair.privateKey);
  writeFileSync(file, JSON.stringify(privateJwk), { mode: 0o600, flag: 'wx' });
  chmodSync(file, 0o600);
  return fromPrivateJwk(privateJwk);
}

export type JwsHeader = { nonce: string; url: string } & ({ jwk: EcJwk } | { kid: string });

/** A flattened JWS. `payload: null` makes a POST-as-GET (empty payload). */
export async function signJws(
  key: AccountKey,
  header: JwsHeader,
  payload: unknown | null,
): Promise<{ protected: string; payload: string; signature: string }> {
  const protectedB64 = b64url(JSON.stringify({ alg: 'ES256', ...header }));
  const payloadB64 = payload === null ? '' : b64url(JSON.stringify(payload));
  const signature = await crypto.subtle.sign(
    { name: 'ECDSA', hash: 'SHA-256' },
    key.privateKey,
    new TextEncoder().encode(`${protectedB64}.${payloadB64}`),
  );
  // WebCrypto's ECDSA output is already the raw r||s that JWS ES256 wants.
  return { protected: protectedB64, payload: payloadB64, signature: b64url(signature) };
}
