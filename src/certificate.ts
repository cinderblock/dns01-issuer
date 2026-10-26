/**
 * Facts about an issued certificate chain that renewal needs: validity, the
 * leaf's key, and its RFC 9773 certificate identifier.
 */

import { b64url } from './acme/jws';
import { spkiPin } from './keys';
import { x509 } from './x509';

export type CertificateFacts = {
  notBefore: Date;
  notAfter: Date;
  /** Hex, as the CA wrote it. */
  serial: string;
  /** RFC 9773 `base64url(AKI keyIdentifier) "." base64url(serial)`; undefined without an AKI. */
  certId?: string;
  pin: string;
  names: string[];
};

export function hexToBytes(hex: string): Uint8Array {
  const clean = hex.replace(/[^0-9a-f]/gi, '');
  if (clean.length % 2) throw new Error(`odd-length hex ${hex}`);
  return Uint8Array.from(clean.match(/../g) ?? [], b => parseInt(b, 16));
}

/**
 * RFC 9773 §4.1: the AKI keyIdentifier and the DER INTEGER contents of the
 * serial (two's complement: minimal, with a leading 0x00 when the high bit is set).
 */
export function ariCertId(akiKeyId: Uint8Array, serial: Uint8Array): string {
  let s = serial;
  while (s.length > 1 && s[0] === 0 && s[1]! < 0x80) s = s.subarray(1);
  if (s[0]! >= 0x80) s = Uint8Array.from([0, ...s]);
  return `${b64url(akiKeyId)}.${b64url(s)}`;
}

/** The leaf of a PEM chain. */
export function leafPem(chainPem: string): string {
  const match = /-----BEGIN CERTIFICATE-----[\s\S]+?-----END CERTIFICATE-----/.exec(chainPem);
  if (!match) throw new Error('no certificate in chain');
  return match[0];
}

export async function certificateFacts(chainPem: string): Promise<CertificateFacts> {
  const leaf = new x509.X509Certificate(leafPem(chainPem));
  // By OID; see the note in csr.ts about class lookups.
  const aki = leaf.getExtension('2.5.29.35') as x509.AuthorityKeyIdentifierExtension | null;
  const san = leaf.getExtension('2.5.29.17') as x509.SubjectAlternativeNameExtension | null;
  return {
    notBefore: leaf.notBefore,
    notAfter: leaf.notAfter,
    serial: leaf.serialNumber,
    certId: aki?.keyId ? ariCertId(hexToBytes(aki.keyId), hexToBytes(leaf.serialNumber)) : undefined,
    pin: await spkiPin(leaf.publicKey.rawData),
    names: (san?.names.items ?? []).filter(i => i.type === 'dns').map(i => i.value.toLowerCase()),
  };
}
