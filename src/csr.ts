/**
 * Certificate signing requests: parse, check the signature (proof that the
 * sender holds the private key), and pull out the names and the key.
 */

import { x509 } from './x509';
import { keyKind, spkiPin } from './keys';

export type ParsedCsr = {
  pem: string;
  der: Uint8Array;
  /** DNS names asked for, lower case, deduplicated, in request order. */
  names: string[];
  spkiDer: ArrayBuffer;
  pin: string;
};

export class CsrError extends Error {
  override name = 'CsrError';
}

const MAX_CSR_BYTES = 16 * 1024;

export async function parseCsr(text: string): Promise<ParsedCsr> {
  if (text.length > MAX_CSR_BYTES) throw new CsrError('CSR too large');
  const pem = text.trim();
  if (!/^-----BEGIN (NEW )?CERTIFICATE REQUEST-----/.test(pem)) throw new CsrError('not a PEM certificate request');

  let csr: x509.Pkcs10CertificateRequest;
  try {
    csr = new x509.Pkcs10CertificateRequest(pem);
  } catch (err) {
    throw new CsrError(`cannot parse CSR: ${(err as Error).message}`);
  }
  if (!(await csr.verify())) throw new CsrError('CSR signature does not verify');

  const spkiDer = csr.publicKey.rawData;
  try {
    keyKind(spkiDer);
  } catch (err) {
    throw new CsrError((err as Error).message);
  }

  const names: string[] = [];
  const add = (n: string) => {
    const lower = n.toLowerCase();
    if (!names.includes(lower)) names.push(lower);
  };
  // By OID, not by class: with @peculiar/x509 2.2.0 under Bun 1.4,
  // `getExtension(SubjectAlternativeNameExtension)` returns null for a CSR that
  // carries the extension, while the OID lookup returns it (seen 2026-10-26).
  const san = csr.getExtension('2.5.29.17') as x509.SubjectAlternativeNameExtension | null;
  for (const item of san?.names.items ?? []) {
    if (item.type !== 'dns') throw new CsrError(`CSR asks for a ${item.type} name; only DNS names are issued`);
    add(item.value);
  }
  // A subject CN must repeat one of the SANs; the CA would reject anything else.
  for (const cn of csr.subjectName.getField('CN')) {
    if (!names.includes(cn.toLowerCase())) throw new CsrError(`CSR subject CN ${cn} is not among its DNS names`);
  }
  if (names.length === 0) throw new CsrError('CSR asks for no DNS names');
  if (names.some(n => n.startsWith('*.'))) throw new CsrError('wildcard names are not issued');

  return { pem, der: new Uint8Array(csr.rawData), names, spkiDer, pin: await spkiPin(spkiDer) };
}
