import { x509 } from '../src/x509';
import { mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { spkiPin } from '../src/keys';

export type TestKey = { keys: CryptoKeyPair; spkiDer: ArrayBuffer; pin: string };

export async function ecKey(curve: 'P-256' | 'P-384' = 'P-256'): Promise<TestKey> {
  const keys = (await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: curve }, true, [
    'sign',
    'verify',
  ])) as CryptoKeyPair;
  const spkiDer = await crypto.subtle.exportKey('spki', keys.publicKey);
  return { keys, spkiDer, pin: await spkiPin(spkiDer) };
}

export async function makeCsr(key: TestKey, names: string[], opts: { cn?: string } = {}): Promise<string> {
  const csr = await x509.Pkcs10CertificateRequestGenerator.create({
    name: opts.cn ? `CN=${opts.cn}` : '',
    keys: key.keys,
    signingAlgorithm: { name: 'ECDSA', hash: 'SHA-256' },
    extensions: names.length
      ? [new x509.SubjectAlternativeNameExtension(names.map(n => ({ type: 'dns', value: n })))]
      : [],
  });
  return csr.toString('pem');
}

/** Run openssl, failing loudly. */
export function openssl(args: string[], input?: string | Uint8Array): Uint8Array {
  const proc = Bun.spawnSync(['openssl', ...args], { stdin: input === undefined ? 'ignore' : Buffer.from(input) });
  if (proc.exitCode !== 0) throw new Error(`openssl ${args.join(' ')} failed: ${proc.stderr.toString()}`);
  return proc.stdout;
}

export function tempDir(prefix = 'dns01-issuer-test-'): string {
  return mkdtempSync(join(tmpdir(), prefix));
}

/** An OpenSSL-made P-256 key and CSR, exactly as the device client makes them. */
export function opensslKeyAndCsr(names: string[]): { dir: string; keyFile: string; csrPem: string; pin: string } {
  const dir = tempDir();
  const keyFile = join(dir, 'key.pem');
  openssl(['genpkey', '-algorithm', 'EC', '-pkeyopt', 'ec_paramgen_curve:P-256', '-out', keyFile]);
  const conf = join(dir, 'req.cnf');
  writeFileSync(
    conf,
    `[req]\ndistinguished_name=dn\nprompt=no\n[dn]\nO=dns01-issuer test\n[ext]\nsubjectAltName=${names.map(n => `DNS:${n}`).join(',')}\n`,
  );
  const csrPem = new TextDecoder().decode(
    openssl(['req', '-new', '-key', keyFile, '-config', conf, '-reqexts', 'ext', '-outform', 'PEM']),
  );
  const spki = openssl(['pkey', '-in', keyFile, '-pubout', '-outform', 'DER']);
  const digest = new Bun.CryptoHasher('sha256').update(spki).digest('base64');
  return { dir, keyFile, csrPem, pin: `sha256/${digest}` };
}

export function read(file: string): string {
  return readFileSync(file, 'utf8');
}
