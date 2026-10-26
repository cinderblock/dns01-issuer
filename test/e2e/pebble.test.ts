/**
 * End to end against Pebble (Let's Encrypt's test CA) and pebble-challtestsrv
 * (its mock DNS): binding refusals, the public-DNS precondition, issuance,
 * certificate fetch, signed check-ins, challenge cleanup, ARI and renewal.
 *
 * Needs `pebble` and `pebble-challtestsrv` on PATH, or PEBBLE_BIN and
 * CHALLTESTSRV_BIN. Fails, rather than skips, when they are missing.
 */

import { afterAll, beforeAll, describe, expect, test } from 'bun:test';
import { Resolver } from 'node:dns/promises';
import { readFileSync, writeFileSync } from 'node:fs';
import { join, resolve } from 'node:path';
import type { Subprocess } from 'bun';
import { AcmeClient } from '../../src/acme/client';
import { loadOrCreateAccountKey } from '../../src/acme/jws';
import { certificateFacts } from '../../src/certificate';
import { parseConfig, type Config } from '../../src/config';
import { makeProvider } from '../../src/dns/providers';
import { Issuer } from '../../src/issuer';
import { makeHandler } from '../../src/server';
import { Store } from '../../src/store';
import { existsSync } from 'node:fs';
import { openssl, opensslKeyAndCsr, tempDir } from '../helpers';

const PEBBLE_DIR = resolve(import.meta.dir, '../pebble');
const DNS = '127.0.0.1:18053';
const MGMT = 'http://127.0.0.1:18055';
const ACME = 'https://localhost:14000/dir';
const ZONE = 'fleet.example.test';
const ROBOT = `robot-1.${ZONE}`;

function binary(env: string, name: string): string {
  const path = process.env[env] ?? Bun.which(name);
  if (!path) {
    throw new Error(
      `${name} not found: put it on PATH or set ${env} (go install github.com/letsencrypt/pebble/v2/cmd/${name}@latest)`,
    );
  }
  return path;
}

async function waitForPort(url: string, opts: RequestInit = {}) {
  const deadline = Date.now() + 15_000;
  for (;;) {
    try {
      await fetch(url, opts);
      return;
    } catch {
      if (Date.now() > deadline) throw new Error(`${url} did not come up`);
      await Bun.sleep(200);
    }
  }
}

const procs: Subprocess[] = [];
let work: string;
let config: Config;
let store: Store;
let issuer: Issuer;
let clock = Date.now();
let handle: ReturnType<typeof makeHandler>;
const device = opensslKeyAndCsr([ROBOT]);
// The shell client's key, made ahead so the config can bind it; the client
// finds the file in place and uses it, as it would after its first run.
const CLIENT_ROBOT = `robot-3.${ZONE}`;
const clientDevice = opensslKeyAndCsr([CLIENT_ROBOT]);
const minica = readFileSync(join(PEBBLE_DIR, 'minica.pem'), 'utf8');

beforeAll(async () => {
  work = tempDir('dns01-issuer-e2e-');
  procs.push(
    Bun.spawn(
      [
        binary('CHALLTESTSRV_BIN', 'pebble-challtestsrv'),
        '-dnsserver',
        DNS,
        '-management',
        '127.0.0.1:18055',
        '-defaultIPv4',
        '',
        '-defaultIPv6',
        '',
        '-http01',
        '',
        '-https01',
        '',
        '-tlsalpn01',
        '',
        '-doh',
        '',
      ],
      { stdout: 'ignore', stderr: 'ignore' },
    ),
  );
  const pebbleConfig = join(work, 'pebble.json');
  writeFileSync(
    pebbleConfig,
    JSON.stringify({
      pebble: {
        listenAddress: '127.0.0.1:14000',
        managementListenAddress: '127.0.0.1:15000',
        certificate: join(PEBBLE_DIR, 'localhost-cert.pem'),
        privateKey: join(PEBBLE_DIR, 'localhost-key.pem'),
        httpPort: 5002,
        tlsPort: 5001,
        ocspResponderURL: '',
        externalAccountBindingRequired: false,
        retryAfter: { authz: 1, order: 1 },
      },
    }),
  );
  procs.push(
    Bun.spawn([binary('PEBBLE_BIN', 'pebble'), '-config', pebbleConfig, '-dnsserver', DNS], {
      env: { ...process.env, PEBBLE_VA_NOSLEEP: '1', PEBBLE_WFE_NONCEREJECT: '0' },
      stdout: 'ignore',
      stderr: 'ignore',
    }),
  );
  await waitForPort(`${MGMT}/`);
  await waitForPort(ACME, { tls: { ca: minica } } as RequestInit);

  config = parseConfig({
    acme: { directory: ACME, terms_of_service_agreed: true, ca_bundle: join(PEBBLE_DIR, 'minica.pem') },
    data_dir: work,
    listen: { hostname: '127.0.0.1', port: 1 },
    trusted_proxies: ['127.0.0.1'],
    display_timezone: 'America/Los_Angeles',
    public_dns: { nameservers: [DNS] },
    zones: [{ zone: ZONE, provider: 'challtestsrv', url: MGMT, nameservers: [DNS] }],
    certificates: [
      { name: ROBOT, key: device.pin, require_public_dns: true, inside_resolver: DNS },
      { name: `robot-2.${ZONE}`, key: 'sha256/' + Buffer.alloc(32, 9).toString('base64') },
      { name: CLIENT_ROBOT, key: clientDevice.pin },
    ],
  });
  store = new Store(join(work, 'issuer.sqlite'));
  const acme = new AcmeClient({
    directoryUrl: ACME,
    accountKey: await loadOrCreateAccountKey(join(work, 'acme-account.json')),
    contact: [],
    caBundle: minica,
    pollTimeoutMs: 60_000,
  });
  issuer = new Issuer({
    config,
    store,
    acme,
    providers: new Map(config.zones.map(z => [z.zone, makeProvider(z)])),
    now: () => clock,
    log: () => {},
  });
  handle = makeHandler({ config, issuer, store, now: () => clock });
});

afterAll(() => {
  for (const p of procs) p.kill();
  store?.close();
});

const call = (method: string, path: string, init: RequestInit = {}, peer = '10.9.9.9') =>
  handle(new Request(`http://issuer${path}`, { method, ...init }), peer);

const sign = (body: string): string => {
  const file = join(device.dir, `body-${Math.random()}`);
  writeFileSync(file, body);
  return Buffer.from(openssl(['dgst', '-sha256', '-sign', device.keyFile, file])).toString('base64');
};

describe('dns01-issuer against Pebble', () => {
  test('a CSR from an unbound key, or for unconfigured names, is refused and listed', async () => {
    const stranger = opensslKeyAndCsr([ROBOT]);
    const res = await call('POST', '/api/v1/csr', { body: stranger.csrPem });
    expect(res.status).toBe(403);
    expect(await res.json()).toMatchObject({ status: 'unbound', reason: 'key-mismatch', fingerprint: stranger.pin });

    const other = opensslKeyAndCsr([`nobody.${ZONE}`]);
    const res2 = await call('POST', '/api/v1/csr', { body: other.csrPem });
    expect(res2.status).toBe(403);
    expect(await res2.json()).toMatchObject({ reason: 'unknown-names' });

    // A superset of a bound name set is not that name set.
    const superset = opensslKeyAndCsr([ROBOT, `extra.${ZONE}`]);
    expect((await call('POST', '/api/v1/csr', { body: superset.csrPem })).status).toBe(403);

    expect(store.allUnbound().map(u => u.pin)).toContain(stranger.pin);
    expect(store.cert(ROBOT)).toBeNull();
  });

  test('the bound CSR is queued, then waits for public DNS', async () => {
    const res = await call('POST', '/api/v1/csr', { body: device.csrPem }, '127.0.0.1');
    expect(res.status).toBe(202);
    await issuer.kick();
    const row = store.cert(ROBOT)!;
    expect(row.cert_pem).toBeNull();
    expect(row.waiting).toContain('to resolve in public DNS');
    expect(row.failures).toBe(0);
  });

  test('once the name resolves, the certificate is issued for the device key', async () => {
    const add = await fetch(`${MGMT}/add-a`, {
      method: 'POST',
      body: JSON.stringify({ host: `${ROBOT}.`, addresses: ['10.0.0.5'] }),
    });
    expect(add.ok).toBe(true);
    clock += 11 * 60_000; // past the "check again in 10 minutes"
    await issuer.kick();

    const row = store.cert(ROBOT)!;
    expect(row.last_error).toBeNull();
    expect(row.waiting).toBeNull();
    expect(row.cert_pin).toBe(device.pin);
    expect(row.inside_ok).toBe(1);

    const res = await call('GET', `/api/v1/certificates/${ROBOT}`);
    expect(res.status).toBe(200);
    const chain = await res.text();
    const facts = await certificateFacts(chain);
    expect(facts.names).toEqual([ROBOT]);
    expect(facts.pin).toBe(device.pin);
    expect(facts.certId).toBeDefined();

    // The certificate's key is the device's: openssl agrees.
    const certFile = join(device.dir, 'cert.pem');
    writeFileSync(certFile, chain);
    const certPub = openssl(['x509', '-in', certFile, '-noout', '-pubkey']);
    const keyPub = openssl(['pkey', '-in', device.keyFile, '-pubout']);
    expect(Buffer.from(certPub).toString()).toBe(Buffer.from(keyPub).toString());
  });

  test('challenge records are gone afterwards', async () => {
    const r = new Resolver();
    r.setServers([DNS]);
    const txt = await r.resolveTxt(`_acme-challenge.${ROBOT}`).catch(() => []);
    expect(txt).toEqual([]);
  });

  test('re-submitting the same CSR reports the current certificate', async () => {
    const res = await call('POST', '/api/v1/csr', { body: device.csrPem });
    expect(res.status).toBe(200);
    expect(await res.json()).toMatchObject({ status: 'current', name: ROBOT });
  });

  test('ARI gave a renewal window', () => {
    const row = store.cert(ROBOT)!;
    expect(row.ari_error).toBeNull();
    expect(row.ari_start).toBeGreaterThan(0);
    expect(row.renew_at).toBeGreaterThanOrEqual(row.ari_start!);
    expect(row.renew_at).toBeLessThanOrEqual(row.ari_end!);
  });

  test('a signed check-in is recorded; replays and bad signatures are refused', async () => {
    const body = JSON.stringify({ name: ROBOT, time: Math.floor(clock / 1000), addresses: ['10.0.0.5'] });
    const res = await call('POST', '/api/v1/checkin', { body, headers: { 'x-signature': sign(body) } }, '127.0.0.1');
    expect(res.status).toBe(200);
    const ok = (await res.json()) as { certificate: { serial: string } };
    expect(ok.certificate.serial).toBe(store.cert(ROBOT)!.serial!);

    const replay = await call('POST', '/api/v1/checkin', { body, headers: { 'x-signature': sign(body) } });
    expect(replay.status).toBe(409);

    // Same second, different body (the client's nonce): a genuine second check-in.
    const sameSecond = JSON.stringify({ name: ROBOT, time: Math.floor(clock / 1000), nonce: 'b' });
    const again = await call('POST', '/api/v1/checkin', {
      body: sameSecond,
      headers: { 'x-signature': sign(sameSecond) },
    });
    expect(again.status).toBe(200);

    const later = JSON.stringify({ name: ROBOT, time: Math.floor(clock / 1000) + 1 });
    const forged = await call('POST', '/api/v1/checkin', { body: later, headers: { 'x-signature': sign(body) } });
    expect(forged.status).toBe(401);

    const stale = JSON.stringify({ name: ROBOT, time: Math.floor(clock / 1000) - 3600 });
    expect(
      (await call('POST', '/api/v1/checkin', { body: stale, headers: { 'x-signature': sign(stale) } })).status,
    ).toBe(400);

    // Behind a trusted proxy, the source is the forwarded address.
    const viaProxy = JSON.stringify({ name: ROBOT, time: Math.floor(clock / 1000) + 2 });
    await call(
      'POST',
      '/api/v1/checkin',
      { body: viaProxy, headers: { 'x-signature': sign(viaProxy), 'x-forwarded-for': '6.6.6.6, 10.0.0.5' } },
      '127.0.0.1',
    );
    expect(store.checkin(ROBOT)!.source_ip).toBe('10.0.0.5');
  });

  test('when renewal is due, it renews with a new serial', async () => {
    const before = store.cert(ROBOT)!;
    clock = before.renew_at! + 1000;
    await issuer.kick();
    const after = store.cert(ROBOT)!;
    expect(after.last_error).toBeNull();
    expect(after.serial).not.toBe(before.serial);
    expect(after.cert_pin).toBe(device.pin);
    expect(store.recentEvents().some(e => e.message.startsWith('renewed:'))).toBe(true);
  });

  test('the status page renders every section', async () => {
    const res = await call('GET', '/');
    expect(res.status).toBe(200);
    const html = await res.text();
    expect(html).toContain(ROBOT);
    // Each configured name links to its site, in the list at the top and in its heading.
    expect(html.split(`<a href="https://${ROBOT}/">${ROBOT}</a>`).length - 1).toBe(2);
    expect(html).toContain('current');
    expect(html).toContain('Requests with no binding');
    expect(html).toMatch(/P[DS]T <small>\(\d\d:\d\dZ\)<\/small>/);
    expect(html).not.toContain('title=');
  });
});

/** Git Bash on Windows, not WSL's bash.exe, which PATH may find first. */
function bash(): string {
  if (process.env.BASH_BIN) return process.env.BASH_BIN;
  if (process.platform !== 'win32') return 'bash';
  const git = 'C:/Program Files/Git/bin/bash.exe';
  if (!existsSync(git)) throw new Error(`set BASH_BIN: ${git} not found`);
  return git;
}

/** Run the client asynchronously: the issuer it talks to runs in this process. */
async function runClient(issuerUrl: string, dir: string, reload: string) {
  const proc = Bun.spawn([bash(), resolve(import.meta.dir, '../../client/dns01-issuer-client'), 'run'], {
    env: {
      ...process.env,
      ISSUER: issuerUrl,
      NAME: CLIENT_ROBOT,
      KEY_FILE: clientDevice.keyFile.replace(/\\/g, '/'),
      CERT_FILE: `${dir}/tls/cert.pem`,
      STATE_DIR: `${dir}/state`,
      RELOAD: reload,
      WAIT_SECONDS: '90',
    },
    stdout: 'pipe',
    stderr: 'pipe',
  });
  const [code, out, err] = await Promise.all([
    proc.exited,
    new Response(proc.stdout).text(),
    new Response(proc.stderr).text(),
  ]);
  return { code, out, err };
}

describe('the shell client', () => {
  test('fingerprint prints the pin the issuer computes', async () => {
    const dir = tempDir().replace(/\\/g, '/');
    const proc = Bun.spawnSync([bash(), resolve(import.meta.dir, '../../client/dns01-issuer-client'), 'fingerprint'], {
      env: {
        ...process.env,
        ISSUER: 'http://unused',
        NAME: CLIENT_ROBOT,
        KEY_FILE: clientDevice.keyFile.replace(/\\/g, '/'),
        CERT_FILE: `${dir}/cert.pem`,
        STATE_DIR: `${dir}/state`,
      },
    });
    expect(proc.exitCode).toBe(0);
    expect(proc.stdout.toString()).toContain(`key: ${clientDevice.pin}`);
  });

  test('run: sends its CSR, waits for issuance, installs, reloads and checks in', async () => {
    clock = Date.now();
    let csrPosts = 0;
    const server = Bun.serve({
      hostname: '127.0.0.1',
      port: 0,
      fetch: (req, srv) => {
        if (new URL(req.url).pathname === '/api/v1/csr') csrPosts++;
        return handle(req, srv.requestIP(req)?.address ?? '');
      },
    });
    try {
      const dir = tempDir().replace(/\\/g, '/');
      const { code, out, err } = await runClient(`http://127.0.0.1:${server.port}`, dir, `touch '${dir}/reloaded'`);
      if (code !== 0) console.error(out, err);
      expect(code).toBe(0);
      expect(out).toContain('installed serial=');
      expect(out).toContain('checked in');
      expect(existsSync(`${dir}/reloaded`)).toBe(true);
      const installed = await certificateFacts(readFileSync(`${dir}/tls/cert.pem`, 'utf8'));
      expect(installed.pin).toBe(clientDevice.pin);
      expect(store.checkin(CLIENT_ROBOT)?.source_ip).toBe('127.0.0.1');

      expect(csrPosts).toBe(1);

      // A second run sends no CSR (the issuer has it), and changes and reloads nothing.
      const again = await runClient(`http://127.0.0.1:${server.port}`, dir, `echo reloaded-again`);
      if (again.code !== 0) console.error(again.out, again.err);
      expect(again.code).toBe(0);
      expect(again.out).toContain('certificate unchanged');
      expect(again.out).not.toContain('reloaded-again');
      expect(csrPosts).toBe(1);
    } finally {
      server.stop(true);
    }
  }, 120_000);
});
