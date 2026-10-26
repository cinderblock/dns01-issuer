/**
 * Entry point. Config path from DNS01_ISSUER_CONFIG; everything else from the config.
 */

import { mkdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { AcmeClient } from './acme/client';
import { loadOrCreateAccountKey } from './acme/jws';
import { loadConfig } from './config';
import { makeProvider, type DnsProvider } from './dns/providers';
import { Issuer } from './issuer';
import { makeHandler } from './server';
import { Store } from './store';

const configFile = process.env.DNS01_ISSUER_CONFIG;
if (!configFile) {
  console.error('DNS01_ISSUER_CONFIG must name the config file');
  process.exit(2);
}

const config = loadConfig(configFile);
mkdirSync(config.dataDir, { recursive: true });

// Every zone's provider is built now, so a missing token fails startup rather
// than the first issuance.
const providers = new Map<string, DnsProvider>(config.zones.map(z => [z.zone, makeProvider(z)]));
const store = new Store(join(config.dataDir, 'issuer.sqlite'));
const accountKey = await loadOrCreateAccountKey(join(config.dataDir, 'acme-account.json'));
const acme = new AcmeClient({
  directoryUrl: config.acme.directory,
  accountKey,
  contact: config.acme.contact,
  caBundle: config.acme.caBundle ? readFileSync(config.acme.caBundle, 'utf8') : undefined,
  log: m => console.log(`acme: ${m}`),
});
const issuer = new Issuer({ config, store, acme, providers });
const handle = makeHandler({ config, issuer, store, build: process.env.BUILD_SHA });

const server = Bun.serve({
  hostname: config.listen.hostname,
  port: config.listen.port,
  fetch(req, srv) {
    return handle(req, srv.requestIP(req)?.address ?? '');
  },
});

console.log(
  `dns01-issuer listening on ${server.hostname}:${server.port}; ${config.certificates.length} certificate(s) configured; CA ${config.acme.directory}`,
);
issuer.start();

for (const signal of ['SIGINT', 'SIGTERM'] as const) {
  process.on(signal, async () => {
    console.log(`${signal}: stopping`);
    await server.stop();
    await issuer.stop();
    store.close();
    process.exit(0);
  });
}
