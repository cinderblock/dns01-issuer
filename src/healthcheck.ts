/**
 * Container health check: GET /healthz on the port the config says. Exits 0
 * when the issuer answers, 1 otherwise.
 */

import { loadConfig } from './config';

const config = loadConfig(process.env.DNS01_ISSUER_CONFIG!);
const host =
  config.listen.hostname === '0.0.0.0' || config.listen.hostname === '::' ? '127.0.0.1' : config.listen.hostname;
try {
  const res = await fetch(`http://${host.includes(':') ? `[${host}]` : host}:${config.listen.port}/healthz`);
  process.exit(res.ok ? 0 : 1);
} catch {
  process.exit(1);
}
