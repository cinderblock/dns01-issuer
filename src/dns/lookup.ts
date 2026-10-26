/**
 * DNS lookups the issuer makes itself:
 *
 * - before asking the CA to validate, that the challenge TXT is visible on
 *   every authoritative server (a recursive resolver could have cached the
 *   name's absence for the zone's negative TTL);
 * - whether a name resolves in public DNS (the `require_public_dns` precondition);
 * - what an inside resolver answers for a name (status only).
 */

import { Resolver } from 'node:dns/promises';
import type { PublicDnsConfig } from '../config';

const QUERY_TIMEOUT_MS = 5000;

function resolverFor(servers: string[]): Resolver {
  const r = new Resolver({ timeout: QUERY_TIMEOUT_MS, tries: 2 });
  r.setServers(servers);
  return r;
}

const notFound = (err: unknown) => {
  const code = (err as { code?: string }).code;
  return code === 'ENOTFOUND' || code === 'ENODATA';
};

/** The addresses of a zone's authoritative servers, found through the system resolver. */
export async function authoritativeServers(zone: string): Promise<string[]> {
  const system = new Resolver({ timeout: QUERY_TIMEOUT_MS, tries: 2 });
  const hosts = await system.resolveNs(zone);
  if (hosts.length === 0) throw new Error(`${zone}: no NS records`);
  const addresses = (
    await Promise.all(hosts.map(h => system.resolve4(h).catch(err => (notFound(err) ? [] : Promise.reject(err)))))
  ).flat();
  if (addresses.length === 0) throw new Error(`${zone}: none of its nameservers (${hosts.join(', ')}) has an address`);
  return addresses;
}

/**
 * Wait until every server in `servers` answers `fqdn TXT` with `value`.
 * Each server is asked on its own, so one lagging server holds the wait.
 */
export async function waitForTxt(
  fqdn: string,
  value: string,
  servers: string[],
  opts: { timeoutMs?: number; intervalMs?: number; log?: (m: string) => void } = {},
): Promise<void> {
  const deadline = Date.now() + (opts.timeoutMs ?? 180_000);
  const pending = new Set(servers);
  for (;;) {
    for (const server of [...pending]) {
      try {
        const records = await resolverFor([server]).resolveTxt(fqdn);
        if (records.some(chunks => chunks.join('') === value)) pending.delete(server);
      } catch (err) {
        if (!notFound(err)) opts.log?.(`TXT ${fqdn} @${server}: ${(err as Error).message}`);
      }
    }
    if (pending.size === 0) return;
    if (Date.now() > deadline) {
      throw new Error(`TXT ${fqdn} not visible on ${[...pending].join(', ')} after waiting`);
    }
    await Bun.sleep(opts.intervalMs ?? 3000);
  }
}

export type LookupResult = { ok: boolean; addresses: string[]; detail: string };

/** Does `name` resolve (A or AAAA, CNAMEs followed) in public DNS? */
export async function publicLookup(name: string, publicDns: PublicDnsConfig): Promise<LookupResult> {
  if ('doh' in publicDns) {
    const addresses: string[] = [];
    for (const type of ['A', 'AAAA']) {
      const url = `${publicDns.doh}?name=${encodeURIComponent(name)}&type=${type}`;
      const res = await fetch(url, { headers: { accept: 'application/dns-json' } });
      if (!res.ok) throw new Error(`${url}: ${res.status}`);
      const body = (await res.json()) as { Status: number; Answer?: { type: number; data: string }[] };
      if (body.Status !== 0 && body.Status !== 3) throw new Error(`${url}: DNS status ${body.Status}`);
      for (const a of body.Answer ?? []) if (a.type === 1 || a.type === 28) addresses.push(a.data);
    }
    return {
      ok: addresses.length > 0,
      addresses,
      detail: addresses.length ? addresses.join(', ') : 'no A/AAAA in public DNS',
    };
  }
  return lookupVia(name, publicDns.nameservers);
}

/** What `servers` answer for `name`. */
export async function lookupVia(name: string, servers: string[]): Promise<LookupResult> {
  const r = resolverFor(servers);
  const emptyIfNoRecords = (err: unknown) => (notFound(err) ? [] : Promise.reject(err));
  const [v4, v6] = await Promise.all([
    r.resolve4(name).catch(emptyIfNoRecords),
    r.resolve6(name).catch(emptyIfNoRecords),
  ]);
  const addresses = [...v4, ...v6];
  return {
    ok: addresses.length > 0,
    addresses,
    detail: addresses.length ? addresses.join(', ') : `no A/AAAA from ${servers.join(', ')}`,
  };
}
