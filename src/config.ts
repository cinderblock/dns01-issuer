/**
 * Config: one YAML file, validated in full at startup.
 *
 * Every error names the file and the key, and nothing deployment-specific has
 * a default: a missing zone, token or directory is a startup failure, not a
 * guess. See plans/build.md for the shape.
 */

import { readFileSync } from 'node:fs';
import { parseCidr, type Cidr } from './net';

export type ZoneConfig = {
  zone: string;
  provider: 'cloudflare' | 'challtestsrv';
  /** cloudflare: the env var holding the API token. */
  tokenEnv?: string;
  /** cloudflare: optional; supplying it lets the token drop Zone:Read. */
  zoneId?: string;
  /** challtestsrv: its management URL (tests only). */
  url?: string;
  /** Where to look for the challenge TXT before asking the CA to validate. Default: the zone's authoritative servers. */
  nameservers?: string[];
};

export type CertificateConfig = {
  name: string;
  altNames: string[];
  /** Every name in the certificate, `name` first. */
  names: string[];
  /** `sha256/<base64>` over the SubjectPublicKeyInfo DER. */
  key: string;
  requirePublicDns: boolean;
  insideResolver?: string;
  zone: ZoneConfig;
};

export type PublicDnsConfig = { doh: string } | { nameservers: string[] };

export type Config = {
  acme: {
    directory: string;
    contact: string[];
    /** A PEM bundle to trust for the ACME server's own TLS. Tests only (Pebble). */
    caBundle?: string;
  };
  dataDir: string;
  listen: { hostname: string; port: number };
  trustedProxies: Cidr[];
  displayTimezone: string;
  publicDns: PublicDnsConfig;
  zones: ZoneConfig[];
  certificates: CertificateConfig[];
};

export const KEY_PIN = /^sha256\/[A-Za-z0-9+/]{43}=$/;
const HOSTNAME = /^(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]([a-z0-9-]{0,61}[a-z0-9])?$/;

class ConfigError extends Error {
  constructor(file: string, path: string, message: string) {
    super(`${file}: ${path}: ${message}`);
    this.name = 'ConfigError';
  }
}

export function loadConfig(file: string): Config {
  let raw: unknown;
  try {
    raw = Bun.YAML.parse(readFileSync(file, 'utf8'));
  } catch (err) {
    throw new Error(`${file}: cannot read config: ${(err as Error).message}`);
  }
  return parseConfig(raw, file);
}

export function parseConfig(raw: unknown, file = '<config>'): Config {
  const fail = (path: string, message: string): never => {
    throw new ConfigError(file, path, message);
  };

  const obj = (v: unknown, path: string): Record<string, unknown> => {
    if (typeof v !== 'object' || v === null || Array.isArray(v)) fail(path, 'must be a mapping');
    return v as Record<string, unknown>;
  };
  const known = (o: Record<string, unknown>, path: string, keys: string[]) => {
    for (const k of Object.keys(o)) if (!keys.includes(k)) fail(`${path}.${k}`, 'unknown key');
  };
  const str = (v: unknown, path: string): string => {
    if (typeof v !== 'string' || v.length === 0) fail(path, 'must be a non-empty string');
    return v as string;
  };
  const optStr = (v: unknown, path: string): string | undefined => (v === undefined ? undefined : str(v, path));
  const strList = (v: unknown, path: string): string[] => {
    if (!Array.isArray(v)) fail(path, 'must be a list');
    return (v as unknown[]).map((x, i) => str(x, `${path}[${i}]`));
  };
  const bool = (v: unknown, path: string, dflt: boolean): boolean => {
    if (v === undefined) return dflt;
    if (typeof v !== 'boolean') fail(path, 'must be true or false');
    return v as boolean;
  };
  const hostname = (v: unknown, path: string): string => {
    const s = str(v, path);
    if (s !== s.toLowerCase()) fail(path, `${s}: must be lower case`);
    if (!HOSTNAME.test(s)) fail(path, `${s}: not a valid DNS name`);
    return s;
  };
  const url = (v: unknown, path: string): string => {
    const s = str(v, path);
    let u: URL;
    try {
      u = new URL(s);
    } catch {
      return fail(path, `${s}: not a URL`);
    }
    if (u.protocol !== 'https:' && u.protocol !== 'http:') fail(path, `${s}: must be http(s)`);
    return s;
  };

  const top = obj(raw, '(top level)');
  known(top, '', [
    'acme',
    'data_dir',
    'listen',
    'trusted_proxies',
    'display_timezone',
    'public_dns',
    'zones',
    'certificates',
  ]);

  const acmeRaw = obj(top.acme, 'acme');
  known(acmeRaw, 'acme', ['directory', 'contact', 'terms_of_service_agreed', 'ca_bundle']);
  if (acmeRaw.terms_of_service_agreed !== true) {
    fail('acme.terms_of_service_agreed', "must be true: the CA's terms are agreed to when the account is created");
  }
  const contact = acmeRaw.contact === undefined ? [] : strList(acmeRaw.contact, 'acme.contact');
  contact.forEach((c, i) => {
    if (!c.startsWith('mailto:')) fail(`acme.contact[${i}]`, `${c}: must be a mailto: URL`);
  });
  const acme = {
    directory: url(acmeRaw.directory, 'acme.directory'),
    contact,
    caBundle: optStr(acmeRaw.ca_bundle, 'acme.ca_bundle'),
  };

  const dataDir = str(top.data_dir, 'data_dir');

  const listenRaw = obj(top.listen, 'listen');
  known(listenRaw, 'listen', ['hostname', 'port']);
  const port = listenRaw.port;
  if (typeof port !== 'number' || !Number.isInteger(port) || port < 1 || port > 65535) {
    fail('listen.port', 'must be an integer from 1 to 65535');
  }
  const listen = { hostname: str(listenRaw.hostname, 'listen.hostname'), port: port as number };

  const trustedProxies = (top.trusted_proxies === undefined ? [] : strList(top.trusted_proxies, 'trusted_proxies')).map(
    (c, i) => {
      try {
        return parseCidr(c);
      } catch (err) {
        return fail(`trusted_proxies[${i}]`, (err as Error).message);
      }
    },
  );

  const displayTimezone = top.display_timezone === undefined ? 'UTC' : str(top.display_timezone, 'display_timezone');
  try {
    new Intl.DateTimeFormat('en-US', { timeZone: displayTimezone });
  } catch {
    fail('display_timezone', `${displayTimezone}: unknown time zone`);
  }

  let publicDns: PublicDnsConfig = { doh: 'https://cloudflare-dns.com/dns-query' };
  if (top.public_dns !== undefined) {
    const p = obj(top.public_dns, 'public_dns');
    known(p, 'public_dns', ['doh', 'nameservers']);
    if ((p.doh === undefined) === (p.nameservers === undefined))
      fail('public_dns', 'set exactly one of doh, nameservers');
    publicDns =
      p.doh !== undefined
        ? { doh: url(p.doh, 'public_dns.doh') }
        : { nameservers: strList(p.nameservers, 'public_dns.nameservers') };
  }

  if (!Array.isArray(top.zones) || top.zones.length === 0) fail('zones', 'must be a non-empty list');
  const zones = (top.zones as unknown[]).map((z, i): ZoneConfig => {
    const path = `zones[${i}]`;
    const o = obj(z, path);
    known(o, path, ['zone', 'provider', 'token_env', 'zone_id', 'url', 'nameservers']);
    const zone = hostname(o.zone, `${path}.zone`);
    const nameservers = o.nameservers === undefined ? undefined : strList(o.nameservers, `${path}.nameservers`);
    if (o.provider === 'cloudflare') {
      if (o.url !== undefined) fail(`${path}.url`, 'only for provider challtestsrv');
      const tokenEnv = str(o.token_env, `${path}.token_env`);
      return { zone, provider: 'cloudflare', tokenEnv, zoneId: optStr(o.zone_id, `${path}.zone_id`), nameservers };
    }
    if (o.provider === 'challtestsrv') {
      if (o.token_env !== undefined || o.zone_id !== undefined) fail(path, 'token_env/zone_id are for cloudflare only');
      return { zone, provider: 'challtestsrv', url: url(o.url, `${path}.url`), nameservers };
    }
    return fail(`${path}.provider`, 'must be cloudflare or challtestsrv');
  });
  const zoneNames = new Set<string>();
  zones.forEach((z, i) => {
    if (zoneNames.has(z.zone)) fail(`zones[${i}].zone`, `${z.zone}: listed twice`);
    zoneNames.add(z.zone);
  });

  const certsRaw = top.certificates === undefined ? [] : top.certificates;
  if (!Array.isArray(certsRaw)) fail('certificates', 'must be a list');
  const seenNames = new Map<string, string>();
  const certificates = (certsRaw as unknown[]).map((c, i): CertificateConfig => {
    const path = `certificates[${i}]`;
    const o = obj(c, path);
    known(o, path, ['name', 'alt_names', 'key', 'require_public_dns', 'inside_resolver']);
    const name = hostname(o.name, `${path}.name`);
    const altNames =
      o.alt_names === undefined
        ? []
        : strList(o.alt_names, `${path}.alt_names`).map((n, j) => hostname(n, `${path}.alt_names[${j}]`));
    const names = [name, ...altNames];
    if (new Set(names).size !== names.length) fail(`${path}.alt_names`, 'repeats a name');
    for (const n of names) {
      const other = seenNames.get(n);
      if (other) fail(path, `${n}: already in ${other}; a name belongs to one certificate`);
      seenNames.set(n, path);
    }
    const key = str(o.key, `${path}.key`);
    if (!KEY_PIN.test(key)) fail(`${path}.key`, 'must be sha256/<base64 of the SHA-256 of the SubjectPublicKeyInfo>');
    // Every name must sit in one configured zone, and all in the same one: the
    // whole certificate's challenges are written with a single credential.
    const zoneOf = (n: string) =>
      zones.filter(z => n === z.zone || n.endsWith(`.${z.zone}`)).sort((a, b) => b.zone.length - a.zone.length)[0];
    const zone = zoneOf(name);
    if (!zone) fail(`${path}.name`, `${name}: not inside any configured zone`);
    for (const n of altNames) {
      if (zoneOf(n) !== zone) fail(`${path}.alt_names`, `${n}: not in the same zone as ${name}`);
    }
    return {
      name,
      altNames,
      names,
      key,
      requirePublicDns: bool(o.require_public_dns, `${path}.require_public_dns`, false),
      insideResolver: optStr(o.inside_resolver, `${path}.inside_resolver`),
      zone: zone!,
    };
  });

  return { acme, dataDir, listen, trustedProxies, displayTimezone, publicDns, zones, certificates };
}

/** The config entry whose name set is exactly `names` (order-insensitive), if any. */
export function findCertificate(config: Config, names: string[]): CertificateConfig | undefined {
  const want = [...new Set(names)].sort().join(' ');
  return config.certificates.find(c => [...c.names].sort().join(' ') === want);
}
