import { describe, expect, test } from 'bun:test';
import { findCertificate, parseConfig } from '../../src/config';
import { cidrContains, clientAddress, parseCidr } from '../../src/net';

const PIN = 'sha256/' + Buffer.alloc(32, 7).toString('base64');

const base = () => ({
  acme: { directory: 'https://acme.example/dir', terms_of_service_agreed: true },
  data_dir: '/data',
  listen: { hostname: '127.0.0.1', port: 8080 },
  zones: [{ zone: 'example.com', provider: 'cloudflare', token_env: 'CF_TOKEN' }],
  certificates: [{ name: 'a.fleet.example.com', key: PIN }],
});

describe('config', () => {
  test('a minimal config parses with the documented defaults', () => {
    const c = parseConfig(base());
    expect(c.displayTimezone).toBe('UTC');
    expect(c.publicDns).toEqual({ doh: 'https://cloudflare-dns.com/dns-query' });
    expect(c.certificates[0]!.names).toEqual(['a.fleet.example.com']);
    expect(c.certificates[0]!.zone.zone).toBe('example.com');
    expect(c.certificates[0]!.requirePublicDns).toBe(false);
  });

  const bad: [string, (c: ReturnType<typeof base>) => unknown, string][] = [
    ['terms not agreed', c => ({ ...c, acme: { directory: c.acme.directory } }), 'terms_of_service_agreed'],
    ['unknown key', c => ({ ...c, surprise: 1 }), '.surprise: unknown key'],
    ['bad pin', c => ({ ...c, certificates: [{ name: 'a.fleet.example.com', key: 'abc' }] }), 'certificates[0].key'],
    [
      'name outside every zone',
      c => ({ ...c, certificates: [{ name: 'a.other.org', key: PIN }] }),
      'not inside any configured zone',
    ],
    [
      'name in two certificates',
      c => ({
        ...c,
        certificates: [
          { name: 'a.fleet.example.com', key: PIN },
          { name: 'b.fleet.example.com', alt_names: ['a.fleet.example.com'], key: PIN },
        ],
      }),
      'a name belongs to one certificate',
    ],
    ['upper case name', c => ({ ...c, certificates: [{ name: 'A.example.com', key: PIN }] }), 'lower case'],
    ['missing token_env', c => ({ ...c, zones: [{ zone: 'example.com', provider: 'cloudflare' }] }), 'token_env'],
    ['bad timezone', c => ({ ...c, display_timezone: 'Mars/Olympus' }), 'unknown time zone'],
    ['bad proxy', c => ({ ...c, trusted_proxies: ['10.0.0.0/40'] }), 'trusted_proxies[0]'],
    ['no zones', c => ({ ...c, zones: [] }), 'zones: must be a non-empty list'],
  ];
  for (const [what, mutate, message] of bad) {
    test(`rejects: ${what}`, () => {
      expect(() => parseConfig(mutate(base()), 'issuer.yaml')).toThrow(message);
    });
  }

  test('the longest matching zone wins', () => {
    const c = parseConfig({
      ...base(),
      zones: [
        { zone: 'example.com', provider: 'cloudflare', token_env: 'A' },
        { zone: 'fleet.example.com', provider: 'cloudflare', token_env: 'B' },
      ],
    });
    expect(c.certificates[0]!.zone.zone).toBe('fleet.example.com');
  });

  test('findCertificate matches the exact name set, in any order', () => {
    const c = parseConfig({
      ...base(),
      certificates: [{ name: 'a.example.com', alt_names: ['b.example.com'], key: PIN }],
    });
    expect(findCertificate(c, ['b.example.com', 'a.example.com'])?.name).toBe('a.example.com');
    expect(findCertificate(c, ['a.example.com'])).toBeUndefined();
    expect(findCertificate(c, ['a.example.com', 'b.example.com', 'c.example.com'])).toBeUndefined();
  });
});

describe('net', () => {
  test('CIDR matching, v4, v6 and v4-mapped', () => {
    expect(cidrContains(parseCidr('172.16.0.0/12'), '172.17.0.1')).toBe(true);
    expect(cidrContains(parseCidr('172.16.0.0/12'), '172.32.0.1')).toBe(false);
    expect(cidrContains(parseCidr('172.16.0.0/12'), '::ffff:172.17.0.1')).toBe(true);
    expect(cidrContains(parseCidr('fd00::/8'), 'fd12:3456::1')).toBe(true);
    expect(cidrContains(parseCidr('fd00::/8'), 'fe80::1')).toBe(false);
    expect(cidrContains(parseCidr('::1'), '::1')).toBe(true);
    expect(cidrContains(parseCidr('127.0.0.1'), '127.0.0.2')).toBe(false);
  });

  test('X-Forwarded-For only from a trusted peer, rightmost entry only', () => {
    const trusted = [parseCidr('172.16.0.0/12')];
    expect(clientAddress('172.17.0.1', '6.6.6.6, 10.0.0.9', trusted)).toBe('10.0.0.9');
    expect(clientAddress('203.0.113.5', '10.0.0.9', trusted)).toBe('203.0.113.5');
    expect(clientAddress('172.17.0.1', 'garbage', trusted)).toBe('172.17.0.1');
    expect(clientAddress('172.17.0.1', null, trusted)).toBe('172.17.0.1');
  });
});
