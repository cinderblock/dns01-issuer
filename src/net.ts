/**
 * Address helpers: CIDR matching for trusted proxies, and the client address a
 * request really came from.
 */

import { isIP } from 'node:net';

export type Cidr = { family: 4 | 6; bits: bigint; prefix: number };

function toBigInt(address: string): { family: 4 | 6; value: bigint } {
  // An IPv4-mapped IPv6 address is the IPv4 address; Bun reports Docker's
  // bridge peers that way on dual-stack sockets.
  const mapped = /^::ffff:(\d+\.\d+\.\d+\.\d+)$/i.exec(address);
  if (mapped) address = mapped[1]!;
  const family = isIP(address);
  if (family === 4) {
    const value = address.split('.').reduce((acc, octet) => (acc << 8n) | BigInt(Number(octet)), 0n);
    return { family: 4, value };
  }
  if (family === 6) {
    const [head, tail] = address.split('::') as [string, string | undefined];
    const parse = (s: string | undefined) => (s ? s.split(':').filter(Boolean) : []);
    const h = parse(head);
    const t = parse(tail);
    const groups = tail === undefined ? h : [...h, ...Array(8 - h.length - t.length).fill('0'), ...t];
    const value = groups.reduce((acc, g) => (acc << 16n) | BigInt(parseInt(g, 16)), 0n);
    return { family: 6, value };
  }
  throw new Error(`${address}: not an IP address`);
}

export function parseCidr(cidr: string): Cidr {
  const [address, prefixText] = cidr.split('/') as [string, string | undefined];
  const { family, value } = toBigInt(address);
  const max = family === 4 ? 32 : 128;
  const prefix = prefixText === undefined ? max : Number(prefixText);
  if (!Number.isInteger(prefix) || prefix < 0 || prefix > max) throw new Error(`${cidr}: bad prefix length`);
  return { family, bits: value >> BigInt(max - prefix), prefix };
}

export function cidrContains(cidr: Cidr, address: string): boolean {
  let parsed;
  try {
    parsed = toBigInt(address);
  } catch {
    return false;
  }
  if (parsed.family !== cidr.family) return false;
  const max = cidr.family === 4 ? 32 : 128;
  return parsed.value >> BigInt(max - cidr.prefix) === cidr.bits;
}

/**
 * The client's address. X-Forwarded-For is believed only from a trusted peer,
 * and then only its rightmost entry: the one that peer appended. A client can
 * write anything to the left of it.
 */
export function clientAddress(peer: string, forwardedFor: string | null, trusted: Cidr[]): string {
  if (!forwardedFor || !trusted.some(c => cidrContains(c, peer))) return peer;
  const entries = forwardedFor
    .split(',')
    .map(s => s.trim())
    .filter(Boolean);
  const last = entries[entries.length - 1];
  return last && isIP(last.replace(/^\[|\]$/g, '')) ? last.replace(/^\[|\]$/g, '') : peer;
}
