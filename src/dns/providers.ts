/**
 * Where challenge TXT records get written. One provider per configured zone.
 */

import type { ZoneConfig } from '../config';

export type TxtHandle = { fqdn: string; value: string; id?: string };

export interface DnsProvider {
  readonly zone: string;
  /** Create `fqdn TXT value`. Must not touch other records at that name. */
  createTxt(fqdn: string, value: string): Promise<TxtHandle>;
  deleteTxt(handle: TxtHandle): Promise<void>;
}

export function makeProvider(zone: ZoneConfig, env: Record<string, string | undefined> = process.env): DnsProvider {
  switch (zone.provider) {
    case 'cloudflare': {
      const token = env[zone.tokenEnv!];
      if (!token) throw new Error(`zone ${zone.zone}: environment variable ${zone.tokenEnv} is not set`);
      return new CloudflareProvider(zone.zone, token, zone.zoneId);
    }
    case 'challtestsrv':
      return new ChalltestsrvProvider(zone.zone, zone.url!);
  }
}

const CF_API = 'https://api.cloudflare.com/client/v4';

type CfEnvelope<T> = { success: boolean; errors: { code: number; message: string }[]; result: T };

/**
 * Cloudflare DNS. The token needs `Zone:DNS:Edit` on the zone, plus `Zone:Read`
 * unless `zone_id` is configured. Records carry a comment so a person looking
 * at the dashboard can tell what made them.
 */
export class CloudflareProvider implements DnsProvider {
  private zoneIdPromise?: Promise<string>;

  constructor(
    readonly zone: string,
    private readonly token: string,
    private readonly zoneId?: string,
  ) {}

  private async api<T>(method: string, path: string, body?: unknown): Promise<T> {
    const res = await fetch(`${CF_API}${path}`, {
      method,
      headers: { authorization: `Bearer ${this.token}`, 'content-type': 'application/json' },
      body: body === undefined ? undefined : JSON.stringify(body),
    });
    const text = await res.text();
    let parsed: CfEnvelope<T>;
    try {
      parsed = JSON.parse(text) as CfEnvelope<T>;
    } catch {
      throw new Error(`Cloudflare ${method} ${path}: ${res.status}: ${text.slice(0, 300)}`);
    }
    if (!res.ok || !parsed.success) {
      const errors = parsed.errors?.map(e => `${e.code} ${e.message}`).join('; ') || res.statusText;
      throw new Error(`Cloudflare ${method} ${path}: ${res.status}: ${errors}`);
    }
    return parsed.result;
  }

  private resolveZoneId(): Promise<string> {
    if (this.zoneId) return Promise.resolve(this.zoneId);
    this.zoneIdPromise ??= this.api<{ id: string; name: string }[]>(
      'GET',
      `/zones?name=${encodeURIComponent(this.zone)}`,
    ).then(zones => {
      const match = zones.find(z => z.name === this.zone);
      if (!match) throw new Error(`Cloudflare: no zone named ${this.zone} is visible to this token`);
      return match.id;
    });
    return this.zoneIdPromise;
  }

  async createTxt(fqdn: string, value: string): Promise<TxtHandle> {
    const zoneId = await this.resolveZoneId();
    const record = await this.api<{ id: string }>('POST', `/zones/${zoneId}/dns_records`, {
      type: 'TXT',
      name: fqdn,
      content: `"${value}"`,
      ttl: 60,
      comment: 'dns01-issuer: ACME challenge, deleted after validation',
    });
    return { fqdn, value, id: record.id };
  }

  async deleteTxt(handle: TxtHandle): Promise<void> {
    if (!handle.id) throw new Error(`Cloudflare: no record id for ${handle.fqdn}`);
    const zoneId = await this.resolveZoneId();
    await this.api('DELETE', `/zones/${zoneId}/dns_records/${handle.id}`);
  }
}

/** pebble-challtestsrv's management API. Tests only. */
export class ChalltestsrvProvider implements DnsProvider {
  constructor(
    readonly zone: string,
    private readonly url: string,
  ) {}

  private async call(path: string, body: unknown) {
    const res = await fetch(`${this.url.replace(/\/$/, '')}${path}`, {
      method: 'POST',
      body: JSON.stringify(body),
    });
    if (!res.ok) throw new Error(`challtestsrv ${path}: ${res.status}: ${await res.text()}`);
  }

  async createTxt(fqdn: string, value: string): Promise<TxtHandle> {
    await this.call('/set-txt', { host: `${fqdn}.`, value });
    return { fqdn, value };
  }

  async deleteTxt(handle: TxtHandle): Promise<void> {
    await this.call('/clear-txt', { host: `${handle.fqdn}.` });
  }
}
