/**
 * The issuer: takes CSRs, decides whether they are bound, issues and renews
 * certificates by DNS-01, and keeps the DNS status the page shows.
 *
 * Only one issuance runs at a time. Every failure is recorded on the
 * certificate's row and in the event log, and retried with backoff.
 */

import { AcmeProblem, type AcmeClient } from './acme/client';
import { certificateFacts } from './certificate';
import { findCertificate, type CertificateConfig, type Config } from './config';
import { parseCsr, type ParsedCsr } from './csr';
import { authoritativeServers, lookupVia, publicLookup, waitForTxt, type LookupResult } from './dns/lookup';
import type { DnsProvider, TxtHandle } from './dns/providers';
import { verifySignature } from './keys';
import type { CertRow, Store } from './store';

const MINUTE = 60_000;
const HOUR = 60 * MINUTE;
const DNS_CHECK_EVERY = 10 * MINUTE;
const ARI_CHECK_EVERY = 6 * HOUR;
const BACKOFF_BASE = 5 * MINUTE;
const BACKOFF_CAP = 24 * HOUR;
const CHECKIN_CLOCK_SKEW = 5 * MINUTE;

export type Lookups = {
  publicLookup: (name: string) => Promise<LookupResult>;
  insideLookup: (name: string, resolver: string) => Promise<LookupResult>;
  challengeServers: (zone: CertificateConfig['zone']) => Promise<string[]>;
  waitForTxt: (fqdn: string, value: string, servers: string[]) => Promise<void>;
};

export type IssuerDeps = {
  config: Config;
  store: Store;
  acme: AcmeClient;
  providers: Map<string, DnsProvider>;
  lookups?: Partial<Lookups>;
  now?: () => number;
  random?: () => number;
  log?: (message: string) => void;
};

export type SubmitResult =
  | { status: 'unbound'; reason: 'unknown-names' | 'key-mismatch'; names: string[]; fingerprint: string }
  | { status: 'current'; name: string; notAfter: string }
  | { status: 'queued'; name: string };

export type CheckinResult =
  | { ok: true; certificate: { serial: string; notAfter: string } | null }
  | { ok: false; status: 400 | 401 | 404 | 409; error: string };

export class Issuer {
  private readonly config: Config;
  private readonly store: Store;
  private readonly acme: AcmeClient;
  private readonly providers: Map<string, DnsProvider>;
  private readonly lookups: Lookups;
  private readonly now: () => number;
  private readonly random: () => number;
  private readonly log: (message: string) => void;
  private running?: Promise<void>;
  private rerun = false;
  private timer?: ReturnType<typeof setInterval>;

  constructor(deps: IssuerDeps) {
    this.config = deps.config;
    this.store = deps.store;
    this.acme = deps.acme;
    this.providers = deps.providers;
    this.now = deps.now ?? Date.now;
    this.random = deps.random ?? Math.random;
    this.log = deps.log ?? (m => console.log(m));
    this.lookups = {
      publicLookup: name => publicLookup(name, this.config.publicDns),
      insideLookup: (name, resolver) => lookupVia(name, [resolver]),
      challengeServers: zone =>
        zone.nameservers ? Promise.resolve(zone.nameservers) : authoritativeServers(zone.zone),
      waitForTxt: (fqdn, value, servers) => waitForTxt(fqdn, value, servers, { log: this.log }),
      ...deps.lookups,
    };
    this.reconcileWithConfig();
  }

  private event(name: string | null, level: 'info' | 'error', message: string) {
    this.log(`${level === 'error' ? 'ERROR ' : ''}${name ? `${name}: ` : ''}${message}`);
    this.store.event(name, level, message, this.now());
  }

  /** A config edit can rebind a name to a new key; a CSR for the old key is then void. */
  private reconcileWithConfig() {
    for (const c of this.config.certificates) {
      const row = this.store.cert(c.name);
      if (row?.csr_pin && row.csr_pin !== c.key) {
        this.store.updateCert(c.name, { csr_pem: null, csr_pin: null, csr_received_at: null, waiting: null });
        this.event(c.name, 'info', 'the bound key changed in config; waiting for a CSR from the new key');
      }
    }
  }

  // ── Intake ────────────────────────────────────────────────────────────

  async submitCsr(pem: string, sourceIp: string): Promise<SubmitResult> {
    const csr = await parseCsr(pem);
    const entry = findCertificate(this.config, csr.names);
    if (!entry || entry.key !== csr.pin) {
      const reason = entry ? 'key-mismatch' : 'unknown-names';
      this.store.noteUnbound(csr.pin, csr.names, reason, sourceIp, this.now());
      return { status: 'unbound', reason, names: csr.names, fingerprint: csr.pin };
    }

    this.store.clearUnbound(csr.pin);
    const row = this.store.cert(entry.name);
    if (row?.csr_pem !== csr.pem) {
      this.store.updateCert(entry.name, { csr_pem: csr.pem, csr_pin: csr.pin, csr_received_at: this.now() });
      if (!row?.csr_pem) this.event(entry.name, 'info', `CSR received from ${sourceIp}`);
    }
    const fresh = this.store.cert(entry.name)!;
    if (fresh.cert_pem && fresh.cert_pin === entry.key && !this.renewalDue(fresh)) {
      return { status: 'current', name: entry.name, notAfter: new Date(fresh.not_after!).toISOString() };
    }
    this.kick();
    return { status: 'queued', name: entry.name };
  }

  /** The current full chain for `name`, only if it is for the key bound in config. */
  certificatePem(name: string): string | undefined {
    const entry = this.config.certificates.find(c => c.name === name);
    if (!entry) return undefined;
    const row = this.store.cert(entry.name);
    return row?.cert_pem && row.cert_pin === entry.key ? row.cert_pem : undefined;
  }

  /**
   * A device reports in, signing the exact body bytes with its bound key.
   * Body: `{"name": ..., "time": <unix seconds>, ...anything else the page shows}`.
   */
  async checkin(body: Uint8Array, signatureB64: string | null, sourceIp: string): Promise<CheckinResult> {
    if (!signatureB64) return { ok: false, status: 401, error: 'missing X-Signature' };
    let report: { name?: unknown; time?: unknown };
    try {
      report = JSON.parse(new TextDecoder().decode(body));
    } catch {
      return { ok: false, status: 400, error: 'body is not JSON' };
    }
    if (typeof report.name !== 'string' || typeof report.time !== 'number') {
      return { ok: false, status: 400, error: 'body needs a string "name" and a numeric "time"' };
    }
    const entry = this.config.certificates.find(c => c.name === report.name);
    if (!entry) return { ok: false, status: 404, error: `${report.name} is not configured` };
    const row = this.store.cert(entry.name);
    if (!row?.csr_pem || row.csr_pin !== entry.key) {
      return { ok: false, status: 409, error: 'no CSR from the bound key yet; submit one first' };
    }
    const csr: ParsedCsr = await parseCsr(row.csr_pem);
    const signature = Buffer.from(signatureB64, 'base64');
    if (!(await verifySignature(csr.spkiDer, signature, body))) {
      return { ok: false, status: 401, error: 'signature does not verify with the bound key' };
    }
    const deviceTime = report.time * 1000;
    if (Math.abs(deviceTime - this.now()) > CHECKIN_CLOCK_SKEW) {
      return { ok: false, status: 400, error: '"time" is more than 5 minutes from the issuer\'s clock' };
    }
    const previous = this.store.checkin(entry.name);
    if (previous && deviceTime <= previous.device_time) {
      return { ok: false, status: 409, error: '"time" is not later than the previous check-in (replay?)' };
    }
    this.store.putCheckin({
      name: entry.name,
      at: this.now(),
      device_time: deviceTime,
      source_ip: sourceIp,
      report: new TextDecoder().decode(body),
    });
    const current = this.certificatePem(entry.name) ? this.store.cert(entry.name)! : null;
    return {
      ok: true,
      certificate: current ? { serial: current.serial!, notAfter: new Date(current.not_after!).toISOString() } : null,
    };
  }

  // ── Scheduling ────────────────────────────────────────────────────────

  start(intervalMs = MINUTE) {
    this.timer = setInterval(() => this.kick(), intervalMs);
    this.kick();
  }

  async stop() {
    clearInterval(this.timer);
    await this.running;
  }

  /** Run a pass now, or right after the one in progress. */
  kick(): Promise<void> {
    if (this.running) {
      this.rerun = true;
      return this.running;
    }
    this.running = (async () => {
      try {
        do {
          this.rerun = false;
          await this.pass();
        } while (this.rerun);
      } finally {
        this.running = undefined;
      }
    })();
    return this.running;
  }

  /** Wait for any pass in progress (tests). */
  idle(): Promise<void> {
    return this.running ?? Promise.resolve();
  }

  private renewalDue(row: CertRow): boolean {
    return row.renew_at !== null && this.now() >= row.renew_at;
  }

  private async pass() {
    // A device that has just sent a CSR is usually polling for the result, so
    // certificates with a CSR and no current certificate go first; the DNS and
    // ARI refreshes for everything else can wait behind them.
    const waitingForFirst = (c: CertificateConfig) => {
      const row = this.store.cert(c.name);
      return row?.csr_pin === c.key && row.cert_pin !== c.key ? 0 : 1;
    };
    const ordered = [...this.config.certificates].sort((a, b) => waitingForFirst(a) - waitingForFirst(b));
    for (const entry of ordered) {
      try {
        await this.refreshDns(entry);
        await this.refreshAri(entry);
        await this.maybeIssue(entry);
      } catch (err) {
        // maybeIssue records its own failures; anything reaching here is a bug
        // in the pass itself. Record it and move on to the next certificate.
        this.event(entry.name, 'error', `pass failed: ${(err as Error).stack ?? err}`);
      }
    }
  }

  private async refreshDns(entry: CertificateConfig, force = false) {
    const row = this.store.cert(entry.name);
    if (!force && row?.dns_checked_at && this.now() - row.dns_checked_at < DNS_CHECK_EVERY) return;
    // A failed lookup is a status to show, not a reason to stop the pass: it
    // lands in the detail column, and a `require_public_dns` entry stays waiting.
    const settle = async (lookup: Promise<LookupResult>): Promise<LookupResult> => {
      try {
        return await lookup;
      } catch (err) {
        return { ok: false, addresses: [], detail: `lookup failed: ${(err as Error).message}` };
      }
    };
    const [p, i] = await Promise.all([
      settle(this.lookups.publicLookup(entry.name)),
      entry.insideResolver ? settle(this.lookups.insideLookup(entry.name, entry.insideResolver)) : null,
    ]);
    this.store.updateCert(entry.name, {
      public_ok: p.ok ? 1 : 0,
      public_detail: p.detail,
      inside_ok: i ? (i.ok ? 1 : 0) : null,
      inside_detail: i ? i.detail : null,
      dns_checked_at: this.now(),
    });
  }

  private async refreshAri(entry: CertificateConfig) {
    const row = this.store.cert(entry.name);
    if (!row?.cert_id || row.cert_pin !== entry.key) return;
    if (row.ari_next_check && this.now() < row.ari_next_check) return;
    try {
      const info = await this.acme.renewalInfo(row.cert_id);
      if (!info) {
        this.store.updateCert(entry.name, { ari_next_check: this.now() + ARI_CHECK_EVERY, ari_error: null });
        return;
      }
      const start = info.start.valueOf();
      const end = info.end.valueOf();
      const windowChanged = start !== row.ari_start || end !== row.ari_end;
      const renewAt = windowChanged ? start + Math.floor(this.random() * (end - start)) : row.renew_at;
      const next = Math.max(info.retryAfter?.valueOf() ?? 0, this.now() + HOUR);
      this.store.updateCert(entry.name, {
        ari_start: start,
        ari_end: end,
        renew_at: renewAt,
        ari_next_check: Math.min(next, this.now() + ARI_CHECK_EVERY),
        ari_error: null,
      });
      if (windowChanged) {
        this.event(
          entry.name,
          'info',
          `renewal window ${info.start.toISOString()} to ${info.end.toISOString()}; renewing at ${new Date(renewAt!).toISOString()}`,
        );
      }
    } catch (err) {
      // ARI is advisory: the two-thirds-of-lifetime renew_at set at issuance still stands.
      this.store.updateCert(entry.name, { ari_error: (err as Error).message, ari_next_check: this.now() + HOUR });
      this.event(entry.name, 'error', `renewal info: ${(err as Error).message}`);
    }
  }

  private async maybeIssue(entry: CertificateConfig) {
    const row = this.store.cert(entry.name);
    if (!row?.csr_pem || row.csr_pin !== entry.key) return;
    const haveCurrent = row.cert_pem && row.cert_pin === row.csr_pin;
    if (haveCurrent && !this.renewalDue(row)) return;
    if (this.now() < row.next_attempt_at) return;

    if (entry.requirePublicDns) {
      await this.refreshDns(entry, row.public_ok !== 1);
      const checked = this.store.cert(entry.name)!;
      if (checked.public_ok !== 1) {
        const waiting = `waiting for ${entry.name} to resolve in public DNS (${checked.public_detail})`;
        if (row.waiting !== waiting) this.event(entry.name, 'info', waiting);
        this.store.updateCert(entry.name, { waiting, next_attempt_at: this.now() + DNS_CHECK_EVERY });
        return;
      }
    }

    this.store.updateCert(entry.name, { waiting: null });
    const replaces = haveCurrent && row.cert_id ? row.cert_id : undefined;
    try {
      const chain = await this.issue(entry, row.csr_pem, replaces);
      const facts = await certificateFacts(chain);
      if (facts.pin !== entry.key) throw new Error(`CA returned a certificate for a different key (${facts.pin})`);
      const lifetime = facts.notAfter.valueOf() - facts.notBefore.valueOf();
      this.store.updateCert(entry.name, {
        cert_pem: chain,
        cert_pin: facts.pin,
        not_before: facts.notBefore.valueOf(),
        not_after: facts.notAfter.valueOf(),
        serial: facts.serial,
        cert_id: facts.certId ?? null,
        issued_at: this.now(),
        renew_at: facts.notBefore.valueOf() + Math.floor((lifetime * 2) / 3),
        ari_start: null,
        ari_end: null,
        ari_next_check: null,
        ari_error: null,
        failures: 0,
        next_attempt_at: 0,
        last_error: null,
        last_error_at: null,
      });
      this.event(
        entry.name,
        'info',
        `${replaces ? 'renewed' : 'issued'}: serial ${facts.serial}, valid until ${facts.notAfter.toISOString()}`,
      );
      // Ask for the renewal window straight away rather than on the next cycle.
      await this.refreshAri(entry);
    } catch (err) {
      const failures = row.failures + 1;
      const delay = Math.min(BACKOFF_BASE * 2 ** (failures - 1), BACKOFF_CAP);
      const message = (err as Error).message;
      this.store.updateCert(entry.name, {
        failures,
        next_attempt_at: this.now() + delay,
        last_error: message,
        last_error_at: this.now(),
      });
      this.event(
        entry.name,
        'error',
        `issuance failed (attempt ${failures}; next in ${Math.round(delay / MINUTE)} min): ${message}`,
      );
    }
  }

  /** One ACME order, start to finish. Challenge records are always removed, success or not. */
  private async issue(entry: CertificateConfig, csrPem: string, replaces: string | undefined): Promise<string> {
    const csr = await parseCsr(csrPem);
    const provider = this.providers.get(entry.zone.zone);
    if (!provider) throw new Error(`no DNS provider for zone ${entry.zone.zone}`);

    let order;
    try {
      order = await this.acme.newOrder(entry.names, replaces);
    } catch (err) {
      // RFC 9773 §5: a CA that says the predecessor was already replaced will
      // refuse this `replaces` value for good; a plain order is still allowed.
      if (replaces && err instanceof AcmeProblem && err.problem.type === 'urn:ietf:params:acme:error:alreadyReplaced') {
        this.event(
          entry.name,
          'info',
          'the CA says the previous certificate was already replaced; ordering without "replaces"',
        );
        order = await this.acme.newOrder(entry.names);
      } else throw err;
    }

    const presented: TxtHandle[] = [];
    try {
      const servers = await this.lookups.challengeServers(entry.zone);
      const pending: string[] = [];
      for (const url of order.authorizations) {
        const authz = await this.acme.getAuthorization(url);
        if (authz.status === 'valid') continue;
        const challenge = authz.challenges.find(c => c.type === 'dns-01');
        if (!challenge) throw new Error(`${authz.identifier.value}: the CA offered no dns-01 challenge`);
        const fqdn = `_acme-challenge.${authz.identifier.value}`;
        const value = await this.acme.dns01TxtValue(challenge.token);
        presented.push(await provider.createTxt(fqdn, value));
        await this.lookups.waitForTxt(fqdn, value, servers);
        await this.acme.respondToChallenge(challenge.url);
        pending.push(url);
      }
      for (const url of pending) await this.acme.waitForAuthorization(url);
    } finally {
      for (const handle of presented) {
        try {
          await provider.deleteTxt(handle);
        } catch (err) {
          this.event(entry.name, 'error', `could not remove ${handle.fqdn} TXT: ${(err as Error).message}`);
        }
      }
    }
    return this.acme.finalizeAndDownload(order, csr.der);
  }
}
