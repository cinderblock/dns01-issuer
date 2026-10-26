/**
 * An RFC 8555 ACME client, just the parts DNS-01 issuance from a supplied CSR
 * needs, plus ACME Renewal Information (RFC 9773).
 */

import { b64url, signJws, type AccountKey } from './jws';

export type Directory = {
  newNonce: string;
  newAccount: string;
  newOrder: string;
  renewalInfo?: string;
  meta?: { termsOfService?: string };
};

export type Identifier = { type: 'dns'; value: string };

export type Order = {
  url: string;
  status: 'pending' | 'ready' | 'processing' | 'valid' | 'invalid';
  identifiers: Identifier[];
  authorizations: string[];
  finalize: string;
  certificate?: string;
  error?: Problem;
};

export type Challenge = { type: string; url: string; status: string; token: string; error?: Problem };

export type Authorization = {
  identifier: Identifier;
  status: 'pending' | 'valid' | 'invalid' | 'deactivated' | 'expired' | 'revoked';
  challenges: Challenge[];
};

export type RenewalInfo = { start: Date; end: Date; retryAfter?: Date; explanationUrl?: string };

export type Problem = { type: string; detail?: string; subproblems?: Problem[] };

export class AcmeProblem extends Error {
  override name = 'AcmeProblem';
  constructor(
    readonly status: number,
    readonly problem: Problem,
    readonly url: string,
  ) {
    super(
      `${url}: ${status} ${problem.type}${problem.detail ? `: ${problem.detail}` : ''}` +
        (problem.subproblems?.length
          ? ` (${problem.subproblems.map(p => `${p.type}${p.detail ? `: ${p.detail}` : ''}`).join('; ')})`
          : ''),
    );
  }
}

export type AcmeClientOptions = {
  directoryUrl: string;
  accountKey: AccountKey;
  contact: string[];
  /** Extra CA certificates (PEM) to trust for the ACME server's own TLS. */
  caBundle?: string;
  /** Upper bound on any one poll loop. */
  pollTimeoutMs?: number;
  log?: (message: string) => void;
};

const JOSE = 'application/jose+json';

export class AcmeClient {
  private directoryCache?: Directory;
  private nonces: string[] = [];
  private kid?: string;
  private readonly pollTimeoutMs: number;
  private readonly log: (message: string) => void;

  constructor(private readonly opts: AcmeClientOptions) {
    this.pollTimeoutMs = opts.pollTimeoutMs ?? 5 * 60_000;
    this.log = opts.log ?? (() => {});
  }

  /** Key authorization's DNS-01 TXT value (RFC 8555 §8.4). */
  async dns01TxtValue(token: string): Promise<string> {
    const keyAuthorization = `${token}.${this.opts.accountKey.thumbprint}`;
    return b64url(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(keyAuthorization)));
  }

  private fetch(url: string, init: RequestInit = {}): Promise<Response> {
    return fetch(url, { ...init, ...(this.opts.caBundle ? { tls: { ca: this.opts.caBundle } } : {}) });
  }

  async directory(): Promise<Directory> {
    if (!this.directoryCache) {
      const res = await this.fetch(this.opts.directoryUrl);
      if (!res.ok) throw new Error(`${this.opts.directoryUrl}: directory fetch failed: ${res.status}`);
      this.directoryCache = (await res.json()) as Directory;
    }
    return this.directoryCache;
  }

  private remember(res: Response) {
    const nonce = res.headers.get('replay-nonce');
    if (nonce) this.nonces.push(nonce);
  }

  private async nonce(): Promise<string> {
    const cached = this.nonces.pop();
    if (cached) return cached;
    const url = (await this.directory()).newNonce;
    const res = await this.fetch(url, { method: 'HEAD' });
    const nonce = res.headers.get('replay-nonce');
    if (!nonce) throw new Error(`${url}: no Replay-Nonce (status ${res.status})`);
    return nonce;
  }

  /** A signed POST. `payload: null` is POST-as-GET. Retries a rejected nonce, as RFC 8555 §6.5 expects. */
  private async post(url: string, payload: unknown | null, opts: { useJwk?: boolean; accept?: string } = {}) {
    for (let attempt = 1; ; attempt++) {
      const header =
        opts.useJwk || !this.kid
          ? { nonce: await this.nonce(), url, jwk: this.opts.accountKey.jwk }
          : { nonce: await this.nonce(), url, kid: this.kid };
      if (!opts.useJwk && !this.kid) throw new Error('ACME account not set up');
      const body = JSON.stringify(await signJws(this.opts.accountKey, header, payload));
      const res = await this.fetch(url, {
        method: 'POST',
        headers: { 'content-type': JOSE, ...(opts.accept ? { accept: opts.accept } : {}) },
        body,
      });
      this.remember(res);
      if (res.ok) return res;
      const problem = await readProblem(res);
      if (problem.type === 'urn:ietf:params:acme:error:badNonce' && attempt < 5) continue;
      throw new AcmeProblem(res.status, problem, url);
    }
  }

  /** Find or create the account for this key. */
  async ensureAccount(): Promise<string> {
    if (this.kid) return this.kid;
    const res = await this.post(
      (await this.directory()).newAccount,
      { termsOfServiceAgreed: true, ...(this.opts.contact.length ? { contact: this.opts.contact } : {}) },
      { useJwk: true },
    );
    const kid = res.headers.get('location');
    if (!kid) throw new Error('newAccount: no Location header');
    this.kid = kid;
    return kid;
  }

  async newOrder(names: string[], replaces?: string): Promise<Order> {
    await this.ensureAccount();
    const payload: Record<string, unknown> = { identifiers: names.map(value => ({ type: 'dns', value })) };
    if (replaces) payload.replaces = replaces;
    const res = await this.post((await this.directory()).newOrder, payload);
    const url = res.headers.get('location');
    if (!url) throw new Error('newOrder: no Location header');
    return { url, ...((await res.json()) as Omit<Order, 'url'>) };
  }

  async getAuthorization(url: string): Promise<Authorization> {
    return (await (await this.post(url, null)).json()) as Authorization;
  }

  async getOrder(url: string): Promise<Order> {
    return { url, ...((await (await this.post(url, null)).json()) as Omit<Order, 'url'>) };
  }

  async respondToChallenge(url: string): Promise<void> {
    await this.post(url, {});
  }

  /** Poll an authorization until it leaves `pending`. Throws if it ends anywhere but `valid`. */
  async waitForAuthorization(url: string): Promise<Authorization> {
    const deadline = Date.now() + this.pollTimeoutMs;
    for (;;) {
      const res = await this.post(url, null);
      const authz = (await res.json()) as Authorization;
      if (authz.status === 'valid') return authz;
      if (authz.status !== 'pending') {
        const failed = authz.challenges.find(c => c.error);
        throw new Error(
          `authorization for ${authz.identifier.value} is ${authz.status}` +
            (failed?.error ? `: ${failed.error.type}: ${failed.error.detail ?? ''}` : ''),
        );
      }
      await this.sleepFor(res, deadline, `authorization for ${authz.identifier.value}`);
    }
  }

  /** Finalize with the device's CSR, wait for the certificate, and download the full chain. */
  async finalizeAndDownload(order: Order, csrDer: Uint8Array): Promise<string> {
    const deadline = Date.now() + this.pollTimeoutMs;
    let res = await this.post(order.finalize, { csr: b64url(csrDer) });
    let current = { ...order, ...((await res.json()) as Omit<Order, 'url'>) };
    while (current.status === 'processing' || current.status === 'ready' || current.status === 'pending') {
      if (current.status === 'pending') throw new Error(`order ${order.url} went back to pending after finalize`);
      await this.sleepFor(res, deadline, `order ${order.url}`);
      res = await this.post(order.url, null);
      current = { ...order, ...((await res.json()) as Omit<Order, 'url'>) };
    }
    if (current.status !== 'valid' || !current.certificate) {
      throw new Error(
        `order ${order.url} is ${current.status}` +
          (current.error ? `: ${current.error.type}: ${current.error.detail ?? ''}` : ''),
      );
    }
    const cert = await this.post(current.certificate, null, { accept: 'application/pem-certificate-chain' });
    return await cert.text();
  }

  /** RFC 9773 renewal window for a certificate, or undefined if the CA offers no ARI. */
  async renewalInfo(certId: string): Promise<RenewalInfo | undefined> {
    const base = (await this.directory()).renewalInfo;
    if (!base) return undefined;
    const url = `${base.replace(/\/$/, '')}/${certId}`;
    const res = await this.fetch(url);
    if (!res.ok) throw new Error(`${url}: renewalInfo ${res.status}: ${await res.text()}`);
    const body = (await res.json()) as { suggestedWindow?: { start: string; end: string }; explanationURL?: string };
    if (!body.suggestedWindow) throw new Error(`${url}: renewalInfo has no suggestedWindow`);
    const start = new Date(body.suggestedWindow.start);
    const end = new Date(body.suggestedWindow.end);
    if (Number.isNaN(start.valueOf()) || Number.isNaN(end.valueOf()) || end < start) {
      throw new Error(`${url}: renewalInfo has a malformed suggestedWindow`);
    }
    return { start, end, retryAfter: retryAfter(res), explanationUrl: body.explanationURL };
  }

  private async sleepFor(res: Response, deadline: number, what: string) {
    if (Date.now() > deadline) throw new Error(`timed out waiting for ${what}`);
    const after = retryAfter(res);
    const ms = Math.min(Math.max(after ? after.valueOf() - Date.now() : 2000, 1000), 30_000);
    this.log(`waiting ${Math.round(ms / 1000)}s for ${what}`);
    await Bun.sleep(ms);
  }
}

function retryAfter(res: Response): Date | undefined {
  const value = res.headers.get('retry-after');
  if (!value) return undefined;
  const seconds = Number(value);
  if (Number.isFinite(seconds)) return new Date(Date.now() + seconds * 1000);
  const date = new Date(value);
  return Number.isNaN(date.valueOf()) ? undefined : date;
}

async function readProblem(res: Response): Promise<Problem> {
  const text = await res.text();
  try {
    const parsed = JSON.parse(text) as Problem;
    if (typeof parsed.type === 'string') return parsed;
  } catch {
    // not JSON; reported below as the raw body
  }
  return { type: 'about:blank', detail: text.slice(0, 500) || res.statusText };
}
