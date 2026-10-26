/**
 * HTTP: the device API and the status page.
 */

import type { Config } from './config';
import { CsrError } from './csr';
import type { Issuer } from './issuer';
import { clientAddress } from './net';
import { renderStatus } from './status-page';
import type { Store } from './store';

const MAX_BODY = 16 * 1024;

const json = (status: number, body: unknown) =>
  new Response(JSON.stringify(body, null, 2) + '\n', { status, headers: { 'content-type': 'application/json' } });

async function readBody(req: Request): Promise<Uint8Array | Response> {
  const length = Number(req.headers.get('content-length') ?? '0');
  if (length > MAX_BODY) return json(413, { error: `body over ${MAX_BODY} bytes` });
  const body = new Uint8Array(await req.arrayBuffer());
  if (body.length > MAX_BODY) return json(413, { error: `body over ${MAX_BODY} bytes` });
  return body;
}

export function makeHandler(deps: { config: Config; issuer: Issuer; store: Store; now?: () => number }) {
  const { config, issuer, store } = deps;
  const now = deps.now ?? Date.now;

  return async function handle(req: Request, peer: string): Promise<Response> {
    const url = new URL(req.url);
    const source = clientAddress(peer, req.headers.get('x-forwarded-for'), config.trustedProxies);
    const path = url.pathname;

    try {
      if (path === '/api/v1/csr') {
        if (req.method !== 'POST') return json(405, { error: 'POST a PEM CSR' });
        const body = await readBody(req);
        if (body instanceof Response) return body;
        const result = await issuer.submitCsr(new TextDecoder().decode(body), source);
        if (result.status === 'unbound') {
          return json(403, {
            ...result,
            error:
              result.reason === 'key-mismatch'
                ? 'this name set is bound to a different key'
                : 'no certificate is configured for exactly this name set',
          });
        }
        return json(result.status === 'current' ? 200 : 202, result);
      }

      const certMatch = /^\/api\/v1\/certificates\/([a-z0-9.-]+)$/.exec(path);
      if (certMatch) {
        if (req.method !== 'GET' && req.method !== 'HEAD') return json(405, { error: 'GET only' });
        const pem = issuer.certificatePem(certMatch[1]!);
        if (!pem) return json(404, { error: `no current certificate for ${certMatch[1]}` });
        return new Response(pem, { headers: { 'content-type': 'application/pem-certificate-chain' } });
      }

      if (path === '/api/v1/checkin') {
        if (req.method !== 'POST') return json(405, { error: 'POST a signed JSON report' });
        const body = await readBody(req);
        if (body instanceof Response) return body;
        const result = await issuer.checkin(body, req.headers.get('x-signature'), source);
        return result.ok ? json(200, result) : json(result.status, { error: result.error });
      }

      if (path === '/healthz') return new Response('ok\n');

      if (path === '/') {
        if (req.method !== 'GET' && req.method !== 'HEAD') return json(405, { error: 'GET only' });
        const html = renderStatus({
          config,
          certs: new Map(store.allCerts().map(r => [r.name, r])),
          checkins: new Map(store.allCheckins().map(r => [r.name, r])),
          unbound: store.allUnbound(),
          events: store.recentEvents(),
          now: now(),
        });
        return new Response(html, { headers: { 'content-type': 'text/html; charset=utf-8' } });
      }

      return json(404, { error: 'not found' });
    } catch (err) {
      if (err instanceof CsrError) return json(400, { error: err.message });
      console.error(`${req.method} ${path} from ${source}:`, err);
      return json(500, { error: 'internal error; see the issuer log' });
    }
  };
}
