/**
 * The read-only status page. Server-rendered, no script, readable on a phone.
 *
 * Times lead with the configured zone; UTC sits beside them in smaller text,
 * visible without hovering (there are no tooltips on touch screens).
 */

import type { Config } from './config';
import type { CertRow, CheckinRow, EventRow, UnboundRow } from './store';

const esc = (s: unknown) =>
  String(s ?? '').replace(
    /[&<>"']/g,
    c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c]!,
  );

export function formatTime(ms: number | null | undefined, timeZone: string): string {
  if (!ms) return '<span class="dim">never</span>';
  const d = new Date(ms);
  const local = new Intl.DateTimeFormat('en-US', {
    timeZone,
    year: 'numeric',
    month: '2-digit',
    day: '2-digit',
    hour: 'numeric',
    minute: '2-digit',
    hour12: true,
    timeZoneName: 'short',
  }).formatToParts(d);
  const part = (t: string) => local.find(p => p.type === t)?.value ?? '';
  const localText = `${part('year')}-${part('month')}-${part('day')} ${part('hour')}:${part('minute')} ${part('dayPeriod')} ${part('timeZoneName')}`;
  const utc = d.toISOString().slice(11, 16);
  if (timeZone === 'UTC') return `<span class="t">${esc(d.toISOString().slice(0, 16).replace('T', ' '))}Z</span>`;
  return `<span class="t">${esc(localText)} <small>(${utc}Z)</small></span>`;
}

function relative(ms: number | null, now: number): string {
  if (!ms) return '';
  const diff = ms - now;
  const abs = Math.abs(diff);
  const unit = abs >= 86_400_000 ? [86_400_000, 'd'] : abs >= 3_600_000 ? [3_600_000, 'h'] : [60_000, 'min'];
  const n = Math.round(abs / (unit[0] as number));
  return diff >= 0 ? `in ${n} ${unit[1]}` : `${n} ${unit[1]} ago`;
}

const badge = (ok: boolean | null, text: string) =>
  `<span class="badge ${ok === null ? 'na' : ok ? 'ok' : 'bad'}">${esc(text)}</span>`;

export type StatusData = {
  config: Config;
  certs: Map<string, CertRow>;
  checkins: Map<string, CheckinRow>;
  unbound: UnboundRow[];
  events: EventRow[];
  now: number;
  /** The running build's commit, if known. */
  build?: string;
};

export function renderStatus(d: StatusData): string {
  const tz = d.config.displayTimezone;
  const configured = new Set(d.config.certificates.map(c => c.name));

  const rows = d.config.certificates
    .map(c => {
      const r = d.certs.get(c.name);
      const ci = d.checkins.get(c.name);
      const current = !!r?.cert_pem && r.cert_pin === c.key;
      let state: string;
      if (r?.last_error && r.failures > 0) state = badge(false, `failing (${r.failures})`);
      else if (r?.waiting) state = badge(null, 'waiting');
      else if (current && r!.not_after! > d.now) state = badge(true, 'current');
      else if (current) state = badge(false, 'expired');
      else if (r?.csr_pin === c.key) state = badge(null, 'issuing');
      else state = badge(null, 'no CSR yet');

      let report = '';
      if (ci) {
        try {
          const parsed = JSON.parse(ci.report) as { addresses?: unknown; lookup?: unknown };
          const addrs = Array.isArray(parsed.addresses) ? parsed.addresses.join(', ') : '';
          const look = Array.isArray(parsed.lookup) ? parsed.lookup.join(', ') : '';
          report = `${addrs ? `addresses ${esc(addrs)}` : ''}${look ? `<br>its own lookup: ${esc(look)}` : ''}`;
        } catch {
          report = '<span class="bad">unreadable report</span>';
        }
      }

      const notes = [
        r?.waiting ? `<div class="note">${esc(r.waiting)}</div>` : '',
        r?.last_error ? `<div class="err">${formatTime(r.last_error_at, tz)}: ${esc(r.last_error)}</div>` : '',
        r?.ari_error ? `<div class="err">renewal info: ${esc(r.ari_error)}</div>` : '',
      ].join('');

      return `<section class="cert">
  <h2>${esc(c.name)} ${state}</h2>
  ${c.altNames.length ? `<p class="dim">also ${esc(c.altNames.join(', '))}</p>` : ''}
  <dl>
    <dt>Key</dt><dd><code>${esc(c.key)}</code></dd>
    <dt>Certificate</dt><dd>${
      current
        ? `serial <code>${esc(r!.serial)}</code><br>expires ${formatTime(r!.not_after, tz)} <span class="dim">${relative(r!.not_after, d.now)}</span>`
        : '<span class="dim">none for this key</span>'
    }</dd>
    <dt>Renewal</dt><dd>${
      current
        ? `${formatTime(r!.renew_at, tz)} <span class="dim">${relative(r!.renew_at, d.now)}${r!.ari_start ? ", from the CA's renewal window" : ', at two thirds of the lifetime'}</span>`
        : '—'
    }</dd>
    <dt>Public DNS</dt><dd>${r?.public_ok === null || r?.public_ok === undefined ? '<span class="dim">not checked yet</span>' : `${badge(r.public_ok === 1, r.public_ok === 1 ? 'resolves' : 'missing')} ${esc(r.public_detail)}`}${c.requirePublicDns ? ' <span class="dim">(required before issuing)</span>' : ''}</dd>
    ${
      c.insideResolver
        ? `<dt>Inside DNS</dt><dd>${r?.inside_ok === null || r?.inside_ok === undefined ? '<span class="dim">not checked yet</span>' : `${badge(r.inside_ok === 1, r.inside_ok === 1 ? 'resolves' : 'missing')} ${esc(r.inside_detail)}`} <span class="dim">via ${esc(c.insideResolver)}</span>${
            ci && r?.inside_ok === 1 && ci.source_ip && !(r.inside_detail ?? '').split(', ').includes(ci.source_ip)
              ? `<div class="note">does not include the address it last checked in from (${esc(ci.source_ip)})</div>`
              : ''
          }</dd>`
        : ''
    }
    <dt>Last check-in</dt><dd>${ci ? `${formatTime(ci.at, tz)} <span class="dim">${relative(ci.at, d.now)}</span> from ${esc(ci.source_ip)}<br>${report}` : '<span class="dim">never</span>'}</dd>
  </dl>
  ${notes}
</section>`;
    })
    .join('\n');

  const orphans = [...d.certs.keys()].filter(n => !configured.has(n));
  const unbound = d.unbound.length
    ? `<section><h2>Requests with no binding</h2>
  <p class="dim">Nothing is issued for these. To allow one, add its name set and key to the config.</p>
  ${d.unbound
    .map(
      u => `<div class="cert"><p><strong>${esc(u.names)}</strong> ${badge(false, u.reason === 'key-mismatch' ? 'different key' : 'name not configured')}<br>
  from ${esc(u.source_ip)}, ${u.count}× , last ${formatTime(u.last_seen, tz)}</p>
  <pre>- name: ${esc(u.names.split(' ')[0])}${u.names.includes(' ') ? `\n  alt_names: [${esc(u.names.split(' ').slice(1).join(', '))}]` : ''}\n  key: ${esc(u.pin)}</pre></div>`,
    )
    .join('\n')}
</section>`
    : '';

  const events = d.events
    .map(
      e =>
        `<li class="${e.level === 'error' ? 'err' : ''}">${formatTime(e.at, tz)} ${e.name ? `<strong>${esc(e.name)}</strong> ` : ''}${esc(e.message)}</li>`,
    )
    .join('\n');

  return `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>dns01-issuer</title>
<style>
:root { color-scheme: light dark; --ok: #2e7d32; --bad: #c62828; --na: #757575; }
body { font: 15px/1.5 system-ui, sans-serif; max-width: 60rem; margin: 2rem auto; padding: 0 1rem; }
h1 { font-size: 1.3rem; } h2 { font-size: 1.05rem; margin: 0 0 .4rem; }
.cert { border: 1px solid color-mix(in srgb, currentColor 20%, transparent); border-radius: .5rem; padding: .8rem 1rem; margin: .8rem 0; }
dl { display: grid; grid-template-columns: max-content 1fr; gap: .2rem 1rem; margin: 0; }
dt { opacity: .7; } dd { margin: 0; overflow-wrap: anywhere; }
code, pre { font-size: .85em; } pre { padding: .5rem; overflow-x: auto; background: color-mix(in srgb, currentColor 8%, transparent); }
small, .dim { opacity: .65; }
.badge { font-size: .75rem; padding: .05rem .45rem; border-radius: 1rem; color: white; vertical-align: middle; }
.badge.ok { background: var(--ok); } .badge.bad { background: var(--bad); } .badge.na { background: var(--na); }
.err { color: var(--bad); } .note { opacity: .8; font-style: italic; }
ul.events { padding-left: 1rem; font-size: .9rem; }
</style></head><body>
<h1>dns01-issuer</h1>
<p class="dim">Read-only. What may be issued is decided by the config file, not here. Generated ${formatTime(d.now, tz)}${d.build ? `, build <code>${esc(d.build.slice(0, 12))}</code>` : ''}.</p>
${rows || '<p>No certificates are configured.</p>'}
${orphans.length ? `<p class="dim">In the database but no longer configured: ${esc(orphans.join(', '))}</p>` : ''}
${unbound}
<section><h2>Recent events</h2><ul class="events">${events || '<li class="dim">none</li>'}</ul></section>
</body></html>`;
}
