/**
 * Durable state, in SQLite under the data directory. Times are epoch
 * milliseconds. Rows are keyed by a certificate's primary name, the `name:` of
 * its config entry.
 */

import { Database } from 'bun:sqlite';

export type CertRow = {
  name: string;
  csr_pem: string | null;
  csr_pin: string | null;
  csr_received_at: number | null;
  cert_pem: string | null;
  cert_pin: string | null;
  not_before: number | null;
  not_after: number | null;
  serial: string | null;
  cert_id: string | null;
  issued_at: number | null;
  renew_at: number | null;
  ari_start: number | null;
  ari_end: number | null;
  ari_next_check: number | null;
  ari_error: string | null;
  next_attempt_at: number;
  failures: number;
  last_error: string | null;
  last_error_at: number | null;
  waiting: string | null;
  public_ok: number | null;
  public_detail: string | null;
  inside_ok: number | null;
  inside_detail: string | null;
  dns_checked_at: number | null;
};

export type CheckinRow = { name: string; at: number; device_time: number; source_ip: string; report: string };

export type UnboundRow = {
  pin: string;
  names: string;
  reason: string;
  source_ip: string;
  first_seen: number;
  last_seen: number;
  count: number;
};

export type EventRow = { id: number; at: number; name: string | null; level: 'info' | 'error'; message: string };

const SCHEMA = `
create table if not exists certificates (
  name text primary key,
  csr_pem text, csr_pin text, csr_received_at integer,
  cert_pem text, cert_pin text, not_before integer, not_after integer, serial text, cert_id text, issued_at integer,
  renew_at integer, ari_start integer, ari_end integer, ari_next_check integer, ari_error text,
  next_attempt_at integer not null default 0, failures integer not null default 0,
  last_error text, last_error_at integer, waiting text,
  public_ok integer, public_detail text, inside_ok integer, inside_detail text, dns_checked_at integer
);
create table if not exists checkins (
  name text primary key, at integer not null, device_time integer not null, source_ip text not null, report text not null
);
create table if not exists unbound (
  pin text not null, names text not null, reason text not null, source_ip text not null,
  first_seen integer not null, last_seen integer not null, count integer not null,
  primary key (pin, names)
);
create table if not exists events (
  id integer primary key autoincrement, at integer not null, name text, level text not null, message text not null
);
`;

const MAX_EVENTS = 1000;
const MAX_UNBOUND = 200;

export class Store {
  readonly db: Database;

  constructor(file: string) {
    this.db = new Database(file, { create: true, strict: true });
    this.db.exec('pragma journal_mode = wal; pragma busy_timeout = 5000;');
    this.db.exec(SCHEMA);
  }

  close() {
    this.db.close();
  }

  cert(name: string): CertRow | null {
    return this.db.query<CertRow, [string]>('select * from certificates where name = ?').get(name);
  }

  allCerts(): CertRow[] {
    return this.db.query<CertRow, []>('select * from certificates order by name').all();
  }

  /** Create the row if missing, then set the given columns. */
  updateCert(name: string, fields: Partial<Omit<CertRow, 'name'>>) {
    this.db.query('insert into certificates (name) values (?) on conflict(name) do nothing').run(name);
    const keys = Object.keys(fields) as (keyof typeof fields)[];
    if (keys.length === 0) return;
    const sql = `update certificates set ${keys.map(k => `${k} = $${k}`).join(', ')} where name = $name`;
    const params: Record<string, string | number | null> = { name };
    for (const k of keys) params[k] = (fields[k] ?? null) as string | number | null;
    this.db.query(sql).run(params);
  }

  checkin(name: string): CheckinRow | null {
    return this.db.query<CheckinRow, [string]>('select * from checkins where name = ?').get(name);
  }

  allCheckins(): CheckinRow[] {
    return this.db.query<CheckinRow, []>('select * from checkins').all();
  }

  putCheckin(row: CheckinRow) {
    this.db
      .query(
        `insert into checkins (name, at, device_time, source_ip, report) values ($name, $at, $device_time, $source_ip, $report)
         on conflict(name) do update set at = excluded.at, device_time = excluded.device_time,
           source_ip = excluded.source_ip, report = excluded.report`,
      )
      .run(row);
  }

  noteUnbound(pin: string, names: string[], reason: string, sourceIp: string, now: number) {
    this.db
      .query(
        `insert into unbound (pin, names, reason, source_ip, first_seen, last_seen, count)
         values ($pin, $names, $reason, $source_ip, $now, $now, 1)
         on conflict(pin, names) do update set reason = excluded.reason, source_ip = excluded.source_ip,
           last_seen = excluded.last_seen, count = count + 1`,
      )
      .run({ pin, names: names.join(' '), reason, source_ip: sourceIp, now });
    // Anyone who can reach the CSR endpoint can add a row, so keep only the
    // most recent ones.
    this.db
      .query('delete from unbound where rowid not in (select rowid from unbound order by last_seen desc limit ?)')
      .run(MAX_UNBOUND);
  }

  /** Once a key is bound, its earlier unbound requests are history, not news. */
  clearUnbound(pin: string) {
    this.db.query('delete from unbound where pin = ?').run(pin);
  }

  allUnbound(): UnboundRow[] {
    return this.db.query<UnboundRow, []>('select * from unbound order by last_seen desc').all();
  }

  event(name: string | null, level: 'info' | 'error', message: string, now: number) {
    this.db.query('insert into events (at, name, level, message) values (?, ?, ?, ?)').run(now, name, level, message);
    this.db.query('delete from events where id <= (select max(id) from events) - ?').run(MAX_EVENTS);
  }

  recentEvents(limit = 100): EventRow[] {
    return this.db.query<EventRow, [number]>('select * from events order by id desc limit ?').all(limit);
  }
}
