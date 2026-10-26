import { expect, test } from 'bun:test';
import { join } from 'node:path';
import { Store } from '../../src/store';
import { tempDir } from '../helpers';

test('the unbound list keeps only the most recent 200 requests', () => {
  const store = new Store(join(tempDir(), 'issuer.sqlite'));
  for (let i = 0; i < 205; i++) store.noteUnbound(`sha256/${i}`, [`n${i}.example.com`], 'unknown-names', '1.2.3.4', i);
  const rows = store.allUnbound();
  expect(rows).toHaveLength(200);
  expect(rows[0]!.pin).toBe('sha256/204');
  expect(rows.some(r => r.pin === 'sha256/4')).toBe(false);
  // A repeat updates its row instead of adding one.
  store.noteUnbound('sha256/204', ['n204.example.com'], 'unknown-names', '1.2.3.4', 999);
  expect(store.allUnbound()).toHaveLength(200);
  expect(store.allUnbound()[0]!.count).toBe(2);
  store.close();
});

test('updateCert creates the row and sets only the given columns', () => {
  const store = new Store(join(tempDir(), 'issuer.sqlite'));
  store.updateCert('a.example.com', { failures: 2, last_error: 'x' });
  store.updateCert('a.example.com', { last_error: null });
  const row = store.cert('a.example.com')!;
  expect(row.failures).toBe(2);
  expect(row.last_error).toBeNull();
  expect(row.next_attempt_at).toBe(0);
  store.close();
});
