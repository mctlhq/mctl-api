import { DatabaseSync } from 'node:sqlite';
import { chmodSync, mkdirSync } from 'node:fs';
import { dirname } from 'node:path';

// One process owns this pilot database. No network I/O occurs inside a transaction.
// Claims commit before verification/execution/settlement. Unknown operations are
// never automatically replayed, including after an unclean restart.
export class Store {
  constructor(path) {
    if (path !== ':memory:') mkdirSync(dirname(path), { recursive: true, mode: 0o700 });
    this.db = new DatabaseSync(path);
    if (path !== ':memory:') chmodSync(path, 0o600);
    this.db.exec(`PRAGMA journal_mode=DELETE; PRAGMA synchronous=FULL;
      CREATE TABLE IF NOT EXISTS calls (
        id TEXT PRIMARY KEY, binding TEXT NOT NULL, data TEXT NOT NULL,
        phase TEXT NOT NULL, proof_hash TEXT, report TEXT, receipt TEXT,
        updated INTEGER NOT NULL
      );
      CREATE UNIQUE INDEX IF NOT EXISTS proof_once ON calls(proof_hash)
        WHERE proof_hash IS NOT NULL;
      CREATE TABLE IF NOT EXISTS audit (
        seq INTEGER PRIMARY KEY, id TEXT NOT NULL, phase TEXT NOT NULL, at INTEGER NOT NULL
      );`);
  }
  get(id) {
    const row = this.db.prepare('SELECT * FROM calls WHERE id=?').get(id);
    if (!row) return null;
    return { ...row, data: JSON.parse(row.data), report: row.report && JSON.parse(row.report),
      receipt: row.receipt && JSON.parse(row.receipt) };
  }
  create(id, binding, data, now) {
    this.db.prepare(`INSERT OR IGNORE INTO calls(id,binding,data,phase,updated)
      VALUES(?,?,?,'challenged',?)`).run(id, binding, JSON.stringify(data), now);
    return this.get(id);
  }
  move(id, from, phase, now, { proofHash = null, report = null, receipt = null } = {}) {
    this.db.exec('BEGIN IMMEDIATE');
    try {
      const r = this.db.prepare(`UPDATE calls SET phase=?,updated=?,
        proof_hash=COALESCE(?,proof_hash),report=COALESCE(?,report),receipt=COALESCE(?,receipt)
        WHERE id=? AND phase=?`).run(phase, now, proofHash,
          report && JSON.stringify(report), receipt && JSON.stringify(receipt), id, from);
      if (r.changes) this.db.prepare('INSERT INTO audit(id,phase,at) VALUES(?,?,?)').run(id, phase, now);
      this.db.exec('COMMIT');
      return Boolean(r.changes);
    } catch (e) { this.db.exec('ROLLBACK'); throw e; }
  }
  recover(now) {
    // Explicitly conservative: a diagnostic may have run, or a transfer may
    // have broadcast. Reconciliation is an operator task, never a new call.
    for (const phase of ['verifying', 'executing', 'settling']) {
      for (const row of this.db.prepare('SELECT id FROM calls WHERE phase=?').all(phase)) {
        this.move(row.id, phase, phase === 'settling' ? 'settlement_unknown' : 'outcome_unknown', now);
      }
    }
  }
  purgeReports(now) {
    // Keep invocation/payment tombstones so expiry never permits re-execution.
    this.db.prepare(`UPDATE calls SET report=NULL WHERE report IS NOT NULL
      AND CAST(json_extract(data,'$.expires') AS INTEGER) < ?`).run(now - 86400);
  }
  close() { this.db.close(); }
}
