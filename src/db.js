import { DatabaseSync } from 'node:sqlite';
import { mkdirSync } from 'node:fs';
import { dirname } from 'node:path';

const SCHEMA = `
CREATE TABLE IF NOT EXISTS decoys (
  id INTEGER PRIMARY KEY,
  path TEXT NOT NULL UNIQUE,
  kind TEXT NOT NULL,
  token TEXT NOT NULL,
  sha256 TEXT NOT NULL,
  size INTEGER NOT NULL,
  mtime_ms REAL NOT NULL,
  atime_ms REAL NOT NULL,
  state TEXT NOT NULL DEFAULT 'ok',
  created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS alerts (
  id INTEGER PRIMARY KEY,
  decoy_id INTEGER,
  path TEXT NOT NULL,
  ts TEXT NOT NULL,
  source TEXT NOT NULL,
  detail TEXT NOT NULL,
  process TEXT
);
CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
`;

export class RegistryError extends Error {}

export function openRegistry(file) {
  mkdirSync(dirname(file), { recursive: true });
  let db;
  try {
    db = new DatabaseSync(file);
    db.exec(SCHEMA);
    db.prepare('SELECT id, path, kind, token, sha256, size, mtime_ms, atime_ms, state, created_at FROM decoys LIMIT 1').all();
    db.prepare('SELECT id, decoy_id, path, ts, source, detail, process FROM alerts LIMIT 1').all();
  } catch (e) {
    try { db?.close(); } catch {}
    throw new RegistryError('registry ' + file + ' is not a usable tripwire registry (' + e.message + ')');
  }
  return db;
}

export const listDecoys = (db) => db.prepare('SELECT * FROM decoys ORDER BY id').all();
export const getDecoyByPath = (db, p) => db.prepare('SELECT * FROM decoys WHERE path = ?').get(p);

export function addDecoy(db, d) {
  const r = db.prepare('INSERT INTO decoys (path, kind, token, sha256, size, mtime_ms, atime_ms, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)')
    .run(d.path, d.kind, d.token, d.sha256, d.size, d.mtime_ms, d.atime_ms, new Date().toISOString());
  return Number(r.lastInsertRowid);
}

export const updateBaseline = (db, id, mtime, atime, state) =>
  db.prepare('UPDATE decoys SET mtime_ms = ?, atime_ms = ?, state = ? WHERE id = ?').run(mtime, atime, state, id);

export const deleteDecoy = (db, id) => db.prepare('DELETE FROM decoys WHERE id = ?').run(id);

export function addAlert(db, a) {
  const r = db.prepare('INSERT INTO alerts (decoy_id, path, ts, source, detail, process) VALUES (?, ?, ?, ?, ?, ?)')
    .run(a.decoy_id, a.path, a.ts, a.source, a.detail, a.process ?? null);
  return Number(r.lastInsertRowid);
}

export const listAlerts = (db, limit = 100) =>
  db.prepare('SELECT * FROM alerts ORDER BY id DESC LIMIT ?').all(limit);

export const getMeta = (db, key) => db.prepare('SELECT value FROM meta WHERE key = ?').get(key)?.value;
export const setMeta = (db, key, value) =>
  db.prepare('INSERT INTO meta (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value').run(key, value);
