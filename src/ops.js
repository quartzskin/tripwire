import { createHash } from 'node:crypto';
import { existsSync, mkdirSync, readFileSync, statSync, unlinkSync, writeFileSync } from 'node:fs';
import { join, resolve, sep } from 'node:path';
import { KINDS, build, newToken } from './decoys.js';
import { addDecoy, deleteDecoy, getDecoyByPath, listDecoys } from './db.js';

const sha = (buf) => createHash('sha256').update(buf).digest('hex');

export function plant(db, dir, { only, dryRun = false } = {}) {
  const kinds = only?.length ? only : Object.keys(KINDS);
  for (const k of kinds) if (!KINDS[k]) throw new Error('unknown kind "' + k + '" (have: ' + Object.keys(KINDS).join(', ') + ')');
  const root = resolve(dir);
  if (!dryRun) mkdirSync(root, { recursive: true });
  return kinds.map((kind) => {
    const path = join(root, KINDS[kind].file);
    if (existsSync(path) || getDecoyByPath(db, path)) return { kind, path, status: 'skipped', reason: 'already exists' };
    if (dryRun) return { kind, path, status: 'would plant' };
    const token = newToken();
    const { data } = build(kind, token);
    writeFileSync(path, data, { flag: 'wx' });
    const st = statSync(path);
    addDecoy(db, { path, kind, token, sha256: sha(data), size: data.length, mtime_ms: st.mtimeMs, atime_ms: st.atimeMs });
    return { kind, path, status: 'planted', token };
  });
}

export function removeDecoys(db, { dir, dryRun = false, forget = false } = {}) {
  const fold = (x) => (process.platform === 'win32' ? x.toLowerCase() : x);
  const prefix = dir ? fold(resolve(dir) + sep) : null;
  const results = [];
  for (const d of listDecoys(db)) {
    if (prefix && !fold(d.path).startsWith(prefix)) continue;
    let actual = null;
    try { actual = sha(readFileSync(d.path)); } catch {}
    let status;
    if (actual === null) status = 'gone';
    else if (actual === d.sha256) status = 'deleted';
    else status = 'refused';
    if (status === 'refused' && forget) status = 'forgotten';
    if (!dryRun) {
      if (status === 'deleted') unlinkSync(d.path);
      if (status !== 'refused') deleteDecoy(db, d.id);
    }
    results.push({ path: d.path, status: dryRun ? 'would be ' + status : status });
  }
  return results;
}

export function decoyStates(db) {
  const counts = new Map(db.prepare('SELECT decoy_id, count(*) AS n, max(ts) AS last FROM alerts GROUP BY decoy_id').all().map((r) => [r.decoy_id, r]));
  return listDecoys(db).map((d) => ({
    ...d,
    state: existsSync(d.path) ? 'ok' : 'missing',
    alerts: counts.get(d.id)?.n ?? 0,
    last_alert: counts.get(d.id)?.last ?? null,
  }));
}
