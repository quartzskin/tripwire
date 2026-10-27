import { statSync, watch } from 'node:fs';
import { basename, dirname, join } from 'node:path';
import { recordAlert } from './alert.js';
import { getMeta, listDecoys, setMeta, updateBaseline } from './db.js';
import { readEvents } from './audit.js';
import { guessProcess } from './proc.js';

const recentAlert = (db, id) => {
  const last = db.prepare('SELECT ts FROM alerts WHERE decoy_id = ? ORDER BY id DESC LIMIT 1').get(id)?.ts;
  return last && Date.now() - Date.parse(last) < 3000;
};
const norm = (p) => p.toLowerCase();

function lookupProcess(ctx, cache) {
  if (!ctx.who) return null;
  if (cache.value === undefined) cache.value = (ctx.guess ?? guessProcess)();
  return cache.value;
}

// One pass over the registry; compares stat() against the stored baseline and re-baselines on a hit.
export function checkAll(db, ctx) {
  const found = [];
  const cache = {};
  for (const d of listDecoys(db)) {
    let st = null;
    try { st = statSync(d.path); } catch {}
    if (!st) {
      if (d.state !== 'missing') {
        updateBaseline(db, d.id, d.mtime_ms, d.atime_ms, 'missing');
        found.push(recordAlert(db, ctx, d, 'missing', 'file is gone or unreadable', lookupProcess(ctx, cache)));
      }
    } else if (st.mtimeMs !== d.mtime_ms) {
      updateBaseline(db, d.id, st.mtimeMs, st.atimeMs, 'ok');
      found.push(recordAlert(db, ctx, d, 'modified', 'mtime changed (' + new Date(d.mtime_ms).toISOString() + ' -> ' + new Date(st.mtimeMs).toISOString() + ')', lookupProcess(ctx, cache)));
    } else if (st.atimeMs !== d.atime_ms) {
      updateBaseline(db, d.id, st.mtimeMs, st.atimeMs, 'ok');
      found.push(recordAlert(db, ctx, d, 'accessed', 'atime changed (' + new Date(d.atime_ms).toISOString() + ' -> ' + new Date(st.atimeMs).toISOString() + ')', lookupProcess(ctx, cache)));
    } else if (d.state === 'missing') {
      updateBaseline(db, d.id, st.mtimeMs, st.atimeMs, 'ok');
    }
  }
  return found;
}

// Turns 4663 events into alerts for decoy paths only; remembers the newest event time.
export function checkAudit(db, ctx, events = null) {
  const since = getMeta(db, 'audit_since') ?? new Date().toISOString();
  const evs = events ?? readEvents(since);
  const byPath = new Map(listDecoys(db).map((d) => [norm(d.path), d]));
  const found = [];
  let newest = since;
  for (const e of evs) {
    if (e.time <= since) continue;
    if (e.time > newest) newest = e.time;
    const d = byPath.get(norm(e.path));
    if (!d) continue;
    found.push(recordAlert(db, ctx, d, 'audit-4663', 'access mask ' + e.mask + ' at ' + e.time, [e.process, e.user && 'user ' + e.user].filter(Boolean).join(', ') || null));
  }
  setMeta(db, 'audit_since', newest);
  return found;
}

export function createMonitor(db, ctx, { interval = 5, fsWatch = true, audit = false } = {}) {
  let warnedAudit = false;
  const tick = () => {
    const found = checkAll(db, ctx);
    if (audit) {
      try { found.push(...checkAudit(db, ctx)); } catch (e) {
        if (!warnedAudit) ctx.warn?.('audit: ' + e.message);
        warnedAudit = true;
      }
    }
    return found;
  };
  const timer = setInterval(tick, interval * 1000);
  const watchers = [];
  const pending = new Map();

  if (fsWatch) {
    const dirs = new Set(listDecoys(db).map((d) => dirname(d.path)));
    for (const dir of dirs) {
      try {
        const w = watch(dir, (evt, name) => {
          if (!name) return;
          const full = join(dir, basename(String(name)));
          clearTimeout(pending.get(full));
          pending.set(full, setTimeout(() => {
            pending.delete(full);
            const d = listDecoys(db).find((x) => norm(x.path) === norm(full));
            if (!d) return;
            if (checkAll(db, ctx).length === 0 && !recentAlert(db, d.id)) recordAlert(db, ctx, d, 'fs-event', 'directory watcher reported ' + evt, null);
          }, 400));
        });
        w.on('error', () => {});
        watchers.push(w);
      } catch (e) {
        ctx.warn?.('cannot watch ' + dir + ': ' + e.message);
      }
    }
  }
  return {
    tick,
    stop() {
      clearInterval(timer);
      for (const t of pending.values()) clearTimeout(t);
      for (const w of watchers) w.close();
    },
  };
}
