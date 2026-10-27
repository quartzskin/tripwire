import { appendFileSync } from 'node:fs';
import { addAlert } from './db.js';

export function recordAlert(db, ctx, decoy, source, detail, process = null) {
  const a = { decoy_id: decoy.id, path: decoy.path, ts: new Date().toISOString(), source, detail, process };
  a.id = addAlert(db, a);
  try {
    appendFileSync(ctx.logFile, JSON.stringify(a) + '\n');
  } catch (e) {
    ctx.warn?.('could not write ' + ctx.logFile + ': ' + e.message);
  }
  ctx.onAlert?.(a);
  return a;
}

export async function sendWebhook(url, alert, warn = () => {}) {
  const text = 'tripwire: ' + alert.source + ' on ' + alert.path + (alert.process ? ' (' + alert.process + ')' : '');
  try {
    const res = await fetch(url, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ text, content: text, alert }),
      signal: AbortSignal.timeout(5000),
    });
    if (!res.ok) warn('webhook answered ' + res.status);
  } catch (e) {
    warn('webhook failed: ' + e.message);
  }
}
