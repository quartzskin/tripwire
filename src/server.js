import { createServer } from 'node:http';
import { readFileSync } from 'node:fs';
import { basename, dirname } from 'node:path';
import { listAlerts } from './db.js';
import { decoyStates } from './ops.js';
import { checkAll } from './monitor.js';

const page = readFileSync(new URL('./ui.html', import.meta.url));
const CSP = "default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; connect-src 'self'; base-uri 'none'; form-action 'none'";

// Only file and folder names leave the process; full paths stay in the CLI.
export function snapshot(db, info) {
  return {
    info,
    decoys: decoyStates(db).map((d) => ({
      id: d.id, name: basename(d.path), dir: basename(dirname(d.path)), kind: d.kind,
      state: d.state, alerts: d.alerts, last_alert: d.last_alert,
    })),
    alerts: listAlerts(db, 100).map((a) => ({
      id: a.id, decoy_id: a.decoy_id, name: basename(a.path), ts: a.ts, source: a.source, detail: a.detail, process: a.process,
    })),
  };
}

export function startServer(db, ctx, { port = 7733, info = {} } = {}) {
  let hostOk;
  const server = createServer((req, res) => {
    const send = (code, body, type = 'text/plain; charset=utf-8') => {
      res.writeHead(code, { 'content-type': type, 'cache-control': 'no-store', 'content-security-policy': CSP, 'x-content-type-options': 'nosniff' });
      res.end(body);
    };
    if (!hostOk.test(req.headers.host ?? '')) return send(403, 'bad host');
    const origin = req.headers.origin;
    if (req.method !== 'GET' && origin !== 'http://' + req.headers.host) return send(403, 'bad origin');
    const url = new URL(req.url, 'http://x');
    try {
      if (req.method === 'GET' && url.pathname === '/') return send(200, page, 'text/html; charset=utf-8');
      if (req.method === 'GET' && url.pathname === '/api/state') return send(200, JSON.stringify(snapshot(db, info)), 'application/json');
      if (req.method === 'POST' && url.pathname === '/api/check') {
        checkAll(db, ctx);
        return send(200, JSON.stringify(snapshot(db, info)), 'application/json');
      }
    } catch (e) {
      return send(500, 'error: ' + e.message);
    }
    send(404, 'not found');
  });
  return new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(port, '127.0.0.1', () => {
      const p = server.address().port;
      hostOk = new RegExp('^(127\\.0\\.0\\.1|localhost):' + p + '$');
      resolve({ server, port: p, url: 'http://127.0.0.1:' + p + '/', close: () => new Promise((r) => { server.closeAllConnections(); server.close(r); }) });
    });
  });
}
