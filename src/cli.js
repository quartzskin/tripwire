import { join, resolve } from 'node:path';
import { spawn } from 'node:child_process';
import { homedir } from 'node:os';
import { openRegistry, RegistryError, listAlerts, listDecoys } from './db.js';
import { KINDS } from './decoys.js';
import { plant, removeDecoys, decoyStates } from './ops.js';
import { checkAll, createMonitor } from './monitor.js';
import { sendWebhook } from './alert.js';
import { auditCommands } from './audit.js';
import { startServer } from './server.js';

const HELP = `tripwire - decoy-file canaries

  tripwire plant <dir> [--only xlsx,env,...] [--dry-run]
  tripwire status [--json]
  tripwire check                     one scan; exit code 2 if anything tripped
  tripwire watch [--interval 5] [--who] [--audit] [--webhook <url>] [--no-fswatch]
  tripwire ui [--port 7733] [--no-open] [--browser <exe>] [watch options]
  tripwire remove [<dir>] [--dry-run] [--forget]
  tripwire audit-help                print the commands that enable 4663 auditing

  --home <dir>   registry and log location (default %LOCALAPPDATA%\\tripwire, or TRIPWIRE_HOME)
  decoy kinds: ${Object.keys(KINDS).join(', ')}
`;

const FLAGS = new Set(['dry-run', 'json', 'no-open', 'who', 'audit', 'no-fswatch', 'forget', 'help']);

function parse(argv) {
  const pos = [];
  const opt = {};
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (!a.startsWith('--')) { pos.push(a); continue; }
    const name = a.slice(2);
    if (FLAGS.has(name)) opt[name] = true;
    else if (i + 1 < argv.length) opt[name] = argv[++i];
    else throw new Error('--' + name + ' needs a value');
  }
  return { pos, opt };
}

function home(opt) {
  return resolve(opt.home || process.env.TRIPWIRE_HOME || join(process.env.LOCALAPPDATA || join(homedir(), '.local', 'share'), 'tripwire'));
}

function num(opt, name, dflt, min) {
  if (opt[name] === undefined) return dflt;
  const n = Number(opt[name]);
  if (!Number.isFinite(n) || n < min) throw new Error('--' + name + ' must be a number >= ' + min);
  return n;
}

function context(opt, out) {
  const dir = home(opt);
  const ctx = { home: dir, logFile: join(dir, 'alerts.log'), who: !!opt.who, warn: (m) => out('warning: ' + m) };
  if (opt.webhook) {
    if (!/^https?:\/\//i.test(opt.webhook)) throw new Error('--webhook must be an http(s) URL');
    ctx.onAlert = (a) => sendWebhook(opt.webhook, a, ctx.warn);
  }
  const base = ctx.onAlert;
  ctx.onAlert = (a) => {
    out('[' + a.ts + '] ' + a.source + ' ' + a.path + (a.process ? ' (' + a.process + ')' : ''));
    base?.(a);
  };
  return { ctx, db: openRegistry(join(dir, 'registry.db')) };
}

function openBrowser(url, exe) {
  const cmd = exe || process.env.BROWSER;
  const [bin, args] = cmd ? [cmd, [url]]
    : process.platform === 'win32' ? ['cmd.exe', ['/c', 'start', '""', url]]
    : [process.platform === 'darwin' ? 'open' : 'xdg-open', [url]];
  const c = spawn(bin, args, { detached: true, stdio: 'ignore', windowsHide: true });
  c.on('error', () => {});
  c.unref();
}

const untilSignal = () => new Promise((r) => { process.once('SIGINT', r); process.once('SIGTERM', r); });

export async function main(argv, out = console.log) {
  let parsed;
  try { parsed = parse(argv); } catch (e) { out('tripwire: ' + e.message); return 1; }
  const { pos, opt } = parsed;
  const cmd = pos.shift();
  if (!cmd || opt.help || cmd === 'help') { out(HELP); return cmd || opt.help ? 0 : 1; }
  let db;
  try {
    const known = ['plant', 'status', 'check', 'watch', 'ui', 'remove', 'audit-help'];
    if (!known.includes(cmd)) { out('tripwire: unknown command "' + cmd + '"\n\n' + HELP); return 1; }
    const c = context(opt, out);
    db = c.db;
    const { ctx } = c;

    if (cmd === 'plant') {
      if (!pos[0]) throw new Error('plant needs a directory');
      const res = plant(db, pos[0], { only: opt.only?.split(',').filter(Boolean), dryRun: opt['dry-run'] });
      for (const r of res) out(r.status.padEnd(11) + ' ' + r.path + (r.reason ? ' (' + r.reason + ')' : ''));
      return 0;
    }
    if (cmd === 'status') {
      const decoys = decoyStates(db);
      const alerts = listAlerts(db, 5);
      if (opt.json) { out(JSON.stringify({ home: ctx.home, decoys, alerts }, null, 2)); return 0; }
      out('registry: ' + join(ctx.home, 'registry.db') + '  (' + decoys.length + ' decoys)');
      for (const d of decoys) out(d.state.padEnd(8) + String(d.alerts).padStart(3) + ' alerts  ' + d.path);
      if (alerts.length) { out('\nlatest alerts:'); for (const a of alerts) out('  ' + a.ts + '  ' + a.source + '  ' + a.path + (a.process ? '  ' + a.process : '')); }
      return 0;
    }
    if (cmd === 'check') {
      return checkAll(db, ctx).length ? 2 : 0;
    }
    if (cmd === 'remove') {
      const res = removeDecoys(db, { dir: pos[0], dryRun: opt['dry-run'], forget: opt.forget });
      for (const r of res) out(r.status.padEnd(18) + ' ' + r.path);
      if (res.some((r) => r.status.endsWith('refused'))) out('refused files changed since planting; they are not ours to delete. Use --forget to drop them from the registry only.');
      if (!res.length) out('nothing to remove');
      return res.some((r) => r.status.endsWith('refused')) ? 3 : 0;
    }
    if (cmd === 'audit-help') {
      out(auditCommands(listDecoys(db).map((d) => d.path)));
      return 0;
    }

    const interval = num(opt, 'interval', 5, 1);
    const mon = createMonitor(db, ctx, { interval, fsWatch: !opt['no-fswatch'], audit: !!opt.audit });
    if (cmd === 'watch') {
      out('watching ' + listDecoys(db).length + ' decoys every ' + interval + 's (ctrl-c to stop)');
      await untilSignal();
      mon.stop();
      return 0;
    }
    const srv = await startServer(db, ctx, { port: num(opt, 'port', 7733, 0), info: { interval, webhook: !!opt.webhook, audit: !!opt.audit } });
    out('ui at ' + srv.url);
    if (!opt['no-open']) openBrowser(srv.url, opt.browser);
    await untilSignal();
    mon.stop();
    await srv.close();
    return 0;
  } catch (e) {
    out('tripwire: ' + e.message);
    return e instanceof RegistryError ? 4 : 1;
  } finally {
    db?.close();
  }
}
