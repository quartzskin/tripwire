import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync, writeFileSync, readFileSync, existsSync, utimesSync, statSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import http from 'node:http';
import { unzip } from '../src/zip.js';
import { openRegistry, RegistryError, listAlerts, listDecoys, updateBaseline } from '../src/db.js';
import { plant, removeDecoys, decoyStates } from '../src/ops.js';
import { checkAll, checkAudit } from '../src/monitor.js';
import { parseEvents, auditCommands } from '../src/audit.js';
import { formatGuess } from '../src/proc.js';
import { startServer } from '../src/server.js';
import { sendWebhook } from '../src/alert.js';
import { main } from '../src/cli.js';

function setup() {
  const root = mkdtempSync(join(tmpdir(), 'tripwire-'));
  const db = openRegistry(join(root, 'home', 'registry.db'));
  const warnings = [];
  const seen = [];
  const ctx = { logFile: join(root, 'home', 'alerts.log'), warn: (m) => warnings.push(m), onAlert: (a) => seen.push(a) };
  return { root, db, ctx, warnings, seen, dir: join(root, 'docs'), done: () => { db.close(); rmSync(root, { recursive: true, force: true }); } };
}

// utimes truncates sub-ms precision, so pin known times and re-baseline before simulating access.
function pin(db, file) {
  utimesSync(file, 1700000000, 1700000000);
  const st = statSync(file);
  updateBaseline(db, listDecoys(db).find((d) => d.path === file).id, st.mtimeMs, st.atimeMs, 'ok');
}

test('plant writes every kind, with tokens inside the files', () => {
  const t = setup();
  try {
    const res = plant(t.db, t.dir);
    assert.equal(res.length, 7);
    for (const d of listDecoys(t.db)) {
      let buf = readFileSync(d.path);
      if (d.kind === 'ssh') buf = Buffer.from(buf.toString('latin1').replace(/-----[^\n]*|\n/g, ''), 'base64');
      assert.ok(buf.includes(d.token), d.kind + ' should contain its token');
      assert.equal(readFileSync(d.path).length, d.size);
    }
    assert.ok(readFileSync(join(t.dir, 'id_rsa'), 'utf8').startsWith('-----BEGIN OPENSSH PRIVATE KEY-----'));
    assert.match(readFileSync(join(t.dir, '.env'), 'utf8'), /AKIA[A-Z2-7]{16}/);
  } finally { t.done(); }
});

test('generated zip, docx and xlsx are readable archives', () => {
  const t = setup();
  try {
    plant(t.db, t.dir);
    for (const f of ['passwords.xlsx', 'logins.docx', 'backup_keys.zip']) {
      const names = unzip(readFileSync(join(t.dir, f))).map((e) => e.name);
      assert.ok(names.length >= 2, f);
    }
    assert.ok(unzip(readFileSync(join(t.dir, 'passwords.xlsx'))).some((e) => e.name === 'xl/worksheets/sheet1.xml'));
  } finally { t.done(); }
});

test('plant skips existing files and rejects unknown kinds; dry run writes nothing', () => {
  const t = setup();
  try {
    plant(t.db, t.dir, { only: ['env'] });
    writeFileSync(join(t.dir, 'id_rsa'), 'my real key');
    const res = plant(t.db, t.dir, { only: ['env', 'ssh'] });
    assert.deepEqual(res.map((r) => r.status), ['skipped', 'skipped']);
    assert.equal(readFileSync(join(t.dir, 'id_rsa'), 'utf8'), 'my real key');
    assert.throws(() => plant(t.db, t.dir, { only: ['nope'] }), /unknown kind/);
    const dry = plant(t.db, join(t.root, 'other'), { dryRun: true });
    assert.ok(dry.every((r) => r.status === 'would plant'));
    assert.equal(existsSync(join(t.root, 'other')), false);
  } finally { t.done(); }
});

test('untouched decoys raise nothing; modification, access and deletion each alert once', () => {
  const t = setup();
  try {
    plant(t.db, t.dir, { only: ['env', 'txt', 'wallet'] });
    assert.deepEqual(checkAll(t.db, t.ctx), []);

    const env = join(t.dir, '.env');
    pin(t.db, env);
    utimesSync(env, 1700000500, 1700000000);
    const a1 = checkAll(t.db, t.ctx);
    assert.equal(a1.length, 1);
    assert.equal(a1[0].source, 'accessed');
    assert.deepEqual(checkAll(t.db, t.ctx), []);

    const txt = join(t.dir, 'passwords.txt');
    utimesSync(txt, new Date(), new Date(Date.now() + 120000));
    assert.equal(checkAll(t.db, t.ctx)[0].source, 'modified');

    rmSync(join(t.dir, 'wallet.dat'));
    assert.equal(checkAll(t.db, t.ctx)[0].source, 'missing');
    assert.deepEqual(checkAll(t.db, t.ctx), []);

    assert.equal(listAlerts(t.db).length, 3);
    assert.equal(t.seen.length, 3);
    const log = readFileSync(t.ctx.logFile, 'utf8').trim().split('\n').map((l) => JSON.parse(l));
    assert.equal(log.length, 3);
    assert.ok(decoyStates(t.db).some((d) => d.state === 'missing'));
  } finally { t.done(); }
});

test('process guess is only looked up when asked for', () => {
  const t = setup();
  try {
    plant(t.db, t.dir, { only: ['env'] });
    let calls = 0;
    const ctx = { ...t.ctx, guess: () => { calls++; return 'guess - foreground: notepad (1)'; } };
    const env = join(t.dir, '.env');
    utimesSync(env, new Date(), new Date(Date.now() + 5000));
    assert.equal(checkAll(t.db, ctx)[0].process, null);
    assert.equal(calls, 0);
    utimesSync(env, new Date(), new Date(Date.now() + 9000));
    assert.match(checkAll(t.db, { ...ctx, who: true })[0].process, /notepad/);
    assert.equal(formatGuess({ fg: null, recent: [] }), null);
  } finally { t.done(); }
});

test('4663 events: parsing, decoy filtering and de-duplication', () => {
  const t = setup();
  try {
    plant(t.db, t.dir, { only: ['env'] });
    const env = join(t.dir, '.env');
    const xml = (time, path) => "<Event xmlns='x'><System><TimeCreated SystemTime='" + time + "'/></System><EventData>" +
      "<Data Name='SubjectUserName'>me</Data><Data Name='ObjectName'>" + path.replace(/&/g, '&amp;') + "</Data>" +
      "<Data Name='ProcessName'>C:\\Windows\\notepad.exe</Data><Data Name='AccessMask'>0x1</Data></EventData></Event>";
    const events = parseEvents(xml('2999-01-01T00:00:01.0000000Z', env) + xml('2999-01-01T00:00:02.0000000Z', 'C:\\other\\file.txt') + '<Event><broken');
    assert.equal(events.length, 2);
    const found = checkAudit(t.db, t.ctx, events);
    assert.equal(found.length, 1);
    assert.match(found[0].process, /notepad\.exe, user me/);
    assert.equal(checkAudit(t.db, t.ctx, events).length, 0);
    assert.deepEqual(parseEvents('garbage'), []);
  } finally { t.done(); }
});

test('audit-help only prints commands', () => {
  const text = auditCommands(["C:\\x\\it's.env"]);
  assert.match(text, /auditpol/);
  assert.match(text, /it''s\.env/);
});

test('remove deletes untouched decoys and refuses a file replaced by someone else', () => {
  const t = setup();
  try {
    plant(t.db, t.dir, { only: ['env', 'txt', 'ssh'] });
    writeFileSync(join(t.dir, 'passwords.txt'), 'my actual passwords');
    rmSync(join(t.dir, 'id_rsa'));

    const dry = removeDecoys(t.db, { dir: t.dir, dryRun: true });
    assert.deepEqual(dry.map((r) => r.status), ['would be deleted', 'would be refused', 'would be gone']);
    assert.ok(existsSync(join(t.dir, '.env')));

    const res = removeDecoys(t.db, { dir: t.dir });
    assert.deepEqual(res.map((r) => r.status), ['deleted', 'refused', 'gone']);
    assert.equal(existsSync(join(t.dir, '.env')), false);
    assert.equal(readFileSync(join(t.dir, 'passwords.txt'), 'utf8'), 'my actual passwords');
    assert.equal(listDecoys(t.db).length, 1);

    assert.equal(removeDecoys(t.db, { dir: t.dir, forget: true })[0].status, 'forgotten');
    assert.equal(readFileSync(join(t.dir, 'passwords.txt'), 'utf8'), 'my actual passwords');
    assert.equal(listDecoys(t.db).length, 0);
  } finally { t.done(); }
});

test('remove ignores registry entries outside the given directory', () => {
  const t = setup();
  try {
    plant(t.db, t.dir, { only: ['env'] });
    plant(t.db, join(t.root, 'b'), { only: ['env'] });
    removeDecoys(t.db, { dir: join(t.root, 'b') });
    assert.ok(existsSync(join(t.dir, '.env')));
    assert.equal(listDecoys(t.db).length, 1);
  } finally { t.done(); }
});

test('remove matches the directory case-insensitively on Windows', { skip: process.platform !== 'win32' }, () => {
  const t = setup();
  try {
    plant(t.db, t.dir, { only: ['env'] });
    const res = removeDecoys(t.db, { dir: t.dir.toUpperCase() });
    assert.deepEqual(res.map((r) => r.status), ['deleted']);
    assert.equal(existsSync(join(t.dir, '.env')), false);
  } finally { t.done(); }
});

test('malformed registries are reported, not crashed on', () => {
  const root = mkdtempSync(join(tmpdir(), 'tripwire-'));
  try {
    const bad = join(root, 'bad.db');
    writeFileSync(bad, 'this is not a sqlite file, just some text padding '.repeat(40));
    assert.throws(() => openRegistry(bad), RegistryError);

    const other = join(root, 'other.db');
    const db = openRegistry(other);
    db.exec('DROP TABLE decoys; CREATE TABLE decoys (id INTEGER, wrong TEXT)');
    db.close();
    assert.throws(() => openRegistry(other), /not a usable tripwire registry/);
  } finally { rmSync(root, { recursive: true, force: true }); }
});

test('cli: bad input gives messages and exit codes', async () => {
  const root = mkdtempSync(join(tmpdir(), 'tripwire-'));
  try {
    const lines = [];
    const out = (s) => lines.push(s);
    const base = ['--home', join(root, 'h')];
    assert.equal(await main(['bogus', ...base], out), 1);
    assert.equal(await main(['plant', ...base], out), 1);
    assert.equal(await main(['plant', join(root, 'd'), '--only', 'zzz', ...base], out), 1);
    assert.equal(await main(['watch', '--interval', 'x', ...base], out), 1);
    assert.equal(await main(['watch', '--webhook', 'ftp://x', ...base], out), 1);
    assert.equal(await main(['status', '--home'], out), 1);
    assert.equal(await main(['plant', join(root, 'd'), '--only', 'env,txt', ...base], out), 0);
    assert.equal(await main(['check', ...base], out), 0);
    const f = join(root, 'd', '.env');
    utimesSync(f, new Date(), new Date(Date.now() + 5000));
    assert.equal(await main(['check', ...base], out), 2);
    writeFileSync(join(root, 'd', 'passwords.txt'), 'foreign');
    assert.equal(await main(['remove', join(root, 'd'), ...base], out), 3);
    assert.equal(existsSync(f), false);
    writeFileSync(join(root, 'h', 'registry.db'), 'junk'.repeat(100));
    assert.equal(await main(['status', ...base], out), 4);
    assert.ok(lines.some((l) => /not a usable tripwire registry/.test(l)));
  } finally { rmSync(root, { recursive: true, force: true }); }
});

function get(port, path, { host, method = 'GET', origin } = {}) {
  return new Promise((resolve, reject) => {
    const headers = { host: host ?? '127.0.0.1:' + port };
    if (origin) headers.origin = origin;
    const r = http.request({ port, host: '127.0.0.1', path, method, headers }, (res) => {
      let body = '';
      res.on('data', (d) => (body += d));
      res.on('end', () => resolve({ status: res.statusCode, body }));
    });
    r.on('error', reject);
    r.end();
  });
}

test('ui server: state is served, foreign Host and Origin are refused, paths are not leaked', async () => {
  const t = setup();
  const srv = await startServer(t.db, t.ctx, { port: 0 });
  try {
    plant(t.db, t.dir, { only: ['env'] });
    utimesSync(join(t.dir, '.env'), new Date(), new Date(Date.now() + 5000));
    checkAll(t.db, t.ctx);

    const page = await get(srv.port, '/');
    assert.equal(page.status, 200);
    assert.match(page.body, /<svg id="web"/);

    const st = await get(srv.port, '/api/state');
    const j = JSON.parse(st.body);
    assert.equal(j.decoys[0].name, '.env');
    assert.equal(j.alerts[0].source, 'modified');
    assert.ok(!st.body.includes(t.root.replace(/\\/g, '\\\\')));

    assert.equal((await get(srv.port, '/api/state', { host: 'evil.example:' + srv.port })).status, 403);
    assert.equal((await get(srv.port, '/api/state', { host: '127.0.0.1:1' })).status, 403);
    assert.equal((await get(srv.port, '/api/check', { method: 'POST' })).status, 403);
    assert.equal((await get(srv.port, '/api/check', { method: 'POST', origin: 'http://evil.example' })).status, 403);
    assert.equal((await get(srv.port, '/api/check', { method: 'POST', origin: 'http://127.0.0.1:' + srv.port })).status, 200);
    assert.equal((await get(srv.port, '/nope')).status, 404);
  } finally { await srv.close(); t.done(); }
});

test('webhook posts the alert and reports failures through warn', async () => {
  let got;
  const hook = http.createServer((req, res) => {
    let b = '';
    req.on('data', (d) => (b += d));
    req.on('end', () => { got = JSON.parse(b); res.writeHead(200).end(); });
  });
  await new Promise((r) => hook.listen(0, '127.0.0.1', r));
  const warns = [];
  try {
    await sendWebhook('http://127.0.0.1:' + hook.address().port + '/', { source: 'accessed', path: 'x', process: null }, (m) => warns.push(m));
    assert.equal(got.alert.source, 'accessed');
    assert.match(got.text, /accessed on x/);
  } finally { hook.close(); }
  await sendWebhook('http://127.0.0.1:1/', { source: 'a', path: 'p' }, (m) => warns.push(m));
  assert.equal(warns.length, 1);
});
