import { randomBytes, randomInt } from 'node:crypto';
import { zip } from './zip.js';

const B32 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
const PWCHARS = 'abcdefghijkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789!#%*';
const SITES = ['mail.example.com', 'bank.example.net', 'vpn.example.org', 'shop.example.com',
  'nas.example.lan', 'git.example.com', 'cloud.example.net', 'payroll.example.org'];
const USERS = ['admin', 'jsmith', 'm.keller', 'backup', 'finance', 'root'];

const pick = (list) => list[randomInt(list.length)];
const chars = (n, set) => Array.from({ length: n }, () => set[randomInt(set.length)]).join('');
const esc = (s) => s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');

export const newToken = () => chars(12, B32);

function rows(token) {
  const out = SITES.map((site) => [site, pick(USERS), chars(12, PWCHARS)]);
  const i = randomInt(out.length);
  out[i][2] = token + chars(3, PWCHARS);
  return out;
}

function xlsx(token) {
  const data = [['Site', 'Username', 'Password'], ...rows(token)];
  const col = 'ABC';
  const sheet = data.map((r, y) => '<row r="' + (y + 1) + '">' + r.map((v, x) =>
    '<c r="' + col[x] + (y + 1) + '" t="inlineStr"><is><t>' + esc(v) + '</t></is></c>').join('') + '</row>').join('');
  const xml = '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n';
  return zip([
    { name: '[Content_Types].xml', data: xml + '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/><Default Extension="xml" ContentType="application/xml"/><Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/><Override PartName="/xl/worksheets/sheet1.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/></Types>' },
    { name: '_rels/.rels', data: xml + '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="xl/workbook.xml"/></Relationships>' },
    { name: 'xl/workbook.xml', data: xml + '<workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"><sheets><sheet name="Logins" sheetId="1" r:id="rId1"/></sheets></workbook>' },
    { name: 'xl/_rels/workbook.xml.rels', data: xml + '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" Target="worksheets/sheet1.xml"/></Relationships>' },
    { name: 'xl/worksheets/sheet1.xml', data: xml + '<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"><sheetData>' + sheet + '</sheetData></worksheet>' },
  ]);
}

function docx(token) {
  const lines = ['Server and VPN logins (internal, do not share)', ...rows(token).map((r) => r[0] + '  ' + r[1] + '  ' + r[2])];
  const body = lines.map((l) => '<w:p><w:r><w:t xml:space="preserve">' + esc(l) + '</w:t></w:r></w:p>').join('');
  const xml = '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n';
  return zip([
    { name: '[Content_Types].xml', data: xml + '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/><Default Extension="xml" ContentType="application/xml"/><Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/></Types>' },
    { name: '_rels/.rels', data: xml + '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/></Relationships>' },
    { name: 'word/document.xml', data: xml + '<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"><w:body>' + body + '</w:body></w:document>' },
  ]);
}

function txt(token) {
  return rows(token).map((r) => r.join('\t')).join('\r\n') + '\r\n';
}

function zipped(token) {
  const sql = '-- dump\nINSERT INTO users VALUES (1, \'admin\', \'' + token + chars(4, PWCHARS) + '\');\n';
  return zip([
    { name: 'keys/README.txt', data: 'old key backup, keep offline\r\n' },
    { name: 'keys/db_dump.sql', data: sql },
  ]);
}

function env(token) {
  const akid = 'AKIA' + token + chars(4, B32);
  return [
    'NODE_ENV=production',
    'DATABASE_URL=postgres://app:' + chars(16, PWCHARS.replace(/[!#%*]/g, '')) + '@db.example.lan:5432/app',
    'AWS_ACCESS_KEY_ID=' + akid,
    'AWS_SECRET_ACCESS_KEY=' + randomBytes(30).toString('base64'),
    'STRIPE_SECRET_KEY=sk_live_' + chars(24, B32.toLowerCase() + '0123456789'),
    '',
  ].join('\n');
}

function ssh(token) {
  const payload = Buffer.concat([
    Buffer.from('openssh-key-v1\0FAKE DECOY KEY - NOT A REAL KEY ' + token + ' '),
    randomBytes(1200),
  ]).toString('base64').match(/.{1,70}/g).join('\n');
  return '-----BEGIN OPENSSH PRIVATE KEY-----\n' + payload + '\n-----END OPENSSH PRIVATE KEY-----\n';
}

function wallet(token) {
  const buf = randomBytes(32768);
  buf.fill(0, 0, 12);
  buf.writeUInt32LE(0x00053162, 12);
  buf.writeUInt32LE(9, 16);
  buf.writeUInt32LE(4096, 20);
  buf.write('\x04mkey', 2048, 'latin1');
  buf.write(token, 2060, 'latin1');
  return buf;
}

export const KINDS = {
  xlsx: { file: 'passwords.xlsx', make: xlsx },
  txt: { file: 'passwords.txt', make: txt },
  docx: { file: 'logins.docx', make: docx },
  zip: { file: 'backup_keys.zip', make: zipped },
  env: { file: '.env', make: env },
  ssh: { file: 'id_rsa', make: ssh },
  wallet: { file: 'wallet.dat', make: wallet },
};

export function build(kind, token) {
  const k = KINDS[kind];
  if (!k) throw new Error('unknown decoy kind: ' + kind);
  const data = k.make(token);
  return { name: k.file, data: Buffer.isBuffer(data) ? data : Buffer.from(data, 'utf8') };
}
