import { execFileSync } from 'node:child_process';

const unescapeXml = (s) => s.replace(/&lt;/g, '<').replace(/&gt;/g, '>').replace(/&quot;/g, '"').replace(/&apos;/g, "'").replace(/&amp;/g, '&');

// Pulls the fields we use out of wevtutil's XML output; unknown or truncated events are skipped.
export function parseEvents(xml) {
  const out = [];
  for (const chunk of xml.split(/<Event[ >]/).slice(1)) {
    const time = /<TimeCreated SystemTime=['"]([^'"]+)['"]/.exec(chunk)?.[1];
    const data = {};
    for (const m of chunk.matchAll(/<Data Name=['"](\w+)['"]>([^<]*)<\/Data>/g)) data[m[1]] = unescapeXml(m[2]);
    if (!time || !data.ObjectName) continue;
    out.push({ time, path: data.ObjectName, process: data.ProcessName ?? null, user: data.SubjectUserName ?? null, mask: data.AccessMask ?? null });
  }
  return out;
}

export function readEvents(sinceIso) {
  const q = '*[System[(EventID=4663) and TimeCreated[@SystemTime>=\'' + sinceIso + '\']]]';
  try {
    const xml = execFileSync('wevtutil.exe', ['qe', 'Security', '/q:' + q, '/c:500', '/rd:true', '/f:xml'],
      { encoding: 'utf8', timeout: 15000, windowsHide: true, maxBuffer: 32 << 20, stdio: ['ignore', 'pipe', 'pipe'] });
    return parseEvents(xml);
  } catch (e) {
    const msg = String(e.stderr || e.message);
    throw new Error(/denied/i.test(msg) ? 'reading the Security log needs an elevated prompt' : msg.trim());
  }
}

export function auditCommands(paths) {
  const lines = [
    'REM Run in an elevated prompt. tripwire does not run these for you.',
    'auditpol /set /subcategory:"File System" /success:enable',
    '',
    'REM Audit reads on each decoy (PowerShell, elevated):',
  ];
  for (const p of paths) {
    const q = p.replace(/'/g, "''");
    lines.push("$a = Get-Acl -Path '" + q + "' -Audit; $a.AddAuditRule((New-Object System.Security.AccessControl.FileSystemAuditRule('Everyone','ReadData','None','None','Success'))); Set-Acl -Path '" + q + "' -AclObject $a");
  }
  lines.push('', 'REM To undo, remove the audit rule from each file in the Security tab (Advanced > Auditing),', 'REM and set the File System subcategory back with: auditpol /set /subcategory:"File System" /success:disable');
  return lines.join('\n');
}
