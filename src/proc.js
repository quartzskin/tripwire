import { execFileSync } from 'node:child_process';

const SCRIPT = `
Add-Type -Name W -Namespace T -MemberDefinition '[DllImport("user32.dll")] public static extern IntPtr GetForegroundWindow(); [DllImport("user32.dll")] public static extern uint GetWindowThreadProcessId(IntPtr h, out uint p);'
$p = 0
[void][T.W]::GetWindowThreadProcessId([T.W]::GetForegroundWindow(), [ref]$p)
$fg = Get-Process -Id $p -ErrorAction SilentlyContinue
$cut = (Get-Date).AddMinutes(-2)
$recent = @(Get-Process | Where-Object { try { $_.StartTime -gt $cut -and $_.Id -ne $PID } catch { $false } })
@{ fg = if ($fg) { "$($fg.ProcessName) ($($fg.Id))" } else { $null }; recent = @($recent | ForEach-Object { "$($_.ProcessName) ($($_.Id))" }) } | ConvertTo-Json -Compress
`;

// Windows cannot tell us who opened a file without auditing, so this only names candidates.
export function guessProcess() {
  if (process.platform !== 'win32') return null;
  try {
    const out = execFileSync('powershell.exe', ['-NoProfile', '-NonInteractive', '-Command', SCRIPT],
      { encoding: 'utf8', timeout: 10000, windowsHide: true });
    return formatGuess(JSON.parse(out));
  } catch {
    return null;
  }
}

export function formatGuess(g) {
  const parts = [];
  if (g.fg) parts.push('foreground: ' + g.fg);
  const recent = [g.recent].flat().filter(Boolean);
  if (recent.length) parts.push('started <2min ago: ' + recent.slice(0, 6).join(', '));
  return parts.length ? 'guess - ' + parts.join('; ') : null;
}
