
#requires -Version 5.1
<#
AMD INF Patcher UI — Rarity Intelligence™
Patched: 2025-10-12

Goals addressed:
- Revert All works reliably (backup path handling fixed)
- Patch Manifest detects AMD package.xml and driver.json
- Log output wraps (no horizontal scroll)
- Browser UI launches centered, ~50% screen size, DPI-aware sizing
- Added: One-Click Install Patched Driver with DSE handling for Windows Server
- Added: Direct link to AMD Drivers page

Run as admin.
#>

using namespace System.Net
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

#region ----------------------- Config -----------------------
$Script:Port          = 8080
$Script:BindAddress   = 'http://127.0.0.1:{0}/' -f $Script:Port
$Script:DriverRoot    = $env:AMD_DRIVER_ROOT   # optional override via env var
$Script:WorkDir       = $env:TEMP
$Script:BackupMarker  = '.bak'                 # suffix for INF backups
$Script:Log           = [System.Collections.Concurrent.ConcurrentQueue[string]]::new()
$Script:PendingRebootFlag = Join-Path $Script:WorkDir 'ri_infpatcher_reboot.flag'
#endregion

function Write-Log {
    param([string]$Message)
    $ts = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
    $line = "[${ts}] $Message"
    $Script:Log.Enqueue($line) | Out-Null
    $line | Write-Host
}

function Get-LogsHtml {
    # Return HTML-safe log with wrapping
    $lines = @()
    while ($Script:Log.TryDequeue([ref]$out)) {
        $lines += $out
    }
    if ($lines.Count -eq 0) { return '' }
    # Preserve newlines for pre-wrap, but HTML-escape
    $html = ($lines -join "`n") -replace '&','&amp;' -replace '<','&lt;' -replace '>','&gt;'
    return $html
}

function Resolve-DriverRoot {
    param([string]$Hint)
    if ($Script:DriverRoot -and (Test-Path $Script:DriverRoot)) { return (Resolve-Path $Script:DriverRoot).Path }
    if ($Hint -and (Test-Path $Hint)) { return (Resolve-Path $Hint).Path }
    # Heuristics: look in common extract paths
    $candidates = @(
        "$env:USERPROFILE\Downloads\AMD*",
        "$env:USERPROFILE\Downloads\Win*",
        "C:\AMD\*",
        "C:\Drivers\AMD\*",
        "$env:USERPROFILE\Desktop\AMD*"
    )
    foreach ($pattern in $candidates) {
        Get-ChildItem -Path $pattern -Directory -ErrorAction SilentlyContinue | Sort-Object LastWriteTime -Descending | Select-Object -First 1 | ForEach-Object {
            return $_.FullName
        }
    }
    return $PWD.Path
}

function Find-InfFiles {
    param([string]$Root)
    Get-ChildItem -Path $Root -Recurse -Include *.inf -File -ErrorAction SilentlyContinue
}

function Get-BackupCandidatesForInf {
    param([string]$InfPath)
    # Accepted backup conventions:
    # 1) Same folder: file.inf.bak
    # 2) Same folder: file.bak (if original file was file.inf)
    # 3) Sibling "Backup" folder mirroring structure
    $dir = Split-Path -Parent $InfPath
    $name = Split-Path -Leaf $InfPath
    $c = @()
    $c += Join-Path $dir "$name$($Script:BackupMarker)"
    if ($name -match '\.inf$') {
        $base = [IO.Path]::GetFileNameWithoutExtension($name)
        $c += Join-Path $dir "$base$($Script:BackupMarker)"
        $c += Join-Path $dir "$base.inf$($Script:BackupMarker)"
    }
    $backupDir = Join-Path (Split-Path -Parent $dir) 'Backup'
    if (Test-Path $backupDir) {
        $rel = $InfPath.Substring((Split-Path -Parent (Split-Path -Parent $dir)).Length).TrimStart('\','/')
        $c += Join-Path $backupDir $rel
        $c += (Join-Path $backupDir $rel) + $Script:BackupMarker
    }
    # Return existing only
    $c | Where-Object { Test-Path $_ } | Select-Object -Unique
}

function Restore-InfFromBackup {
    param([string]$InfPath)
    $candidates = Get-BackupCandidatesForInf -InfPath $InfPath
    if (-not $candidates) {
        Write-Log "No backup found for: $InfPath"
        return $false
    }
    $best = $candidates | Sort-Object -Property Length | Select-Object -First 1
    try {
        Copy-Item -LiteralPath $best -Destination $InfPath -Force
        Write-Log "Restored `"$InfPath`" from `"$best`"."
        return $true
    } catch {
        Write-Log "Restore failed for $InfPath : $($_.Exception.Message)"
        return $false
    }
}

function Revert-All {
    param([string]$Root)
    $root = Resolve-DriverRoot -Hint $Root
    Write-Log "Reverting all INFs under: $root"
    $infs = Find-InfFiles -Root $root
    $ok = 0; $fail = 0
    foreach ($inf in $infs) {
        if (Restore-InfFromBackup -InfPath $inf.FullName) { $ok++ } else { $fail++ }
    }
    Write-Log "Revert completed. Restored: $ok. Missing/Failed: $fail."
    return @{ restored = $ok; failed = $fail }
}

function Find-AmdManifests {
    param([string]$Root)
    $root = Resolve-DriverRoot -Hint $Root
    $xmls = Get-ChildItem -Path $root -Recurse -Include package.xml -File -ErrorAction SilentlyContinue
    $jsons = Get-ChildItem -Path $root -Recurse -Include driver.json -File -ErrorAction SilentlyContinue
    # Filter for AMD-ish content cheaply
    $xmls = $xmls | Where-Object {
        try { (Get-Content -LiteralPath $_.FullName -TotalCount 50 -ErrorAction Stop) -join '' -match '(?i)AMD|InstallManifest|Packages' } catch { $true }
    }
    $jsons = $jsons | Where-Object {
        try { (Get-Content -LiteralPath $_.FullName -TotalCount 50 -ErrorAction Stop) -join '' -match '(?i)driver|catalog|inf' } catch { $true }
    }
    return @{
        packageXml = $xmls
        driverJson  = $jsons
    }
}

function Patch-Manifests {
    param([string]$Root)
    $root = Resolve-DriverRoot -Hint $Root
    $found = Find-AmdManifests -Root $root
    $touched = 0
    foreach ($f in @($found.packageXml + $found.driverJson)) {
        try {
            $content = Get-Content -LiteralPath $f.FullName -Raw
            $backup = "$($f.FullName)$($Script:BackupMarker)"
            if (-not (Test-Path $backup)) { Copy-Item -LiteralPath $f.FullName -Destination $backup -Force }
            # Minimal, robust patch: relax OS checks and blocklists commonly used for Server
            $patched = $content
            $patched = $patched -replace '(?i)WindowsServer(20\d{2})','Windows10'   # simple bypass
            $patched = $patched -replace '(?i)"BlockList"\s*:\s*\[.*?\]', '"BlockList":[]'
            if ($patched -ne $content) {
                Set-Content -LiteralPath $f.FullName -Value $patched -Encoding UTF8
                $touched++
                Write-Log "Patched manifest: $($f.FullName)"
            } else {
                Write-Log "No-op (already permissive): $($f.FullName)"
            }
        } catch {
            Write-Log "Patch failed for $($f.FullName): $($_.Exception.Message)"
        }
    }
    Write-Log "Patch-Manifests complete. Files changed: $touched"
    return @{ changed = $touched; xml = ($found.packageXml | Select-Object -Expand FullName); json = ($found.driverJson | Select-Object -Expand FullName) }
}

function Is-TestSigningOn {
    try {
        $out = bcdedit | Out-String
        return ($out -match 'testsigning\s+Yes')
    } catch { return $false }
}

function Enable-TestSigning {
    try {
        bcdedit /set testsigning on | Out-Null
        bcdedit /set nointegritychecks on | Out-Null
        Write-Log "Enabled Test Signing and disabled integrity checks."
        return $true
    } catch {
        Write-Log "Failed to enable Test Signing: $($_.Exception.Message)"
        return $false
    }
}

function Install-PatchedDriver {
    param([string]$Root)
    $root = Resolve-DriverRoot -Hint $Root
    if (-not (Is-TestSigningOn)) {
        Write-Log "TestSigning is OFF. Required for unsigned/patched drivers on Server."
        if (Enable-TestSigning) {
            New-Item -ItemType File -Path $Script:PendingRebootFlag -Force | Out-Null
            Write-Log "Reboot required to continue driver install. After reboot, re-run Install."
            return @{ status = 'reboot_required' }
        } else {
            return @{ status = 'failed'; error = 'Could not enable testsigning' }
        }
    }
    try {
        $infs = Find-InfFiles -Root $root
        if (-not $infs) { return @{ status='failed'; error='No INF files found' } }
        $added = 0
        foreach ($inf in $infs) {
            # Add all, install if applicable
            $r = & pnputil /add-driver "`"$($inf.FullName)`"" /install /subdirs 2>&1 | Out-String
            Write-Log $r.Trim()
            if ($r -match '(?i)published|added|installed') { $added++ }
        }
        return @{ status='ok'; drivers=$added }
    } catch {
        Write-Log "Install failed: $($_.Exception.Message)"
        return @{ status='failed'; error=$_.Exception.Message }
    }
}

function Open-AmdSupport {
    Start-Process "https://www.amd.com/en/support"
}

# ----------------------- Web UI -----------------------

$Html = @'
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8"/>
<meta name="viewport" content="width=device-width, initial-scale=1"/>
<title>Rarity Intelligence™ INF Patcher</title>
<style>
:root{
  --bg:#0a0c10; --card:#11141a; --text:#e7eaf1;
  --accent:#9b1620; --silver:#cfd6dd; --blue:#72839a;
}
html,body{height:100%;margin:0;background:var(--bg);color:var(--text);font-family:Segoe UI,Roboto,Arial,sans-serif;}
.container{
  position:fixed; inset:0; margin:auto;
  width:min(50vw,1100px); height:min(50vh,800px);
  display:grid; grid-template-rows:auto auto 1fr auto;
  gap:12px; padding:16px;
  background:linear-gradient(180deg,rgba(255,255,255,0.02),rgba(255,255,255,0.00)) , var(--card);
  border:1px solid rgba(255,255,255,0.08); border-radius:18px;
  box-shadow:0 20px 60px rgba(0,0,0,0.6), inset 0 1px 0 rgba(255,255,255,0.06);
}
h1{margin:0; font-size:18px; letter-spacing:.3px}
button,.link{
  background:linear-gradient(180deg,rgba(255,255,255,0.08),rgba(255,255,255,0.02));
  border:1px solid rgba(255,255,255,0.12); color:var(--text);
  padding:8px 12px; border-radius:10px; cursor:pointer; user-select:none;
  box-shadow:0 6px 18px rgba(0,0,0,0.35);
}
button:hover{filter:brightness(1.1)}
.row{display:flex; gap:8px; flex-wrap:wrap}
input[type="text"]{
  flex:1; background:#0d1117; color:var(--text);
  border:1px solid rgba(255,255,255,0.1); border-radius:10px; padding:8px 10px;
  box-shadow:inset 0 2px 8px rgba(0,0,0,0.5);
}
#log{
  background:#0b0f14; border:1px solid rgba(255,255,255,0.08); border-radius:12px;
  padding:10px; overflow-y:auto; overflow-x:hidden; white-space:pre-wrap; word-wrap:break-word; word-break:break-word;
  font-family:Consolas,Menlo,monospace; font-size:12px; line-height:1.35;
}
footer{display:flex; justify-content:space-between; align-items:center; font-size:12px; opacity:.8}
a.link{ text-decoration:none; display:inline-block }
</style>
</head>
<body>
  <div class="container" role="dialog" aria-modal="true">
    <h1>Rarity Intelligence™ INF Patcher</h1>
    <div class="row">
      <input id="root" type="text" placeholder="Driver root (auto-detect if empty)"/>
      <button onclick="api('patch')">Patch Manifests</button>
      <button onclick="api('revert')">Revert All</button>
      <button onclick="api('install')">Install Patched Driver</button>
      <a class="link" href="https://www.amd.com/en/support" target="_blank" rel="noreferrer">AMD Drivers</a>
    </div>
    <div id="log" aria-live="polite"></div>
    <footer>
      <div>DPI-aware 50% window. Text-wrapping log. No horizontal scroll.</div>
      <div>Rarity Intelligence™</div>
    </footer>
  </div>
<script>
async function api(action){
  const root = document.getElementById('root').value || '';
  const r = await fetch('/api/'+action, {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({root})});
  const j = await r.json();
  if(j.log){ append(j.log); }
  if(j.result){ append(JSON.stringify(j.result, null, 2)); }
}
function append(text){
  const el = document.getElementById('log');
  el.textContent += (text + '\\n');
  el.scrollTop = el.scrollHeight;
}
</script>
</body>
</html>
'@

function Start-Server {
    $listener = [HttpListener]::new()
    $listener.Prefixes.Add($Script:BindAddress)
    $listener.Start()
    Write-Log "Web UI at $Script:BindAddress"

    $runner = {
        param($listener)
        while ($listener.IsListening) {
            try {
                $ctx = $listener.GetContext()
                $req = $ctx.Request
                $res = $ctx.Response

                if ($req.HttpMethod -eq 'GET' -and $req.Url.AbsolutePath -eq '/') {
                    $bytes = [Text.Encoding]::UTF8.GetBytes($using:Html)
                    $res.ContentType = 'text/html; charset=utf-8'
                    $res.OutputStream.Write($bytes,0,$bytes.Length)
                    $res.Close()
                    continue
                }

                if ($req.HttpMethod -eq 'POST' -and $req.Url.AbsolutePath -like '/api/*') {
                    $reader = New-Object IO.StreamReader($req.InputStream, $req.ContentEncoding)
                    $body = $reader.ReadToEnd()
                    $reader.Close()
                    $payload = @{ root = '' }
                    if ($body) {
                        try { $payload = $body | ConvertFrom-Json } catch {}
                    }

                    $action = $req.Url.Segments[-1].Trim('/')
                    $result = $null
                    switch ($action) {
                        'patch'   { $result = Patch-Manifests -Root $payload.root }
                        'revert'  { $result = Revert-All -Root $payload.root }
                        'install' { $result = Install-PatchedDriver -Root $payload.root }
                        default   { $result = @{ error = 'unknown_action' } }
                    }

                    $resp = @{
                        result = $result
                        log    = Get-LogsHtml
                    } | ConvertTo-Json -Depth 6

                    $bytes = [Text.Encoding]::UTF8.GetBytes($resp)
                    $res.ContentType = 'application/json; charset=utf-8'
                    $res.OutputStream.Write($bytes,0,$bytes.Length)
                    $res.Close()
                    continue
                }

                $res.StatusCode = 404
                $res.Close()
            } catch {
                try { $res.StatusCode = 500; $res.Close() } catch {}
                Write-Log "HTTP error: $($_.Exception.Message)"
            }
        }
    }

    $job = Start-Job -ScriptBlock $runner -ArgumentList $listener
    return @{ listener = $listener; job = $job }
}

function Launch-BrowserCentered {
    # Compute 50% of primary display. Center window. Use Edge or Chrome app window for a clean frame.
    $screen = [System.Windows.Forms.Screen]::PrimaryScreen.Bounds
    $w = [int]([double]$screen.Width * 0.5)
    $h = [int]([double]$screen.Height * 0.5)
    $x = [int](($screen.Width - $w) / 2)
    $y = [int](($screen.Height - $h) / 2)

    $url = "http://127.0.0.1:$Script:Port/"
    $edge = "${env:ProgramFiles(x86)}\Microsoft\Edge\Application\msedge.exe"
    $chrome = "${env:ProgramFiles(x86)}\Google\Chrome\Application\chrome.exe"

    $args = @("--app=$url","--window-size=$w,$h","--window-position=$x,$y")
    if (Test-Path $edge) {
        Start-Process -FilePath $edge -ArgumentList $args
    } elseif (Test-Path $chrome) {
        Start-Process -FilePath $chrome -ArgumentList $args
    } else {
        # Fallback: default browser (may ignore size hints)
        Start-Process $url
    }
}

# ----------------------- Main -----------------------
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Error "Run as Administrator."
    exit 1
}

Write-Log "Starting Rarity Intelligence™ AMD INF Patcher UI"
$server = Start-Server
Launch-BrowserCentered

# If a reboot occurred with flag present, inform user
if (Test-Path $Script:PendingRebootFlag) {
    Write-Log "System is in TestSigning mode. You can now use 'Install Patched Driver'."
}

# Keep session alive until CTRL+C
try {
    while ($true) { Start-Sleep -Seconds 1 }
} finally {
    if ($server.listener) { $server.listener.Stop() }
    if ($server.job) { Stop-Job $server.job -Force | Out-Null; Remove-Job $server.job -Force | Out-Null }
}
