
#requires -Version 5.1
<#
AMD INF Patcher UI — Rarity Intelligence™
Version: 0.6b (2025-10-12)

Fixes:
- Remove prelaunch HTTP probe that hung on some Server builds.
- Listen on both 127.0.0.1 and localhost.
- Fix Stop-Job calls for Windows PowerShell 5.1 (no -Force).
- Keep strict WebView checks and all UI/feature work.

#>

using namespace System.Net
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

#region ----------------------- Config -----------------------
$Script:PortCandidates = @(8080, 8123, 8130, 8177, 8820)
$Script:BindAddress    = $null
$Script:BindAddressAlt = $null
$Script:DriverRoot     = $env:AMD_DRIVER_ROOT
$Script:WorkDir        = $env:TEMP
$Script:BackupMarker   = '.bak'
$Script:Log            = [System.Collections.Concurrent.ConcurrentQueue[string]]::new()
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
    $lines = @()
    while ($Script:Log.TryDequeue([ref]$out)) { $lines += $out }
    if ($lines.Count -eq 0) { return '' }
    $html = ($lines -join "`n") -replace '&','&amp;' -replace '<','&lt;' -replace '>','&gt;'
    return $html
}

function Assert-Admin {
    $isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    if (-not $isAdmin) { Write-Error "Run as Administrator."; exit 1 }
}

# ---------- Port + Firewall ----------
function Test-PortFree { param([int]$Port) try { $tcp = New-Object Net.Sockets.TcpListener([Net.IPAddress]::Loopback, $Port); $tcp.Start(); $tcp.Stop(); return $true } catch { return $false } }
function Ensure-FirewallRule {
    param([int]$Port)
    try {
        if (Get-Command -Name New-NetFirewallRule -ErrorAction SilentlyContinue) {
            $name = "RI-INF-Patcher-$Port"
            if (-not (Get-NetFirewallRule -DisplayName $name -ErrorAction SilentlyContinue)) {
                New-NetFirewallRule -DisplayName $name -Direction Inbound -Action Allow -Protocol TCP -LocalPort $Port -LocalAddress 127.0.0.1 -Profile Any | Out-Null
                Write-Log "Firewall rule added for 127.0.0.1:$Port"
            }
        }
    } catch { Write-Log "Firewall rule add skipped: $($_.Exception.Message)" }
}
function Select-Port {
    foreach ($p in $Script:PortCandidates) {
        if (Test-PortFree -Port $p) {
            $Script:BindAddress   = 'http://127.0.0.1:{0}/' -f $p
            $Script:BindAddressAlt= 'http://localhost:{0}/' -f $p
            Ensure-FirewallRule -Port $p
            return $p
        } else { Write-Log "Port $p busy. Trying next." }
    }
    throw "No free ports in candidate list."
}

# ---------- Driver helpers ----------
function Resolve-DriverRoot {
    param([string]$Hint)
    if ($Script:DriverRoot -and (Test-Path $Script:DriverRoot)) { return (Resolve-Path $Script:DriverRoot).Path }
    if ($Hint -and (Test-Path $Hint)) { return (Resolve-Path $Hint).Path }
    $candidates = @("$env:USERPROFILE\Downloads\AMD*","$env:USERPROFILE\Downloads\Win*","C:\AMD\*","C:\Drivers\AMD\*","$env:USERPROFILE\Desktop\AMD*")
    foreach ($pattern in $candidates) {
        $d = Get-ChildItem -Path $pattern -Directory -ErrorAction SilentlyContinue | Sort-Object LastWriteTime -Descending | Select-Object -First 1
        if ($d) { return $d.FullName }
    }
    return $PWD.Path
}
function Find-InfFiles { param([string]$Root) Get-ChildItem -Path $Root -Recurse -Include *.inf -File -ErrorAction SilentlyContinue }

function Get-BackupCandidatesForInf {
    param([string]$InfPath)
    $dir = Split-Path -Parent $InfPath
    $name = Split-Path -Leaf $InfPath
    $c = @()
    $c += Join-Path $dir "$name$($Script:BackupMarker)"
    if ($name -match '\.inf$') {
        $base = [IO.Path]::GetFileNameWithoutExtension($name)
        $c += Join-Path $dir "$base$($Script:BackupMarker)"
        $c += Join-Path $dir "$base.inf$($Script:BackupMarker)"
    }
    foreach ($b in @('Backup','_backup','backup')) {
        $up = Split-Path -Parent $dir
        $backupDir = Join-Path $up $b
        if (Test-Path $backupDir) {
            $rel = $InfPath.Substring($up.Length).TrimStart('\','/')
            $c += Join-Path $backupDir $rel
            $c += (Join-Path $backupDir $rel) + $Script:BackupMarker
        }
    }
    $c | Where-Object { Test-Path $_ } | Select-Object -Unique
}
function Restore-InfFromBackup {
    param([string]$InfPath)
    $candidates = Get-BackupCandidatesForInf -InfPath $InfPath
    if (-not $candidates) { Write-Log "No backup found: $InfPath"; return $false }
    $best = $candidates | Sort-Object -Property Length | Select-Object -First 1
    try { Copy-Item -LiteralPath $best -Destination $InfPath -Force; Write-Log "Restored `"$InfPath`" from `"$best`"."; return $true }
    catch { Write-Log "Restore failed $InfPath : $($_.Exception.Message)"; return $false }
}
function Revert-All {
    param([string]$Root)
    $root = Resolve-DriverRoot -Hint $Root
    if (-not (Test-Path $root)) { Write-Log "Root not found: $root"; return @{restored=0;failed=0;error='root_not_found'} }
    Write-Log "Reverting all INFs under: $root"
    $infs = Find-InfFiles -Root $root
    if (-not $infs) { Write-Log "No INF files found under: $root"; return @{restored=0;failed=0;error='no_inf'} }
    $ok = 0; $fail = 0
    foreach ($inf in $infs) { if (Restore-InfFromBackup -InfPath $inf.FullName) { $ok++ } else { $fail++ } }
    Write-Log "Revert completed. Restored: $ok. Missing/Failed: $fail."
    return @{ restored = $ok; failed = $fail }
}

function Find-AmdManifests {
    param([string]$Root)
    $root = Resolve-DriverRoot -Hint $Root
    $xmls = Get-ChildItem -Path $root -Recurse -Include package.xml -File -ErrorAction SilentlyContinue
    $jsons = Get-ChildItem -Path $root -Recurse -Include driver.json -File -ErrorAction SilentlyContinue
    $xmls = $xmls | Where-Object { try { (Get-Content -LiteralPath $_.FullName -TotalCount 80 -ErrorAction Stop) -join '' -match '(?i)AMD|InstallManifest|Packages' } catch { $true } }
    $jsons = $jsons | Where-Object { try { (Get-Content -LiteralPath $_.FullName -TotalCount 80 -ErrorAction Stop) -join '' -match '(?i)driver|catalog|inf' } catch { $true } }
    return @{ packageXml = $xmls; driverJson = $jsons }
}
function Patch-Manifests {
    param([string]$Root)
    $root = Resolve-DriverRoot -Hint $Root
    if (-not (Test-Path $root)) { Write-Log "Root not found: $root"; return @{changed=0;error='root_not_found'} }
    $found = Find-AmdManifests -Root $root
    $touched = 0
    foreach ($f in @($found.packageXml + $found.driverJson)) {
        try {
            $content = Get-Content -LiteralPath $f.FullName -Raw
            $backup = "$($f.FullName)$($Script:BackupMarker)"
            if (-not (Test-Path $backup)) { Copy-Item -LiteralPath $f.FullName -Destination $backup -Force }
            $patched = $content
            $patched = $patched -replace '(?i)WindowsServer(20\d{2})','Windows10'
            $patched = $patched -replace '(?is)(?<="BlockList"\s*:\s*)\[(.*?)\]', '[]'
            if ($patched -ne $content) { Set-Content -LiteralPath $f.FullName -Value $patched -Encoding UTF8; $touched++; Write-Log "Patched: $($f.FullName)" }
            else { Write-Log "No changes: $($f.FullName)" }
        } catch { Write-Log "Patch failed $($f.FullName): $($_.Exception.Message)" }
    }
    Write-Log "Patch-Manifests complete. Files changed: $touched"
    return @{ changed = $touched; xml = ($found.packageXml | ForEach-Object FullName); json = ($found.driverJson | ForEach-Object FullName) }
}

function Is-TestSigningOn { try { (bcdedit | Out-String) -match 'testsigning\s+Yes' } catch { $false } }
function Enable-TestSigning {
    try { bcdedit /set testsigning on | Out-Null; bcdedit /set nointegritychecks on | Out-Null; Write-Log "Enabled Test Signing and disabled integrity checks."; return $true }
    catch { Write-Log "Failed to enable Test Signing: $($_.Exception.Message)"; return $false }
}
function Install-PatchedDriver {
    param([string]$Root)
    $root = Resolve-DriverRoot -Hint $Root
    if (-not (Test-Path $root)) { return @{ status='failed'; error='root_not_found' } }
    if (-not (Is-TestSigningOn)) {
        Write-Log "TestSigning is OFF. Required for unsigned/patched drivers on Server."
        if (Enable-TestSigning) { New-Item -ItemType File -Path $Script:PendingRebootFlag -Force | Out-Null; Write-Log "Reboot required. After reboot, re-run Install."; return @{ status = 'reboot_required' } }
        else { return @{ status = 'failed'; error = 'enable_testsigning_failed' } }
    }
    $infs = Find-InfFiles -Root $root
    if (-not $infs) { return @{ status='failed'; error='no_inf' } }
    $added = 0
    foreach ($inf in $infs) {
        $r = & pnputil /add-driver "`"$($inf.FullName)`"" /install /subdirs 2>&1 | Out-String
        Write-Log ($r.Trim())
        if ($r -match '(?i)published|added|installed|staged') { $added++ }
    }
    return @{ status='ok'; drivers=$added }
}

# ---------- WebView2 detection + install chain ----------
function Get-WebView2ExePath {
    $base = "${env:ProgramFiles(x86)}\Microsoft\EdgeWebView\Application"
    if (Test-Path $base) {
        $ver = Get-ChildItem -Path $base -Directory -ErrorAction SilentlyContinue | Sort-Object Name -Descending | Select-Object -First 1
        if ($ver) {
            $exe = Join-Path $ver.FullName 'msedgewebview2.exe'
            if (Test-Path $exe) { return $exe }
        }
    }
    return $null
}
function Get-WebView2Version {
    $exe = Get-WebView2ExePath
    if ($exe) { try { return (Get-Item $exe).VersionInfo.ProductVersion } catch { return $null } }
    foreach ($k in @('HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*','HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*')) {
        Get-ItemProperty -Path $k -ErrorAction SilentlyContinue | Where-Object { $_.DisplayName -like 'Microsoft Edge WebView2 Runtime*' } | ForEach-Object { return $_.DisplayVersion }
    }
    return $null
}
function Test-WebView2Installed {
    if (Get-WebView2ExePath) { return $true }
    foreach ($k in @('HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*','HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*')) {
        $hit = Get-ItemProperty -Path $k -ErrorAction SilentlyContinue | Where-Object { $_.DisplayName -like 'Microsoft Edge WebView2 Runtime*' }
        if ($hit) { return $true }
    }
    if (Get-Command winget -ErrorAction SilentlyContinue) {
        try { $out = winget list --id Microsoft.EdgeWebView2Runtime 2>$null; if ($LASTEXITCODE -eq 0 -and ($out | Out-String) -match 'WebView2') { return $true } } catch {}
    }
    return $false
}
function Refresh-EnvPath {
    try {
        $machine = [Environment]::GetEnvironmentVariable('Path','Machine')
        $user    = [Environment]::GetEnvironmentVariable('Path','User')
        if ($machine -and $user) { $env:Path = "$machine;$user" }
        elseif ($machine) { $env:Path = $machine }
        elseif ($user) { $env:Path = $user }
    } catch {}
}
function Ensure-WinGet { [bool](Get-Command -Name winget -ErrorAction SilentlyContinue) }
function Install-WebView2-ByWinGet {
    try {
        Write-Log "Installing WebView2 via winget."
        $args = @('install','--id','Microsoft.EdgeWebView2Runtime','-e','--silent','--accept-source-agreements','--accept-package-agreements')
        Start-Process -FilePath 'winget' -ArgumentList $args -PassThru -Wait -WindowStyle Hidden | Out-Null
        Refresh-EnvPath; return $true
    } catch { Write-Log "winget install failed: $($_.Exception.Message)"; return $false }
}
function Ensure-Chocolatey {
    $choco = Get-Command choco -ErrorAction SilentlyContinue
    if ($choco) { return $true }
    try {
        Write-Log "Installing Chocolatey."
        Set-ExecutionPolicy Bypass -Scope Process -Force
        [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12
        Invoke-Expression ((New-Object System.Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1'))
        Refresh-EnvPath; return [bool](Get-Command choco -ErrorAction SilentlyContinue)
    } catch { Write-Log "Chocolatey install failed: $($_.Exception.Message)"; return $false }
}
function Install-WebView2-ByChoco {
    try { Write-Log "Installing WebView2 via Chocolatey."; choco install microsoft-edge-webview2-runtime -y --no-progress | Out-String | Write-Log; Refresh-EnvPath; return $true }
    catch { Write-Log "choco install failed: $($_.Exception.Message)"; return $false }
}
function Install-WebView2-ByBootstrapper {
    try {
        Write-Log "Installing WebView2 via Microsoft bootstrapper."
        [Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12
        $url = 'https://go.microsoft.com/fwlink/p/?LinkId=2124703'
        $dst = Join-Path $env:TEMP 'MicrosoftEdgeWebview2Setup.exe'
        Invoke-WebRequest -Uri $url -OutFile $dst -UseBasicParsing -ErrorAction Stop
        Start-Process -FilePath $dst -ArgumentList '/silent','/install' -Wait
        Start-Sleep 2
        return $true
    } catch { Write-Log "Bootstrapper install failed: $($_.Exception.Message)"; return $false }
}
function Ensure-WebView2-Strict {
    $pre = Test-WebView2Installed
    $preVer = Get-WebView2Version
    Write-Log ("WebView2 pre-check: {0} {1}" -f ($(if($pre){'installed'}else{'missing'}), $(if($preVer){"v$preVer"}else{''})))
    if ($pre) { return $true }
    if (Ensure-WinGet) { [void](Install-WebView2-ByWinGet) } else { Write-Log "winget not available." }
    if (-not (Test-WebView2Installed)) { if (Ensure-Chocolatey) { [void](Install-WebView2-ByChoco) } else { Write-Log "Chocolatey not available and install failed." } }
    if (-not (Test-WebView2Installed)) { [void](Install-WebView2-ByBootstrapper) }
    $post = Test-WebView2Installed
    $postVer = Get-WebView2Version
    Write-Log ("WebView2 final-check: {0} {1}" -f ($(if($post){'installed'}else{'missing'}), $(if($postVer){"v$postVer"}else{''})))
    return $post
}

# ---------- HTTP server with access logging ----------
function Start-Server {
    $port = Select-Port
    $prefix1 = 'http://127.0.0.1:{0}/' -f $port
    $prefix2 = 'http://localhost:{0}/' -f $port
    $Script:BindAddress = $prefix1
    $Script:BindAddressAlt = $prefix2

    $listener = [HttpListener]::new()
    $listener.Prefixes.Add($prefix1)
    $listener.Prefixes.Add($prefix2)
    try { $listener.Start() } catch { throw "Failed to start HTTP listener on $prefix1 : $($_.Exception.Message)" }
    Write-Log "Web UI at $prefix1"

    $runner = {
        param($listener, $Html)
        while ($listener.IsListening) {
            try {
                $ctx = $listener.GetContext()
                $req = $ctx.Request
                $res = $ctx.Response
                [Console]::WriteLine("[{0}] {1} {2}" -f (Get-Date).ToString('HH:mm:ss'), $req.HttpMethod, $req.RawUrl)
                if ($req.HttpMethod -eq 'GET' -and $req.Url.AbsolutePath -eq '/') {
                    $bytes = [Text.Encoding]::UTF8.GetBytes($Html); $res.ContentType='text/html; charset=utf-8'; $res.OutputStream.Write($bytes,0,$bytes.Length); $res.Close(); continue
                }
                if ($req.HttpMethod -eq 'POST' -and $req.Url.AbsolutePath -like '/api/*') {
                    $reader = New-Object IO.StreamReader($req.InputStream, $req.ContentEncoding); $body=$reader.ReadToEnd(); $reader.Close()
                    $payload = @{ root = '' }; if ($body) { try { $payload = $body | ConvertFrom-Json } catch {} }
                    $action = $req.Url.Segments[-1].Trim('/')
                    $result = switch ($action) { 'patch' { Patch-Manifests -Root $payload.root } 'revert' { Revert-All -Root $payload.root } 'install' { Install-PatchedDriver -Root $payload.root } default { @{ error='unknown_action' } } }
                    $resp = @{ result=$result; log=Get-LogsHtml } | ConvertTo-Json -Depth 6
                    $bytes = [Text.Encoding]::UTF8.GetBytes($resp); $res.ContentType='application/json; charset=utf-8'
                    $res.OutputStream.Write($bytes,0,$bytes.Length); $res.Close(); continue
                }
                $res.StatusCode = 404; $res.Close()
            } catch { try { $res.StatusCode = 500; $res.Close() } catch {}; Write-Log "HTTP error: $($_.Exception.Message)" }
        }
    }

    $job = Start-Job -ScriptBlock $runner -ArgumentList $listener, $Html
    return @{ listener = $listener; job = $job; port = $port }
}

# ---------- Edge detection and launch ----------
function Get-EdgePath {
    $candidates = @(
        "${env:ProgramFiles}\Microsoft\Edge\Application\msedge.exe",
        "${env:ProgramFiles(x86)}\Microsoft\Edge\Application\msedge.exe"
    )
    foreach ($p in $candidates) { if (Test-Path $p) { return $p } }
    return $null
}
function Launch-EdgeAppWindow {
    $edge = Get-EdgePath
    if (-not $edge) { throw "Microsoft Edge not found in Program Files." }
    Write-Log "Using Edge: $edge"

    $screen = [System.Windows.Forms.Screen]::PrimaryScreen.Bounds
    $w = [int]([double]$screen.Width * 0.5)
    $h = [int]([double]$screen.Height * 0.5)
    $x = [int](($screen.Width - $w) / 2)
    $y = [int](($screen.Height - $h) / 2)

    $url = $Script:BindAddress
    $args = @("--app=$url","--window-size=$w,$h","--window-position=$x,$y")
    Start-Process -FilePath $edge -ArgumentList $args | Out-Null
}

# ----------------------- Main -----------------------
Assert-Admin
Write-Log "Starting Rarity Intelligence™ AMD INF Patcher UI"
$server = Start-Server

# Strict WebView check and install chain
if (-not (Ensure-WebView2-Strict)) {
    Write-Log "WebView2 install/verify failed. Exiting."
    if ($server.listener) { $server.listener.Stop() }
    if ($server.job) { Stop-Job $server.job | Out-Null; Remove-Job $server.job | Out-Null }
    exit 2
}
$wvVer = Get-WebView2Version; if ($wvVer) { Write-Log "WebView2 verified v$wvVer" }

# Launch
try { Launch-EdgeAppWindow } catch { Write-Log "Edge launch failed: $($_.Exception.Message)"; if ($server.listener) { $server.listener.Stop() }; if ($server.job) { Stop-Job $server.job | Out-Null; Remove-Job $server.job | Out-Null }; exit 3 }

if (Test-Path $Script:PendingRebootFlag) { Write-Log "System is in TestSigning mode. You can now use 'Install Patched Driver'." }

try { while ($true) { Start-Sleep -Seconds 1 } }
finally { if ($server.listener) { $server.listener.Stop() }; if ($server.job) { Stop-Job $server.job | Out-Null; Remove-Job $server.job | Out-Null } }
