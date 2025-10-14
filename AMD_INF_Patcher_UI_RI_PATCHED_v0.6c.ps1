#requires -Version 5.1
#requires -RunAsAdministrator
<#
AMD INF Patcher UI — Rarity Intelligence™
Version: 4.3 (2025-04-05)

Changes:
- Unified single-file design with robust infrastructure
- Fixed Revert All (backups stored next to originals + in C:\RepairLogs)
- Enhanced manifest patching: package.xml, driver.json
- One-click Install with DSE/TestSigning handling for Windows Server
- Log output wraps (no horizontal scroll)
- Launches Edge in app mode (no browser chrome)
- Auto-port fallback (8080 → 8123 → 8130 → 8177 → 8820)
- WebView2 runtime check + auto-install (winget → choco → bootstrapper)
- Auto-retry with localhost if 127.0.0.1 fails
- Firewall rule for localhost port
- Telemetry via %TEMP%\ri_infpatcher_reqcount.txt
- Pending reboot flag for DSE flow
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
$Script:BackupBase     = "C:\RepairLogs"
$Script:BackupMarker   = '.bak'
$Script:Log            = [System.Collections.Concurrent.ConcurrentQueue[string]]::new()
$Script:PendingRebootFlag = Join-Path $Script:WorkDir 'ri_infpatcher_reboot.flag'
$Script:ReqCountPath   = Join-Path $env:TEMP 'ri_infpatcher_reqcount.txt'
$Script:SessionID      = (Get-Date -Format 'yyyyMMdd_HHmmss')

$ValidTargets = @{
    'Generic'      = 'NTamd64'
    'Server2019_2' = 'NTamd64.10.0.2.17763'
    'Server2019_3' = 'NTamd64.10.0.3.17763'
    'Server2022'   = 'NTamd64.10.0...20348'
    'Win11_24H2'   = 'NTamd64.10.0...26100'
    'Server2025'   = 'NTamd64.10.0...26100'
    'Win7'         = 'NTamd64.6.1...7601'
    'Custom'       = $null
}
#endregion

function Write-Log {
    param([string]$Message, [string]$Level='Info')
    $ts = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
    $line = "[$ts] [$Level] $Message"
    $Script:Log.Enqueue($line) | Out-Null
    Write-Host $line
}

function Get-LogsHtml {
    $lines = @()
    while ($Script:Log.TryDequeue([ref]$out)) { $lines += $out }
    if ($lines.Count -eq 0) { return '' }
    $html = ($lines -join "`n") -replace '&','&amp;' -replace '<','<' -replace '>','>'
    return $html
}

function Assert-Admin {
    $isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    if (-not $isAdmin) { Write-Error "❌ Run as Administrator."; exit 1 }
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

# ---------- File I/O Helpers ----------
function Read-TextFileSafe {
    param([string]$Path, [int]$MaxBytes=10485760)
    if (-not (Test-Path -LiteralPath $Path)) { Write-Log "Read fail. Missing: $Path" "Warning"; return $null }
    $fi = Get-Item -LiteralPath $Path -EA Stop
    if ($fi.Length -gt $MaxBytes) { Write-Log "Read skip. Large file: $Path ($($fi.Length) bytes)" "Warning"; return $null }
    $bytes = [System.IO.File]::ReadAllBytes($fi.FullName)
    if ($bytes.Length -eq 0) { Write-Log "Read empty: $Path" "Warning"; return $null }
    $nulCount = ($bytes | Where-Object { $_ -eq 0 }).Count
    if ($nulCount -gt [math]::Max(64, $bytes.Length * 0.10)) { Write-Log "Binary-like content: $Path" "Warning"; return $null }
    if ($bytes.Length -ge 3 -and $bytes[0]-eq 0xEF -and $bytes[1]-eq 0xBB -and $bytes[2]-eq 0xBF) {
        $text = [System.Text.Encoding]::UTF8.GetString($bytes,3,$bytes.Length-3)
    }
    elseif ($bytes.Length -ge 2 -and $bytes[0]-eq 0xFF -and $bytes[1]-eq 0xFE) {
        $text = [System.Text.Encoding]::Unicode.GetString($bytes,2,$bytes.Length-2)
    }
    elseif ($bytes.Length -ge 2 -and $bytes[0]-eq 0xFE -and $bytes[1]-eq 0xFF) {
        $text = [System.Text.Encoding]::BigEndianUnicode.GetString($bytes,2,$bytes.Length-2)
    }
    else {
        $text = [System.Text.Encoding]::UTF8.GetString($bytes)
    }
    if ([string]::IsNullOrWhiteSpace($text)) { Write-Log "Read whitespace-only: $Path" "Warning"; return $null }
    return [string]$text
}

function Write-TextFileSafe {
    param([string]$Path, [string]$Text, [string]$Encoding='ASCII')
    try {
        if ($null -eq $Text) { return $false }
        if ($Encoding -eq 'ASCII') {
            [System.IO.File]::WriteAllText($Path, $Text, [System.Text.Encoding]::ASCII)
        } else {
            [System.IO.File]::WriteAllText($Path, $Text, [System.Text.Encoding]::UTF8)
        }
        return $true
    } catch { Write-Log "Write error: $Path :: $_" "Error"; return $false }
}

# ---------- Backup & Revert ----------
function Backup-File {
    param([string]$FilePath)
    if (-not (Test-Path -LiteralPath $FilePath)) { throw "File not found: $FilePath" }
    $hash = (Get-FileHash -Path $FilePath -Algorithm SHA256).Hash.Substring(0,8)
    # Backup next to original
    $backupName = "$FilePath.bak_$($Script:SessionID)_$hash"
    Copy-Item -LiteralPath $FilePath -Destination $backupName -Force
    # Also backup in central location
    if (-not (Test-Path $Script:BackupBase)) { New-Item -ItemType Directory -Path $Script:BackupBase -Force | Out-Null }
    $encoded = $FilePath -replace '^([a-zA-Z]):', '$1_' -replace '[\\/:*?"<>|]', '_'
    $centralBackup = Join-Path $Script:BackupBase "backup_$encoded.bak_$($Script:SessionID)_$hash"
    Copy-Item -LiteralPath $FilePath -Destination $centralBackup -Force
    return $backupName
}

function Revert-AllChanges {
    Write-Log "Starting full revert process..." "Warning"
    $reverted = 0
    # Try central backups first
    if (Test-Path $Script:BackupBase) {
        $backups = Get-ChildItem -Path $Script:BackupBase -Filter "backup_*.bak_$($Script:SessionID)_*" -EA SilentlyContinue
        if (-not $backups) {
            $backups = Get-ChildItem -Path $Script:BackupBase -Filter "backup_*.bak_*" -EA SilentlyContinue
        }
        foreach ($bak in $backups) {
            $name = [System.IO.Path]::GetFileName($bak.FullName)
            if ($name -notmatch '^backup_(.+?)\.bak_\d{8}_\d{6}_[0-9a-f]{8}$') { continue }
            $encoded = $matches[1]
            $orig = $encoded -replace '^([a-zA-Z])_', '$1:' -replace '_', '\'
            try {
                if (Test-Path $orig) { Remove-Item -LiteralPath $orig -Force }
                Move-Item -LiteralPath $bak.FullName -Destination $orig -Force
                Write-Log "Reverted: $orig" "Success"
                $reverted++
            } catch { Write-Log "Revert failed for $orig : $_" "Error" }
        }
    }
    if ($reverted -eq 0) { Write-Log "No revertable backups found." "Info" }
    else { Write-Log "Reverted $reverted file(s)." "Success" }
    return @{ restored = $reverted; failed = 0 }
}

# ---------- Patching Logic ----------
function Update-ManufacturerBlock {
    param([string]$Text, [string]$Decoration)
    if ([string]::IsNullOrWhiteSpace($Text)) { return $Text }
    $opts = [System.Text.RegularExpressions.RegexOptions]::IgnoreCase -bor [System.Text.RegularExpressions.RegexOptions]::Multiline -bor [System.Text.RegularExpressions.RegexOptions]::Singleline
    $rx = [regex]::new('^\[Manufacturer\]\s*(?<blk>.*?)(?=^\[[^\]\r\n]+\]|\Z)', $opts)
    $mc = $rx.Matches($Text)
    if ($mc.Count -eq 0) {
        return "[Manufacturer]`r`n%ATI% = ATI.Mfg, $Decoration`r`n" + $Text
    }
    if ($mc.Count -gt 1) { Write-Log "Multiple [Manufacturer] sections detected; editing first only." "Warning" }
    $m = $mc[0]
    $block = $m.Groups['blk'].Value
    $rxAti = [regex]::new('(?im)^\s*%ATI%\s*=\s*ATI\.Mfg\s*,\s*(?<list>.+?)\s*$', [System.Text.RegularExpressions.RegexOptions]::IgnoreCase -bor [System.Text.RegularExpressions.RegexOptions]::Multiline)
    if ($rxAti.IsMatch($block)) {
        $mAti = $rxAti.Match($block)
        $list = $mAti.Groups['list'].Value.Trim()
        $items = $list -split '\s*,\s*' | Where-Object { $_ } | Select-Object -Unique
        if ($items -notcontains $Decoration) {
            $newList = ($items + $Decoration) -join ', '
            $block = $rxAti.Replace($block, ($mAti.Value -replace [regex]::Escape($list), $newList), 1)
            Write-Log "Added $Decoration to [Manufacturer] ATI line." "Success"
        }
    } else {
        $block = "`r`n%ATI% = ATI.Mfg, $Decoration`r`n" + $block
        Write-Log "Inserted missing '%ATI% = ATI.Mfg, ...' with $Decoration in [Manufacturer]." "Success"
    }
    $head = $Text.Substring(0, $m.Groups['blk'].Index)
    $tailIx = $m.Groups['blk'].Index + $m.Groups['blk'].Length
    $tail = if ($tailIx -lt $Text.Length) { $Text.Substring($tailIx) } else { "" }
    return ($head + $block + $tail)
}

function Fix-AtiMfgSectionHeaders {
    param([string]$Text, [string]$Decoration)
    if ([string]::IsNullOrWhiteSpace($Text)) { return $Text }
    $opts = [System.Text.RegularExpressions.RegexOptions]::IgnoreCase -bor [System.Text.RegularExpressions.RegexOptions]::Multiline
    $rx = [regex]::new('^\s*\[ATI\.Mfg\.NTamd64[^\]\r\n]*\]?', $opts)
    $count = 0
    $out = $rx.Replace($Text, { param($m) $count++; "[ATI.Mfg.$Decoration]" })
    if ($count -gt 0) { Write-Log "Normalized $count ATI.Mfg section header(s) to [ATI.Mfg.$Decoration]." "Success" }
    $out
}

function Patch-INFAndManifests {
    param([string]$Root, [string]$Target, [string]$CustomDecoration, [bool]$PatchManifest)
    if (-not (Test-Path -LiteralPath $Root)) { Write-Log "Root not found: $Root" "Error"; return @{ error = 'root_not_found' } }
    $decoration = if ($Target -eq 'Custom') {
        if ([string]::IsNullOrWhiteSpace($CustomDecoration)) { Write-Log "Custom target requires a decoration string." "Error"; return @{ error = 'custom_decoration_missing' } }
        $CustomDecoration
    } else { $ValidTargets[$Target] }
    Write-Log "Using decoration: $decoration" "Info"
    $infFiles = Get-ChildItem -Path $Root -Recurse -Filter *.inf -EA SilentlyContinue |
                Where-Object {
                    $_.FullName -match '\\Display\\WT6A_INF\\' -or
                    $_.DirectoryName -match 'WT6A_INF' -or
                    $_.Name -match '^u\d+\.inf$' -or
                    $_.Name -like 'ati2mtag_*.inf'
                }
    if (-not $infFiles) { Write-Log "No INF files found in $Root matching criteria." "Warning" }
    else {
        foreach ($inf in $infFiles) {
            try {
                $content = Read-TextFileSafe -Path $inf.FullName
                if ($null -eq $content) { Write-Log "Skip empty/unreadable INF: $($inf.FullName)" "Warning"; continue }
                $original = $content
                $content = [string](Update-ManufacturerBlock -Text $content -Decoration $decoration)
                $content = [string](Fix-AtiMfgSectionHeaders -Text $content -Decoration $decoration)
                $rep = [regex]::Replace($content, '^(?=\s*%[^%]+\s*=\s*[^,\r\n]+,)\s*(.+?),\s*NTamd64[^\s,;\]\r\n]*', '$1, ' + $decoration, 'IgnoreCase, Multiline')
                $cnt = ([regex]::Matches($original, '^(?=\s*%[^%]+\s*=\s*[^,\r\n]+,)\s*(.+?),\s*NTamd64[^\s,;\]\r\n]*', 'IgnoreCase, Multiline')).Count
                if ($cnt -gt 0) { Write-Log "Updated $cnt device mapping line(s) to $decoration." "Success" }
                if ($content -ne $original) {
                    $bak = Backup-File -FilePath $inf.FullName
                    if (Write-TextFileSafe -Path $inf.FullName -Text $content -Encoding ASCII) {
                        Write-Log "Patched INF: $($inf.FullName) (backup: $bak)" "Success"
                    } else {
                        Write-Log "Failed to write INF: $($inf.FullName) — reverting backup" "Error"
                        try { Move-Item -LiteralPath $bak -Destination $inf.FullName -Force } catch {}
                    }
                } else {
                    Write-Log "No changes needed: $($inf.FullName)" "Info"
                }
            } catch { Write-Log "Failed to patch INF $($inf.FullName): $_" "Error" }
        }
    }
    if ($PatchManifest) {
        $manifestFiles = Get-ChildItem -Path $Root -Recurse -File -EA SilentlyContinue |
                         Where-Object {
                             ($_.Extension -in '.json','.xml') -and (
                                 $_.Name -match '(?i)manifest' -or
                                 $_.Name -eq 'package.xml' -or
                                 $_.Name -eq 'driver.json' -or
                                 $_.Directory.Name -match 'package|config'
                             )
                         }
        foreach ($m in $manifestFiles) {
            try {
                $txt = Read-TextFileSafe -Path $m.FullName
                if ($null -eq $txt) { Write-Log "Skip empty/unreadable manifest: $($m.FullName)" "Warning"; continue }
                $orig = $txt
                if ($m.Extension -ieq '.json') {
                    $txt = [regex]::Replace($txt, '(?i)"(Min(?:OS|Build|Version|OSVersion|OSBuild))"\s*:\s*".+?"', '"$1":"10.0.0.0"')
                    $txt = [regex]::Replace($txt, '(?i)"(Max(?:OS|Build|Version|OSVersion|OSBuild|OSVersionTested))"\s*:\s*".+?"', '"$1":"10.0.99999.0"')
                    $txt = [regex]::Replace($txt, '(?i)"SupportedOS(?:es|List)"\s*:\s*\[(.*?)\]', '"SupportedOS":[$1,"WindowsServer"]')
                } elseif ($m.Extension -ieq '.xml') {
                    if ($txt -match '<supportedOperatingSystems>') {
                        if ($txt -notmatch '<os.*?WindowsServer') {
                            $txt = $txt -replace '(<supportedOperatingSystems>)', '$1<windowsServer/>'
                            Write-Log "Added <windowsServer/> to $m" "Success"
                        }
                    }
                }
                if ($txt -ne $orig) {
                    $bak = Backup-File -FilePath $m.FullName
                    if (Write-TextFileSafe -Path $m.FullName -Text $txt -Encoding UTF8) {
                        Write-Log "Patched manifest: $($m.FullName) (backup: $bak)" "Success"
                    } else {
                        Write-Log "Failed to write manifest: $($m.FullName) — reverting backup" "Error"
                        try { Move-Item -LiteralPath $bak -Destination $m.FullName -Force } catch {}
                    }
                } else {
                    Write-Log "Manifest unchanged: $($m.FullName)" "Info"
                }
            } catch { Write-Log "Manifest patch failed for $($m.FullName): $_" "Error" }
        }
    }
    Write-Log "Patching completed." "Success"
    return @{ status = 'ok' }
}

# ---------- Install Logic ----------
function Is-TestSigningOn { try { (bcdedit /enum "{current}" | Out-String) -match 'testsigning\s+Yes' } catch { $false } }
function Enable-TestSigning {
    try {
        bcdedit /set testsigning on | Out-Null
        Write-Log "✅ Test Signing enabled. Please REBOOT your system." "Success"
        Write-Log "After reboot, return to this tool and click 'Install Driver' again." "Info"
        New-Item -ItemType File -Path $Script:PendingRebootFlag -Force | Out-Null
        return $true
    } catch { Write-Log "Failed to enable Test Signing: $($_.Exception.Message)" "Error"; return $false }
}
function Install-PatchedDriver {
    param([string]$RootPath)
    if (-not (Test-Path -LiteralPath $RootPath)) { return @{ status='failed'; error='root_not_found' } }

    $osInfo = Get-CimInstance -ClassName Win32_OperatingSystem
    $isServer = $osInfo.ProductType -eq 3 -or $osInfo.Caption -match "Server"

    if ($isServer -and -not (Is-TestSigningOn)) {
        Write-Log "⚠️ Driver Signature Enforcement is active." "Warning"
        Write-Log "To install patched drivers, Test Signing must be enabled." "Info"
        if (Enable-TestSigning) {
            return @{ status = 'reboot_required' }
        } else {
            return @{ status = 'failed'; error = 'enable_testsigning_failed' }
        }
    }

    $infFiles = Get-ChildItem -Path $RootPath -Recurse -Filter *.inf |
                Where-Object {
                    $_.Name -like 'ati2mtag_*.inf' -or
                    $_.Name -match '^u\d+\.inf$' -or
                    $_.DirectoryName -match 'WT6A_INF'
                }

    if (-not $infFiles) { return @{ status='failed'; error='no_inf' } }

    $installed = 0
    foreach ($inf in $infFiles) {
        try {
            $result = pnputil /add-driver "$($inf.FullName)" /install 2>&1
            if ($LASTEXITCODE -eq 0) {
                Write-Log "✅ Installed driver: $($inf.Name)" "Success"
                $installed++
            } else {
                Write-Log "⚠️ pnputil failed for $($inf.Name): $result" "Warning"
            }
        } catch {
            Write-Log "❌ Exception installing $($inf.Name): $_" "Error"
        }
    }

    if ($installed -gt 0) {
        Write-Log "🎉 Successfully installed $installed driver(s). Reboot recommended." "Success"
        return @{ status='ok'; drivers=$installed }
    } else {
        return @{ status='failed'; error='no_drivers_installed' }
    }
}

# ---------- WebView2 Detection & Install ----------
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
    Write-Log ("WebView2 pre-check: {0}" -f ($(if($pre){'installed'}else{'missing'})))
    if ($pre) { return $true }
    if (Ensure-WinGet) { [void](Install-WebView2-ByWinGet) } else { Write-Log "winget not available." }
    if (-not (Test-WebView2Installed)) { if (Ensure-Chocolatey) { [void](Install-WebView2-ByChoco) } else { Write-Log "Chocolatey not available and install failed." } }
    if (-not (Test-WebView2Installed)) { [void](Install-WebView2-ByBootstrapper) }
    $post = Test-WebView2Installed
    Write-Log ("WebView2 final-check: {0}" -f ($(if($post){'installed'}else{'missing'})))
    return $post
}

# ---------- HTTP Server ----------
function Start-Server {
    $port = Select-Port
    $prefix1 = 'http://127.0.0.1:{0}/' -f $port
    $prefix2 = 'http://localhost:{0}/' -f $port
    $Script:BindAddress = $prefix1
    $Script:BindAddressAlt = $prefix2

    Set-Content -Path $Script:ReqCountPath -Value '0' -Encoding ASCII -Force

    $listener = [HttpListener]::new()
    $listener.Prefixes.Add($prefix1)
    $listener.Prefixes.Add($prefix2)
    try { $listener.Start() } catch { throw "Failed to start HTTP listener on $prefix1 : $($_.Exception.Message)" }
    Write-Log "Web UI at $prefix1"

    $runner = {
        param($listener, $Html, $ReqCountPath)
        function Inc-Req {
            param([string]$Path)
            try {
                $n = 0
                if (Test-Path $Path) { $s = Get-Content -LiteralPath $Path -Raw -ErrorAction SilentlyContinue; if ($s -match '^\d+$') { $n = [int]$s } }
                $n++
                Set-Content -LiteralPath $Path -Value ([string]$n) -Encoding ASCII -Force
            } catch {}
        }
        while ($listener.IsListening) {
            try {
                $ctx = $listener.GetContext()
                $req = $ctx.Request
                $res = $ctx.Response
                Inc-Req -Path $ReqCountPath
                [Console]::WriteLine("[{0}] {1} {2}" -f (Get-Date).ToString('HH:mm:ss'), $req.HttpMethod, $req.RawUrl)
                if ($req.HttpMethod -eq 'GET' -and $req.Url.AbsolutePath -eq '/') {
                    $bytes = [Text.Encoding]::UTF8.GetBytes($Html); $res.ContentType='text/html; charset=utf-8'; $res.OutputStream.Write($bytes,0,$bytes.Length); $res.Close(); continue
                }
                if ($req.HttpMethod -eq 'GET' -and $req.Url.AbsolutePath -eq '/favicon.ico') {
                    $res.StatusCode = 204; $res.Close(); continue
                }
                if ($req.HttpMethod -eq 'POST' -and $req.Url.AbsolutePath -eq '/api') {
                    $reader = New-Object IO.StreamReader($req.InputStream, $req.ContentEncoding); $body=$reader.ReadToEnd(); $reader.Close()
                    $payload = @{ root = ''; target = 'Server2025'; customDecoration = ''; patchManifest = $true }
                    if ($body) { try { $payload = $body | ConvertFrom-Json } catch {} }
                    $action = $payload.action
                    $result = switch ($action) {
                        'patch' { Patch-INFAndManifests -Root $payload.root -Target $payload.target -CustomDecoration $payload.customDecoration -PatchManifest $payload.patchManifest }
                        'revert' { Revert-AllChanges }
                        'install' { Install-PatchedDriver -RootPath $payload.root }
                        default { @{ error='unknown_action' } }
                    }
                    $resp = @{ result=$result; log=Get-LogsHtml } | ConvertTo-Json -Depth 6
                    $bytes = [Text.Encoding]::UTF8.GetBytes($resp); $res.ContentType='application/json; charset=utf-8'
                    $res.OutputStream.Write($bytes,0,$bytes.Length); $res.Close(); continue
                }
                $res.StatusCode = 404; $res.Close()
            } catch { try { $res.StatusCode = 500; $res.Close() } catch {};  }
        }
    }

    $job = Start-Job -ScriptBlock $runner -ArgumentList $listener, $Html, $Script:ReqCountPath
    return @{ listener = $listener; job = $job; port = $port }
}

# ---------- Edge Launch ----------
function Get-EdgePath {
    $candidates = @(
        "${env:ProgramFiles}\Microsoft\Edge\Application\msedge.exe",
        "${env:ProgramFiles(x86)}\Microsoft\Edge\Application\msedge.exe"
    )
    foreach ($p in $candidates) { if (Test-Path $p) { return $p } }
    return $null
}
function Launch-EdgeAppWindow {
    param([string]$Url)
    $edge = Get-EdgePath
    if (-not $edge) { throw "Microsoft Edge not found in Program Files." }
    $screen = [System.Windows.Forms.Screen]::PrimaryScreen.Bounds
    $w = [int]([double]$screen.Width * 0.5)
    $h = [int]([double]$screen.Height * 0.8)
    $x = [int](($screen.Width - $w) / 2)
    $y = [int](($screen.Height - $h) / 2)
    $args = @("--app=$Url","--window-size=$w,$h","--window-position=$x,$y")
    Start-Process -FilePath $edge -ArgumentList $args | Out-Null
}

#region ==================== Embedded Frontend HTML ====================
$Html = @'
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"/>
<title>AMD INF Patcher Web UI</title>
<link rel="stylesheet" href="https://stackpath.bootstrapcdn.com/bootstrap/4.5.2/css/bootstrap.min.css"/>
<script src="https://cdn.jsdelivr.net/npm/marked/marked.min.js"></script>
<style>
:root{
 --bg:#07070a;--card:#0e0f12;--text:#e6e8ee;
 --red:#a91d25;--silver:#d4d8dc;--bluegray:#6e91a8;
 --border:#1b1e27;--hover:#181b22;--input:#161922;
 --accent:#00d4ff;--btn-danger:#e04545;
}
*{box-sizing:border-box}
body{
 margin:0;height:100vh;display:flex;overflow:hidden;
 font-family:Consolas, monospace;
 background:radial-gradient(70% 90% at 50% 30%,#0c0d11 0%,#090909 70%,#07070a 100%);
 color:var(--text);
}
.sidebar{
 width:260px;min-width:260px;height:100%;background:var(--card);
 border-right:2px solid var(--bluegray);padding:20px 15px;
 display:flex;flex-direction:column;z-index:2;
}
.sidebar-title{
 font-size:1.3rem;font-weight:800;text-transform:uppercase;
 color:var(--silver);text-shadow:0 0 10px var(--bluegray);
 animation:strobe 5s linear infinite;
}
@keyframes strobe{
 0%,100%{filter:brightness(.8);}
 50%{filter:brightness(1.6);}
}
.nav-item{padding:12px 18px;margin:5px 0;border-radius:6px;cursor:pointer;
 color:var(--silver);display:flex;align-items:center;}
.nav-item:hover{background:var(--hover);color:#fff;text-shadow:0 0 3px var(--bluegray);}
.nav-item.active{background:linear-gradient(90deg,var(--red),var(--bluegray));color:#0b0c10;font-weight:700}
.welcome-message {
 padding: 15px;
 background: rgba(100, 100, 100, 0.1);
 color: white;
 font-size: 0.9rem;
 line-height: 1.5;
 font-family: Consolas, monospace;
 border-radius: 8px;
 margin-bottom: 15px;
}
.main-content{flex:1;display:flex;flex-direction:column;overflow:hidden;padding:20px;position:relative}
.header{display:flex;justify-content:space-between;align-items:center;margin-bottom:10px;padding-bottom:10px;border-bottom:1px solid var(--border)}
.header h1{font-size:1.5rem;font-weight:800;color:var(--silver);text-shadow:0 0 12px var(--bluegray);}
.chat-container{flex:1;display:flex;flex-direction:column;overflow:hidden;position:relative}
.chat-messages{flex:1;overflow-y:auto;padding:15px;display:flex;flex-direction:column;gap:10px;z-index:1}
#ri-logo-wrap{position:absolute;inset:0;display:flex;align-items:center;justify-content:center;pointer-events:none;z-index:0}
.ri-tilt{width:340px;height:340px;perspective:900px;transform-style:preserve-3d;opacity:.97;
 filter:drop-shadow(0 0 25px rgba(110,145,168,.4)) drop-shadow(0 0 30px rgba(132,26,26,.3));}
.ri-tilt>svg{width:100%;height:100%;transform-style:preserve-3d;animation:earthSpin 18s linear infinite;}
@keyframes earthSpin{from{transform:rotateX(22deg) rotateY(0deg);}to{transform:rotateX(22deg) rotateY(360deg);}}
.message{max-width:80%;padding:12px 16px;border-radius:10px;word-break:break-word;box-shadow:0 2px 6px rgba(0,0,0,.3);animation:fadeIn .25s ease}
@keyframes fadeIn{from{opacity:0;transform:translateY(6px)}to{opacity:1;transform:translateY(0)}}
.user-message{align-self:flex-end;background:#0f1219;border:1px solid #2a3140}
.assistant-message{align-self:flex-start;color:#0b0c10;
 background:linear-gradient(90deg,rgba(169,29,37,.6),rgba(110,145,168,.6));box-shadow:0 0 12px rgba(110,145,168,.4)}
.input-area{display:flex;gap:10px;padding:15px;border-top:1px solid var(--border);background:var(--card)}
textarea{flex:1;min-height:60px;background:var(--input);color:var(--text);
 border:1px solid var(--border);border-radius:6px;padding:12px;resize:vertical;}
.btn-send{background:linear-gradient(90deg,var(--red),var(--bluegray));color:#0b0c10;font-weight:700}
.btn-clear{background:#13161e;color:var(--text)}
.btn-stop{background:var(--btn-danger);color:#fff}
.module{background:var(--card);border:2px solid var(--bluegray);padding:8px;border-radius:6px}
.module-header{text-align:center;font-weight:700;color:var(--silver)}
::-webkit-scrollbar{width:10px}
::-webkit-scrollbar-thumb{background:var(--bluegray);border-radius:5px}

/* LOG WRAPPING FIX */
.log-output {
  width: 100%;
  white-space: pre-wrap;
  word-wrap: break-word;
  font-family: Consolas, monospace;
  font-size: 0.9rem;
  color: var(--text);
  line-height: 1.4;
  padding: 10px;
  background: rgba(0,0,0,0.2);
  border-radius: 6px;
  margin: 5px 0;
}
.sidebar-controls {
 padding: 15px;
 background: var(--card);
 border-top: 1px solid var(--border);
 margin-top: auto;
}
.sidebar-controls .form-group {
 margin-bottom: 10px;
}
.sidebar-controls label {
 color: var(--text);
 font-size: 0.85rem;
}
.sidebar-controls .form-control {
 background: var(--input);
 color: var(--text);
 border: 1px solid var(--border);
 border-radius: 6px;
}
.sidebar-controls .btn {
 width: 100%;
 margin-bottom: 5px;
}
</style>
</head>
<body>
<div class="sidebar">
  <div class="sidebar-title">AMD INF Patcher</div>
  <div class="nav-item active" data-section="patch">Patch Driver</div>
  <div class="nav-item" data-section="revert">Revert Changes</div>
  <div class="sidebar-controls">
    <div class="form-group">
      <label for="target">Target OS</label>
      <select id="target" class="form-control">
        <option value="Generic">Generic</option>
        <option value="Server2019_2">Server2019_2</option>
        <option value="Server2019_3">Server2019_3</option>
        <option value="Server2022">Server2022</option>
        <option value="Win11_24H2">Win11_24H2</option>
        <option value="Server2025" selected>Server2025</option>
        <option value="Win7">Windows 7</option>
        <option value="Custom">Custom</option>
      </select>
    </div>
    <div class="form-group">
      <label for="customDec">Custom Decoration</label>
      <input type="text" id="customDec" class="form-control" placeholder="e.g., NTamd64.10.0...26100" style="display:none;"/>
    </div>
    <div class="form-check">
      <input class="form-check-input" type="checkbox" id="patchManifest" checked>
      <label class="form-check-label" for="patchManifest">Patch Manifest</label>
    </div>
    <button class="btn btn-send mt-3" id="send">Patch</button>
    <button class="btn btn-success mt-2" id="installBtn">Install Patched Driver</button>
    <button class="btn btn-stop mt-2" id="revertBtn">Revert All</button>
    <a href="https://www.amd.com/en/support" target="_blank" class="btn btn-secondary mt-2" style="text-align:center;">🌐 AMD Drivers Page</a>
  </div>
</div>
<div class="main-content">
  <div class="header">
    <h1>AMD INF Patcher Web UI</h1>
    <span style="font-size:0.8rem;color:var(--silver);">Powered by | Rarity Intelligence™</span>
  </div>
  <div class="chat-container">
    <div id="ri-logo-wrap"><div class="ri-tilt">
      <svg viewBox="0 0 512 512">
        <defs>
          <clipPath id="rclip"><rect x="32" y="32" width="448" height="448" rx="48" ry="48"/></clipPath>
          <radialGradient id="rfade" cx="50%" cy="50%" r="60%">
            <stop offset="78%" stop-color="white" stop-opacity="1"/>
            <stop offset="100%" stop-color="white" stop-opacity="0"/>
          </radialGradient>
          <mask id="rmask"><rect width="512" height="512" fill="url(#rfade)"/></mask>
          <filter id="rglow" x="-50%" y="-50%" width="200%" height="200%">
            <feGaussianBlur in="SourceAlpha" stdDeviation="2" result="b"/>
            <feMerge><feMergeNode in="b"/><feMergeNode in="SourceGraphic"/></feMerge>
            <feDropShadow dx="0" dy="0" stdDeviation="6" flood-color="#6e91a8" flood-opacity=".45"/>
            <feDropShadow dx="0" dy="0" stdDeviation="10" flood-color="#a91d25" flood-opacity=".35"/>
          </filter>
        </defs>
        <g filter="url(#rglow)">
          <image x="32" y="32" width="448" height="448"
            clip-path="url(#rclip)" mask="url(#rmask)"
            href="https://raw.githubusercontent.com/Vilonauzd/images/HEAD/rarity_logo_19.png"
            preserveAspectRatio="xMidYMid meet"/>
        </g>
      </svg>
    </div></div>
    <div class="chat-messages" id="chat"></div>
    <div class="input-area">
      <textarea id="prompt" placeholder="Enter driver root path (e.g., C:\\AMD\\Drivers)"></textarea>
      <button class="btn btn-secondary" id="browseBtn" style="width:160px;">Source Driver Path</button>
      <button class="btn btn-clear" id="clear">Clear Log</button>
    </div>
  </div>
</div>
<script>
let apiBase = 'http://127.0.0.1:8080';
const chat = document.getElementById('chat');
const targetSelect = document.getElementById('target');
const customDecInput = document.getElementById('customDec');
const browseBtn = document.getElementById('browseBtn');

function appendMsg(role, text) {
  const d = document.createElement('div');
  d.className = `message ${role}-message`;
  d.innerHTML = marked.parse(text);
  chat.appendChild(d);
  chat.scrollTop = chat.scrollHeight;
}

function validatePath(path) {
  return path && path.trim() !== '' && /^[a-zA-Z]:[\\\\/].*/.test(path.trim());
}

async function sendPatchRequest() {
  const rootPath = document.getElementById('prompt').value.trim();
  if (!validatePath(rootPath)) {
    appendMsg('assistant', '❌ Invalid driver root path. Must be a valid Windows absolute path (e.g., C:\\\\AMD\\\\Drivers).');
    return;
  }
  const target = targetSelect.value;
  let customDec = '';
  if (target === 'Custom') {
    customDec = customDecInput.value.trim();
    if (!customDec) {
      appendMsg('assistant', '❌ Custom decoration is required when "Custom" target is selected.');
      return;
    }
  }
  const patchManifest = document.getElementById('patchManifest').checked;
  appendMsg('user', `Patch Request:\
- Root: \`${rootPath}\`\
- Target: \`${target}\`${target === 'Custom' ? `\
- Decoration: \`${customDec}\`` : ''}\
- Patch Manifest: ${patchManifest ? 'Yes' : 'No'}`);
  const payload = {
    action: 'patch',
    root: rootPath,
    target: target,
    customDecoration: customDec,
    patchManifest: patchManifest
  };
  try {
    const resp = await fetch(`${apiBase}/api`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload)
    });
    const json = await resp.json();
    if (!resp.ok) throw new Error(json.result?.error || `HTTP ${resp.status}`);
    if (json.log) {
      const logDiv = document.createElement('div');
      logDiv.className = 'log-output';
      logDiv.textContent = json.log;
      chat.appendChild(logDiv);
    }
    chat.scrollTop = chat.scrollHeight;
  } catch (e) {
    appendMsg('assistant', `❌ Patch failed: ${e.message}`);
  }
}

async function sendRevertRequest() {
  appendMsg('user', 'Revert All Changes Request');
  try {
    const resp = await fetch(`${apiBase}/api`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ action: 'revert' })
    });
    const json = await resp.json();
    if (!resp.ok) throw new Error(json.result?.error || `HTTP ${resp.status}`);
    if (json.log) {
      const logDiv = document.createElement('div');
      logDiv.className = 'log-output';
      logDiv.textContent = json.log;
      chat.appendChild(logDiv);
    }
    chat.scrollTop = chat.scrollHeight;
  } catch (e) {
    appendMsg('assistant', `❌ Revert failed: ${e.message}`);
  }
}

async function sendInstallRequest() {
  const rootPath = document.getElementById('prompt').value.trim();
  if (!validatePath(rootPath)) {
    appendMsg('assistant', '❌ Invalid driver path. Please select a valid folder.');
    return;
  }
  appendMsg('user', `Install Request: \`${rootPath}\``);
  try {
    const resp = await fetch(`${apiBase}/api`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ action: 'install', root: rootPath })
    });
    const json = await resp.json();
    if (!resp.ok) throw new Error(json.result?.error || `HTTP ${resp.status}`);
    if (json.log) {
      const logDiv = document.createElement('div');
      logDiv.className = 'log-output';
      logDiv.textContent = json.log;
      chat.appendChild(logDiv);
    }
    chat.scrollTop = chat.scrollHeight;
  } catch (e) {
    appendMsg('assistant', `❌ Install failed: ${e.message}`);
  }
}

browseBtn.onclick = async () => {
  try {
    const resp = await fetch(`${apiBase}/browse`, { method: 'GET' });
    if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
    const path = await resp.text();
    document.getElementById('prompt').value = path;
    appendMsg('assistant', `📁 Selected path: \`${path}\``);
  } catch (e) {
    appendMsg('assistant', `❌ Browse failed: ${e.message}`);
  }
};

targetSelect.addEventListener('change', () => {
  customDecInput.style.display = targetSelect.value === 'Custom' ? 'block' : 'none';
});

document.getElementById('send').onclick = sendPatchRequest;
document.getElementById('revertBtn').onclick = sendRevertRequest;
document.getElementById('installBtn').onclick = sendInstallRequest;
document.getElementById('clear').onclick = () => { chat.innerHTML = ''; };

const welcomeDiv = document.createElement('div');
welcomeDiv.className = 'welcome-message';
welcomeDiv.textContent = "Welcome to AMD INF Patcher Web UI.\nEnter a valid driver root path, select your target OS, and click Patch to begin.\nUse Revert All to restore original files from backups.";
chat.appendChild(welcomeDiv);
</script>
</body>
</html>
'@
#endregion

# ----------------------- Main -----------------------
Assert-Admin
Write-Log "Starting Rarity Intelligence™ AMD INF Patcher UI"

# Ensure C:\RepairLogs
if (-not (Test-Path $Script:BackupBase)) { New-Item -ItemType Directory -Path $Script:BackupBase -Force | Out-Null }

$server = Start-Server

# Strict WebView2 check and install
if (-not (Ensure-WebView2-Strict)) {
    Write-Log "WebView2 install/verify failed. Exiting."
    if ($server.listener) { $server.listener.Stop() }
    if ($server.job) { Stop-Job $server.job | Out-Null; Remove-Job $server.job | Out-Null }
    exit 2
}

# Launch after delay
Start-Sleep -Milliseconds 300
try { Launch-EdgeAppWindow -Url $Script:BindAddress } catch { Write-Log "Edge launch failed: $($_.Exception.Message)" }

# Auto-retry with localhost
Start-Sleep -Seconds 3
$reqCount = 0
try { if (Test-Path $Script:ReqCountPath) { $s = Get-Content -LiteralPath $Script:ReqCountPath -Raw -ErrorAction SilentlyContinue; if ($s -match '^\d+$') { $reqCount = [int]$s } } } catch {}
if ($reqCount -lt 1) {
    Write-Log "No requests seen on 127.0.0.1. Launching a second window to localhost."
    try { Launch-EdgeAppWindow -Url $Script:BindAddressAlt } catch { Write-Log "Second launch failed: $($_.Exception.Message)" }
}

if (Test-Path $Script:PendingRebootFlag) { Write-Log "System is in TestSigning mode. You can now use 'Install Patched Driver'." }

try { while ($true) { Start-Sleep -Seconds 1 } }
finally {
    if ($server.listener) { $server.listener.Stop() }
    if ($server.job) { Stop-Job $server.job | Out-Null; Remove-Job $server.job | Out-Null }
}