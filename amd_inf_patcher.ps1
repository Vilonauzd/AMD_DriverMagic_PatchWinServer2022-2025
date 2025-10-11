#requires -RunAsAdministrator
<#
    AMD INF Patcher – WPF Edition (v2.9)
    UI:
      • Log panel hard-capped to 50% of window height (never hides controls)
      • Modern palette: maroon reds, blue-grays, subtle gradients, shadows
      • Buttons and inputs keep space; responsive layout

    Engine:
      • Same hardened logic as v2.7 (safe reads/writes, robust regex, backups)
      • Server2019_2/_3 targets included

    PowerShell 5.1+ / .NET Framework 4.8
    © AMD_DriverMagic | Reddit Community
#>

param([string]$InitialRootPath = '')

#region ==================== Global State & Constants ====================
$script:LogLines       = [System.Collections.ArrayList]::new()
$script:CurrentLogPath = $null
$script:SessionID      = (Get-Date -Format 'yyyyMMdd_HHmmss')
$script:BackupBase     = "C:\RepairLogs"
$script:txtLogControl  = $null

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

#region ==================== Logging & Common ============================
function Write-Log {
    param(
        [Parameter(Mandatory)][AllowNull()][AllowEmptyString()][string]$Message,
        [ValidateSet('Info','Success','Warning','Error')][string]$Level='Info'
    )
    if ($null -eq $Message) { return }
    $Message  = [string]$Message
    if ([string]::IsNullOrWhiteSpace($Message)) { return }

    $timeStamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    $entry     = "[$timeStamp] [$Level] $Message"
    [void]$script:LogLines.Add($entry)

    if ($script:txtLogControl -and $script:txtLogControl.IsInitialized) {
        $action = {
            try {
                $p = New-Object System.Windows.Documents.Paragraph
                $r = New-Object System.Windows.Documents.Run($entry)
                $p.Inlines.Add($r)
                $script:txtLogControl.Document.Blocks.Add($p)
                $script:txtLogControl.ScrollToEnd()
            } catch {}
        }
        try {
            if ($script:txtLogControl.Dispatcher.CheckAccess()) { & $action } else { $script:txtLogControl.Dispatcher.Invoke($action) }
        } catch {}
    }

    if ($script:CurrentLogPath) { try { Add-Content -Path $script:CurrentLogPath -Value $entry -EA Stop } catch {} }
}

function Get-FunctionText {
    param([string[]]$Names)
    $out=@{}
    foreach($n in $Names){
        try {
            $sb = (Get-Command -Name $n -CommandType Function -EA SilentlyContinue).ScriptBlock
            if($sb){
                $txt=$sb.ToString()
                if(-not [string]::IsNullOrWhiteSpace($txt)){$out[$n]=$txt}
            }
        } catch { Write-Log "Get-FunctionText error on $n :: $_" "Warning" }
    }
    $out
}

# Safe file read with BOM detection and size cap; returns $null for empty/whitespace/binary
function Read-TextFileSafe {
    param(
        [Parameter(Mandatory)][ValidateNotNullOrEmpty()][string]$Path,
        [int]$MaxBytes=10485760
    )
    try {
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
    } catch { Write-Log "Read error: $Path :: $_" "Error"; return $null }
}

# Safe file write; ASCII for INF, UTF8 for JSON
function Write-TextFileSafe {
    param(
        [Parameter(Mandatory)][ValidateNotNullOrEmpty()][string]$Path,
        [Parameter(Mandatory)][AllowNull()][AllowEmptyString()][string]$Text,
        [ValidateSet('ASCII','UTF8')]$Encoding='ASCII'
    )
    try {
        if ($null -eq $Text) { Write-Log "Write skip. Null text to $Path" "Warning"; return $false }
        $Text = [string]$Text
        if ($Encoding -eq 'ASCII') {
            [System.IO.File]::WriteAllText($Path, $Text, [System.Text.Encoding]::ASCII)
        } else {
            [System.IO.File]::WriteAllText($Path, $Text, [System.Text.Encoding]::UTF8)
        }
        return $true
    } catch { Write-Log "Write error: $Path :: $_" "Error"; return $false }
}
#endregion

#region ==================== Dependency Checks ===========================
function Ensure-Dependencies {
    Write-Log "Checking system dependencies..." "Info"
    try {
        if ($PSVersionTable.PSVersion.Major -lt 5) { Write-Log "PowerShell 5.1 or later is required." "Error"; return $false }
        $isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
        if (-not $isAdmin) { Write-Log "Administrator privileges required." "Error"; return $false }
        if (-not (Test-Path $script:BackupBase)) {
            New-Item -ItemType Directory -Path $script:BackupBase -Force | Out-Null
            Write-Log "Created log dir: $($script:BackupBase)" "Success"
        }
        Write-Log "All dependencies satisfied." "Success"; return $true
    } catch { Write-Log "Dependency check error: $_" "Error"; return $false }
}
#endregion

#region ==================== Backup / Revert =============================
function Backup-File {
    param([Parameter(Mandatory)][ValidateNotNullOrEmpty()][string]$FilePath)
    if (-not (Test-Path -LiteralPath $FilePath)) { throw "File not found: $FilePath" }
    try {
        $hash = (Get-FileHash -Path $FilePath -Algorithm SHA256).Hash.Substring(0,8)
        $backupName = "$FilePath.bak_$($script:SessionID)_$hash"
        Copy-Item -LiteralPath $FilePath -Destination $backupName -Force
        $backupName
    } catch { throw "Backup failed for $FilePath :: $_" }
}

function Revert-AllChanges {
    Write-Log "Starting full revert process..." "Warning"
    try {
        $logFiles = Get-ChildItem -Path $script:BackupBase -Filter "*amd_inf_patch_*.log" -EA SilentlyContinue
        $reverted = 0
        foreach ($log in $logFiles) {
            if ($log.BaseName -match 'amd_inf_patch_(\d{8}_\d{6})') {
                $sessionID = $matches[1]
                $pattern   = [regex]::Escape(".bak_$sessionID`_")
                $backups   = Get-ChildItem -Path "$script:BackupBase\*" -Include "*.bak_*" -Recurse -EA SilentlyContinue |
                             Where-Object { $_.Name -match $pattern }

                foreach ($bak in $backups) {
                    $orig = $bak.FullName -replace [regex]::Escape(".bak_$sessionID`_") + '[0-9a-f]{8}', ''
                    try {
                        if (Test-Path $orig) { Remove-Item -LiteralPath $orig -Force }
                        Move-Item -LiteralPath $bak.FullName -Destination $orig -Force
                        Write-Log "Reverted: $orig" "Success"; $reverted++
                    } catch { Write-Log "Revert failed for $orig : $_" "Error" }
                }
            }
        }
        if ($reverted -eq 0) { Write-Log "No revertable backups found." "Info" }
        else { Write-Log "Reverted $reverted file(s)." "Success" }
    } catch { Write-Log "Revert error: $_" "Error" }
}
#endregion

#region ==================== Regex/Text Utilities ========================
function Safe-Replace {
    param(
        [Parameter(Mandatory)][AllowEmptyString()][string]$Input,
        [Parameter(Mandatory)][ValidateNotNullOrEmpty()][string]$Pattern,
        [Parameter(Mandatory)][AllowEmptyString()][string]$Replacement,
        [switch]$MultilineIgnoreCase
    )
    $Input = [string]$Input
    if ([string]::IsNullOrEmpty($Input)) { return ,@($Input,0) }
    try {
        $opts = [System.Text.RegularExpressions.RegexOptions]::None
        if ($MultilineIgnoreCase) { $opts = $opts -bor [System.Text.RegularExpressions.RegexOptions]::IgnoreCase -bor [System.Text.RegularExpressions.RegexOptions]::Multiline }
        $regex = [System.Text.RegularExpressions.Regex]::new($Pattern, $opts)
        $count = 0
        $evaluator = [System.Text.RegularExpressions.MatchEvaluator]{ param($m) $script:__ = $m; $script:count++; return $Replacement }
        $out = $regex.Replace($Input, $evaluator)
        ,@([string]$out, [int]$count)
    } catch { Write-Log "Safe-Replace error: $Pattern :: $_" "Error"; return ,@($Input,0) }
}

function Update-ManufacturerBlock {
    param(
        [Parameter(Mandatory)][AllowEmptyString()][string]$Text,
        [Parameter(Mandatory)][ValidateNotNullOrEmpty()][string]$Decoration
    )
    $Text = [string]$Text
    if ([string]::IsNullOrWhiteSpace($Text)) { return $Text }

    $opts = [System.Text.RegularExpressions.RegexOptions]::IgnoreCase -bor `
            [System.Text.RegularExpressions.RegexOptions]::Multiline -bor `
            [System.Text.RegularExpressions.RegexOptions]::Singleline

    $rx = [regex]::new('^\[Manufacturer\]\s*(?<blk>.*?)(?=^\[[^\]\r\n]+\]|\Z)', $opts)
    $mc = $rx.Matches($Text)
    if ($mc.Count -eq 0) {
        $prefix = "[Manufacturer]`r`n%ATI% = ATI.Mfg, $Decoration`r`n"
        Write-Log "No [Manufacturer] section. Prepending with ATI line." "Warning"
        return ($prefix + $Text)
    }
    if ($mc.Count -gt 1) { Write-Log "Multiple [Manufacturer] sections detected; editing first only." "Warning" }

    $m          = $mc[0]
    $block      = $m.Groups['blk'].Value
    $blockStart = $m.Groups['blk'].Index
    $blockLen   = $m.Groups['blk'].Length

    $rxAti = [regex]::new('(?im)^\s*%ATI%\s*=\s*ATI\.Mfg\s*,\s*(?<list>.+?)\s*$', [System.Text.RegularExpressions.RegexOptions]::IgnoreCase -bor [System.Text.RegularExpressions.RegexOptions]::Multiline)

    if ($rxAti.IsMatch($block)) {
        $mAti  = $rxAti.Match($block)
        $list  = $mAti.Groups['list'].Value.Trim()
        $items = $list -split '\s*,\s*' | Where-Object { $_ } | Select-Object -Unique
        if ($items -notcontains $Decoration) {
            $newList = ($items + $Decoration) -join ', '
            $block   = $rxAti.Replace($block, ($mAti.Value -replace [regex]::Escape($list), $newList), 1)
            Write-Log "Added $Decoration to [Manufacturer] ATI line." "Success"
        } else {
            Write-Log "Decoration $Decoration already present in [Manufacturer]." "Info"
        }
    } else {
        $block = "`r`n%ATI% = ATI.Mfg, $Decoration`r`n" + $block
        Write-Log "Inserted missing '%ATI% = ATI.Mfg, ...' with $Decoration in [Manufacturer]." "Success"
    }

    $head   = $Text.Substring(0, $blockStart)
    $tailIx = $blockStart + $blockLen
    $tail   = if ($tailIx -lt $Text.Length) { $Text.Substring($tailIx) } else { "" }
    return ($head + $block + $tail)
}

function Fix-AtiMfgSectionHeaders {
    param(
        [Parameter(Mandatory)][AllowEmptyString()][string]$Text,
        [Parameter(Mandatory)][ValidateNotNullOrEmpty()][string]$Decoration
    )
    $Text = [string]$Text
    if ([string]::IsNullOrWhiteSpace($Text)) { return $Text }

    $opts = [System.Text.RegularExpressions.RegexOptions]::IgnoreCase -bor [System.Text.RegularExpressions.RegexOptions]::Multiline
    $rx   = [regex]::new('^\s*\[ATI\.Mfg\.NTamd64[^\]\r\n]*\]?', $opts)

    $count = 0
    $out = $rx.Replace($Text, { param($m) $script:count++; "[ATI.Mfg.$Decoration]" })
    if ($count -gt 0) { Write-Log "Normalized $count ATI.Mfg section header(s) to [ATI.Mfg.$Decoration]." "Success" }
    else { Write-Log "No ATI.Mfg section headers matched for normalization." "Info" }
    $out
}
#endregion

#region ==================== Core Patching ===============================
function Patch-INFAndManifests {
    param(
        [Parameter(Mandatory)][ValidateNotNullOrEmpty()][string]$Root,
        [Parameter(Mandatory)][ValidateSet('Generic','Server2019_2','Server2019_3','Server2022','Win11_24H2','Server2025','Win7','Custom')][string]$Target,
        [AllowEmptyString()][string]$CustomDecoration,
        [bool]$PatchManifest
    )

    if (-not (Test-Path -LiteralPath $Root)) { Write-Log "Root not found: $Root" "Error"; return }

    $decoration = if ($Target -eq 'Custom') {
        if ([string]::IsNullOrWhiteSpace($CustomDecoration)) { Write-Log "Custom target requires a decoration string." "Error"; return }
        $CustomDecoration
    } else { $ValidTargets[$Target] }

    Write-Log "Using decoration: $decoration" "Info"
    $script:CurrentLogPath = Join-Path $script:BackupBase "amd_inf_patch_$($script:SessionID).log"
    Write-Log "Session log: $($script:CurrentLogPath)" "Info"

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

                $rep = Safe-Replace -Input $content `
                                    -Pattern '^(?=\s*%[^%]+\s*=\s*[^,\r\n]+,)\s*(.+?),\s*NTamd64[^\s,;\]\r\n]*' `
                                    -Replacement ('$1, ' + $decoration) `
                                    -MultilineIgnoreCase
                $content = [string]$rep[0]; $cnt = [int]$rep[1]
                if ($cnt -gt 0) { Write-Log "Updated $cnt device mapping line(s) to $decoration." "Success" }
                else { Write-Log "No device mapping lines required update." "Info" }

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
                             ($_.Extension -in '.json','.xml') -and ($_.Name -match '(?i)manifest')
                         }

        foreach ($m in $manifestFiles) {
            try {
                $txt = Read-TextFileSafe -Path $m.FullName
                if ($null -eq $txt) { Write-Log "Skip empty/unreadable manifest: $($m.FullName)" "Warning"; continue }
                $orig = $txt

                if ($m.Extension -ieq '.json') {
                    $rep1 = Safe-Replace -Input $txt -Pattern '(?i)"(Min(?:OS|Build|Version|OSVersion|OSBuild))"\s*:\s*".+?"' -Replacement '"$1":"10.0.0.0"'
                    $txt  = [string]$rep1[0]
                    $rep2 = Safe-Replace -Input $txt -Pattern '(?i)"(Max(?:OS|Build|Version|OSVersion|OSBuild|OSVersionTested))"\s*:\s*".+?"' -Replacement '"$1":"10.0.99999.0"'
                    $txt  = [string]$rep2[0]
                    $rep3 = Safe-Replace -Input $txt -Pattern '(?i)"SupportedOS(?:es|List)"\s*:\s*\[(.*?)\]' -Replacement '"SupportedOS":[$1,"WindowsServer"]'
                    $txt  = [string]$rep3[0]
                }

                if ($txt -ne $orig) {
                    $bak = Backup-File -FilePath $m.FullName
                    if (Write-TextFileSafe -Path $m.FullName -Text $txt -Encoding UTF8) {
                        Write-Log "Patched manifest: $($m.FullName) (backup: $bak)" "Success"
                    } else {
                        Write-Log "Failed to write manifest: $($m.FullName) — reverting backup" "Error"
                        try { Move-Item -LiteralPath $bak -Destination $m.FullName -Force } catch {}
                    }
                } else { Write-Log "Manifest unchanged: $($m.FullName)" "Info" }
            } catch { Write-Log "Manifest patch failed for $($m.FullName): $_" "Error" }
        }
    }

    Write-Log "Patching completed." "Success"
}
#endregion

#region ==================== Win7 Support Modal ==========================
function Show-Win7SupportWindow {
    $win7Xaml = @'
<Window xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
        xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
        Title="Windows 7 Support (Experimental)"
        Width="720" Height="620"
        WindowStartupLocation="CenterOwner"
        Background="#12141A"
        FontFamily="Consolas">
    <Grid Margin="15">
        <Grid.RowDefinitions>
            <RowDefinition Height="Auto"/>
            <RowDefinition Height="*"/>
            <RowDefinition Height="Auto"/>
        </Grid.RowDefinitions>

        <TextBlock Grid.Row="0" Text="Windows 7 + RDNA2/3 Warning" 
                   Foreground="#D53F3F" FontSize="18" FontWeight="Bold" Margin="0,0,0,10"/>

        <Border Grid.Row="1" Background="#0F1B2B" Padding="10" CornerRadius="8" BorderBrush="#263043" BorderThickness="1">
            <ScrollViewer VerticalScrollBarVisibility="Auto">
                <TextBlock Foreground="#E0E6ED" TextWrapping="Wrap">
                    <Run Text="AMD dropped Windows 7 support after April 2020 (Adrenalin 20.4.2)."/>
                    <LineBreak/><LineBreak/>
                    <Run Text="RDNA2/3 require WDDM 2.7+, which Windows 7 does NOT support."/>
                    <LineBreak/><LineBreak/>
                    <Run Text="This tool will attempt to patch INF with NTamd64.6.1...7601 and relax some manifests."/>
                    <LineBreak/><LineBreak/>
                    <Run Text="Expected: Basic output only."/>
                </TextBlock>
            </ScrollViewer>
        </Border>

        <StackPanel Grid.Row="2" Orientation="Horizontal" HorizontalAlignment="Center" Margin="0,15,0,0">
            <Button x:Name="btnAttemptWin7" Content="Attempt Win7 Patch" Width="180" Height="34"
                    Background="#7A1F2A" Foreground="#FFFFFF" Margin="5,0">
                <Button.Effect><DropShadowEffect BlurRadius="8" ShadowDepth="2" Opacity="0.5"/></Button.Effect>
            </Button>
            <Button x:Name="btnClose" Content="Close" Width="110" Height="34"
                    Background="#2B3445" Foreground="#FFFFFF" Margin="5,0">
                <Button.Effect><DropShadowEffect BlurRadius="8" ShadowDepth="2" Opacity="0.5"/></Button.Effect>
            </Button>
        </StackPanel>
    </Grid>
</Window>
'@

    $reader = [System.Xml.XmlReader]::Create([System.IO.StringReader]::new($win7Xaml))
    $win7Window = [Windows.Markup.XamlReader]::Load($reader)
    $win7Window.Owner = $window

    $btnAttempt = $win7Window.FindName('btnAttemptWin7')
    $btnClose   = $win7Window.FindName('btnClose')

    $btnClose.Add_Click({ $win7Window.Close() })

    $btnAttempt.Add_Click({
        $win7Window.IsEnabled = $false
        $driverRoot = $txtRoot.Text
        if ([string]::IsNullOrWhiteSpace($driverRoot) -or -not (Test-Path $driverRoot)) {
            [System.Windows.MessageBox]::Show("Set a valid driver root folder (e.g., extracted Adrenalin 20.4.2).", "Error", "OK", "Error") | Out-Null
            $win7Window.IsEnabled = $true
            return
        }

        Start-Job -ScriptBlock {
            param($Root, $SessionID, $BackupBase)
            Set-StrictMode -Off
            function Write-LogLocal { param($Msg,$Lvl='Info'); Write-Output @{Message=$Msg;Level=$Lvl} }
            function Backup-FileLocal { param($FP); $h=(Get-FileHash $FP -Algorithm SHA256).Hash.Substring(0,8); $b="$FP.bak_$SessionID`_$h"; Copy-Item $FP $b -Force; $b }

            try {
                Write-LogLocal "Starting Windows 7 experimental patch..." "Warning"
                $infFiles = Get-ChildItem -Path $Root -Recurse -Filter "*.inf" -EA 0 | Where-Object { $_.Name -notlike "oem*.inf" }
                if (-not $infFiles) { throw "No INF files found" }

                foreach ($inf in $infFiles) {
                    $content = try { Get-Content -Raw -LiteralPath $inf.FullName } catch { $null }
                    if ([string]::IsNullOrWhiteSpace([string]$content)) { continue }
                    $original = $content

                    $regex = '^(?=\s*%[^%]+\s*=\s*[^,\r\n]+,)\s*(.+?),\s*NTamd64[^\s,;\]\r\n]*'
                    $content = ([regex]::Replace($content, $regex, '$1, NTamd64.6.1...7601', 'IgnoreCase, Multiline'))
                    $content = ([regex]::Replace($content, '^\s*\[ATI\.Mfg\.NTamd64[^\]\r\n]*\]?', '[ATI.Mfg.NTamd64.6.1...7601]', 'IgnoreCase, Multiline'))

                    if ($content -ne $original) {
                        $bak = Backup-FileLocal -FP $inf.FullName
                        [System.IO.File]::WriteAllText($inf.FullName, $content, [System.Text.Encoding]::ASCII)
                        Write-LogLocal "Patched INF for Win7: $($inf.FullName)" "Success"
                    }
                }

                $manifests = Get-ChildItem -Path $Root -Recurse -File -EA 0 |
                             Where-Object { $_.Extension -in '.json','.xml' -and $_.Name -match '(?i)manifest' }
                foreach ($m in $manifests) {
                    if ($m.Extension -ieq '.json') {
                        $txt = try { Get-Content -Raw -LiteralPath $m.FullName } catch { $null }
                        if ([string]::IsNullOrWhiteSpace([string]$txt)) { continue }
                        $orig = $txt
                        $txt = [regex]::Replace($txt, '"MinOS"\s*:\s*".+?"', '"MinOS":"6.1.0.0"', 'IgnoreCase')
                        $txt = [regex]::Replace($txt, '"MaxOS"\s*:\s*".+?"', '"MaxOS":"6.1.99999.0"', 'IgnoreCase')
                        if ($txt -ne $orig) {
                            $bak = Backup-FileLocal -FP $m.FullName
                            [System.IO.File]::WriteAllText($m.FullName, $txt, [System.Text.Encoding]::UTF8)
                            Write-LogLocal "Patched manifest for Win7: $($m.FullName)" "Success"
                        }
                    }
                }

                Write-LogLocal "Windows 7 patch completed. Use at your own risk!" "Warning"
            } catch { Write-LogLocal "Win7 patch failed: $_" "Error" }
        } -ArgumentList $driverRoot, $script:SessionID, $script:BackupBase | Out-Null

        $timer = New-Object System.Windows.Threading.DispatcherTimer
        $timer.Interval = [TimeSpan]::FromMilliseconds(500)
        $timer.Add_Tick({
            param($sender,$e)
            $job = Get-Job | Where-Object {$_.State -in 'Completed','Failed'} | Select-Object -First 1
            if ($job) {
                $results = Receive-Job $job -EA SilentlyContinue
                Remove-Job $job -EA SilentlyContinue
                foreach($r in $results){ if($r -is [hashtable]){ Write-Log $r.Message $r.Level } }
                if ($sender) { $sender.Stop() }
                $win7Window.IsEnabled = $true
                [System.Windows.MessageBox]::Show('Win7 patch attempt complete. Check logs.', 'Done', 'OK', 'Information') | Out-Null
            }
        })
        $timer.Start()
    })

    [void]$win7Window.ShowDialog()
}
#endregion

#region ==================== WPF UI ===========================
$Xaml = @'
<Window xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
        xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
        Title="AMD INF Patcher (Server 2025 Ready)"
        Width="900" Height="740" MinWidth="820" MinHeight="600"
        WindowStartupLocation="CenterScreen"
        Background="#12141A" FontFamily="Consolas"
        AllowsTransparency="False" WindowStyle="SingleBorderWindow">
    <Grid>
        <Grid.Background>
            <LinearGradientBrush StartPoint="0,0" EndPoint="0,1">
                <GradientStop Color="#12141A" Offset="0"/>
                <GradientStop Color="#0E1825" Offset="1"/>
            </LinearGradientBrush>
        </Grid.Background>

        <Grid Margin="14">
            <Grid.RowDefinitions>
                <RowDefinition Height="Auto"/>   <!-- Title -->
                <RowDefinition Height="Auto"/>   <!-- Root -->
                <RowDefinition Height="Auto"/>   <!-- Target -->
                <RowDefinition Height="Auto"/>   <!-- Buttons -->
                <RowDefinition Height="*"/>      <!-- Log (capped by MaxHeight) -->
                <RowDefinition Height="Auto"/>   <!-- Footer -->
            </Grid.RowDefinitions>

            <TextBlock Grid.Row="0" Text="AMD INF PATCHER"
                       Foreground="#F04444" FontSize="26" FontWeight="Bold"
                       HorizontalAlignment="Center" Margin="0,0,0,12">
                <TextBlock.Effect><DropShadowEffect BlurRadius="12" ShadowDepth="2" Opacity="0.6"/></TextBlock.Effect>
            </TextBlock>

            <!-- Root selector -->
            <Border Grid.Row="1" CornerRadius="10" Padding="12" Margin="0,0,0,10"
                    Background="#0F1B2B" BorderBrush="#263043" BorderThickness="1">
                <Grid>
                    <Grid.ColumnDefinitions>
                        <ColumnDefinition Width="Auto"/>
                        <ColumnDefinition Width="*"/>
                        <ColumnDefinition Width="Auto"/>
                    </Grid.ColumnDefinitions>
                    <TextBlock Text="Driver Root:" Foreground="#E0E6ED" VerticalAlignment="Center"/>
                    <TextBox x:Name="txtRoot" Grid.Column="1" Height="30" Margin="10,0,10,0"
                             Background="#1A2A3D" Foreground="#F9B0B0" BorderBrush="#3B4B63" />
                    <Button x:Name="btnBrowse" Grid.Column="2" Content="Browse..." Width="100" Height="30"
                            Background="#7A1F2A" Foreground="#FFFFFF">
                        <Button.Effect><DropShadowEffect BlurRadius="10" ShadowDepth="2" Opacity="0.5"/></Button.Effect>
                    </Button>
                </Grid>
            </Border>

            <!-- Target selector -->
            <Border Grid.Row="2" CornerRadius="10" Padding="12" Margin="0,0,0,12"
                    Background="#0F1B2B" BorderBrush="#263043" BorderThickness="1">
                <Grid>
                    <Grid.ColumnDefinitions>
                        <ColumnDefinition Width="Auto"/>
                        <ColumnDefinition Width="220"/>
                        <ColumnDefinition Width="*"/>
                    </Grid.ColumnDefinitions>
                    <TextBlock Text="Target OS:" Foreground="#E0E6ED" VerticalAlignment="Center"/>
                    <ComboBox x:Name="cboTarget" Grid.Column="1" Height="30" Margin="10,0,10,0"
                              Background="#1A2A3D" Foreground="#F9B0B0" BorderBrush="#3B4B63">
                        <ComboBoxItem Content="Generic"/>
                        <ComboBoxItem Content="Server2019_2"/>
                        <ComboBoxItem Content="Server2019_3"/>
                        <ComboBoxItem Content="Server2022"/>
                        <ComboBoxItem Content="Win11_24H2"/>
                        <ComboBoxItem Content="Server2025" IsSelected="True"/>
                        <ComboBoxItem Content="Win7"/>
                        <ComboBoxItem Content="Custom"/>
                    </ComboBox>
                    <TextBox x:Name="txtCustom" Grid.Column="2" Height="30" Text="e.g., NTamd64.10.0...26100"
                             Background="#1A2A3D" Foreground="#8FA6C1" BorderBrush="#3B4B63" IsEnabled="False"/>
                </Grid>
            </Border>

            <!-- Buttons -->
            <StackPanel Grid.Row="3" Orientation="Horizontal" HorizontalAlignment="Center" Margin="0,0,0,10">
                <CheckBox x:Name="chkManifest" Content="Patch Adrenalin Manifest (Best Effort)" IsChecked="True" Foreground="#C7D2E2" Margin="0,0,12,0"/>
                <Button x:Name="btnPatch" Content="Patch INF" Width="120" Height="34" Margin="4,0"
                        Background="#7A1F2A" Foreground="#FFFFFF">
                    <Button.Effect><DropShadowEffect BlurRadius="10" ShadowDepth="2" Opacity="0.55"/></Button.Effect>
                </Button>
                <Button x:Name="btnRevert" Content="Revert All" Width="120" Height="34" Margin="4,0"
                        Background="#8A2B3A" Foreground="#FFFFFF">
                    <Button.Effect><DropShadowEffect BlurRadius="10" ShadowDepth="2" Opacity="0.55"/></Button.Effect>
                </Button>
                <Button x:Name="btnCheckDeps" Content="Check Dependencies" Width="170" Height="34" Margin="4,0"
                        Background="#2B3445" Foreground="#FFFFFF">
                    <Button.Effect><DropShadowEffect BlurRadius="10" ShadowDepth="2" Opacity="0.55"/></Button.Effect>
                </Button>
                <Button x:Name="btnWin7" Content="Windows 7 Support" Width="170" Height="34" Margin="4,0"
                        Background="#2B3445" Foreground="#FFFFFF">
                    <Button.Effect><DropShadowEffect BlurRadius="10" ShadowDepth="2" Opacity="0.55"/></Button.Effect>
                </Button>
            </StackPanel>

            <!-- Log (capped by MaxHeight, independent scroll) -->
            <Border Grid.Row="4" CornerRadius="10" Padding="10"
                    Background="#0F1B2B" BorderBrush="#263043" BorderThickness="1">
                <RichTextBox x:Name="txtLog"
                             Background="#0B0B0B"
                             Foreground="#FF3A3A"
                             FontSize="12"
                             IsReadOnly="True"
                             VerticalScrollBarVisibility="Auto"
                             BorderBrush="#3B4B63"
                             BorderThickness="1"/>
            </Border>

            <TextBlock Grid.Row="5" Text="By AMD_DriverMagic | Reddit Community"
                       HorizontalAlignment="Center" Foreground="#7C8DA5" FontSize="11" Margin="0,10,0,0"/>
        </Grid>
    </Grid>
</Window>
'@
#endregion

#region ==================== Load XAML & Wire Events =====================
Add-Type -AssemblyName PresentationFramework, WindowsBase, System.Windows.Forms

$reader = [System.Xml.XmlReader]::Create([System.IO.StringReader]::new($Xaml))
$window = [Windows.Markup.XamlReader]::Load($reader)

$txtRoot      = $window.FindName('txtRoot')
$btnBrowse    = $window.FindName('btnBrowse')
$cboTarget    = $window.FindName('cboTarget')
$txtCustom    = $window.FindName('txtCustom')
$chkManifest  = $window.FindName('chkManifest')
$btnPatch     = $window.FindName('btnPatch')
$btnRevert    = $window.FindName('btnRevert')
$btnCheckDeps = $window.FindName('btnCheckDeps')
$btnWin7      = $window.FindName('btnWin7')
$txtLog       = $window.FindName('txtLog')

$script:txtLogControl = $txtLog
$txtRoot.Text = $InitialRootPath

# Ensure log never exceeds 50% of window height
$setLogCap = {
    param($w,$t)
    try {
        $half = [math]::Floor($w.ActualHeight * 0.5)
        if ($half -lt 200) { $half = 200 }   # minimum comfortable height
        $t.MaxHeight = $half
    } catch {}
}
$window.Add_SizeChanged({ $setLogCap.Invoke($window,$txtLog) })
$window.Add_ContentRendered({ $setLogCap.Invoke($window,$txtLog) })

# Browse
$btnBrowse.Add_Click({
    $dlg = New-Object System.Windows.Forms.FolderBrowserDialog
    $dlg.Description = "Select AMD Driver Root Folder"
    if ($dlg.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) { $txtRoot.Text = $dlg.SelectedPath }
})

# Target change
$cboTarget.Add_SelectionChanged({
    $isCustom = ($cboTarget.SelectedItem.Content -eq 'Custom')
    $txtCustom.IsEnabled = $isCustom
    if (-not $isCustom) { $txtCustom.Text = "e.g., NTamd64.10.0...26100"; $txtCustom.Foreground = [System.Windows.Media.Brushes]::LightGray }
    else { $txtCustom.Text = ''; $txtCustom.Foreground = [System.Windows.Media.Brushes]::White }
})

# Custom placeholder UX
$txtCustom.AddHandler([System.Windows.UIElement]::GotFocusEvent, [System.Windows.RoutedEventHandler]{ if ($txtCustom.Text -eq "e.g., NTamd64.10.0...26100") { $txtCustom.Text = ""; $txtCustom.Foreground = [System.Windows.Media.Brushes]::White } })
$txtCustom.AddHandler([System.Windows.UIElement]::LostFocusEvent, [System.Windows.RoutedEventHandler]{ if ([string]::IsNullOrWhiteSpace($txtCustom.Text)) { $txtCustom.Text = "e.g., NTamd64.10.0...26100"; $txtCustom.Foreground = [System.Windows.Media.Brushes]::LightGray } })

# Buttons
$btnCheckDeps.Add_Click({ if (Ensure-Dependencies) { [System.Windows.MessageBox]::Show('All dependencies OK.', 'Success', 'OK', 'Information') | Out-Null } else { [System.Windows.MessageBox]::Show('Dependency check failed. See log.', 'Error', 'OK', 'Error') | Out-Null } })

# ===== Core patch job (rehydrates functions in background) =====
function Start-CorePatchJob {
    param($RootPath,$Target,$CustomDecText,$PatchManFlag)
    $funcs = Get-FunctionText @('Write-Log','Safe-Replace','Update-ManufacturerBlock','Fix-AtiMfgSectionHeaders','Read-TextFileSafe','Write-TextFileSafe','Backup-File')

    Start-Job -ScriptBlock {
        param($Root,$Target,$CustomDec,$PatchMan,$SessionID,$BackupBase,$FuncTexts)
        Set-StrictMode -Off
        foreach($k in $FuncTexts.Keys){ Set-Item -Path ("Function:\{0}" -f $k) -Value ([scriptblock]::Create($FuncTexts[$k])) }
        function Write-LogLocal { param($Msg,$Lvl='Info'); Write-Output @{Message=$Msg;Level=$Lvl} }
        ${function:Write-Log} = ${function:Write-LogLocal}

        $map=@{
            Generic='NTamd64'
            Server2019_2='NTamd64.10.0.2.17763'
            Server2019_3='NTamd64.10.0.3.17763'
            Server2022='NTamd64.10.0...20348'
            Win11_24H2='NTamd64.10.0...26100'
            Server2025='NTamd64.10.0...26100'
            Win7='NTamd64.6.1...7601'
        }
        $dec = if($Target -eq 'Custom'){$CustomDec}else{$map[$Target]}
        Write-Log "Patching with: $dec"

        ${function:Read-TextFileSafe} = ${function:Read-TextFileSafe}
        ${function:Write-TextFileSafe} = ${function:Write-TextFileSafe}
        ${function:Backup-File} = ${function:Backup-File}

        $infFiles = Get-ChildItem -Path $Root -Recurse -Filter *.inf -EA 0 | Where-Object {
            $_.FullName -match '\\Display\\WT6A_INF\\' -or
            $_.DirectoryName -match 'WT6A_INF' -or
            $_.Name -match '^u\d+\.inf$' -or
            $_.Name -like 'ati2mtag_*.inf'
        }

        foreach ($inf in $infFiles) {
            try {
                $txt = Read-TextFileSafe -Path $inf.FullName
                if ($null -eq $txt) { Write-Log "Skip empty/unreadable INF: $($inf.FullName)" "Warning"; continue }
                $orig=$txt

                $txt = [string](Update-ManufacturerBlock -Text $txt -Decoration $dec)
                $txt = [string](Fix-AtiMfgSectionHeaders -Text $txt -Decoration $dec)

                $rep = Safe-Replace -Input $txt -Pattern '^(?=\s*%[^%]+\s*=\s*[^,\r\n]+,)\s*(.+?),\s*NTamd64[^\s,;\]\r\n]*' -Replacement ('$1, ' + $dec) -MultilineIgnoreCase
                $txt = [string]$rep[0]; $cnt = [int]$rep[1]
                if ($cnt -gt 0) { Write-Log "Updated $cnt device mapping line(s) to $dec." "Success" }

                if ($txt -ne $orig){
                    $h=(Get-FileHash $inf.FullName -Algorithm SHA256).Hash.Substring(0,8)
                    $bak="$($inf.FullName).bak_$SessionID`_$h"
                    Copy-Item $inf.FullName $bak -Force
                    if (Write-TextFileSafe -Path $inf.FullName -Text $txt -Encoding ASCII) {
                        Write-Log "Patched INF: $($inf.FullName) (backup: $bak)" "Success"
                    } else {
                        Write-Log "Write failed for INF: $($inf.FullName) — reverting" "Error"
                        Move-Item -LiteralPath $bak -Destination $inf.FullName -Force
                    }
                } else { Write-Log "No changes needed: $($inf.FullName)" "Info" }
            } catch { Write-Log "INF error: $_" "Error" }
        }

        if ($PatchMan) {
            $manifests = Get-ChildItem -Path $Root -Recurse -File -EA 0 | Where-Object {
                ($_.Extension -in '.json','.xml') -and ($_.Name -match '(?i)manifest')
            }
            foreach ($m in $manifests) {
                try {
                    $txt = Read-TextFileSafe -Path $m.FullName
                    if ($null -eq $txt) { Write-Log "Skip empty/unreadable manifest: $($m.FullName)" "Warning"; continue }
                    $orig=$txt
                    if ($m.Extension -ieq '.json') {
                        $r1 = Safe-Replace -Input $txt -Pattern '(?i)"Min(?:OS|Build|Version|OSVersion|OSBuild)"\s*:\s*".+?"' -Replacement '"MinOS":"10.0.0.0"'
                        $txt = [string]$r1[0]
                        $r2 = Safe-Replace -Input $txt -Pattern '(?i)"Max(?:OS|Build|Version|OSVersion|OSBuild|OSVersionTested)"\s*:\s*".+?"' -Replacement '"MaxOS":"10.0.99999.0"'
                        $txt = [string]$r2[0]
                        $r3 = Safe-Replace -Input $txt -Pattern '(?i)"SupportedOS(?:es|List)"\s*:\s*\[(.*?)\]' -Replacement '"SupportedOS":[$1,"WindowsServer"]'
                        $txt = [string]$r3[0]
                    }
                    if ($txt -ne $orig){
                        $h=(Get-FileHash $m.FullName -Algorithm SHA256).Hash.Substring(0,8)
                        $bak="$($m.FullName).bak_$SessionID`_$h"
                        Copy-Item $m.FullName $bak -Force
                        if (Write-TextFileSafe -Path $m.FullName -Text $txt -Encoding UTF8) {
                            Write-Log "Patched manifest: $($m.FullName) (backup: $bak)" "Success"
                        } else {
                            Write-Log "Write failed for manifest: $($m.FullName) — reverting" "Error"
                            Move-Item -LiteralPath $bak -Destination $m.FullName -Force
                        }
                    } else { Write-Log "Manifest unchanged: $($m.FullName)" "Info" }
                } catch { Write-Log "Manifest error: $_" "Error" }
            }
        }
        Write-Log "Patching completed." "Success"
    } -ArgumentList $RootPath,$Target,$CustomDecText,$PatchManFlag,$script:SessionID,$script:BackupBase,$funcs | Out-Null
}

$btnPatch.Add_Click({
    if ([string]::IsNullOrWhiteSpace($txtRoot.Text) -or -not (Test-Path $txtRoot.Text)) { [System.Windows.MessageBox]::Show('Invalid driver root path.', 'Error', 'OK', 'Error') | Out-Null; return }
    $target = $cboTarget.SelectedItem.Content
    if ($target -eq 'Custom' -and ([string]::IsNullOrWhiteSpace($txtCustom.Text) -or $txtCustom.Text -like '*e.g.,*')) { [System.Windows.MessageBox]::Show('Enter a custom decoration.', 'Error', 'OK', 'Error') | Out-Null; return }
    $customDec = if ($target -eq 'Custom') { $txtCustom.Text } else { '' }

    $window.IsEnabled = $false
    Start-CorePatchJob -RootPath $txtRoot.Text -Target $target -CustomDecText $customDec -PatchManFlag $chkManifest.IsChecked

    $script:PatchTimer = New-Object System.Windows.Threading.DispatcherTimer
    $script:PatchTimer.Interval = [TimeSpan]::FromMilliseconds(500)
    $script:PatchTimer.Add_Tick({
        param($sender,$e)
        $job = Get-Job | Where-Object {$_.State -in 'Completed','Failed'} | Select-Object -First 1
        if ($job) {
            $results = Receive-Job $job -EA SilentlyContinue
            Remove-Job $job -EA SilentlyContinue
            foreach($r in $results){ if($r -is [hashtable]){ Write-Log $r.Message $r.Level } }
            if ($sender) { $sender.Stop() }
            $window.IsEnabled = $true
            [System.Windows.MessageBox]::Show('Operation complete. Check logs.', 'Done', 'OK', 'Information') | Out-Null
        }
    })
    $script:PatchTimer.Start()
})

$btnRevert.Add_Click({
    $window.IsEnabled = $false
    Start-Job -ScriptBlock {
        param($BackupBase,$SessionID)
        Set-StrictMode -Off
        function Write-LogLocal { param($Msg,$Lvl='Info'); Write-Output @{Message=$Msg;Level=$Lvl} }
        try {
            $logFiles = Get-ChildItem -Path $BackupBase -Filter "*amd_inf_patch_*.log" -EA 0
            $reverted=0
            foreach($log in $logFiles){
                if($log.BaseName -match 'amd_inf_patch_(\d{8}_\d{6})'){
                    $sid=$matches[1]
                    $backs = Get-ChildItem -Path "$BackupBase\*" -Include "*.bak_*" -Recurse -EA 0 |
                             Where-Object {$_.Name -match [regex]::Escape(".bak_$sid`_")}
                    foreach($b in $backs){
                        $orig=$b.FullName -replace [regex]::Escape(".bak_$sid`_") + '[0-9a-f]{8}',''
                        if(Test-Path $orig){ Remove-Item -LiteralPath $orig -Force }
                        Move-Item -LiteralPath $b.FullName -Destination $orig -Force
                        $reverted++
                    }
                }
            }
            Write-LogLocal "Reverted $reverted file(s)."
        } catch { Write-LogLocal "Revert error: $_" "Error" }
    } -ArgumentList $script:BackupBase,$script:SessionID | Out-Null

    $timer = New-Object System.Windows.Threading.DispatcherTimer
    $timer.Interval = [TimeSpan]::FromMilliseconds(500)
    $timer.Add_Tick({
        param($sender,$e)
        $job = Get-Job | Where-Object {$_.State -eq 'Completed'} | Select-Object -First 1
        if ($job) {
            $results = Receive-Job $job -EA SilentlyContinue
            Remove-Job $job -EA SilentlyContinue
            foreach($r in $results){ if($r -is [hashtable]){ Write-Log $r.Message $r.Level } }
            if ($sender) { $sender.Stop() }
            $window.IsEnabled = $true
            [System.Windows.MessageBox]::Show('Revert complete.', 'Done', 'OK', 'Information') | Out-Null
        }
    })
    $timer.Start()
})

$btnWin7.Add_Click({ Show-Win7SupportWindow })

Write-Log "AMD INF Patcher GUI Loaded." "Info"
if (-not (Ensure-Dependencies)) { [System.Windows.MessageBox]::Show('Critical dependency missing. App may not function.', 'Warning', 'OK', 'Exclamation') | Out-Null }

[void]$window.ShowDialog()
#endregion
