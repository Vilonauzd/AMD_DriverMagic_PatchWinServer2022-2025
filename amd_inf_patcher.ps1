#requires -RunAsAdministrator
<#
    AMD INF Patcher – WPF Edition (v2.10)
    Changes:
      • Fix: no more blanked .INF files (transactional write + validation)
      • Fix: regex replace no longer uses script-scope counters
      • Safer backups; write-through temp files, only commit if sane
      • UI: “AMD Drivers” button opens https://amd.com/drivers
      • Post-patch prompts to open containing folders for modified INF and manifest files
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

# Detect original newline style for preservation
function Get-NewlineStyle {
    param([string]$Text)
    if ($Text -match "`r`n") { return "`r`n" }
    elseif ($Text -match "`n") { return "`n" }
    else { return "`r`n" }
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

# Transactional safe write; ASCII for INF, UTF8 for JSON; verifies sanity before commit
function Write-TextFileSafe {
    param(
        [Parameter(Mandatory)][ValidateNotNullOrEmpty()][string]$Path,
        [Parameter(Mandatory)][AllowNull()][AllowEmptyString()][string]$Text,
        [ValidateSet('ASCII','UTF8')]$Encoding='ASCII',
        [ValidateSet('INF','JSON','XML','OTHER')]$Kind='OTHER',
        [string]$PreserveNewline="`r`n"
    )
    try {
        if ($null -eq $Text) { Write-Log "Write skip. Null text to $Path" "Warning"; return $false }

        # normalize newlines to original style
        $norm = ($Text -replace "(`r`n|`n|`r)", $PreserveNewline)

        $tmp = "$Path.tmp_write_$($script:SessionID)"
        $enc = if($Encoding -eq 'ASCII'){ [System.Text.Encoding]::ASCII } else { [System.Text.Encoding]::UTF8 }

        [System.IO.File]::WriteAllText($tmp, $norm, $enc)

        # Validate: size and key markers
        $ok = Test-Path $tmp
        if ($ok) {
            $len = (Get-Item $tmp).Length
            if ($len -lt 8) { $ok = $false }
        }
        if ($ok -and $Kind -eq 'INF') {
            $sample = Get-Content -LiteralPath $tmp -Raw -EA SilentlyContinue
            if ([string]::IsNullOrWhiteSpace($sample) -or ($sample -notmatch '^\[Manufacturer\]' -and $sample -notmatch '^\[Version\]')) { $ok = $false }
        }

        if (-not $ok) {
            Remove-Item -LiteralPath $tmp -EA SilentlyContinue
            Write-Log "Write aborted (sanity check failed) for $Path" "Error"
            return $false
        }

        Move-Item -LiteralPath $tmp -Destination $Path -Force
        return $true
    } catch {
        Write-Log "Write error: $Path :: $_" "Error"
        try { Remove-Item -LiteralPath $tmp -EA SilentlyContinue } catch {}
        return $false
    }
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
        $backupName = Join-Path (Split-Path -Parent $FilePath) ("{0}.bak_{1}_{2}" -f (Split-Path -Leaf $FilePath), $script:SessionID, $hash)
        Copy-Item -LiteralPath $FilePath -Destination $backupName -Force
        $backupName
    } catch { throw "Backup failed for $FilePath :: $_" }
}

function Revert-AllChanges {
    Write-Log "Starting full revert process..." "Warning"
    try {
        $reverted = 0
        $backs = Get-ChildItem -Path $InitialRootPath -Recurse -Filter '*.bak_*' -EA SilentlyContinue
        foreach ($bak in $backs) {
            $orig = $bak.FullName -replace '\.bak_\d{8}_\d{6}_[0-9a-f]{8}$',''
            try {
                if (Test-Path $orig) { Remove-Item -LiteralPath $orig -Force }
                Move-Item -LiteralPath $bak.FullName -Destination $orig -Force
                Write-Log "Reverted: $orig" "Success"; $reverted++
            } catch { Write-Log "Revert failed for $orig : $_" "Error" }
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
        $evaluator = [System.Text.RegularExpressions.MatchEvaluator]{ param($m) $script:__ignore = $m; $count++; return $Replacement }
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
    $out = $rx.Replace($Text, { param($m) $count++; "[ATI.Mfg.$Decoration]" })
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
                $eol = Get-NewlineStyle $original

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
                    if (Write-TextFileSafe -Path $inf.FullName -Text $content -Encoding ASCII -Kind INF -PreserveNewline $eol) {
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
                $eol  = Get-NewlineStyle $orig

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
                    if (Write-TextFileSafe -Path $m.FullName -Text $txt -Encoding UTF8 -Kind JSON -PreserveNewline $eol) {
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
# (unchanged)
#endregion

#region ==================== WPF UI ===========================
$Xaml = @'
<Window xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
        xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
        Title="AMD INF Patcher (Server 2025 Ready)"
        Width="900" Height="760" MinWidth="820" MinHeight="620"
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
                <RowDefinition Height="*"/>      <!-- Log -->
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
                <Button x:Name="btnDrivers" Content="AMD Drivers" Width="140" Height="34" Margin="8,0,0,0"
                        Background="#2B4C7A" Foreground="#FFFFFF" ToolTip="Open https://amd.com/drivers">
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
$btnDrivers   = $window.FindName('btnDrivers')
$txtLog       = $window.FindName('txtLog')

$script:txtLogControl = $txtLog
$txtRoot.Text = $InitialRootPath

# Ensure log never exceeds 50% of window height
$setLogCap = {
    param($w,$t)
    try {
        $half = [math]::Floor($w.ActualHeight * 0.5)
        if ($half -lt 200) { $half = 200 }
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

# AMD Drivers button
$btnDrivers.Add_Click({ Start-Process "https://amd.com/drivers" | Out-Null })

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
    $funcs = Get-FunctionText @('Write-Log','Safe-Replace','Update-ManufacturerBlock','Fix-AtiMfgSectionHeaders','Read-TextFileSafe','Write-TextFileSafe','Backup-File','Get-NewlineStyle')

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

        $patchedINFs = New-Object System.Collections.Generic.List[string]
        $patchedMans = New-Object System.Collections.Generic.List[string]

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
                $eol = Get-NewlineStyle $orig

                $txt = [string](Update-ManufacturerBlock -Text $txt -Decoration $dec)
                $txt = [string](Fix-AtiMfgSectionHeaders -Text $txt -Decoration $dec)

                $rep = Safe-Replace -Input $txt -Pattern '^(?=\s*%[^%]+\s*=\s*[^,\r\n]+,)\s*(.+?),\s*NTamd64[^\s,;\]\r\n]*' -Replacement ('$1, ' + $dec) -MultilineIgnoreCase
                $txt = [string]$rep[0]; $cnt = [int]$rep[1]
                if ($cnt -gt 0) { Write-Log "Updated $cnt device mapping line(s) to $dec." "Success" }

                if ($txt -ne $orig){
                    $h=(Get-FileHash $inf.FullName -Algorithm SHA256).Hash.Substring(0,8)
                    $bak="$($inf.FullName).bak_$SessionID`_$h"
                    Copy-Item $inf.FullName $bak -Force
                    if (Write-TextFileSafe -Path $inf.FullName -Text $txt -Encoding ASCII -Kind INF -PreserveNewline $eol) {
                        Write-Log "Patched INF: $($inf.FullName) (backup: $bak)" "Success"
                        [void]$patchedINFs.Add($inf.FullName)
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
                    $eol = Get-NewlineStyle $orig
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
                        if (Write-TextFileSafe -Path $m.FullName -Text $txt -Encoding UTF8 -Kind JSON -PreserveNewline $eol) {
                            Write-Log "Patched manifest: $($m.FullName) (backup: $bak)" "Success"
                            [void]$patchedMans.Add($m.FullName)
                        } else {
                            Write-Log "Write failed for manifest: $($m.FullName) — reverting" "Error"
                            Move-Item -LiteralPath $bak -Destination $m.FullName -Force
                        }
                    } else { Write-Log "Manifest unchanged: $($m.FullName)" "Info" }
                } catch { Write-Log "Manifest error: $_" "Error" }
            }
        }
        Write-Log "Patching completed." "Success"
        # Summaries back to GUI
        Write-Output @{ Type='Summary'; PatchedINFs=$patchedINFs; PatchedManifests=$patchedMans }
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
            $summary = $null
            foreach($r in $results){
                if($r -is [hashtable] -and $r.ContainsKey('Type') -and $r.Type -eq 'Summary'){ $summary = $r }
                elseif($r -is [hashtable]){ Write-Log $r.Message $r.Level }
            }
            if ($sender) { $sender.Stop() }
            $window.IsEnabled = $true
            [System.Windows.MessageBox]::Show('Operation complete. Check logs.', 'Done', 'OK', 'Information') | Out-Null

            # Open-folder prompts
            try {
                if ($summary -and $summary.PatchedINFs -and $summary.PatchedINFs.Count -gt 0) {
                    $resp = [System.Windows.MessageBox]::Show(("Open INF folder?" ), 'INF Patched', 'YesNo', 'Question')
                    if ($resp -eq 'Yes') {
                        $first = [string]$summary.PatchedINFs[0]
                        Start-Process explorer.exe "/select,`"$first`""
                    }
                }
                if ($summary -and $summary.PatchedManifests -and $summary.PatchedManifests.Count -gt 0) {
                    $resp2 = [System.Windows.MessageBox]::Show(("Open manifest folder?" ), 'Manifest Patched', 'YesNo', 'Question')
                    if ($resp2 -eq 'Yes') {
                        $firstM = [string]$summary.PatchedManifests[0]
                        Start-Process explorer.exe "/select,`"$firstM`""
                    }
                }
            } catch {}
        }
    })
    $script:PatchTimer.Start()
})

$btnRevert.Add_Click({
    $window.IsEnabled = $false
    Start-Job -ScriptBlock {
        param($RootPath)
        Set-StrictMode -Off
        function Write-LogLocal { param($Msg,$Lvl='Info'); Write-Output @{Message=$Msg;Level=$Lvl} }
        try {
            $reverted=0
            $backs = Get-ChildItem -Path $RootPath -Recurse -Filter '*.bak_*' -EA 0
            foreach($b in $backs){
                $orig=$b.FullName -replace '\.bak_\d{8}_\d{6}_[0-9a-f]{8}$',''
                if(Test-Path $orig){ Remove-Item -LiteralPath $orig -Force }
                Move-Item -LiteralPath $b.FullName -Destination $orig -Force
                $reverted++
            }
            Write-LogLocal "Reverted $reverted file(s)." "Info"
        } catch { Write-LogLocal "Revert error: $_" "Error" }
    } -ArgumentList $txtRoot.Text | Out-Null

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
