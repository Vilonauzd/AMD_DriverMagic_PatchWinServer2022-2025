#requires -RunAsAdministrator
<# 
    AMD INF Patcher – WPF Edition (v2.4)
    Fully compatible with Windows Server 2025 (GA Build 26100) + Experimental Windows 7 Support
    PowerShell 5+ / .NET Framework 4.8
    © AMD_DriverMagic | Reddit Community
#>

param(
    [string]$InitialRootPath = ''
)

#region ==================== Global State & Constants ====================
$script:LogLines      = [System.Collections.ArrayList]::new()
$script:CurrentLogPath= $null
$script:SessionID     = (Get-Date -Format 'yyyyMMdd_HHmmss')
$script:BackupBase    = "C:\RepairLogs"
$script:txtLogControl = $null

$ValidTargets = @{
    'Generic'    = 'NTamd64'
    'Server2022' = 'NTamd64.10.0...20348'
    'Win11_24H2' = 'NTamd64.10.0...26100'
    'Server2025' = 'NTamd64.10.0...26100'   # ✅ Windows Server 2025 GA
    'Win7'       = 'NTamd64.6.1...7601'     # ✅ Windows 7 SP1
    'Custom'     = $null
}
#endregion ====================================================================

#region ==================== Logging Functions ============================
function Write-Log {
    param(
        [Parameter(Mandatory)][string]$Message,
        [ValidateSet('Info','Success','Warning','Error')][string]$Level='Info'
    )
    $timeStamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    $entry     = "[$timeStamp] [$Level] $Message"
    [void]$script:LogLines.Add($entry)

    if ($script:txtLogControl -and $script:txtLogControl.IsInitialized) {
        $action = {
            $paragraph = New-Object System.Windows.Documents.Paragraph
            $run = New-Object System.Windows.Documents.Run($entry)
            $paragraph.Inlines.Add($run)
            $script:txtLogControl.Document.Blocks.Add($paragraph)
            $script:txtLogControl.ScrollToEnd()
        }
        if ($script:txtLogControl.Dispatcher.CheckAccess()) { & $action } else { $script:txtLogControl.Dispatcher.Invoke($action) }
    }

    if ($script:CurrentLogPath) {
        try { Add-Content -Path $script:CurrentLogPath -Value $entry -ErrorAction Stop } catch {}
    }
}
#endregion ====================================================================

#region ==================== Dependency Checks ===========================
function Ensure-Dependencies {
    Write-Log "Checking system dependencies..." "Info"

    if ($PSVersionTable.PSVersion.Major -lt 5) {
        Write-Log "PowerShell 5.1 or later is required." "Error"
        return $false
    }

    $isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    if (-not $isAdmin) {
        Write-Log "Administrator privileges required." "Error"
        return $false
    }

    if (-not (Test-Path $script:BackupBase)) {
        try {
            New-Item -ItemType Directory -Path $script:BackupBase -Force | Out-Null
            Write-Log "Created log directory: $($script:BackupBase)" "Success"
        } catch {
            Write-Log "Failed to create log directory: $_" "Error"
            return $false
        }
    }

    Write-Log "All dependencies satisfied." "Success"
    return $true
}
#endregion ====================================================================

#region ==================== Backup / Revert Utilities ====================
function Backup-File {
    param([Parameter(Mandatory)][string]$FilePath)
    if (-not (Test-Path -LiteralPath $FilePath)) { throw "File not found: $FilePath" }
    $hash = (Get-FileHash -Path $FilePath -Algorithm SHA256).Hash.Substring(0,8)
    $backupName = "$FilePath.bak_$($script:SessionID)_$hash"
    Copy-Item -LiteralPath $FilePath -Destination $backupName -Force
    return $backupName
}

function Revert-AllChanges {
    Write-Log "Starting full revert process..." "Warning"
    $logFiles = Get-ChildItem -Path $script:BackupBase -Filter "*amd_inf_patch_*.log" -ErrorAction SilentlyContinue
    $reverted = 0

    foreach ($log in $logFiles) {
        if ($log.BaseName -match 'amd_inf_patch_(\d{8}_\d{6})') {
            $sessionID = $matches[1]
            $pattern   = [regex]::Escape(".bak_$sessionID`_")
            $backups   = Get-ChildItem -Path "$script:BackupBase\*" -Include "*.bak_*" -Recurse |
                         Where-Object { $_.Name -match $pattern }

            foreach ($bak in $backups) {
                $orig = $bak.FullName -replace [regex]::Escape(".bak_$sessionID`_") + '[0-9a-f]{8}', ''
                try {
                    if (Test-Path $orig) { Remove-Item -LiteralPath $orig -Force }
                    Move-Item -LiteralPath $bak.FullName -Destination $orig -Force
                    Write-Log "Reverted: $orig" "Success"
                    $reverted++
                } catch {
                    Write-Log "Revert failed for $orig : $_" "Error"
                }
            }
        }
    }

    if ($reverted -eq 0) { Write-Log "No revertable backups found." "Info" }
    else               { Write-Log "Reverted $reverted file(s)." "Success" }
}
#endregion ====================================================================

#region ==================== Core Patching Logic =========================
function Patch-INFAndManifests {
    param(
        [Parameter(Mandatory)][string]$Root,
        [Parameter(Mandatory)][ValidateSet('Generic','Server2022','Win11_24H2','Server2025','Win7','Custom')][string]$Target,
        [string]$CustomDecoration,
        [bool]$PatchManifest
    )

    if ($Target -eq 'Custom') {
        if ([string]::IsNullOrWhiteSpace($CustomDecoration)) {
            Write-Log "Custom target requires a decoration string." "Error"
            return
        }
        $decoration = $CustomDecoration
    } else {
        $decoration = $ValidTargets[$Target]
    }

    Write-Log "Using decoration: $decoration" "Info"
    $script:CurrentLogPath = Join-Path $script:BackupBase "amd_inf_patch_$($script:SessionID).log"
    Write-Log "Session log: $($script:CurrentLogPath)" "Info"

    $infFiles = Get-ChildItem -Path $Root -Recurse -Filter *.inf -ErrorAction SilentlyContinue |
                Where-Object {
                    $_.FullName -match '\\Display\\WT6A_INF\\' -or
                    $_.DirectoryName -match 'WT6A_INF' -or
                    $_.Name -match '^u\d+\.inf$'
                }

    if (-not $infFiles) { Write-Log "No INF files found in $Root matching criteria." "Warning" }
    else {
        foreach ($inf in $infFiles) {
            try {
                $content = Get-Content -LiteralPath $inf.FullName -Raw -ErrorAction Stop
                $original = $content
                $content = [regex]::Replace($content, '(?im)^(?=\s*%[^%]+\s*=\s*[^,\r\n]+,).*?NTamd64[^\s,;\]\r\n]*', $decoration)
                $content = [regex]::Replace($content, '(?im)^\[ATI\.Mfg\.NTamd64[^\]]*\]\s*', "[ATI.Mfg.$decoration`r`n")
                if ($content -ne $original) {
                    $bak = Backup-File -FilePath $inf.FullName
                    Set-Content -LiteralPath $inf.FullName -Value $content -Encoding ASCII -ErrorAction Stop
                    Write-Log "Patched INF: $($inf.FullName) (backup: $bak)" "Success"
                } else {
                    Write-Log "No changes needed: $($inf.FullName)" "Info"
                }
            } catch {
                Write-Log "Failed to patch INF $($inf.FullName): $_" "Error"
            }
        }
    }

    if ($PatchManifest) {
        $manifestFiles = Get-ChildItem -Path $Root -Recurse -File -ErrorAction SilentlyContinue |
                         Where-Object {
                             $_.Name -match '(?i)(InstallManifest\.json|AppInstallerManifest\.xml|manifest\.json)' -or
                             $_.DirectoryName -match 'Bin64'
                         }

        foreach ($m in $manifestFiles) {
            try {
                $txt = Get-Content -LiteralPath $m.FullName -Raw -ErrorAction Stop
                $orig = $txt
                $txt = [regex]::Replace($txt, '(?i)"(Min(?:OS|Build|Version|OSVersion|OSBuild))"\s*:\s*".+?"', '"$1":"10.0.0.0"')
                $txt = [regex]::Replace($txt, '(?i)"(Max(?:OS|Build|Version|OSVersion|OSBuild|OSVersionTested))"\s*:\s*".+?"', '"$1":"10.0.99999.0"')
                $txt = [regex]::Replace($txt, '(?i)"SupportedOS(?:es|List)"\s*:\s*\[(.*?)\]', '"SupportedOS":[$1,"WindowsServer"]')
                if ($txt -ne $orig) {
                    $bak = Backup-File -FilePath $m.FullName
                    Set-Content -LiteralPath $m.FullName -Value $txt -Encoding UTF8 -ErrorAction Stop
                    Write-Log "Patched manifest: $($m.FullName)" "Success"
                } else {
                    Write-Log "Manifest unchanged: $($m.FullName)" "Info"
                }
            } catch {
                Write-Log "Manifest patch failed for $($m.FullName): $_" "Error"
            }
        }
    }

    Write-Log "Patching completed." "Success"
}
#endregion ====================================================================

#region ==================== Win7 Support Modal ==========================
function Show-Win7SupportWindow {
    $win7Xaml = @'
<Window xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
        xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
        Title="Windows 7 Support (Experimental)"
        Width="720" Height="620"
        WindowStartupLocation="CenterOwner"
        Background="#FF0A0A0A"
        FontFamily="Consolas">
    <Grid Margin="15">
        <Grid.RowDefinitions>
            <RowDefinition Height="Auto"/>
            <RowDefinition Height="*"/>
            <RowDefinition Height="Auto"/>
        </Grid.RowDefinitions>

        <TextBlock Grid.Row="0" Text="⚠️ Windows 7 + RDNA2/3 Warning" 
                   Foreground="#FFFF4444" FontSize="18" FontWeight="Bold" Margin="0,0,0,10"/>

        <ScrollViewer Grid.Row="1" VerticalScrollBarVisibility="Auto">
            <TextBlock Foreground="#FFFF8888" TextWrapping="Wrap">
                <Run Text="AMD dropped Windows 7 support after April 2020 (Adrenalin 20.4.2)."/>
                <LineBreak/><LineBreak/>
                <Run Text="RDNA2 (6000) and RDNA3 (7000) GPUs require WDDM 2.7+, which Windows 7 does NOT support."/>
                <LineBreak/><LineBreak/>
                <Run Text="This tool will attempt to:" FontWeight="Bold"/>
                <LineBreak/>
                <Run Text="• Patch INF files with Win7 decoration (NTamd64.6.1...7601)"/>
                <LineBreak/>
                <Run Text="• Inject device IDs for common 6000/7000 GPUs into a LEGACY driver base"/>
                <LineBreak/>
                <Run Text="• You MUST use Adrenalin 20.4.2 (or older) as your driver root!"/>
                <LineBreak/><LineBreak/>
                <Run Text="❗ Expected outcome: Basic display output ONLY. No Adrenalin UI, no gaming, no AV1, no HDMI 2.1." Foreground="#FFFF0000"/>
                <LineBreak/><LineBreak/>
                <Run Text="✅ Supported GPUs (partial): RX 5000 series (Navi10/14)."/>
                <LineBreak/>
                <Run Text="❌ Likely failure: RX 6000/7000 series (Navi2x/3x) — may show black screen." Foreground="#FFFF0000"/>
                <LineBreak/><LineBreak/>
                <Run Text="📌 Instructions:" FontWeight="Bold"/>
                <LineBreak/>
                <Run Text="1. Download AMD Adrenalin 20.4.2 for Windows 7 (64-bit)"/>
                <LineBreak/>
                <Run Text="   → https://www.amd.com/en/support/kb/release-notes/rn-rad-win-20-4-2"/>
                <LineBreak/>
                <Run Text="2. Extract it to a folder (e.g., C:\AMD\Win7_20.4.2)"/>
                <LineBreak/>
                <Run Text="3. Point this tool to that folder"/>
                <LineBreak/>
                <Run Text="4. Click 'Attempt Win7 Patch' below"/>
                <LineBreak/><LineBreak/>
                <Run Text="⚠️ BACK UP YOUR SYSTEM BEFORE PROCEEDING." Foreground="#FFFF0000"/>
            </TextBlock>
        </ScrollViewer>

        <StackPanel Grid.Row="2" Orientation="Horizontal" HorizontalAlignment="Center" Margin="0,15,0,0">
            <Button x:Name="btnAttemptWin7" Content="Attempt Win7 Patch" Width="180" Height="32"
                    Background="#FF660000" Foreground="#FFFFFFFF" Margin="5,0"/>
            <Button x:Name="btnClose" Content="Close" Width="100" Height="32"
                    Background="#FF333333" Foreground="#FFFFFFFF" Margin="5,0"/>
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
            [System.Windows.MessageBox]::Show("Please set a valid driver root folder (e.g., extracted Adrenalin 20.4.2).", "Error", "OK", "Error") | Out-Null
            $win7Window.IsEnabled = $true
            return
        }

        $hasW7INF = Get-ChildItem -Path $driverRoot -Recurse -Filter "*.inf" -EA 0 |
                    Where-Object { $_.DirectoryName -match 'W76A_INF' -or $_.Name -like 'ati2mtag*.inf' }
        if (-not $hasW7INF) {
            $result = [System.Windows.MessageBox]::Show(
                "This doesn't look like a Windows 7 driver (missing W76A_INF). Continue anyway?",
                "Warning", "YesNo", "Warning")
            if ($result -ne [System.Windows.MessageBoxResult]::Yes) {
                $win7Window.IsEnabled = $true
                return
            }
        }

        Start-Job -ScriptBlock {
            param($Root, $SessionID, $BackupBase)
            function Write-LogLocal { param($Msg,$Lvl='Info'); Write-Output @{Message=$Msg;Level=$Lvl} }
            function Backup-FileLocal { param($FP); $h=(Get-FileHash $FP -Algorithm SHA256).Hash.Substring(0,8); $b="$FP.bak_$SessionID`_$h"; Copy-Item $FP $b -Force; $b }

            $gpuMap = @{
                "RX 6950 XT" = "73AF"
                "RX 6900 XT" = "73BF"
                "RX 6800 XT" = "73AB"
                "RX 6800"    = "73A0"
                "RX 6700 XT" = "73DF"
                "RX 6600 XT" = "73FF"
                "RX 6600"    = "73E0"
                "RX 7900 XTX"= "744C"
                "RX 7900 XT" = "7440"
                "RX 7800 XT" = "73A0"
                "RX 7700 XT" = "743F"
                "RX 7600"    = "7430"
            }

            try {
                Write-LogLocal "Starting Windows 7 experimental patch..." "Warning"

                $infFiles = Get-ChildItem -Path $Root -Recurse -Filter "ati2mtag_*.inf" -EA 0
                if (-not $infFiles) { $infFiles = Get-ChildItem -Path $Root -Recurse -Filter "*.inf" -EA 0 | Where-Object { $_.Name -notlike "oem*.inf" } }
                if (-not $infFiles) { throw "No INF files found" }

                foreach ($inf in $infFiles) {
                    $content = Get-Content -Raw -LiteralPath $inf.FullName
                    $original = $content

                    $content = [regex]::Replace($content, '(?im)^(?=\s*%[^%]+\s*=\s*[^,\r\n]+,).*?NTamd64[^\s,;\]\r\n]*', 'NTamd64.6.1...7601')
                    $content = [regex]::Replace($content, '(?im)^\[ATI\.Mfg\.NTamd64[^\]]*\]\s*', "[ATI.Mfg.NTamd64.6.1...7601]`r`n")

                    $modelSection = ""
                    foreach ($gpu in $gpuMap.Keys) {
                        $devId = $gpuMap[$gpu]
                        $modelSection += "%AMD$devId.1% = AMD$devId, PCI\VEN_1002&DEV_$devId`r`n"
                    }
                    if ($content -match '(?im)^\[Manufacturer\]\s*') {
                        $content = [regex]::Replace($content, '(?im)(^\[Manufacturer\]\s*)', "`$1$modelSection")
                    }

                    $installSection = "`r`n; === Injected Win7 GPU Support ===`r`n"
                    foreach ($devId in $gpuMap.Values) {
                        $installSection += "[AMD$devId]`r`nCopyFiles = UMD.Files, UMD.Files.X64`r`n`r`n"
                    }
                    $content += $installSection

                    if ($content -ne $original) {
                        $bak = Backup-FileLocal -FP $inf.FullName
                        Set-Content -LiteralPath $inf.FullName -Value $content -Encoding ASCII
                        Write-LogLocal "Patched INF for Win7: $($inf.FullName)" "Success"
                    }
                }

                $manifests = Get-ChildItem -Path $Root -Recurse -File -EA 0 |
                             Where-Object { $_.Name -match 'manifest' -and $_.Extension -eq '.json' }
                foreach ($m in $manifests) {
                    $txt = Get-Content -Raw -LiteralPath $m.FullName
                    $orig = $txt
                    $txt = [regex]::Replace($txt, '"MinOS"\s*:\s*".+?"', '"MinOS":"6.1.0.0"')
                    $txt = [regex]::Replace($txt, '"MaxOS"\s*:\s*".+?"', '"MaxOS":"6.1.99999.0"')
                    if ($txt -ne $orig) {
                        $bak = Backup-FileLocal -FP $m.FullName
                        Set-Content -LiteralPath $m.FullName -Value $txt -Encoding UTF8
                        Write-LogLocal "Patched manifest for Win7: $($m.FullName)" "Success"
                    }
                }

                Write-LogLocal "Windows 7 patch completed. Use at your own risk!" "Warning"
            } catch {
                Write-LogLocal "Win7 patch failed: $_" "Error"
            }
        } -ArgumentList $driverRoot, $script:SessionID, $script:BackupBase | Out-Null

        $timer = New-Object System.Windows.Threading.DispatcherTimer
        $timer.Interval = [TimeSpan]::FromMilliseconds(500)
        $timer.Add_Tick({
            $job = Get-Job | Where-Object {$_.State -in 'Completed','Failed'}
            if ($job) {
                $results = Receive-Job $job
                Remove-Job $job
                foreach($r in $results){ if($r -is [hashtable]){ Write-Log $r.Message $r.Level } }
                $timer.Stop()
                $win7Window.IsEnabled = $true
                [System.Windows.MessageBox]::Show('Win7 patch attempt complete. Check logs.', 'Done', 'OK', 'Information') | Out-Null
            }
        })
        $timer.Start()
    })

    [void]$win7Window.ShowDialog()
}
#endregion ====================================================================

#region ==================== WPF UI Definition ===========================
$Xaml = @'
<Window xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
        xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
        Title="AMD INF Patcher (Server 2025 Ready)"
        Width="860" Height="700"
        WindowStartupLocation="CenterScreen"
        Background="#FF000000"
        FontFamily="Consolas"
        AllowsTransparency="False"
        WindowStyle="SingleBorderWindow">
    <Grid Margin="10">
        <Border Background="#FF0A0A0A"
                CornerRadius="6"
                BorderBrush="#FF330000"
                BorderThickness="1"
                Padding="12">
            <Grid>
                <Grid.RowDefinitions>
                    <RowDefinition Height="Auto"/>
                    <RowDefinition Height="Auto"/>
                    <RowDefinition Height="Auto"/>
                    <RowDefinition Height="5*"/>
                    <RowDefinition Height="Auto"/>
                </Grid.RowDefinitions>

                <TextBlock Grid.Row="0" Text="AMD INF PATCHER"
                           Foreground="#FFFF0000"
                           FontSize="24"
                           FontWeight="Bold"
                           HorizontalAlignment="Center"
                           Margin="0,0,0,10"/>

                <StackPanel Grid.Row="1" Orientation="Horizontal" Margin="0,0,0,10">
                    <TextBlock Text="Driver Root:" Foreground="#FFFF4444" VerticalAlignment="Center"/>
                    <TextBox x:Name="txtRoot" Width="500" Height="26" Margin="10,0,0,0"
                             Background="#FF111111" Foreground="#FFFF4444" BorderBrush="#FF330000"/>
                    <Button x:Name="btnBrowse" Content="Browse..." Width="80" Height="26" Margin="10,0,0,0"
                            Background="#FF220000" Foreground="#FFFFFFFF"/>
                </StackPanel>

                <StackPanel Grid.Row="2" Orientation="Horizontal" Margin="0,0,0,15">
                    <TextBlock Text="Target OS:" Foreground="#FFFF4444" VerticalAlignment="Center"/>
                    <ComboBox x:Name="cboTarget" Width="180" Height="26" Margin="10,0,0,0"
                              Background="#FF111111" Foreground="#FFFF4444" BorderBrush="#FF330000">
                        <ComboBoxItem Content="Generic"/>
                        <ComboBoxItem Content="Server2022"/>
                        <ComboBoxItem Content="Win11_24H2"/>
                        <ComboBoxItem Content="Server2025" IsSelected="True"/>
                        <ComboBoxItem Content="Win7"/>
                        <ComboBoxItem Content="Custom"/>
                    </ComboBox>
                    <TextBox x:Name="txtCustom" Width="250" Height="26" Margin="10,0,0,0"
                             Text="e.g., NTamd64.10.0...26100"
                             IsEnabled="False"
                             Background="#FF111111" Foreground="#FF888888"/>
                </StackPanel>

                <StackPanel Grid.Row="3" Orientation="Vertical" Margin="0,0,0,10">
                    <CheckBox x:Name="chkManifest" Content="Patch Adrenalin Manifest (Best Effort)"
                              IsChecked="True" Foreground="#FFFF6666"/>
                    <WrapPanel HorizontalAlignment="Center" Margin="0,10,0,0">
                        <Button x:Name="btnPatch" Content="Patch INF" Width="100" Height="30" Margin="5,0"
                                Background="#FF330000" Foreground="#FFFFFFFF"/>
                        <Button x:Name="btnRevert" Content="Revert All" Width="100" Height="30" Margin="5,0"
                                Background="#FF440000" Foreground="#FFFFFFFF"/>
                        <Button x:Name="btnCheckDeps" Content="Check Dependencies" Width="150" Height="30" Margin="5,0"
                                Background="#FF220000" Foreground="#FFFFFFFF"/>
                        <Button x:Name="btnWin7" Content="Windows 7 Support" Width="150" Height="30" Margin="5,0"
                                Background="#FF550000" Foreground="#FFFFFFFF"/>
                    </WrapPanel>
                </StackPanel>

                <RichTextBox Grid.Row="4" x:Name="txtLog"
                             Background="#FF000000"
                             Foreground="#FFFF0000"
                             FontSize="12"
                             IsReadOnly="True"
                             VerticalScrollBarVisibility="Auto"
                             BorderBrush="#FF330000"
                             BorderThickness="1"/>

                <TextBlock Grid.Row="5" Text="By AMD_DriverMagic | Reddit Community"
                           HorizontalAlignment="Center"
                           Foreground="#FF555555"
                           FontSize="10"
                           Margin="0,10,0,0"/>
            </Grid>
        </Border>
    </Grid>
</Window>
'@
#endregion ====================================================================

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

# Browse
$btnBrowse.Add_Click({
    $dlg = New-Object System.Windows.Forms.FolderBrowserDialog
    $dlg.Description = "Select AMD Driver Root Folder"
    if ($dlg.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) {
        $txtRoot.Text = $dlg.SelectedPath
    }
})

# Target change
$cboTarget.Add_SelectionChanged({
    $isCustom = ($cboTarget.SelectedItem.Content -eq 'Custom')
    $txtCustom.IsEnabled = $isCustom
    if (-not $isCustom) {
        $txtCustom.Text = "e.g., NTamd64.10.0...26100"
        $txtCustom.Foreground = [System.Windows.Media.Brushes]::LightGray
    } else {
        $txtCustom.Text = ''
        $txtCustom.Foreground = [System.Windows.Media.Brushes]::White
    }
})

# Custom placeholder
$txtCustom.AddHandler([System.Windows.UIElement]::GotFocusEvent, [System.Windows.RoutedEventHandler]{
    param($sender, $e)
    if ($txtCustom.Text -eq "e.g., NTamd64.10.0...26100") {
        $txtCustom.Text = ""
        $txtCustom.Foreground = [System.Windows.Media.Brushes]::White
    }
})
$txtCustom.AddHandler([System.Windows.UIElement]::LostFocusEvent, [System.Windows.RoutedEventHandler]{
    param($sender, $e)
    if ([string]::IsNullOrWhiteSpace($txtCustom.Text)) {
        $txtCustom.Text = "e.g., NTamd64.10.0...26100"
        $txtCustom.Foreground = [System.Windows.Media.Brushes]::LightGray
    }
})

# Buttons
$btnCheckDeps.Add_Click({
    if (Ensure-Dependencies) {
        [System.Windows.MessageBox]::Show('All dependencies OK.', 'Success', 'OK', 'Information') | Out-Null
    } else {
        [System.Windows.MessageBox]::Show('Dependency check failed. See log.', 'Error', 'OK', 'Error') | Out-Null
    }
})

$btnPatch.Add_Click({
    if ([string]::IsNullOrWhiteSpace($txtRoot.Text) -or -not (Test-Path $txtRoot.Text)) {
        [System.Windows.MessageBox]::Show('Invalid driver root path.', 'Error', 'OK', 'Error') | Out-Null
        return
    }
    $target = $cboTarget.SelectedItem.Content
    if ($target -eq 'Custom' -and ([string]::IsNullOrWhiteSpace($txtCustom.Text) -or $txtCustom.Text -like '*e.g.,*')) {
        [System.Windows.MessageBox]::Show('Please enter a custom decoration.', 'Error', 'OK', 'Error') | Out-Null
        return
    }
    $customDec = if ($target -eq 'Custom') { $txtCustom.Text } else { '' }

    $window.IsEnabled = $false
    Start-Job -ScriptBlock {
        param($Root,$Target,$CustomDec,$PatchMan,$SessionID,$BackupBase)
        function Write-LogLocal { param($Msg,$Lvl='Info'); Write-Output @{Message=$Msg;Level=$Lvl} }
        function Backup-FileLocal { param($FP); $h=(Get-FileHash $FP -Algorithm SHA256).Hash.Substring(0,8); $b="$FP.bak_$SessionID`_$h"; Copy-Item $FP $b -Force; $b }
        $map=@{Generic='NTamd64';Server2022='NTamd64.10.0...20348';Win11_24H2='NTamd64.10.0...26100';Server2025='NTamd64.10.0...26100';Win7='NTamd64.6.1...7601'}
        $dec = if($Target -eq 'Custom'){$CustomDec}else{$map[$Target]}
        Write-LogLocal "Patching with: $dec"

        $infFiles = Get-ChildItem -Path $Root -Recurse -Filter *.inf -EA 0 | Where-Object { $_.FullName -match '\\Display\\WT6A_INF\\' -or $_.DirectoryName -match 'WT6A_INF' -or $_.Name -match '^u\d+\.inf$' }
        foreach ($inf in $infFiles) {
            try {
                $txt = Get-Content -Raw -LiteralPath $inf.FullName
                $orig=$txt
                $txt=[regex]::Replace($txt,'(?im)^(?=\s*%[^%]+\s*=\s*[^,\r\n]+,).*?NTamd64[^\s,;\]\r\n]*',$dec)
                $txt=[regex]::Replace($txt,'(?im)^\[ATI\.Mfg\.NTamd64[^\]]*\]\s*',"[ATI.Mfg.$dec`r`n")
                if ($txt -ne $orig){
                    $bak=Backup-FileLocal -FP $inf.FullName
                    Set-Content -LiteralPath $inf.FullName -Value $txt -Encoding ASCII
                    Write-LogLocal "Patched INF: $($inf.FullName)"
                }
            } catch { Write-LogLocal "INF error: $_" "Error" }
        }

        if ($PatchMan) {
            $manifests = Get-ChildItem -Path $Root -Recurse -File -EA 0 | Where-Object { $_.Name -match '(?i)(InstallManifest\.json|AppInstallerManifest\.xml|manifest\.json)' -or $_.DirectoryName -match 'Bin64' }
            foreach ($m in $manifests) {
                try {
                    $txt = Get-Content -Raw -LiteralPath $m.FullName
                    $orig=$txt
                    $txt=[regex]::Replace($txt,'(?i)"Min(?:OS|Build|Version|OSVersion|OSBuild)"\s*:\s*".+?"','"MinOS":"10.0.0.0"')
                    $txt=[regex]::Replace($txt,'(?i)"Max(?:OS|Build|Version|OSVersion|OSBuild|OSVersionTested)"\s*:\s*".+?"','"MaxOS":"10.0.99999.0"')
                    $txt=[regex]::Replace($txt,'(?i)"SupportedOS(?:es|List)"\s*:\s*\[(.*?)\]','"SupportedOS":[$1,"WindowsServer"]')
                    if ($txt -ne $orig){
                        $bak=Backup-FileLocal -FP $m.FullName
                        Set-Content -LiteralPath $m.FullName -Value $txt -Encoding UTF8
                        Write-LogLocal "Patched manifest: $($m.FullName)"
                    }
                } catch { Write-LogLocal "Manifest error: $_" "Error" }
            }
        }
        Write-LogLocal "Patching completed."
    } -ArgumentList $txtRoot.Text,$target,$customDec,$chkManifest.IsChecked,$script:SessionID,$script:BackupBase | Out-Null

    $timer = New-Object System.Windows.Threading.DispatcherTimer
    $timer.Interval = [TimeSpan]::FromMilliseconds(500)
    $timer.Add_Tick({
        $job = Get-Job | Where-Object {$_.State -in 'Completed','Failed'}
        if ($job) {
            $results = Receive-Job $job
            Remove-Job $job
            foreach($r in $results){ if($r -is [hashtable]){ Write-Log $r.Message $r.Level } }
            $timer.Stop()
            $window.IsEnabled = $true
            [System.Windows.MessageBox]::Show('Operation complete. Check logs.', 'Done', 'OK', 'Information') | Out-Null
        }
    })
    $timer.Start()
})

$btnRevert.Add_Click({
    $window.IsEnabled = $false
    Start-Job -ScriptBlock {
        param($BackupBase,$SessionID)
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
        $job = Get-Job | Where-Object {$_.State -eq 'Completed'}
        if ($job) {
            $results = Receive-Job $job
            Remove-Job $job
            foreach($r in $results){ if($r -is [hashtable]){ Write-Log $r.Message $r.Level } }
            $timer.Stop()
            $window.IsEnabled = $true
            [System.Windows.MessageBox]::Show('Revert complete.', 'Done', 'OK', 'Information') | Out-Null
        }
    })
    $timer.Start()
})

$btnWin7.Add_Click({
    Show-Win7SupportWindow
})

Write-Log "AMD INF Patcher GUI Loaded." "Info"
if (-not (Ensure-Dependencies)) {
    [System.Windows.MessageBox]::Show('Critical dependency missing. App may not function.', 'Warning', 'OK', 'Exclamation') | Out-Null
}

[void]$window.ShowDialog()
#endregion ====================================================================