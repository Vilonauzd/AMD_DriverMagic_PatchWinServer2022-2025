#Requires -RunAsAdministrator
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

# ------------------------------------------------------------
# AMD INF Patcher – GUI Edition (v2.0)
# Supports Windows Server 2025 (build 26100)
# ------------------------------------------------------------

param(
    [string]$InitialRootPath = ''
)

# ---------------- Global Config ----------------
$script:LogLines = [System.Collections.ArrayList]::new()
$script:CurrentLogPath = $null
$script:SessionID = (Get-Date -Format 'yyyyMMdd_HHmmss')
$script:BackupBase = "C:\RepairLogs"
$script:ValidTargets = @{
    'Generic'      = 'NTamd64'
    'Server2022'   = 'NTamd64.10.0...20348'
    'Win11_24H2'   = 'NTamd64.10.0...26100'
    'Server2025'   = 'NTamd64.10.0...26100'  # ✅ GA Build
    'Custom'       = $null
}

# ---------------- Helper Functions ----------------
function Write-Log {
    param([string]$Message, [string]$Level = 'Info')
    $time = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    $logEntry = "[$time] [$Level] $Message"
    [void]$script:LogLines.Add($logEntry)
    if ($script:MainForm -and $script:MainForm.txtLog) {
        $script:MainForm.txtLog.AppendText("$logEntry`r`n")
        $script:MainForm.txtLog.SelectionStart = $script:MainForm.txtLog.Text.Length
        $script:MainForm.txtLog.ScrollToCaret()
    }
    if ($script:CurrentLogPath) {
        Add-Content -Path $script:CurrentLogPath -Value $logEntry -ErrorAction SilentlyContinue
    }
}

function Ensure-Dependencies {
    Write-Log "Checking system dependencies..." "Info"
    
    # PowerShell version
    if ($PSVersionTable.PSVersion.Major -lt 5) {
        Write-Log "PowerShell 5.1+ required. Current: $($PSVersionTable.PSVersion)" "Error"
        return $false
    }

    # Admin rights
    $isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    if (-not $isAdmin) {
        Write-Log "Administrator privileges required." "Error"
        return $false
    }

    # RepairLogs folder
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

function Backup-File {
    param([string]$FilePath)
    try {
        $hash = (Get-FileHash -Path $FilePath -Algorithm SHA256).Hash.Substring(0,8)
        $backupName = "$FilePath.bak_$($script:SessionID)_$hash"
        Copy-Item -LiteralPath $FilePath -Destination $backupName -Force
        return $backupName
    } catch {
        throw "Backup failed for $FilePath : $_"
    }
}

function Revert-AllChanges {
    Write-Log "Starting full revert process..." "Warning"
    $logFiles = Get-ChildItem -Path $script:BackupBase -Filter "*amd_inf_patch_*.log" -ErrorAction SilentlyContinue
    $reverted = 0

    foreach ($log in $logFiles) {
        $pattern = [regex]::Escape(".bak_$($log.BaseName.Split('_')[-2])_")
        $backups = Get-ChildItem -Path "$script:BackupBase\*" -Include "*.bak_*" -Recurse -ErrorAction SilentlyContinue |
                   Where-Object { $_.Name -match $pattern }

        foreach ($bak in $backups) {
            $orig = $bak.FullName -replace "\.bak_$($log.BaseName.Split('_')[-2])_[0-9a-f]{8}", ""
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

    if ($reverted -eq 0) {
        Write-Log "No revertable backups found." "Info"
    } else {
        Write-Log "Reverted $reverted file(s)." "Success"
    }
}

function Patch-INFAndManifests {
    param(
        [string]$Root,
        [string]$Target,
        [string]$CustomDecoration,
        [bool]$PatchManifest
    )

    # Resolve decoration
    if ($Target -eq 'Custom') {
        if ([string]::IsNullOrWhiteSpace($CustomDecoration)) {
            Write-Log "Custom target requires Decoration value." "Error"
            return
        }
        $dec = $CustomDecoration
    } else {
        $dec = $script:ValidTargets[$Target]
    }

    Write-Log "Using decoration: $dec" "Info"
    $script:CurrentLogPath = Join-Path $script:BackupBase "amd_inf_patch_$($script:SessionID).log"
    Write-Log "Session log: $($script:CurrentLogPath)" "Info"

    # Find INF files
    $infFiles = Get-ChildItem -Path $Root -Recurse -Filter *.inf -ErrorAction SilentlyContinue |
                Where-Object { $_.FullName -match '\\Display\\WT6A_INF\\' -or $_.DirectoryName -match 'WT6A_INF' -or $_.Name -match '^u\d+\.inf$' }

    if (-not $infFiles) {
        Write-Log "No INF files found in $Root matching criteria." "Warning"
    } else {
        foreach ($inf in $infFiles) {
            try {
                $content = Get-Content -LiteralPath $inf.FullName -Raw -ErrorAction Stop
                $original = $content

                # Patch Manufacturer lines
                $content = [regex]::Replace($content, '(?im)^(?=\s*%[^%]+\s*=\s*[^,\r\n]+,).*?NTamd64[^\s,;\]\r\n]*', $dec)

                # Patch section headers
                $content = [regex]::Replace($content, '(?im)^\[ATI\.Mfg\.NTamd64[^\]]*\]\s*', "[ATI.Mfg.$dec]`r`n")

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

    # Patch manifests if requested
    if ($PatchManifest) {
        $manifests = Get-ChildItem -Path $Root -Recurse -File -ErrorAction SilentlyContinue |
                     Where-Object { $_.Name -match '(?i)(InstallManifest\.json|AppInstallerManifest\.xml|manifest\.json)' -or $_.DirectoryName -match 'Bin64' }

        foreach ($m in $manifests) {
            try {
                $txt = Get-Content -LiteralPath $m.FullName -Raw -ErrorAction Stop
                $orig = $txt

                $txt = [regex]::Replace($txt, '(?i)"(Min(?:OS|Build|Version|OSVersion|OSBuild))"\s*:\s*"(.*?)"', '"$1":"10.0.0.0"')
                $txt = [regex]::Replace($txt, '(?i)"(Max(?:OS|Build|Version|OSVersion|OSBuild|OSVersionTested))"\s*:\s*"(.*?)"', '"$1":"10.0.99999.0"')
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

# ---------------- GUI Setup ----------------
$form = New-Object System.Windows.Forms.Form
$form.Text = "AMD INF Patcher (Server 2025 Ready)"
$form.Size = New-Object System.Drawing.Size(800, 600)
$form.StartPosition = "CenterScreen"
$form.MaximizeBox = $false
$form.MinimizeBox = $false
$form.Icon = [System.Drawing.SystemIcons]::Information

# Root Path
$lblRoot = New-Object System.Windows.Forms.Label
$lblRoot.Location = New-Object System.Drawing.Point(20, 20)
$lblRoot.Size = New-Object System.Drawing.Size(120, 20)
$lblRoot.Text = "Driver Root Folder:"
$form.Controls.Add($lblRoot)

$txtRoot = New-Object System.Windows.Forms.TextBox
$txtRoot.Location = New-Object System.Drawing.Point(150, 20)
$txtRoot.Size = New-Object System.Drawing.Size(400, 20)
$txtRoot.Text = $InitialRootPath
$form.Controls.Add($txtRoot)

$btnBrowse = New-Object System.Windows.Forms.Button
$btnBrowse.Location = New-Object System.Drawing.Point(560, 18)
$btnBrowse.Size = New-Object System.Drawing.Size(80, 23)
$btnBrowse.Text = "Browse..."
$btnBrowse.Add_Click({
    $fd = New-Object System.Windows.Forms.FolderBrowserDialog
    $fd.Description = "Select AMD Driver Root Folder"
    if ($fd.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) {
        $txtRoot.Text = $fd.SelectedPath
    }
})
$form.Controls.Add($btnBrowse)

# Target OS
$lblTarget = New-Object System.Windows.Forms.Label
$lblTarget.Location = New-Object System.Drawing.Point(20, 50)
$lblTarget.Size = New-Object System.Drawing.Size(120, 20)
$lblTarget.Text = "Target OS:"
$form.Controls.Add($lblTarget)

$cboTarget = New-Object System.Windows.Forms.ComboBox
$cboTarget.Location = New-Object System.Drawing.Point(150, 50)
$cboTarget.Size = New-Object System.Drawing.Size(200, 20)
$cboTarget.DropDownStyle = "DropDownList"
@('Generic','Server2022','Win11_24H2','Server2025','Custom') | ForEach-Object { [void]$cboTarget.Items.Add($_) }
$cboTarget.SelectedIndex = 3  # Default to Server2025
$form.Controls.Add($cboTarget)

$txtCustom = New-Object System.Windows.Forms.TextBox
$txtCustom.Location = New-Object System.Drawing.Point(360, 50)
$txtCustom.Size = New-Object System.Drawing.Size(200, 20)
$txtCustom.Enabled = $false
$txtCustom.PlaceholderText = "e.g., NTamd64.10.0...26100"
$form.Controls.Add($txtCustom)

$cboTarget.Add_SelectedValueChanged({
    $txtCustom.Enabled = ($cboTarget.SelectedItem -eq 'Custom')
})

# Options
$chkManifest = New-Object System.Windows.Forms.CheckBox
$chkManifest.Location = New-Object System.Drawing.Point(150, 80)
$chkManifest.Size = New-Object System.Drawing.Size(250, 20)
$chkManifest.Text = "Patch Adrenalin Manifest (Best Effort)"
$chkManifest.Checked = $true
$form.Controls.Add($chkManifest)

# Buttons
$btnPatch = New-Object System.Windows.Forms.Button
$btnPatch.Location = New-Object System.Drawing.Point(150, 110)
$btnPatch.Size = New-Object System.Drawing.Size(100, 30)
$btnPatch.Text = "Patch INF"
$btnPatch.Add_Click({
    if ([string]::IsNullOrWhiteSpace($txtRoot.Text) -or -not (Test-Path $txtRoot.Text)) {
        [System.Windows.Forms.MessageBox]::Show("Invalid driver root path.", "Error", "OK", "Error")
        return
    }
    if ($cboTarget.SelectedItem -eq 'Custom' -and [string]::IsNullOrWhiteSpace($txtCustom.Text)) {
        [System.Windows.Forms.MessageBox]::Show("Custom decoration required.", "Error", "OK", "Error")
        return
    }
    $form.Enabled = $false
    Start-Job -ScriptBlock {
        # Re-import functions (jobs are isolated)
        $functions = @'
function Write-Log { param([string]$Message, [string]$Level = 'Info') { Write-Output @{Time=(Get-Date); Level=$Level; Message=$Message} } }
function Backup-File { param([string]$FilePath) { $hash = (Get-FileHash -Path $FilePath -Algorithm SHA256).Hash.Substring(0,8); $b = "$FilePath.bak_$using:SessionID`_$hash"; Copy-Item $FilePath $b -Force; return $b } }
'@
        . ([ScriptBlock]::Create($functions))
        # Now call main logic
        try {
            Patch-INFAndManifests -Root $using:txtRoot.Text -Target $using:cboTarget.SelectedItem -CustomDecoration $using:txtCustom.Text -PatchManifest $using:chkManifest.Checked
        } catch {
            Write-Log "Fatal error: $_" "Error"
        }
    } | Out-Null

    # Monitor job in background
    $timer = New-Object System.Windows.Forms.Timer
    $timer.Interval = 500
    $timer.Add_Tick({
        $job = Get-Job | Where-Object { $_.State -eq 'Completed' -or $_.State -eq 'Failed' }
        if ($job) {
            $results = Receive-Job $job
            Remove-Job $job
            foreach ($r in $results) {
                if ($r -is [hashtable]) {
                    $script:MainForm.txtLog.AppendText("[$($r.Time)] [$($r.Level)] $($r.Message)`r`n")
                }
            }
            $timer.Stop()
            $form.Enabled = $true
            [System.Windows.Forms.MessageBox]::Show("Patching complete. Check logs.", "Done", "OK", "Information")
        }
    })
    $timer.Start()
})
$form.Controls.Add($btnPatch)

$btnRevert = New-Object System.Windows.Forms.Button
$btnRevert.Location = New-Object System.Drawing.Point(260, 110)
$btnRevert.Size = New-Object System.Drawing.Size(100, 30)
$btnRevert.Text = "Revert All"
$btnRevert.Add_Click({
    $form.Enabled = $false
    Start-Job -ScriptBlock {
        try {
            Revert-AllChanges
        } catch {
            Write-Log "Revert error: $_" "Error"
        }
    } | Out-Null

    $timer = New-Object System.Windows.Forms.Timer
    $timer.Interval = 500
    $timer.Add_Tick({
        $job = Get-Job | Where-Object { $_.State -eq 'Completed' }
        if ($job) {
            $results = Receive-Job $job
            Remove-Job $job
            foreach ($r in $results) {
                if ($r -is [hashtable]) {
                    $script:MainForm.txtLog.AppendText("[$($r.Time)] [$($r.Level)] $($r.Message)`r`n")
                }
            }
            $timer.Stop()
            $form.Enabled = $true
            [System.Windows.Forms.MessageBox]::Show("Revert complete.", "Done", "OK", "Information")
        }
    })
    $timer.Start()
})
$form.Controls.Add($btnRevert)

$btnCheckDeps = New-Object System.Windows.Forms.Button
$btnCheckDeps.Location = New-Object System.Drawing.Point(370, 110)
$btnCheckDeps.Size = New-Object System.Drawing.Size(120, 30)
$btnCheckDeps.Text = "Check Dependencies"
$btnCheckDeps.Add_Click({
    if (Ensure-Dependencies) {
        [System.Windows.Forms.MessageBox]::Show("All dependencies OK.", "Success", "OK", "Information")
    } else {
        [System.Windows.Forms.MessageBox]::Show("Dependency check failed. See log.", "Error", "OK", "Error")
    }
})
$form.Controls.Add($btnCheckDeps)

# Log Box
$txtLog = New-Object System.Windows.Forms.RichTextBox
$txtLog.Location = New-Object System.Drawing.Point(20, 150)
$txtLog.Size = New-Object System.Drawing.Size(750, 380)
$txtLog.ReadOnly = $true
$txtLog.Font = New-Object System.Drawing.Font("Consolas", 9)
$txtLog.ScrollBars = "Vertical"
$form.Controls.Add($txtLog)

# Assign to script scope for logging
$script:MainForm = $form
$script:MainForm.txtLog = $txtLog

# Initial log
Write-Log "AMD INF Patcher GUI Loaded." "Info"
Write-Log "Windows Server 2025 GA build: 26100" "Info"
if (-not (Ensure-Dependencies)) {
    [System.Windows.Forms.MessageBox]::Show("Critical dependency missing. App may not function.", "Warning", "OK", "Exclamation")
}

# Show Form
[void]$form.ShowDialog()