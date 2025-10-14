
#requires -Version 5.1
<#
Rarity Intelligence™ AMD INF Patcher — WPF Edition
Version: 1.0 (2025-10-12)

This build replaces the browser/WebView UI with a native WPF window.
- Fixed, centered window sized to 50% of the primary display.
- Word-wrapped log. No horizontal scrollbar.
- Revert All uses robust .bak discovery.
- Patch Manifest handles package.xml and driver.json.
- One-click Install with DSE handling for Windows Server.
- Direct link to AMD Drivers page.
#>

Add-Type -AssemblyName PresentationFramework, PresentationCore, WindowsBase, System.Xaml

# --------------- Core ops ---------------
$Script:LogLines = New-Object System.Collections.Generic.List[string]

function Write-UILog {
    param([string]$Message,[System.Windows.Controls.TextBox]$LogBox)
    $ts = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
    $line = "[{0}] {1}" -f $ts, $Message
    $Script:LogLines.Add($line) | Out-Null
    if ($LogBox) {
        $LogBox.AppendText($line + [Environment]::NewLine)
        $LogBox.ScrollToEnd()
    } else {
        Write-Host $line
    }
}

function Assert-Admin {
    $isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    if (-not $isAdmin) { throw "Run PowerShell as Administrator." }
}

function Resolve-Root([string]$Hint){
    if ($Hint -and (Test-Path $Hint)) { return (Resolve-Path $Hint).Path }
    $cands = @("$env:USERPROFILE\Downloads\AMD*","$env:USERPROFILE\Downloads\Win*","C:\AMD\*","C:\Drivers\AMD\*","$env:USERPROFILE\Desktop\AMD*")
    foreach ($p in $cands) {
        $d = Get-ChildItem -Path $p -Directory -ErrorAction SilentlyContinue | Sort-Object LastWriteTime -Descending | Select-Object -First 1
        if ($d) { return $d.FullName }
    }
    return $PWD.Path
}
function Find-INFs([string]$root){ Get-ChildItem -Path $root -Recurse -Include *.inf -File -ErrorAction SilentlyContinue }

function Backup-Candidates([string]$inf){
    $dir = Split-Path -Parent $inf
    $name = Split-Path -Leaf $inf
    $base = [IO.Path]::GetFileNameWithoutExtension($name)
    $cand = @(
        (Join-Path $dir "$name.bak"),
        (Join-Path $dir "$base.bak"),
        (Join-Path $dir "$base.inf.bak")
    )
    foreach($b in @('Backup','_backup','backup')){
        $up = Split-Path -Parent $dir
        $bd = Join-Path $up $b
        if(Test-Path $bd){
            $rel = $inf.Substring($up.Length).TrimStart('\','/')
            $cand += (Join-Path $bd $rel)
            $cand += (Join-Path $bd $rel) + '.bak'
        }
    }
    $cand | Where-Object { Test-Path $_ } | Select-Object -Unique
}

function Restore-Inf([string]$inf, [System.Windows.Controls.TextBox]$LogBox){
    $c = Backup-Candidates $inf
    if (-not $c) { Write-UILog "No backup for $inf" $LogBox; return $false }
    $b = $c | Sort-Object Length | Select-Object -First 1
    try {
        Copy-Item -LiteralPath $b -Destination $inf -Force
        Write-UILog ("Restored ""{0}"" from ""{1}""" -f $inf,$b) $LogBox
        return $true
    } catch {
        Write-UILog ("Restore failed {0}: {1}" -f $inf,$_.Exception.Message) $LogBox
        return $false
    }
}

function Revert-All([string]$root, [System.Windows.Controls.TextBox]$LogBox){
    $r = Resolve-Root $root
    if (-not (Test-Path $r)) { Write-UILog "Root not found: $r" $LogBox; return @{restored=0;failed=0;error='root_not_found'} }
    $infs = Find-INFs $r
    if (-not $infs){ Write-UILog "No INF files under $r" $LogBox; return @{restored=0;failed=0;error='no_inf'} }
    $ok=0;$ko=0
    foreach($i in $infs){ if (Restore-Inf $i.FullName $LogBox){$ok++} else {$ko++} }
    Write-UILog "Revert complete. Restored: $ok. Missing/Failed: $ko." $LogBox
    return @{restored=$ok;failed=$ko}
}

function Find-Manifests([string]$root){
    $r = Resolve-Root $root
    $xml = Get-ChildItem -Path $r -Recurse -Include package.xml -File -ErrorAction SilentlyContinue
    $json= Get-ChildItem -Path $r -Recurse -Include driver.json  -File -ErrorAction SilentlyContinue
    @{ xml=$xml; json=$json }
}
function Patch-Manifests([string]$root, [System.Windows.Controls.TextBox]$LogBox){
    $r=Resolve-Root $root
    if(-not(Test-Path $r)){ Write-UILog "Root not found: $r" $LogBox; return @{changed=0;error='root_not_found'} }
    $f=Find-Manifests $r; $t=0
    foreach($x in @($f.xml+$f.json)){
        try{
            $c = Get-Content -LiteralPath $x.FullName -Raw
            $bak = "$($x.FullName).bak"
            if(-not (Test-Path $bak)){ Copy-Item -LiteralPath $x.FullName -Destination $bak -Force }
            $p = $c -replace '(?i)WindowsServer(20\d{2})','Windows10'
            $p = $p -replace '(?is)(?<="BlockList"\s*:\s*)\[(.*?)\]','[]'
            if($p -ne $c){ Set-Content -LiteralPath $x.FullName -Value $p -Encoding UTF8; $t++; Write-UILog "Patched: $($x.FullName)" $LogBox } else { Write-UILog "No changes: $($x.FullName)" $LogBox }
        }catch{ Write-UILog ("Patch failed {0}: {1}" -f $x.FullName,$_.Exception.Message) $LogBox }
    }
    Write-UILog "Patch complete. Files changed: $t" $LogBox
    return @{changed=$t;xml=($f.xml|% FullName);json=($f.json|% FullName)}
}

function TestSigning-On(){ try{ (bcdedit|Out-String) -match 'testsigning\s+Yes' }catch{$false} }
function Enable-TestSigning([System.Windows.Controls.TextBox]$LogBox){
    try{ bcdedit /set testsigning on | Out-Null; bcdedit /set nointegritychecks on | Out-Null; Write-UILog "Enabled Test Signing and disabled integrity checks." $LogBox; return $true }
    catch{ Write-UILog ("Enable TestSigning failed: {0}" -f $_.Exception.Message) $LogBox; return $false }
}
$Script:RebootFlag = Join-Path $env:TEMP 'ri_infpatcher_reboot.flag'
function Install-Patched([string]$root, [System.Windows.Controls.TextBox]$LogBox){
    $r=Resolve-Root $root; if(-not(Test-Path $r)){ return @{status='failed';error='root_not_found'} }
    if(-not(TestSigning-On)){
        Write-UILog "TestSigning is OFF. Required for unsigned/patched drivers on Server." $LogBox
        if(Enable-TestSigning $LogBox){ New-Item -ItemType File -Path $Script:RebootFlag -Force | Out-Null; Write-UILog "Reboot required. After reboot, re-run Install." $LogBox; return @{status='reboot_required'} }
        else { return @{status='failed';error='enable_testsigning_failed'} }
    }
    $infs=Find-INFs $r; if(-not $infs){ return @{status='failed';error='no_inf'} }
    $added=0
    foreach($i in $infs){
        $rtxt = & pnputil /add-driver "`"$($i.FullName)`"" /install /subdirs 2>&1 | Out-String
        Write-UILog ($rtxt.Trim()) $LogBox
        if($rtxt -match '(?i)published|added|installed|staged'){ $added++ }
    }
    return @{status='ok';drivers=$added}
}

# --------------- XAML UI ---------------
$xaml = @'
<Window xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
        xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
        Title="Rarity Intelligence™ AMD INF Patcher" WindowStartupLocation="CenterScreen"
        ResizeMode="NoResize" SizeToContent="Manual" Background="#11141A" Foreground="#E7EAF1" FontFamily="Segoe UI">
  <Grid Margin="16">
    <Grid.RowDefinitions>
      <RowDefinition Height="Auto"/>
      <RowDefinition Height="Auto"/>
      <RowDefinition Height="*"/>
      <RowDefinition Height="Auto"/>
    </Grid.RowDefinitions>
    <TextBlock Grid.Row="0" Text="Rarity Intelligence™ AMD INF Patcher" FontSize="18" Margin="0,0,0,8"/>
    <Grid Grid.Row="1" Margin="0,0,0,8">
      <Grid.ColumnDefinitions>
        <ColumnDefinition Width="*"/>
        <ColumnDefinition Width="Auto"/>
        <ColumnDefinition Width="Auto"/>
        <ColumnDefinition Width="Auto"/>
        <ColumnDefinition Width="Auto"/>
      </Grid.ColumnDefinitions>
      <TextBox x:Name="RootBox" Grid.Column="0" Margin="0,0,8,0" ToolTip="Driver root (leave blank to auto-detect)"/>
      <Button x:Name="PatchBtn" Grid.Column="1" Content="Patch Manifests" Margin="0,0,8,0" Padding="10,6"/>
      <Button x:Name="RevertBtn" Grid.Column="2" Content="Revert All" Margin="0,0,8,0" Padding="10,6"/>
      <Button x:Name="InstallBtn" Grid.Column="3" Content="Install Patched Driver" Margin="0,0,8,0" Padding="10,6"/>
      <Button x:Name="AmdBtn" Grid.Column="4" Content="AMD Drivers" Padding="10,6"/>
    </Grid>
    <ScrollViewer Grid.Row="2" VerticalScrollBarVisibility="Auto" HorizontalScrollBarVisibility="Disabled">
      <TextBox x:Name="LogBox" IsReadOnly="True" TextWrapping="Wrap" AcceptsReturn="True" Background="#0B0F14" BorderBrush="#222" FontFamily="Consolas" FontSize="12"/>
    </ScrollViewer>
    <StackPanel Grid.Row="3" Orientation="Horizontal" HorizontalAlignment="Right" Opacity="0.8">
      <TextBlock Text="DPI-aware. Centered 50% window. Log wraps.  "/>
      <TextBlock Text="Rarity Intelligence™"/>
    </StackPanel>
  </Grid>
</Window>
'@

# --------------- Launch UI ---------------
try { Assert-Admin } catch { Write-Host $_; exit 1 }

$reader = New-Object System.Xml.XmlNodeReader ([xml]$xaml)
$window = [Windows.Markup.XamlReader]::Load($reader)

# 50% sizing and DPI-aware centering
$screenW = [System.Windows.SystemParameters]::PrimaryScreenWidth
$screenH = [System.Windows.SystemParameters]::PrimaryScreenHeight
$window.Width  = [Math]::Round($screenW * 0.5)
$window.Height = [Math]::Round($screenH * 0.5)

# Grab controls
$RootBox  = $window.FindName('RootBox')
$PatchBtn = $window.FindName('PatchBtn')
$RevertBtn= $window.FindName('RevertBtn')
$InstallBtn = $window.FindName('InstallBtn')
$AmdBtn   = $window.FindName('AmdBtn')
$LogBox   = $window.FindName('LogBox')

# Wire events
$PatchBtn.Add_Click({
    try {
        Write-UILog "Patch Manifests started." $LogBox
        $res = Patch-Manifests -root $RootBox.Text -LogBox $LogBox
        Write-UILog ("Result: " + ($res | ConvertTo-Json -Depth 6)) $LogBox
    } catch { Write-UILog ("Patch error: {0}" -f $_.Exception.Message) $LogBox }
})

$RevertBtn.Add_Click({
    try {
        Write-UILog "Revert All started." $LogBox
        $res = Revert-All -root $RootBox.Text -LogBox $LogBox
        Write-UILog ("Result: " + ($res | ConvertTo-Json -Depth 6)) $LogBox
    } catch { Write-UILog ("Revert error: {0}" -f $_.Exception.Message) $LogBox }
})

$InstallBtn.Add_Click({
    try {
        Write-UILog "Install Patched Driver started." $LogBox
        $res = Install-Patched -root $RootBox.Text -LogBox $LogBox
        Write-UILog ("Result: " + ($res | ConvertTo-Json -Depth 6)) $LogBox
    } catch { Write-UILog ("Install error: {0}" -f $_.Exception.Message) $LogBox }
})

$AmdBtn.Add_Click({
    try { Start-Process "https://www.amd.com/en/support" | Out-Null }
    catch { Write-UILog ("Open AMD link failed: {0}" -f $_.Exception.Message) $LogBox }
})

Write-UILog "WPF UI ready." $LogBox
$null = $window.ShowDialog()
