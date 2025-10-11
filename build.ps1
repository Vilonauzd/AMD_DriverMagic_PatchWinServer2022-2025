param(
  [string]$ProjectRoot = (Split-Path -Parent $MyInvocation.MyCommand.Path),
  [string]$Output = "$PSScriptRoot\AMD_INF_Patcher.exe"
)

$ErrorActionPreference = 'Stop'
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
Install-PackageProvider NuGet -Force -Scope AllUsers -ErrorAction SilentlyContinue | Out-Null
Set-PSRepository PSGallery -InstallationPolicy Trusted -ErrorAction SilentlyContinue

$deps = Join-Path $ProjectRoot "_deps"
New-Item -ItemType Directory -Path $deps -Force | Out-Null
Save-Module -Name ps2exe -Path $deps -Force

$ps2 = Get-ChildItem -Path $deps -Recurse -Filter ps2exe.ps1 | Select-Object -First 1
if (-not $ps2) { throw "ps2exe.ps1 not found under $deps" }

$src = Join-Path $ProjectRoot "AMD_INF_Patcher.ps1"
if (-not (Test-Path $src)) { throw "source not found: $src" }

& $ps2.FullName -inputFile $src -outputFile $Output -noConsole -title "AMD INF Patcher" -description "AMD INF patcher GUI" -company "AMD_DriverMagic"

Write-Host "Built -> $Output"
