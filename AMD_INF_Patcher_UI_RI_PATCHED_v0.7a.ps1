
#requires -Version 5.1
<#
Rarity Intelligence™ AMD INF Patcher UI
Version: 0.7a (compact + proxy-bypass)
Additions:
- Edge launch adds: --no-proxy-server --allow-insecure-localhost --disable-features=BlockInsecurePrivateNetworkRequests
- Logs full Edge args used.
- Everything else same as v0.7.
#>

using namespace System.Net
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

# ---------- Config ----------
$Script:Ports = @(8080, 8123, 8177, 8820)
$Script:URLv4 = $null
$Script:URLHost = $null
$Script:LogQ = [System.Collections.Concurrent.ConcurrentQueue[string]]::new()
$Script:RebootFlag = Join-Path $env:TEMP 'ri_infpatcher_reboot.flag'
$Script:ReqCountPath = Join-Path $env:TEMP 'ri_infpatcher_reqcount.txt'

function Log([string]$m){ $ts=(Get-Date).ToString('yyyy-MM-dd HH:mm:ss'); $l="[$ts] $m"; $Script:LogQ.Enqueue($l)|Out-Null; $l|Write-Host }
function FlushLogHtml(){ $s=@();while($Script:LogQ.TryDequeue([ref]$o)){ $s+=$o }; ($s -join "`n") -replace '&','&amp;' -replace '<','&lt;' -replace '>','&gt;' }

function Assert-Admin(){ if(-not([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)){ Write-Error "Run as Administrator."; exit 1 } }

# ---------- Port + FW ----------
function Port-Free([int]$p){ try{$t=New-Object Net.Sockets.TcpListener([Net.IPAddress]::Loopback,$p);$t.Start();$t.Stop();$true}catch{$false} }
function FW([int]$p){ try{ if(Get-Command New-NetFirewallRule -EA SilentlyContinue){ $n="RI-INF-Patcher-$p"; if(-not(Get-NetFirewallRule -DisplayName $n -EA SilentlyContinue)){ New-NetFirewallRule -DisplayName $n -Direction Inbound -Action Allow -Protocol TCP -LocalPort $p -LocalAddress 127.0.0.1 -Profile Any|Out-Null; Log "Firewall rule added for 127.0.0.1:$p" } } }catch{ Log "FW skip: $($_.Exception.Message)" } }
function Pick-Port(){ foreach($p in $Script:Ports){ if(Port-Free $p){ $Script:URLv4="http://127.0.0.1:$p/"; $Script:URLHost="http://localhost:$p/"; FW $p; return $p } else { Log "Port $p busy." } }; throw "No free ports." }

# ---------- Driver helpers ----------
function Resolve-Root([string]$hint){ if($hint -and (Test-Path $hint)){return (Resolve-Path $hint).Path}
 $c=@("$env:USERPROFILE\Downloads\AMD*","$env:USERPROFILE\Downloads\Win*","C:\AMD\*","C:\Drivers\AMD\*","$env:USERPROFILE\Desktop\AMD*")
 foreach($p in $c){ $d=Get-ChildItem -Path $p -Directory -EA SilentlyContinue|Sort-Object LastWriteTime -Desc|Select-Object -First 1; if($d){return $d.FullName} } $PWD.Path }
function Find-INFs([string]$root){ Get-ChildItem -Path $root -Recurse -Include *.inf -File -EA SilentlyContinue }
function Backup-Candidates([string]$inf){ $dir=Split-Path -Parent $inf; $name=Split-Path -Leaf $inf; $base=[IO.Path]::GetFileNameWithoutExtension($name)
 $cand=@( Join-Path $dir "$name.bak", Join-Path $dir "$base.bak", Join-Path $dir "$base.inf.bak" )
 foreach($b in @('Backup','_backup','backup')){ $up=Split-Path -Parent $dir; $bd=Join-Path $up $b; if(Test-Path $bd){ $rel=$inf.Substring($up.Length).TrimStart('\','/'); $cand+=Join-Path $bd $rel; $cand+=(Join-Path $bd $rel)+'.bak' } }
 $cand|Where-Object{Test-Path $_}|Select-Object -Unique }
function Restore-Inf([string]$inf){ $c=Backup-Candidates $inf; if(-not $c){ Log "No backup: $inf"; return $false }; $b=$c|Sort-Object Length|Select-Object -First 1; try{ Copy-Item -LiteralPath $b -Destination $inf -Force; Log "Restored `"$inf`" from `"$b`""; $true }catch{ Log "Restore failed ${inf}: $($_.Exception.Message)"; $false } }
function Revert-All([string]$root){ $r=Resolve-Root $root; if(-not(Test-Path $r)){ Log "Root not found: $r"; return @{restored=0;failed=0;error='root_not_found'} }
 $infs=Find-INFs $r; if(-not $infs){ Log "No INF files under $r"; return @{restored=0;failed=0;error='no_inf'} }
 $ok=0;$ko=0; foreach($i in $infs){ if(Restore-Inf $i.FullName){$ok++}else{$ko++} } Log "Revert complete. Restored $ok. Missing/Failed $ko."; @{restored=$ok;failed=$ko} }

function Find-Manifests([string]$root){ $r=Resolve-Root $root
 $xml=Get-ChildItem -Path $r -Recurse -Include package.xml -File -EA SilentlyContinue
 $json=Get-ChildItem -Path $r -Recurse -Include driver.json  -File -EA SilentlyContinue
 @{xml=$xml;json=$json} }
function Patch-Manifests([string]$root){
 $r=Resolve-Root $root; if(-not(Test-Path $r)){ Log "Root not found: $r"; return @{changed=0;error='root_not_found'} }
 $f=Find-Manifests $r; $t=0
 foreach($x in @($f.xml+$f.json)){ try{ $c=Get-Content -LiteralPath $x.FullName -Raw
  $bak="$($x.FullName).bak"; if(-not(Test-Path $bak)){ Copy-Item -LiteralPath $x.FullName -Destination $bak -Force }
  $p=$c -replace '(?i)WindowsServer(20\d{2})','Windows10'
  $p=$p -replace '(?is)(?<="BlockList"\s*:\s*)\[(.*?)\]','[]'
  if($p -ne $c){ Set-Content -LiteralPath $x.FullName -Value $p -Encoding UTF8; $t++; Log "Patched: $($x.FullName)" } else { Log "No changes: $($x.FullName)" }
 }catch{ Log "Patch failed $($x.FullName): $($_.Exception.Message)" } }
 Log "Patch complete. Files changed: $t"; @{changed=$t;xml=($f.xml|% FullName);json=($f.json|% FullName)} }

function TestSigning-On(){ try{ (bcdedit|Out-String) -match 'testsigning\s+Yes' }catch{$false} }
function Enable-TestSigning(){ try{ bcdedit /set testsigning on|Out-Null; bcdedit /set nointegritychecks on|Out-Null; Log "Enabled Test Signing + NoIntegrityChecks"; $true }catch{ Log "Enable TestSigning failed: $($_.Exception.Message)"; $false } }
function Install-Patched([string]$root){
 $r=Resolve-Root $root; if(-not(Test-Path $r)){ return @{status='failed';error='root_not_found'} }
 if(-not(TestSigning-On)){ Log "TestSigning OFF. Enabling..."; if(Enable-TestSigning){ New-Item -ItemType File -Path $Script:RebootFlag -Force|Out-Null; Log "Reboot required. Re-run after reboot."; return @{status='reboot_required'} } else { return @{status='failed';error='enable_testsigning_failed'} } }
 $infs=Find-INFs $r; if(-not $infs){ return @{status='failed';error='no_inf'} }
 $added=0; foreach($i in $infs){ $r= & pnputil /add-driver "`"$($i.FullName)`"" /install /subdirs 2>&1 | Out-String; Log ($r.Trim()); if($r -match '(?i)published|added|installed|staged'){ $added++ } }
 @{status='ok';drivers=$added} }

# ---------- WebView2 ensure ----------
function WV2-Path(){ $b="${env:ProgramFiles(x86)}\Microsoft\EdgeWebView\Application"; if(Test-Path $b){ $v=Get-ChildItem -Path $b -Directory -EA SilentlyContinue|Sort-Object Name -Desc|Select-Object -First 1; if($v){ $e=Join-Path $v.FullName 'msedgewebview2.exe'; if(Test-Path $e){return $e}} } $null }
function WV2-Version(){ $e=WV2-Path; if($e){ try{ return (Get-Item $e).VersionInfo.ProductVersion }catch{} }
 foreach($k in @('HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*','HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*')){ $p=Get-ItemProperty -Path $k -EA SilentlyContinue|?{ $_.DisplayName -like 'Microsoft Edge WebView2 Runtime*' }|Select-Object -First 1; if($p){ return $p.DisplayVersion } } $null }
function WV2-Installed(){ if(WV2-Path){return $true}; foreach($k in @('HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*','HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*')){ if(Get-ItemProperty -Path $k -EA SilentlyContinue|?{ $_.DisplayName -like 'Microsoft Edge WebView2 Runtime*' }){return $true} } if(Get-Command winget -EA SilentlyContinue){ try{$o=winget list --id Microsoft.EdgeWebView2Runtime 2>$null; if($LASTEXITCODE -eq 0 -and ($o|Out-String) -match 'WebView2'){return $true}}catch{} } $false }
function Refresh-Env(){ try{$m=[Environment]::GetEnvironmentVariable('Path','Machine');$u=[Environment]::GetEnvironmentVariable('Path','User'); if($m -and $u){$env:Path="$m;$u"}elseif($m){$env:Path=$m}elseif($u){$env:Path=$u} }catch{} }
function WV2-Install-Winget(){ try{ Log "Installing WebView2 via winget"; Start-Process winget -ArgumentList @('install','--id','Microsoft.EdgeWebView2Runtime','-e','--silent','--accept-source-agreements','--accept-package-agreements') -Wait -WindowStyle Hidden|Out-Null; Refresh-Env; $true }catch{ Log "winget failed: $($_.Exception.Message)"; $false } }
function Choco-Ensure(){ if(Get-Command choco -EA SilentlyContinue){return $true}; try{ Log "Installing Chocolatey"; Set-ExecutionPolicy Bypass -Scope Process -Force; [Net.ServicePointManager]::SecurityProtocol=[Net.SecurityProtocolType]::Tls12; Invoke-Expression ((New-Object Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1')); Refresh-Env; [bool](Get-Command choco -EA SilentlyContinue) }catch{ Log "Choco failed: $($_.Exception.Message)"; $false } }
function WV2-Install-Choco(){ try{ Log "Installing WebView2 via Chocolatey"; choco install microsoft-edge-webview2-runtime -y --no-progress | Out-String | Write-Host; Refresh-Env; $true }catch{ Log "choco install failed: $($_.Exception.Message)"; $false } }
function WV2-Install-Bootstrap(){ try{ Log "Installing WebView2 via Microsoft bootstrapper"; [Net.ServicePointManager]::SecurityProtocol=[Net.SecurityProtocolType]::Tls12; $u='https://go.microsoft.com/fwlink/p/?LinkId=2124703'; $d=Join-Path $env:TEMP 'MicrosoftEdgeWebview2Setup.exe'; Invoke-WebRequest -Uri $u -OutFile $d -UseBasicParsing -EA Stop; Start-Process $d -ArgumentList '/silent','/install' -Wait; Start-Sleep 2; $true }catch{ Log "Bootstrapper failed: $($_.Exception.Message)"; $false } }
function WV2-Ensure(){ $pre=WV2-Installed; $ver=WV2-Version; Log ("WebView2 pre-check: {0} {1}" -f ($(if($pre){'installed'}else{'missing'}),$(if($ver){"v$ver"}else{''}))); if($pre){return $true}
 if(Get-Command winget -EA SilentlyContinue){ [void](WV2-Install-Winget) } else { Log "winget not available" }
 if(-not(WV2-Installed)){ if(Choco-Ensure){ [void](WV2-Install-Choco) } else { Log "Chocolatey unavailable" } }
 if(-not(WV2-Installed)){ [void](WV2-Install-Bootstrap) }
 $post=WV2-Installed; $ver2=WV2-Version; Log ("WebView2 final-check: {0} {1}" -f ($(if($post){'installed'}else{'missing'}),$(if($ver2){"v$ver2"}else{''}))); $post }

# ---------- HTML ----------
$HTML = @'
<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Rarity Intelligence™ INF Patcher</title>
<style>
:root{--bg:#0a0c10;--card:#11141a;--txt:#e7eaf1;}
html,body{height:100%;margin:0;background:var(--bg);color:var(--txt);font-family:Segoe UI,Roboto,Arial,sans-serif}
.container{position:fixed;inset:0;margin:auto;width:min(50vw,1100px);height:min(50vh,850px);display:grid;grid-template-rows:auto auto 1fr auto;gap:12px;padding:16px;background:#11141a;border:1px solid rgba(255,255,255,.08);border-radius:16px;box-shadow:0 20px 60px rgba(0,0,0,.6)}
h1{margin:0;font-size:18px}
.row{display:flex;gap:8px;flex-wrap:wrap}
input{flex:1;background:#0d1117;color:var(--txt);border:1px solid rgba(255,255,255,.1);border-radius:10px;padding:8px 10px}
button,a.link{background:#161a22;border:1px solid rgba(255,255,255,.12);color:var(--txt);padding:8px 12px;border-radius:10px;cursor:pointer;text-decoration:none}
#log{background:#0b0f14;border:1px solid rgba(255,255,255,.08);border-radius:12px;padding:10px;overflow-y:auto;overflow-x:hidden;white-space:pre-wrap;word-wrap:break-word;word-break:break-word;font-family:Consolas,monospace;font-size:12px;line-height:1.35}
footer{display:flex;justify-content:space-between;opacity:.8;font-size:12px}
</style></head><body>
<div class="container" role="dialog" aria-modal="true">
<h1>Rarity Intelligence™ INF Patcher</h1>
<div class="row">
  <input id="root" placeholder="Driver root (auto-detect if empty)">
  <button onclick="api('patch')">Patch Manifests</button>
  <button onclick="api('revert')">Revert All</button>
  <button onclick="api('install')">Install Patched Driver</button>
  <a class="link" href="https://www.amd.com/en/support" target="_blank" rel="noreferrer">AMD Drivers</a>
</div>
<div id="log" aria-live="polite"></div>
<footer><div>DPI-aware centered window. Log wraps.</div><div>Rarity Intelligence™</div></footer>
</div>
<script>
async function api(action){
  try{
    const root=document.getElementById('root').value||'';
    const r=await fetch('/api/'+action,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({root})});
    const j=await r.json(); if(j.log){append(j.log)}; if(j.result){append(JSON.stringify(j.result,null,2))}
  }catch(e){append('Request failed: '+e)}
}
function append(t){const el=document.getElementById('log'); el.textContent+=(t+'\\n'); el.scrollTop=el.scrollHeight;}
</script>
</body></html>
'@

# ---------- HTTP server ----------
function Start-Server{
 $port=Pick-Port
 $pfx1="http://127.0.0.1:$port/"; $pfx2="http://localhost:$port/"
 $Script:URLv4=$pfx1; $Script:URLHost=$pfx2
 Set-Content -Path $Script:ReqCountPath -Value '0' -Encoding ASCII -Force
 $l=[HttpListener]::new(); $l.Prefixes.Add($pfx1); $l.Prefixes.Add($pfx2)
 try{$l.Start()}catch{ throw "HTTP listener failed: $($_.Exception.Message)" }
 Log "Web UI at $pfx1"
 $runner={ param($ln,$html,$rcp)
  function Bump($p){ try{ $n=0; if(Test-Path $p){$s=Get-Content -LiteralPath $p -Raw -EA SilentlyContinue; if($s -match '^\d+$'){$n=[int]$s}}; $n++; Set-Content -LiteralPath $p -Value ([string]$n) -Encoding ASCII -Force }catch{} }
  while($ln.IsListening){
   try{ $ctx=$ln.GetContext(); $req=$ctx.Request; $res=$ctx.Response; Bump $rcp
    if($req.HttpMethod -eq 'GET' -and $req.Url.AbsolutePath -eq '/'){ $b=[Text.Encoding]::UTF8.GetBytes($html); $res.ContentType='text/html; charset=utf-8'; $res.OutputStream.Write($b,0,$b.Length); $res.Close(); continue }
    if($req.HttpMethod -eq 'GET' -and $req.Url.AbsolutePath -eq '/favicon.ico'){ $res.StatusCode=204; $res.Close(); continue }
    if($req.HttpMethod -eq 'POST' -and $req.Url.AbsolutePath -like '/api/*'){
      $rd=New-Object IO.StreamReader($req.InputStream,$req.ContentEncoding); $body=$rd.ReadToEnd(); $rd.Close()
      $payload=@{root=''}; if($body){ try{$payload=$body|ConvertFrom-Json}catch{} }
      $act=$req.Url.Segments[-1].Trim('/')
      $resu = switch($act){ 'patch'{ Patch-Manifests $payload.root } 'revert'{ Revert-All $payload.root } 'install'{ Install-Patched $payload.root } default { @{error='unknown_action'} } }
      $json=@{result=$resu;log=(FlushLogHtml)}|ConvertTo-Json -Depth 6
      $b=[Text.Encoding]::UTF8.GetBytes($json); $res.ContentType='application/json; charset=utf-8'; $res.OutputStream.Write($b,0,$b.Length); $res.Close(); continue
    }
    $res.StatusCode=404; $res.Close()
   }catch{ try{$res.StatusCode=500;$res.Close()}catch{} }
  }
 }
 $job=Start-Job -ScriptBlock $runner -ArgumentList $l,$HTML,$Script:ReqCountPath
 @{listener=$l; job=$job; port=$port}
}

# ---------- Edge app launch ----------
function Edge-Path(){ foreach($p in @("${env:ProgramFiles}\Microsoft\Edge\Application\msedge.exe","${env:ProgramFiles(x86)}\Microsoft\Edge\Application\msedge.exe")){ if(Test-Path $p){ return $p } } $null }
function Launch-App([string]$url){
 $edge=Edge-Path; if(-not $edge){ throw "Edge not found." }
 $s=[System.Windows.Forms.Screen]::PrimaryScreen.Bounds; $w=[int]($s.Width*0.5); $h=[int]($s.Height*0.5); $x=[int](($s.Width-$w)/2); $y=[int](($s.Height-$h)/2)
 $args=@("--app=""$url""","--window-size=$w,$h","--window-position=$x,$y","--no-proxy-server","--allow-insecure-localhost","--disable-features=BlockInsecurePrivateNetworkRequests")
 Log ("Launching Edge: " + ($args -join ' '))
 Start-Process -FilePath $edge -ArgumentList $args | Out-Null
}

# ---------------- Main ----------------
Assert-Admin
Log "Starting Rarity Intelligence™ AMD INF Patcher UI"
$server=Start-Server

if(-not (WV2-Ensure)){ Log "WebView2 not installed. Exiting."; if($server.listener){$server.listener.Stop()}; if($server.job){Stop-Job $server.job|Out-Null; Remove-Job $server.job|Out-Null}; exit 2 }
$ver=WV2-Version; if($ver){ Log "WebView2 verified v$ver" }

Start-Sleep -Milliseconds 300
Launch-App $Script:URLv4
Start-Sleep -Seconds 3
$req=0; try{ if(Test-Path $Script:ReqCountPath){ $s=Get-Content -LiteralPath $Script:ReqCountPath -Raw -EA SilentlyContinue; if($s -match '^\d+$'){$req=[int]$s} } }catch{}
if($req -lt 1){ Log "No requests on 127.0.0.1. Launching localhost window."; Launch-App $Script:URLHost }

if(Test-Path $Script:RebootFlag){ Log "TestSigning enabled. Reboot, then re-run Install." }

try{ while($true){ Start-Sleep 1 } }
finally{ if($server.listener){$server.listener.Stop()}; if($server.job){Stop-Job $server.job|Out-Null; Remove-Job $server.job|Out-Null} }
