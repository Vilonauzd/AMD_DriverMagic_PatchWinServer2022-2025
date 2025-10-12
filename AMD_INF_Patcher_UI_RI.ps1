<#
    AMD INF Patcher – Web UI Edition (v4.0)
    • Replaces WPF GUI with embedded web server + Rarity-style UI
    • Fixes log readability, revert logic, adds file browser
    • Compiles to .exe via PS2EXE
    • Launches browser automatically on http://127.0.0.1:8080
#>

#region ==================== Embedded Frontend HTML ====================
$EmbeddedHtml = @'
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

/* Custom welcome message styling */
.welcome-message {
 padding: 15px;
 background: rgba(100, 100, 100, 0.1); /* thin cloud gray */
 color: white; /* white text */
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

/* Sidebar controls styling */
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
  <!-- Win7 Support removed per request -->

  <!-- Sidebar Controls Section -->
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
    <button class="btn btn-stop mt-2" id="revertBtn">Revert All</button>
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

  appendMsg('user', `Patch Request:\\n- Root: \`${rootPath}\`\\n- Target: \`${target}\`${target === 'Custom' ? `\\n- Decoration: \`${customDec}\`` : ''}\\n- Patch Manifest: ${patchManifest ? 'Yes' : 'No'}`);

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

    const text = await resp.text();
    if (!resp.ok) throw new Error(text || `HTTP ${resp.status}`);
    // Display raw log output with custom styling
    const logDiv = document.createElement('div');
    logDiv.className = 'log-output';
    logDiv.innerHTML = `<pre>${text.replace(/\n/g, '<br>').replace(/ /g, '&nbsp;')}</pre>`;
    chat.appendChild(logDiv);
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

    const text = await resp.text();
    if (!resp.ok) throw new Error(text || `HTTP ${resp.status}`);
    // Display raw log output with custom styling
    const logDiv = document.createElement('div');
    logDiv.className = 'log-output';
    logDiv.innerHTML = `<pre>${text.replace(/\n/g, '<br>').replace(/ /g, '&nbsp;')}</pre>`;
    chat.appendChild(logDiv);
    chat.scrollTop = chat.scrollHeight;
  } catch (e) {
    appendMsg('assistant', `❌ Revert failed: ${e.message}`);
  }
}

// File Explorer integration
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
document.getElementById('clear').onclick = () => { chat.innerHTML = ''; };

// Initial welcome message with custom styling
const welcomeDiv = document.createElement('div');
welcomeDiv.className = 'welcome-message';
welcomeDiv.textContent = "Welcome to AMD INF Patcher Web UI.\n\nEnter a valid driver root path, select your target OS, and click Patch to begin.\n\nUse Revert All to restore original files from backups.";
chat.appendChild(welcomeDiv);

</script>
</body>
</html>
'@
#endregion

#region ==================== Original AMD INF Patcher Logic (v2.9) ====================
# (All functions from your script, slightly adapted for headless use)
$script:LogLines       = [System.Collections.ArrayList]::new()
$script:CurrentLogPath = $null
$script:SessionID      = (Get-Date -Format 'yyyyMMdd_HHmmss')
$script:BackupBase     = "C:\RepairLogs"
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

function Write-Log {
    param([string]$Message, [string]$Level='Info')
    if ([string]::IsNullOrWhiteSpace($Message)) { return }
    $timeStamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    $entry = "[$timeStamp] [$Level] $Message"
    [void]$script:LogLines.Add($entry)
    if ($script:CurrentLogPath) { try { Add-Content -Path $script:CurrentLogPath -Value $entry -EA Stop } catch {} }
}

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

function Backup-File {
    param([string]$FilePath)
    if (-not (Test-Path -LiteralPath $FilePath)) { throw "File not found: $FilePath" }
    $hash = (Get-FileHash -Path $FilePath -Algorithm SHA256).Hash.Substring(0,8)
    $backupName = "$FilePath.bak_$($script:SessionID)_$hash"
    Copy-Item -LiteralPath $FilePath -Destination $backupName -Force
    $backupName
}

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
    if (-not (Test-Path -LiteralPath $Root)) { Write-Log "Root not found: $Root" "Error"; return }
    $decoration = if ($Target -eq 'Custom') {
        if ([string]::IsNullOrWhiteSpace($CustomDecoration)) { Write-Log "Custom target requires a decoration string." "Error"; return }
        $CustomDecoration
    } else { $ValidTargets[$Target] }
    Write-Log "Using decoration: $decoration" "Info"
    $script:CurrentLogPath = Join-Path $script:BackupBase "amd_inf_patch_$($script:SessionID).log"
    if (-not (Test-Path $script:BackupBase)) { New-Item -ItemType Directory -Path $script:BackupBase -Force | Out-Null }
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
                         Where-Object { ($_.Extension -in '.json','.xml') -and ($_.Name -match '(?i)manifest') }
        foreach ($m in $manifestFiles) {
            try {
                $txt = Read-TextFileSafe -Path $m.FullName
                if ($null -eq $txt) { Write-Log "Skip empty/unreadable manifest: $($m.FullName)" "Warning"; continue }
                $orig = $txt
                if ($m.Extension -ieq '.json') {
                    $txt = [regex]::Replace($txt, '(?i)"(Min(?:OS|Build|Version|OSVersion|OSBuild))"\s*:\s*".+?"', '"$1":"10.0.0.0"')
                    $txt = [regex]::Replace($txt, '(?i)"(Max(?:OS|Build|Version|OSVersion|OSBuild|OSVersionTested))"\s*:\s*".+?"', '"$1":"10.0.99999.0"')
                    $txt = [regex]::Replace($txt, '(?i)"SupportedOS(?:es|List)"\s*:\s*\[(.*?)\]', '"SupportedOS":[$1,"WindowsServer"]')
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
}

function Revert-AllChanges {
    Write-Log "Starting full revert process..." "Warning"
    try {
        $logFiles = Get-ChildItem -Path $script:BackupBase -Filter "*amd_inf_patch_*.log" -EA SilentlyContinue
        $reverted = 0
        foreach ($log in $logFiles) {
            if ($log.BaseName -match 'amd_inf_patch_(\d{8}_\d{6})') {
                $sessionID = $matches[1]
                $pattern = [regex]::Escape(".bak_$sessionID`_")
                $backups = Get-ChildItem -Path "$script:BackupBase\*" -Include "*.bak_*" -Recurse -EA SilentlyContinue |
                           Where-Object { $_.Name -match $pattern }
                foreach ($bak in $backups) {
                    $orig = $bak.FullName -replace ([regex]::Escape(".bak_$sessionID`_") + '[0-9a-f]{8}'), ''
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

#region ==================== HTTP Server ====================
$listener = New-Object System.Net.HttpListener
$listener.Prefixes.Add("http://127.0.0.1:8080/")
$listener.Start()
Write-Host "🚀 AMD INF Patcher Web UI running at http://127.0.0.1:8080" -ForegroundColor Green

# Open browser
Start-Process "http://127.0.0.1:8080"

try {
    while ($listener.IsListening) {
        $context = $listener.GetContext()
        $request = $context.Request
        $response = $context.Response

        if ($request.Url.AbsolutePath -eq '/') {
            # Serve HTML
            $buffer = [System.Text.Encoding]::UTF8.GetBytes($EmbeddedHtml)
            $response.ContentType = "text/html"
            $response.ContentLength64 = $buffer.Length
            $response.OutputStream.Write($buffer, 0, $buffer.Length)
        }
        elseif ($request.Url.AbsolutePath -eq '/api' -and $request.HttpMethod -eq 'POST') {
            # Handle API
            $raw = [System.IO.StreamReader]::new($request.InputStream, $request.ContentEncoding).ReadToEnd()
            try {
                $data = $raw | ConvertFrom-Json
                $script:LogLines.Clear()
                if ($data.action -eq 'patch') {
                    Patch-INFAndManifests -Root $data.root -Target $data.target -CustomDecoration $data.customDecoration -PatchManifest $data.patchManifest
                } elseif ($data.action -eq 'revert') {
                    Revert-AllChanges
                }
                $output = ($script:LogLines -join "`n")
                $buffer = [System.Text.Encoding]::UTF8.GetBytes($output)
                $response.StatusCode = 200
            } catch {
                $err = "❌ API Error: $($_.Exception.Message)"
                $buffer = [System.Text.Encoding]::UTF8.GetBytes($err)
                $response.StatusCode = 500
            }
            $response.ContentType = "text/plain"
            $response.ContentLength64 = $buffer.Length
            $response.OutputStream.Write($buffer, 0, $buffer.Length)
        }
        elseif ($request.Url.AbsolutePath -eq '/browse' -and $request.HttpMethod -eq 'GET') {
            # Launch folder browser dialog
            try {
                Add-Type -AssemblyName System.Windows.Forms
                $dlg = New-Object System.Windows.Forms.FolderBrowserDialog
                $dlg.Description = "Select AMD Driver Root Folder"
                $result = $dlg.ShowDialog()
                if ($result -eq [System.Windows.Forms.DialogResult]::OK) {
                    $path = $dlg.SelectedPath
                    $buffer = [System.Text.Encoding]::UTF8.GetBytes($path)
                    $response.StatusCode = 200
                } else {
                    $buffer = [System.Text.Encoding]::UTF8.GetBytes("")
                    $response.StatusCode = 200
                }
            } catch {
                $buffer = [System.Text.Encoding]::UTF8.GetBytes("❌ Browse error: $_")
                $response.StatusCode = 500
            }
            $response.ContentType = "text/plain"
            $response.ContentLength64 = $buffer.Length
            $response.OutputStream.Write($buffer, 0, $buffer.Length)
        } else {
            $response.StatusCode = 404
            $buffer = [System.Text.Encoding]::UTF8.GetBytes("Not Found")
            $response.ContentLength64 = $buffer.Length
            $response.OutputStream.Write($buffer, 0, $buffer.Length)
        }
        $response.Close()
    }
} finally {
    $listener.Stop()
    $listener.Dispose()
}