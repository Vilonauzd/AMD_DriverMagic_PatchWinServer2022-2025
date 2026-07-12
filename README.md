# QVERT.NET AMD Server 2022 Adrenalin Patcher

<p align="center">
  <img width="1241" height="1010" alt="image" src="https://github.com/user-attachments/assets/b6734db9-6986-48d6-804d-5046f06e3d8c" />
</p>


<p align="center">
  <img alt="Version 2.20.12" src="https://img.shields.io/badge/version-2.20.12-8E2432" />
  <img alt="Windows Server 2022" src="https://img.shields.io/badge/target-Windows%20Server%202022%20%7C%20Build%2020348-2FA772" />
  <img alt="PowerShell 5.1" src="https://img.shields.io/badge/PowerShell-5.1-4E86C7" />
  <img alt="WPF GUI" src="https://img.shields.io/badge/interface-WPF%20%7C%20no--console-131A27" />
  <img alt="MIT License" src="https://img.shields.io/badge/license-MIT-AAB5C4" />
</p>

> **A zero-touch, guided, transactional AMD Adrenalin package patcher for Windows Server 2022.**  
> Download it. Extract it. Prove it. Patch it. Validate it. Launch the correct installer.

[Watch the project walkthrough](https://www.youtube.com/watch?v=8A1Bu26jm6g)

---

## What This Is

AMD consumer Radeon packages do not officially target Windows Server 2022. The QVERT.NET patcher prepares an AMD Adrenalin package, removes the package-level operating-system restrictions that block Server 2022, validates every write, and then launches only the correct top-level installer.

This is not a blind search-and-replace script with a dark theme.

It is a full guided workflow with:

- automatic package preparation;
- bare-server dependency bootstrap;
- operating-system and security preflight;
- defensive JSON and INF parsing;
- per-file backups;
- transactional writes;
- post-write rescanning;
- automatic rollback on failure;
- responsive background execution;
- a complete themed WPF experience from download through launch.

The current release is intentionally focused on **Windows Server 2022 build family 20348**.

---

## The Workflow

The interface guides the operator through the correct sequence by pulsating the next required action:

1. **AMD Drivers**  
   Opens the AMD driver page and watches the Downloads, Desktop, and application directories for an Adrenalin installer.

2. **Prepare Installer**  
   Selects the downloaded AMD executable, prepares an isolated extraction directory, resolves 7-Zip, and validates the extracted package root.

3. **Preflight Report**  
   Verifies the operating system, package layout, manifests, recursive INF scope, write access, signature posture, boot policy, reboot state, backup storage, and rollback readiness.

4. **Close**  
   Pulsates inside the completed preflight report to hand control back to the main workflow.

5. **Patch All + Validate**  
   Pulsates only after preflight has passed for the currently selected package root.

6. **Continue to Patch**  
   Pulsates at the caution gate before any vendor file is modified.

7. **Patch All + Validate**  
   Pulsates again inside the final transactional patch plan.

8. **Launch Top-Level Setup.exe**  
   Pulsates only after manifest patching, recursive INF patching, post-write validation, and rollback evidence all pass.

9. **Donate via PayPal**  
   An optional themed support window docks to the right side of the QVERT.NET app after the AMD installer launches, keeping clear of the fresh AMD setup wizard.

The workflow does not guess what the operator should do next. It shows them.

---

## Why It Is Different

### Zero-Touch Package Preparation

The patcher can start from the original downloaded AMD Adrenalin executable.

It will:

- use an existing 7-Zip installation when available;
- validate that the resolved command is exactly one existing `7z.exe`;
- bootstrap Chocolatey directly from its official HTTPS installer when 7-Zip is absent;
- install 7-Zip through Chocolatey;
- avoid any dependency on Winget;
- extract into an isolated destination;
- locate the real AMD package root;
- validate the required package structure;
- populate the root automatically for preflight.

Internet access is required only for the AMD package download and, when necessary, the Chocolatey/7-Zip bootstrap.

### Live Operating-System Status

The main GUI includes a continuously pulsating operating-system pill that reads local registry metadata without WMI or CIM startup delay.

| State | Meaning |
|---|---|
| **Green** | Windows Server 2022 build family `20348` detected |
| **Amber** | Windows detected, but the build is not the intended target |
| **Red** | Windows product/build metadata could not be resolved |

Hovering over the pill displays the full product name, version, display version, installation type, and target-build reference.

### One Consistent WPF Experience

The primary workflow no longer drops the operator into mismatched native confirmation boxes.

Themed surfaces cover:

- package-preparation confirmation;
- package-ready handoff;
- preflight findings;
- patch caution;
- final patch plan;
- patch-complete validation summary;
- top-level installer launch;
- optional QVERT.NET donation handoff.

The GUI is designed for a compiled, no-console host and keeps dialogs owned by the main application so they do not disappear behind Explorer.

### Responsive by Design

Long-running work does not execute on the WPF UI thread.

Package extraction, preflight, recursive patching, validation, rollback, and revert operations run through background jobs with:

- live phase text;
- elapsed time;
- indeterminate progress;
- batched log updates;
- safe cancellation only where interruption cannot corrupt files;
- dispatcher-level exception capture;
- persistent logging.

The application remains visibly alive while the real work is happening.

---

## Exact Package Targets

The patcher validates and processes the canonical AMD package structure:

```text
<AMD package root>\
├── Setup.exe
├── Bin64\
│   └── cccmanifest_64.json
├── Config\
│   ├── cccmanifest_64.json
│   └── InstallManifest.json
└── Packages\
    └── Drivers\
        └── **\*.inf
```

The package root must contain the top-level `Setup.exe`, all three required manifests, and the recursive driver tree.

The patcher never launches a lower-level installer executable.

---

## Manifest Engine

The manifest engine defensively scans every exact `OSCheck` property in the required JSON files.

It handles:

- scalar and array forms;
- duplicate keys and repeated blocks;
- case variation;
- changing AMD build-specific identifiers;
- existing compatibility entries that must be preserved;
- duplicate Server 2022 entries that must be normalized;
- adjacent keys such as `OSCheckMinVer` that have separate semantics and must not be rewritten accidentally.

The canonical Server 2022 compatibility identifier is appended exactly once where required:

```text
*-*-10.0.20348.0-Yes-*-Yes
```

The engine reparses JSON after modification and performs a full post-write rescan before declaring success.

---

## Recursive INF Engine

Every INF beneath the driver tree is inspected:

```text
Packages\Drivers\**\*.inf
```

The patcher does not assume that AMD will always use the same manufacturer token or model-section name.

It dynamically preserves and normalizes structures such as:

```ini
%ATI% = ATI.Mfg, NTamd64.10.0...
```

to:

```ini
%ATI% = ATI.Mfg, NTamd64
```

and:

```ini
[ATI.Mfg.NTamd64.10.0...]
```

to:

```ini
[ATI.Mfg.NTamd64]
```

It also handles equivalent structures such as:

```ini
%ManufacturerName%=AMD, NTAMD64.10.0...
[AMD.NTAMD64.10.0...]
```

while preserving:

- the original manufacturer token;
- the original model-section identifier;
- unrelated INF content;
- comments;
- indentation;
- newline style;
- source encoding.

Post-write validation confirms that the intended mappings changed and no unsupported decorated headers remain in the matched scope.

---

## Preflight: Prove It Before Touching It

Preflight classifies findings as pass, caution, or blocker and checks:

- administrator elevation;
- Windows product and build;
- expected Server 2022 build family;
- required package layout;
- top-level `Setup.exe`;
- both `cccmanifest_64.json` files;
- `InstallManifest.json`;
- recursive INF discovery;
- JSON parse validity;
- target-file write access;
- backup/log path write access;
- available disk space;
- pending reboot state;
- test-signing posture;
- Secure Boot posture;
- HVCI / Memory Integrity posture;
- relevant driver-signature state;
- rollback readiness.

Safe, deterministic remediation is built in:

- resolve a selected child directory back to the actual package root;
- discover one valid root below the selected directory or `C:\AMD`;
- create and validate backup/log storage;
- clear read-only attributes only from files the patcher must modify.

The patcher does **not** silently:

- change BCD settings;
- disable Secure Boot;
- disable Memory Integrity;
- fabricate missing vendor files;
- rewrite malformed JSON;
- bypass an unresolved blocker.

---

## Transactional Safety

Every changed file is backed up beside the original before replacement:

```text
<original file>.bak_yyyyMMdd_HHmmss_<8-character-SHA256>
```

The patch engine then:

1. reads the original while preserving encoding;
2. builds the intended modification in memory;
3. creates a hashed backup;
4. writes transactionally;
5. reparses or rescans the written file;
6. validates the complete package;
7. rolls the session back automatically if any write or validation fails.

The **Revert All** workflow recursively locates recoverable backup files and restores the original vendor content.

Persistent logs are stored under:

```text
C:\RepairLogs\amd_server2022_patch_*.log
```

---

## Patch Completion Evidence

The completion window reports:

- manifests scanned and changed;
- `OSCheck` blocks found and additions made;
- INF files scanned, matched, and changed;
- manufacturer mappings normalized;
- decorated `NTamd64` section headers changed;
- validated top-level `Setup.exe` path.

Only after all validation passes does the app offer:

```text
Launch Top-Level Setup.exe
```

That distinction matters. AMD packages contain lower-level executables that can re-enter the unsupported operating-system path.

---

## Requirements

- **Target OS:** Windows Server 2022, build family `20348`
- **Interface:** Windows Server 2022 with WPF/.NET Framework support
- **PowerShell:** Windows PowerShell 5.1
- **Privileges:** Local administrator
- **AMD package:** Current AMD Adrenalin installer executable
- **Disk:** Enough free space for the downloaded package, isolated extraction, backups, and logs
- **Internet:** AMD download; Chocolatey and 7-Zip bootstrap only when 7-Zip is not already installed

Driver-signature policy still applies after INF modification. The patcher reports the relevant security posture but does not silently weaken the operating system.

---

## Running the PowerShell Release

Open an elevated Windows PowerShell 5.1 console:

```powershell
Set-Location "C:\Path\To\AMD_DriverMagic_PatchWinServer2022-2025"
& .\AMD-INF-Patcher.ps1
```

Then follow the pulsating workflow in the application.

---

## Compiled EXE Release

The application is designed for compilation with **PowerEXE** using an execution posture equivalent to:

- x64;
- STA;
- no visible console;
- DPI aware;
- require administrator;
- long-path enabled.

The code resolves its own application directory and does not depend on a console working directory.

No separate build helper is required.

---

## What It Changes — and What It Does Not

### It changes

- AMD package JSON compatibility metadata;
- AMD driver INF operating-system decorations;
- only the specific files required to make the package recognize Server 2022.

### It does not change

- the Windows kernel;
- AMD binary payloads;
- firmware;
- GPU VBIOS;
- Windows security policy;
- Secure Boot configuration;
- HVCI configuration;
- BCD configuration.

---

## Optional Support

This project is maintained and distributed free of charge.

Donations help support continued testing, AMD package-layout changes, regression fixes, and maintenance for the community.

[Support QVERT.NET development through PayPal](https://www.paypal.com/donate/?business=marshall.jonathon@gmail.com&no_recurring=1&item_name=Donation)

No recurring donation is requested.

---

## Disclaimer

This tool modifies third-party driver installation metadata for an unsupported operating-system scenario.

- Use it at your own risk.
- Maintain a system backup or recovery path.
- Test driver releases before production deployment.
- AMD package structures may change between releases.
- Some Radeon software features may remain unavailable or behave differently on Windows Server.
- QVERT.NET is not affiliated with or endorsed by AMD or Microsoft.

---

## License

MIT License — free for personal and commercial use.

Community-built. Not endorsed by AMD or Microsoft.

---

## Search Tags

`AMD` `Radeon` `Adrenalin` `Windows Server 2022` `Build 20348` `INF Patcher` `OSCheck` `cccmanifest_64.json` `InstallManifest.json` `PowerShell 5.1` `WPF` `PowerEXE` `GPU Compute` `Homelab` `AI Server` `OpenCL` `DirectX` `Driver Package` `Transactional Patch` `Automatic Rollback` `7-Zip` `Chocolatey`

---

<p align="center">
  <strong>Because Server 2022 can run the hardware. The installer just needed to be convinced.</strong>
</p>
