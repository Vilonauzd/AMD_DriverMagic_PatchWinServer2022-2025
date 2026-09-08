# TurtleAMD

<p align="center">
  <img src="assets/turtleamd-logo.png" alt="TurtleAMD" width="280" />
</p>

<p align="center">
  <strong>Native AMD compatibility tooling for Windows Server.</strong><br/>
  Adrenalin today. A modular compatibility platform for Ryzen Master and xpertRaidUtility next.
</p>

<p align="center">
  <img alt="Native QA" src="https://img.shields.io/badge/native%20line-3.2.0%20QA-8E2432" />
  <img alt=".NET 10" src="https://img.shields.io/badge/runtime-.NET%2010-512BD4" />
  <img alt="WPF" src="https://img.shields.io/badge/UI-WPF-242B30" />
  <img alt="Windows Server" src="https://img.shields.io/badge/target-Server%202022%20%7C%202025-2F7D61" />
  <img alt="Transactional" src="https://img.shields.io/badge/patching-transactional-344047" />
  <img alt="License" src="https://img.shields.io/badge/license-Personal%20Use%20Only-8E2432" />
</p>

> **Major architecture transition:** TurtleAMD has been rebuilt from the original PowerShell/WPF DriverMagic application into a native **C# / .NET 10 WPF** desktop platform. The proven Adrenalin JSON/INF behavior remains isolated as its own compatibility engine while UI, sidecars, installer, QA, and future AMD product modules live behind explicit subsystem boundaries.

[Watch the TurtleAMD project walkthrough](https://www.youtube.com/watch?v=K_XjCHMmv-o)

---

## Current status

| Component | Status |
|---|---|
| Native C# / .NET 10 WPF application | **Active QA** |
| Adrenalin manifest compatibility engine | **Implemented** |
| Recursive AMD INF normalization | **Implemented** |
| Transactional backup / rollback | **Implemented** |
| Windows Server preflight | **Implemented** |
| Embedded WebView2 AMD Drivers workflow | **Implemented** |
| Integrated Files sidecar | **Implemented** |
| In-app AMD download capture / progress | **Implemented** |
| Validated Setup.exe handoff + optional download cleanup | **Implemented** |
| Tray integration + TurtleAMD notifications | **Implemented** |
| Traditional Windows installer / uninstall / upgrade path | **Implemented** |
| Ryzen Master compatibility module | **Planned** |
| xpertRaidUtility compatibility module | **Planned** |

The native 3.x line is still being exercised against real AMD packages and Windows Server systems before it is promoted as the repository's release artifact.

---

## From DriverMagic to TurtleAMD

The original AMD INF Patcher / DriverMagic project proved the workflow in PowerShell. The native port preserves those production semantics while changing the engineering model:

```text
AMD DriverMagic / AMD INF Patcher
PowerShell + WPF/XAML
        │
        │ production behavior recovered and preserved
        ▼
TurtleAMD 3.x
Native C# / .NET 10 + WPF
        │
        ├── Adrenalin compatibility module      [implemented]
        ├── shared transaction / validation platform
        ├── WebView2 + Files sidecar infrastructure
        ├── installer / tray / notifications / QA
        ├── Ryzen Master compatibility module   [planned]
        └── xpertRaidUtility module              [planned]
```

The port was done for **maintainability, isolation, testability, and extensibility** — not source-code secrecy.

See [Migration Notes](docs/MIGRATION.md) and [Native Architecture](docs/ARCHITECTURE.md).

---

## Native operator experience

TurtleAMD 3.x is designed as a single workflow surface instead of a chain of external browser, Explorer, console, and installer windows.

### Attached WebView2 + Files sidecar

Clicking **AMD Drivers** expands an attached WebView2 sidecar. The main cockpit stays anchored while the application expands to the right. Browser downloads are captured by TurtleAMD, progress is shown in-app, and completed installers can be handed directly into package preparation. The same dock switches to an integrated Files view for installer and package selection.

<p align="center">
  <img src="assets/screenshots/native-qa3/native-sidecar-gallery.jpg" alt="TurtleAMD WebView2 and Files sidecar gallery" width="950" />
</p>

### Critical workflow lock

Extraction, preflight, patching, validation, rollback, and other critical steps own the UI while active. The underlying cockpit is dimmed and disabled so conflicting state cannot be created. Status events are queued and paced for readability; the backend operation itself is **not intentionally slowed**.

<p align="center">
  <img src="assets/screenshots/native-qa3/native-workflow-gallery.jpg" alt="TurtleAMD preflight and patch workflow gallery" width="950" />
</p>

---

## Preflight: prove it before touching vendor files

Preflight is an execution gate, not a decorative checklist. It checks, among other things:

- administrator context
- Windows Server product/build
- package layout and top-level `Setup.exe`
- all three required JSON manifests
- recursive driver INF scope
- current/past patch evidence
- package and backup/log write access
- free disk space
- installer process state
- 7-Zip and PnPUtil availability
- BCD and test-signing state
- Secure Boot posture
- Memory Integrity / HVCI where queryable
- reboot state
- signature consequences
- rollback readiness

`PASS` findings are green. Warnings, informational findings, and blockers remain semantically distinct. A blocker prevents patch execution.

---

## Transactional Adrenalin compatibility engine

The implemented Adrenalin module targets the canonical AMD package structure:

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

### Manifest behavior

The manifest engine targets the three required AMD JSON manifests, finds exact `OSCheck` targets, preserves unrelated JSON and adjacent values such as `OSCheckMinVer`, handles scalar/array forms, removes duplicate required compatibility entries, and adds the required Windows Server compatibility metadata exactly once before reparsing and rescanning.

### INF behavior

The INF engine recursively scans `Packages\Drivers\**\*.inf`, normalizes targeted manufacturer mappings to `NTamd64`, normalizes decorated `.NTamd64.*` model sections, preserves unrelated content/comments/encoding/newlines, and validates every write plus the final package.

### Transaction / recovery behavior

Before a vendor file is replaced, TurtleAMD creates a hashed backup beside the original:

```text
<file>.bak_yyyyMMdd_HHmmss_<sha-prefix>
```

Execution is intentionally staged:

```text
Discover
   ↓
Preflight
   ↓
Patch Plan
   ↓
Backup
   ↓
Transactional Write
   ↓
Post-write Rescan
   ↓
Full-package Validation
   ↓
SUCCESS  ──────────────┐
   │                   │
   └─ failure ─→ reverse-order rollback
```

The manual **Revert All** path restores compatible backup sets after the fact.

See [Adrenalin Module](docs/ADRENALIN-MODULE.md) and [Safety / Rollback](docs/SAFETY-AND-ROLLBACK.md).

---

## Validated AMD Setup handoff

TurtleAMD offers AMD Setup **only after** patching and complete recursive validation succeed. The launch gate can optionally remove the **original downloaded AMD installer** after the validated extracted `Setup.exe` starts; the fresh extraction and recovery data are not deleted by that option.

<p align="center">
  <img src="assets/screenshots/native-qa3/native-amd-handoff-gallery.jpg" alt="TurtleAMD validated AMD Setup handoff gallery" width="950" />
</p>

The QA sequence shown above reaches the real AMD Adrenalin installer after TurtleAMD's validation gate.

---

## Traditional Windows installer

The native application is packaged through a normal Windows setup experience:

- Program Files installation
- selectable destination
- EULA acceptance
- Start Menu shortcut
- optional Desktop shortcut
- Programs & Features / Installed Apps registration
- upgrade / clean-reinstall handling
- normal uninstall
- launch-after-install option
- TurtleAMD application, installer, shortcut, and tray branding

<p align="center">
  <img src="assets/screenshots/native-qa3/native-installer-gallery.jpg" alt="TurtleAMD installer gallery" width="950" />
</p>

See [Installation](docs/INSTALLATION.md) and the [complete native QA gallery](docs/GALLERY.md).

---

## Native architecture

```text
TurtleAMD
│
├── App / WPF shell
│   ├── cockpit + workflow state
│   ├── WebView2 sidecar
│   ├── Files sidecar
│   ├── tray + owned notifications
│   ├── dialogs / progress / completion gates
│   └── installer handoff
│
├── Core / shared platform
│   ├── package discovery
│   ├── preflight primitives
│   ├── patch plans
│   ├── transactions / backups / rollback
│   ├── validation primitives
│   └── logging / evidence
│
├── Compatibility modules
│   ├── Adrenalin         [implemented]
│   ├── RyzenMaster       [planned]
│   └── xpertRaidUtility  [planned]
│
├── QA
│   └── native regression harness
│
└── Installer
    └── install / upgrade / uninstall / shortcuts / EULA
```

> **Product-specific patch logic belongs in its product module. New AMD compatibility work must not accumulate inside the stable Adrenalin engine.**

See [ARCHITECTURE.md](docs/ARCHITECTURE.md).

---

## Upcoming modules

### Ryzen Master compatibility — planned

Ryzen Master can reject Windows Server with an operating-system compatibility gate even when the underlying machine is otherwise capable of running the product. TurtleAMD will handle this as a separate module with its own product/version detection, preflight, exact compatibility-gate discovery, patch plan, recovery evidence, validation, and rollback.

No Ryzen Master code will run during an Adrenalin workflow, and Ryzen Master will not reuse the INF/manifest rewrite logic merely for convenience.

### xpertRaidUtility compatibility — planned / analysis required

xpertRaidUtility will follow the same module contract. Exact patch targets will only be documented after package/version-specific analysis establishes the compatibility barrier. The module will own its detection, patch scope, validation, evidence, and rollback independently of Adrenalin and Ryzen Master.

See [ROADMAP.md](docs/ROADMAP.md).

---

## Requirements / runtime direction

Native QA currently targets:

- Windows x64
- Windows Server 2022 / 2025 compatibility workflows
- .NET 10 WPF application
- self-contained application publishing
- WebView2 Evergreen Runtime for embedded web content
- local administrator for patch operations
- enough disk space for download, fresh extraction, backups, and logs

The normal native runtime does **not** depend on PowerShell as the application language.

Driver-signature policy still matters after INF modification. TurtleAMD reports relevant security posture but does not silently disable Secure Boot, Memory Integrity, or BCD integrity policy.

---

## Repository notes

The repository name is historical: `AMD_DriverMagic_PatchWinServer2022-2025`. The product identity is now **TurtleAMD**.

The previous compiled `amd_inf.exe` was removed from the repository root while the native 3.x QA line is being finalized. Release binaries/installers should be published only after the native QA line is explicitly promoted. The complete PowerShell-era history remains available in Git history.

---

## Documentation

- [Native Architecture](docs/ARCHITECTURE.md)
- [Adrenalin Compatibility Module](docs/ADRENALIN-MODULE.md)
- [Migration from DriverMagic](docs/MIGRATION.md)
- [Safety and Rollback](docs/SAFETY-AND-ROLLBACK.md)
- [Installation / Upgrade / Uninstall](docs/INSTALLATION.md)
- [Roadmap](docs/ROADMAP.md)
- [Complete Native QA Gallery](docs/GALLERY.md)

---

## Disclaimer

TurtleAMD modifies third-party installation metadata for unsupported operating-system scenarios. Use it at your own risk, maintain a system backup/recovery path, and test AMD releases before production deployment. AMD package structures and compatibility gates can change between versions. TurtleAMD is not affiliated with or endorsed by AMD or Microsoft.

---

## License

**TurtleAMD Personal Use License** — free for personal, non-commercial use. Commercial use requires prior written permission and a separate commercial license. See [`LICENSE`](LICENSE) for the complete repository terms.

---

<p align="center">
  <strong>TurtleAMD — prove the package, patch only what is required, validate everything, then hand control back to AMD Setup.</strong>
</p>
