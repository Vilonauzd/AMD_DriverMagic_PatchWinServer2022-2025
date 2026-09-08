# TurtleAMD Native Architecture

TurtleAMD 3.x is a native C#/.NET 10 WPF redesign of the original DriverMagic / AMD INF Patcher application.

The architectural rule is:

> Product-specific patch logic must remain isolated from the application shell and from other AMD compatibility modules.

This is especially important as TurtleAMD grows beyond Adrenalin package compatibility.

---

## Layer model

```text
AMD.DriverMagic / TurtleAMD
│
├── App
│   ├── WPF shell and cockpit
│   ├── workflow state machine
│   ├── dialogs / progress / completion gates
│   ├── tray / notifications
│   ├── WebView2 sidecar
│   └── Files sidecar
│
├── Core
│   ├── package discovery
│   ├── preflight primitives
│   ├── transaction / backup / rollback
│   ├── validation primitives
│   └── Adrenalin engine
│
├── Modules
│   ├── Adrenalin
│   ├── RyzenMaster          [planned]
│   └── xpertRaidUtility     [planned]
│
├── QA
│   ├── transform regression tests
│   ├── rollback tests
│   ├── package-layout tests
│   └── release-gate checks
│
└── Installer
    ├── install / upgrade / clean reinstall
    ├── Start Menu / desktop shortcuts
    ├── Programs & Features registration
    ├── EULA
    └── uninstall
```

---

## App layer

The WPF application owns operator experience and orchestration only.

Responsibilities include:

- TurtleAMD cockpit rendering
- next-step guidance pulse
- critical workflow lock
- queued/paced status presentation
- activity logging view
- WebView2 sidecar
- integrated Files sidecar
- tray menu and TurtleAMD notification cards
- user confirmation gates
- installer launch handoff

The App layer should not contain INF or JSON rewrite semantics.

---

## Core layer

The Core layer remains UI-independent.

The current Adrenalin workflow is conceptually:

```text
package discovery
    ↓
preflight
    ↓
patch plan
    ↓
backup
    ↓
write
    ↓
post-write rescan
    ↓
full-package validation
    ↓
success OR reverse-order rollback
```

The patch plan should remain a first-class object so the application can explain what will change before execution and test what happened afterward.

---

## Adrenalin module

The Adrenalin engine is the stable compatibility module.

It currently owns:

- three required JSON manifest targets
- recursive AMD driver INF scanning
- manufacturer mapping normalization
- decorated `NTamd64` section normalization
- Windows Server compatibility metadata injection
- scalar-to-array JSON conversion where required
- duplicate required `OSCheck` cleanup
- preservation of unrelated JSON values
- preservation of INF comments/encoding/newline structure
- per-file backup evidence
- transactional replacement
- full-package rescan
- rollback on validation failure

Future modules must not add product-specific behavior to this engine.

---

## Shared module contract

The exact public API may evolve while the native line is in QA, but every compatibility module should provide the same conceptual lifecycle:

```text
Detect
  Identify supported product/package/version.

Preflight
  Prove prerequisites and classify blockers/warnings.

Plan
  Produce an explicit list of intended changes.

Execute
  Apply only module-owned changes through shared transaction services.

Validate
  Prove that every intended change succeeded and unrelated state remains valid.

Rollback
  Restore module-owned changes when execution or validation fails.

Report
  Produce operator-readable evidence and structured QA output.
```

Shared services may include:

- logging
- hashing
- backup naming
- temporary/transactional writes
- rollback orchestration
- settings
- UI workflow infrastructure

Product-specific detection and rewrite logic may not be shared across modules merely for convenience.

---

## Ryzen Master module — planned

Ryzen Master support is intentionally separate from Adrenalin.

Initial scope:

- detect supported Ryzen Master installer/package versions
- locate the operating-system compatibility gate
- prove the exact patch target before modifying anything
- create module-owned recovery evidence
- modify only the Ryzen Master compatibility target
- validate the patched result
- rollback independently of driver package state

No Ryzen Master code should run during an Adrenalin workflow.

---

## xpertRaidUtility module — planned

xpertRaidUtility support will follow the same separation.

The exact package and patch targets are intentionally not documented yet because they must be established from version-specific analysis first.

Acceptance criteria will include:

- explicit product/version detection
- isolated preflight
- explicit patch plan
- no mutation outside module-owned files
- backup and rollback
- validation
- no dependency on the Adrenalin engine

---

## Sidecar subsystem

The right-side sidecar is shared application infrastructure.

### WebView2 provider

Used for AMD support/download workflows.

Important behaviors:

- attached to the main window
- main window origin remains fixed
- window expands to the right
- WebView is hidden/non-interactive while initializing
- dark preparation surface covers initialization
- WebView is revealed only after navigation is ready
- download events are captured by TurtleAMD
- Evergreen runtime is detected/bootstraped as needed
- browser profile is application-scoped

### Files provider

Used for AMD installer and extracted-package selection.

Important behaviors:

- same sidecar geometry as WebView mode
- no separate Explorer window for the normal workflow
- Downloads / Desktop / C:\AMD / This PC quick navigation
- readable active/inactive selection colors
- package/installer selection handoff directly into workflow state

---

## Workflow lock and event presentation

Critical operations must not be interruptible by unrelated UI actions.

While package preparation, preflight, patching, validation, or rollback owns the workflow:

- the underlying cockpit is dimmed
- underlying controls are non-interactive
- the critical progress surface becomes the only interactive focus
- safe cancellation is exposed only where supported

Status events are produced at engine speed but serialized for human-readable presentation.

The UI must never slow the patch engine merely to create visual pacing.

---

## QA boundary

Regression safety is a core architectural concern.

Changes should be classified before implementation:

- **Core change:** requires direct patch-engine regression coverage.
- **App/UI change:** should not alter Core behavior.
- **Installer change:** should not alter application/core behavior.
- **Module change:** should not modify unrelated module behavior.

The Adrenalin engine is treated as a stable subsystem. New module work should prefer additive architecture over shared conditional logic.

---

## Build and packaging direction

Native QA builds target:

- .NET 10
- WPF
- x64 Windows
- self-contained deployment
- single-file application publishing
- traditional installer output
- deterministic repository NuGet configuration
- one-shot `build.cmd` / `build.ps1` workflow

The installer produces the installed TurtleAMD application plus normal Windows uninstall/shortcut registration.

---

## Architectural goal

TurtleAMD should be able to add AMD compatibility features without becoming another monolith.

A successful new module should feel integrated to the user while remaining boringly isolated to the engineer.
