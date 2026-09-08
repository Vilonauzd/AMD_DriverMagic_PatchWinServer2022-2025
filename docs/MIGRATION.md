# Native Migration Notes

## From DriverMagic / AMD INF Patcher to TurtleAMD

The 2.x product was a PowerShell/WPF application that accumulated package discovery, preflight, patching, validation, rollback, UI state, and installer handoff in one large runtime.

The 3.x line is a native C#/.NET 10 WPF port.

The migration goal is not source-code secrecy. Managed .NET applications can still be decompiled.

The migration goal is maintainability.

---

## Behavior intentionally preserved

The native Adrenalin engine preserves the important production behaviors:

- exact three-manifest targeting
- recursive INF discovery
- manufacturer alias normalization
- decorated `NTamd64` section normalization
- Server compatibility `OSCheck` handling
- unrelated JSON preservation
- unrelated INF preservation
- encoding/newline preservation
- hashed backups
- transactional writes
- post-write rescan
- full-package validation
- automatic rollback
- manual Revert All
- top-level AMD `Setup.exe` launch only

---

## Behavior intentionally improved

The native line adds:

- type-safe subsystem boundaries
- independent QA harness
- structured installer
- persistent application settings
- tray integration
- integrated WebView2
- integrated Files sidecar
- download capture
- workflow lock
- queued operator-facing progress
- custom dialogs
- explicit future-module architecture

---

## Repository artifact transition

The historical root `amd_inf.exe` artifact was removed while the native 3.x line is being finalized.

The repository documentation now describes the native architecture and QA workflow, but QA screenshots do not imply that every QA build is a promoted public release. Native release binaries should be published through an explicit release/install package once regression acceptance is complete.

---

## Regression rule

When porting or expanding behavior:

- compare against the recovered production implementation
- prefer small subsystem changes
- keep patch plan/validation semantics explicit
- prove changes against clean packages
- do not interpret success against an already-patched extraction as authoritative QA

---

## Future compatibility work

Ryzen Master and xpertRaidUtility will be implemented as separate modules.

That decision is deliberate: the successful Adrenalin engine is now a stable boundary, not a place to accumulate unrelated AMD compatibility patches.
