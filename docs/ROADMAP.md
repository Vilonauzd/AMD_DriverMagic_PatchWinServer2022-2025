# TurtleAMD Roadmap

This roadmap describes the native 3.x direction. It is intentionally organized around regression boundaries rather than feature count.

---

## Phase 1 — Native Adrenalin migration

**Status: active QA / substantially complete**

Goals:

- preserve production Adrenalin patch semantics
- move runtime from PowerShell to C#/.NET 10
- keep WPF as the desktop UI framework
- separate Core, App, QA, and installer responsibilities
- preserve transaction/backup/rollback behavior
- improve responsiveness and maintainability
- establish the TurtleAMD visual identity

Major delivered QA features:

- native Adrenalin manifest/INF engine
- package discovery and fresh extraction
- preflight
- transaction/rollback
- full-package validation
- Revert All
- TurtleAMD cockpit
- red workflow guidance
- critical-operation workflow lock
- WebView2 AMD support sidecar
- integrated Files sidecar
- in-app download capture/progress
- validated AMD Setup launch
- optional downloaded-installer cleanup
- tray menu
- custom TurtleAMD tray notifications
- traditional installer
- Start Menu/Desktop shortcuts
- Programs & Features uninstall
- upgrade / clean-reinstall path
- EULA

Release gate:

- complete Windows QA against clean, previously unpatched AMD packages
- confirm installer/upgrade/uninstall paths
- confirm tray and sidecar behavior across supported display/DPI configurations
- promote a native 3.x installer only after regression acceptance

---

## Phase 2 — Bug-smash

**Status: next**

User-reported defects are handled one at a time.

Process:

1. reproduce against a known package/environment
2. identify the subsystem
3. add a regression test where practical
4. fix with the narrowest possible change
5. verify unrelated Adrenalin behavior
6. preserve evidence in QA notes

Priority is stability over cosmetic feature velocity.

---

## Phase 3 — Additional compatibility modules

### Ryzen Master

**Status: planned**

Purpose:

Ryzen Master can present an invalid/unsupported operating-system gate on Windows Server even when the underlying system is otherwise capable of running the software.

TurtleAMD will treat Ryzen Master as a separate compatibility product.

Planned lifecycle:

```text
Detect Ryzen Master
    ↓
Module-specific preflight
    ↓
Identify exact OS-gate target
    ↓
Build patch plan
    ↓
Backup
    ↓
Patch
    ↓
Validate
    ↓
Rollback on failure
```

Non-goals:

- no reuse of Adrenalin INF logic
- no changes to Adrenalin manifests
- no hidden BCD/security-policy changes
- no broad binary patching without version-specific validation

### xpertRaidUtility

**Status: planned**

xpertRaidUtility will be added as another isolated module after package/version analysis establishes the exact compatibility barrier.

The module must own:

- product detection
- supported-version detection
- preflight
- patch plan
- backup
- patch execution
- validation
- rollback
- reporting

No xpertRaidUtility-specific rewrite logic belongs in the Adrenalin or Ryzen Master modules.

---

## Phase 4 — Module platform hardening

Once multiple modules exist, shared infrastructure can be formalized further.

Candidates:

- module discovery/registration
- common module status cards
- module-specific preflight surfaces
- reusable evidence bundles
- structured dry-run/analysis mode
- richer release regression matrix
- package-version fingerprints
- optional module telemetry that never contains secrets or private files

---

## Release philosophy

TurtleAMD is not trying to patch everything AMD in one engine.

The long-term model is:

```text
one application shell
one transaction/QA discipline
multiple isolated compatibility modules
```

That keeps the UI consistent and the patch logic auditable.
