# Adrenalin Compatibility Module

## Status

**Implemented / active native QA**

The Adrenalin module is the production-proven compatibility path preserved from the original DriverMagic / AMD INF Patcher application and migrated into the native TurtleAMD architecture.

This module is intentionally isolated from future Ryzen Master and xpertRaidUtility work.

---

## Package scope

The module resolves and validates the canonical AMD package root:

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

TurtleAMD only treats the top-level `Setup.exe` as the authoritative vendor installer.

---

## Manifest normalization

The module targets the three required AMD JSON manifests and normalizes only the compatibility metadata required for Windows Server support.

Behavior includes:

- exact `OSCheck` targeting
- Server 2022 and Server 2025 compatibility entries
- scalar-to-array conversion where required
- duplicate required-entry removal
- preservation of unrelated JSON values
- preservation of adjacent properties such as `OSCheckMinVer`
- parse validation after modification
- full post-write rescan

The engine does not perform blind global string replacement.

---

## Recursive INF normalization

All driver INFs beneath:

```text
Packages\Drivers\**\*.inf
```

are scanned recursively.

The engine normalizes targeted AMD manufacturer and model-section decorations so server builds are not excluded by decorated `NTamd64` sections.

It preserves:

- unrelated INF content
- comments
- whitespace where possible
- source newline style
- source encoding / BOM behavior
- manufacturer and model-section identifiers outside the targeted decoration

Every modified INF is rescanned after write.

---

## Transaction boundary

The Adrenalin module never writes vendor files directly without recovery evidence.

For each changed file:

1. read source while preserving encoding
2. create a patch plan
3. write a hashed backup
4. perform a transactional replacement
5. rescan the written file
6. validate the complete package
7. roll back the session in reverse order if any required validation fails

Manual `Revert All` support remains available after the patch session.

---

## Preflight

The module consumes shared TurtleAMD preflight infrastructure and adds Adrenalin-specific checks for:

- expected package layout
- all required manifests
- recursive INF scope
- package write access
- top-level vendor installer presence
- prior patch / backup evidence

Platform preflight also checks administrator context, operating-system/build state, free disk space, relevant boot/security posture, pending reboot state, and tooling prerequisites.

---

## Completion gate

AMD Setup is not offered until:

- preflight is accepted
- patch confirmation is accepted
- all intended writes succeed
- all modified files pass post-write validation
- the final recursive package validation passes

The completion window reports exact scan/change/backup counts before the validated top-level `Setup.exe` can be launched.

The launch workflow can optionally remove the original downloaded AMD installer after the extracted validated Setup process starts. The extracted working package and recovery evidence are not removed by that option.

---

## Regression rule

New compatibility products must not add rewrite rules to this module.

Ryzen Master and xpertRaidUtility are separate compatibility modules with independent detection, preflight, patch scope, validation, and rollback behavior.
