# Safety, Validation and Rollback

TurtleAMD is designed around the assumption that modifying vendor driver metadata is a consequential operation.

The application therefore treats evidence and recovery as part of the patch itself rather than optional logging.

---

## Preflight first

No Adrenalin package should be patched until the selected package root has passed preflight.

Preflight evaluates:

- administrator context
- supported Windows Server family/build
- package layout
- required manifests
- recursive INF scope
- package write access
- backup/log write access
- available disk space
- installer state
- extraction tooling
- PnP tooling
- boot configuration state
- test-signing posture
- Secure Boot posture
- Memory Integrity / HVCI where queryable
- reboot state
- signature consequences
- prior patch evidence

Blockers prevent patch execution. Warnings remain visible to the operator and are not silently converted into success.

---

## Patch plans

TurtleAMD builds intended changes before writing them.

A patch plan describes which files need changes and what validation must succeed afterward. This keeps analysis separate from mutation and makes future dry-run/evidence workflows possible.

---

## Backup format

Changed files receive recoverable backups beside the original vendor file using the production-compatible pattern:

```text
<file>.bak_yyyyMMdd_HHmmss_<sha-prefix>
```

The SHA-derived suffix helps distinguish backup generations and provides lightweight integrity evidence.

---

## Transactional write discipline

For every changed file:

1. read original content
2. preserve encoding/newline behavior
3. create backup
4. write replacement transactionally
5. re-open the written file
6. reparse/rescan the intended target
7. record evidence

The package is not considered patched merely because a write call succeeded.

---

## Full-package validation

After all planned writes complete, TurtleAMD performs a complete recursive validation pass.

Success requires the required manifests and all matched driver INF targets to be compliant at the same time.

If final validation fails, the active patch session is rolled back in reverse order.

---

## Revert All

`Revert All` is a separate recovery path for previously created compatible backups.

It recursively locates recoverable backup files, restores vendor originals, and consumes restored backup entries so stale recovery files are not repeatedly reapplied.

Operators should still maintain normal system backups and recovery media. TurtleAMD backup files are a package-level recovery mechanism, not a substitute for system recovery planning.

---

## Security policy

TurtleAMD reports driver-signature and boot/security posture but does not silently weaken the operating system.

It does not automatically:

- disable Secure Boot
- disable Memory Integrity / HVCI
- change BCD integrity policy
- enable test signing
- bypass unresolved preflight blockers

INF modification invalidates the vendor catalog relationship for the edited INF. The operator remains responsible for the driver-signing/testing posture appropriate to the target system.

---

## Logging

Persistent logs provide an audit trail for package discovery, preflight, patching, validation, rollback, sidecar workflow, and vendor-installer handoff.

The UI activity view is presentation-oriented; the persistent log remains the authoritative detailed record.
