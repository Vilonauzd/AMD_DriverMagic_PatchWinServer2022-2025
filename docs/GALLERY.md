# TurtleAMD Native QA Gallery

These contact sheets use the complete screenshot set captured during the native 3.x QA workflow on September 6, 2026.

They document the actual operator path rather than mockups.

---

## 1. Attached WebView2 + Files sidecar

<img src="../assets/screenshots/native-qa3/native-sidecar-gallery.jpg" alt="TurtleAMD native sidecar gallery" />

1. WebView2 AMD support sidecar with an AMD installer download in progress.
2. Completed embedded download and handoff back into TurtleAMD package preparation.
3. Integrated Files sidecar selecting an AMD package without opening Explorer.
4. WebView2 preparation/retry state with external fallback available.

The sidecar shares one docked region for web and filesystem interaction. The main window stays anchored and expands to the right.

---

## 2. Preflight, patch gating and validation

<img src="../assets/screenshots/native-qa3/native-workflow-gallery.jpg" alt="TurtleAMD workflow gallery" />

5. Critical preflight operation with the underlying cockpit dimmed and locked.
6. Compact preflight report with pass/warn/info findings in a dense table.
7. Transactional patch confirmation gate before vendor files are modified.
8. Patch + validation workflow lock with paced operator narration.
9. Patch completion evidence and exact change counts.

The UI pacing is presentation-only; it does not intentionally slow the underlying patch engine.

---

## 3. Validated AMD Setup handoff

<img src="../assets/screenshots/native-qa3/native-amd-handoff-gallery.jpg" alt="TurtleAMD AMD handoff gallery" />

10. Validated top-level AMD Setup launch gate with optional download cleanup.
11. Alternate capture of the cleanup choice.
12. AMD Software installer detecting system configuration after TurtleAMD handoff.
13. AMD Adrenalin repair-ready screen.
14. AMD Adrenalin repair/additional-options screen.

TurtleAMD only offers the top-level `Setup.exe` after complete patch validation.

---

## 4. Installed identity + traditional Windows setup

<img src="../assets/screenshots/native-qa3/native-installer-gallery.jpg" alt="TurtleAMD installer gallery" />

15. Installed Desktop shortcut using TurtleAMD branding.
16. Setup wizard welcome page.
17. Setup wizard with dark native titlebar treatment.
18. Selectable Program Files destination.
19. Installation progress.
20. Completion page with optional launch.

The installer registers normal Windows uninstall metadata and shortcuts instead of treating TurtleAMD as a loose portable EXE.

---

## QA note

Some captures show intermediate QA build labels because the screenshots span iterative UI refinement. They represent the native 3.x architecture and workflow, not separate public releases.
