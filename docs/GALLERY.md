# TurtleAMD Native QA Gallery

These screenshots document the native 3.x QA workflow captured on September 6, 2026. They are the original full-resolution QA captures rather than reduced contact-sheet placeholders.

---

## 1. Attached WebView2 + Files sidecar

### AMD download in progress

<img src="../assets/screenshots/native-qa3/2026-09-06%2022_30_37-TurtleAMD%20_%20AMD%20INF%20Patcher.png" alt="TurtleAMD WebView2 sidecar with AMD download in progress" />

### Patch confirmation with integrated Files sidecar

<img src="../assets/screenshots/native-qa3/2026-09-06%2022_31_42-TurtleAMD%20_%20AMD%20INF%20Patcher.png" alt="TurtleAMD patch confirmation with integrated Files sidecar" />

The sidecar shares one docked region for web and filesystem interaction. The main window remains anchored while the application expands to the right.

---

## 2. Patch completion and validation

<img src="../assets/screenshots/native-qa3/2026-09-06%2022_31_56-TurtleAMD%20_%20AMD%20INF%20Patcher.png" alt="TurtleAMD patch and validation completion gate" />

The completion gate records exact manifest/INF results and exposes the validated top-level AMD Setup handoff only after full recursive validation succeeds.

---

## 3. Validated AMD Setup handoff

### Launch gate with optional download cleanup

<img src="../assets/screenshots/native-qa3/2026-09-06%2022_32_07-TurtleAMD%20_%20AMD%20INF%20Patcher.png" alt="TurtleAMD validated AMD Setup launch gate" />

### AMD installer startup

<img src="../assets/screenshots/native-qa3/2026-09-06%2022_32_16-TurtleAMD%20_%20AMD%20INF%20Patcher.png" alt="AMD Adrenalin installer starting after TurtleAMD validation" />

<img src="../assets/screenshots/native-qa3/2026-09-06%2022_32_26-TurtleAMD%20_%20AMD%20INF%20Patcher3.png" alt="AMD Adrenalin installer detecting system configuration" />

<img src="../assets/screenshots/native-qa3/2026-09-06%2022_32_30-TurtleAMD%20_%20AMD%20INF%20Patcher4.png" alt="AMD Adrenalin installer detection progress after TurtleAMD handoff" />

### AMD Adrenalin repair-ready screen

<img src="../assets/screenshots/native-qa3/2026-09-06%2022_32_41-TurtleAMD%20_%20AMD%20INF%20Patcher5.png" alt="AMD Adrenalin repair-ready screen after TurtleAMD handoff" />

TurtleAMD only offers the top-level `Setup.exe` after complete patch validation.

---

## 4. Installed identity + traditional Windows setup

### Desktop shortcut branding

<img src="../assets/screenshots/native-qa3/2026-09-06%2022_34_07-Greenshot.png" alt="Installed TurtleAMD Desktop shortcut" />

### Setup wizard

<img src="../assets/screenshots/native-qa3/2026-09-06%2022_35_29-Setup%20-%20TurtleAMD.png" alt="TurtleAMD setup wizard welcome page" />

The installer registers normal Windows uninstall metadata and shortcuts instead of treating TurtleAMD as a loose portable EXE.

---

## QA note

Some captures show intermediate QA build labels because the screenshots span iterative UI refinement. They represent the native 3.x architecture and workflow, not separate public releases.
