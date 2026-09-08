# Installation, Upgrade and Uninstall

## Native installer status

The TurtleAMD 3.x native line is packaged as a traditional Windows installer during QA.

The public repository should not treat a QA binary as a promoted release until the native QA line is explicitly accepted.

---

## Install behavior

The installer provides:

- normal setup wizard
- EULA acceptance
- selectable destination
- default installation under `C:\Program Files\TurtleAMD`
- Start Menu shortcut
- optional Desktop shortcut
- Programs & Features / Installed Apps registration
- launch-after-install option
- TurtleAMD branding and icon

The installed application executable is currently named `amd_inf.exe` internally for compatibility with the existing build line, while the product identity and installation folder are TurtleAMD.

---

## Existing-install detection

The installer is designed to recognize an existing TurtleAMD installation and offer a maintenance path rather than blindly copying files over an unknown state.

Supported QA behavior includes:

- upgrade-in-place
- clean reinstall through the registered uninstaller
- cancel setup
- running-process handling before replacement

Legacy DriverMagic / AMD INF Patcher installations may use different historical identifiers and should be treated as a migration case rather than assumed to be the same product registration.

---

## Uninstall

TurtleAMD registers a normal uninstaller so it can be removed from:

```text
Settings → Apps → Installed apps
```

or:

```text
Control Panel → Programs and Features
```

Start Menu uninstall integration is also supported by the installer configuration.

---

## WebView2 prerequisite

The AMD Drivers sidecar uses Microsoft Edge WebView2.

TurtleAMD checks for the Evergreen WebView2 Runtime and can bootstrap the Microsoft Evergreen runtime when it is absent.

WebView2 is only the embedded browser provider. Files sidecar functionality uses Windows filesystem/shell integration and does not require an external browser window.

---

## Build output contract

For a normal x64 release-style QA build, the build pipeline is expected to produce:

```text
dist\win-x64\amd_inf.exe
dist\installer\amd_inf_setup.exe
```

The installer stage is treated as a build contract rather than a best-effort optional step unless an app-only build explicitly skips installer generation.
