# AMD_DriverMagic_PatchWinServer2022-2025

<img width="852" height="692" alt="image" src="https://github.com/user-attachments/assets/f44bc8fb-3b4f-43a0-8c54-5c9aaaaf62ee" />


# AMD INF Patcher – Windows Server 2025 Ready

> **Unlock AMD GPU driver support on Windows Server 2022 & 2025**  
> A resilient, GUI-powered PowerShell tool to patch AMD Adrenalin driver INF files for unsupported Windows Server editions.

---

##  Overview

AMD does **not officially support** Windows Server for consumer Radeon drivers. This tool safely modifies AMD driver installation files (`*.inf` and manifests) to **trick the installer** into recognizing Windows Server 2022 and **Windows Server 2025 (GA Build 26100)** as valid targets—enabling full GPU acceleration, OpenCL, and display output on headless or workstation-class servers.

Built with **enterprise-grade safety**, **full revert capability**, and a **dark-mode WPF GUI**, this utility is ideal for homelab admins, AI/ML engineers, and virtualization hosts.

---

##  Key Features

| Feature | Description |
|--------|-------------|
| **Windows Server 2025 Support** | Uses correct GA build `26100` (`NTamd64.10.0...26100`) |
| **Multi-Target OS Support** | Server 2022, Win11 24H2, Server 2025, Generic, or Custom |
| **INF File Patching** | Updates `[Manufacturer]` and `[ATI.Mfg.*]` sections with correct OS decoration |
| **Manifest Patching (Best Effort)** | Widens OS version checks in `InstallManifest.json`, `AppInstallerManifest.xml`, etc. |
| **Full Revert System** | Restores all files from SHA256-hashed, timestamped backups |
| **Dark Retro GUI** | Glowing red terminal theme with responsive WPF interface |
| **Live Logging** | Real-time log output during patching/revert operations |
| **Admin Enforcement** | Requires elevated privileges for safety |
| **EXE-Ready** | Compiles cleanly to standalone `.exe` via `ps2exe` |
| **No Internet Required** | 100% offline operation after initial driver download |

---

##  Requirements

- **OS**: Windows 10 / 11 / Server 2016+ (with .NET Framework 4.8+)
- **PowerShell**: 5.1 or later (built into all supported Windows versions)
- **Admin Rights**: Required (script enforces this via `#requires -RunAsAdministrator`)
- **AMD Driver Package**: Extracted Adrenalin installer (e.g., `AMD-Software-Installer.exe` → extracted to folder)

>  **Tip**: Use 7-Zip or Universal Extractor to unpack the AMD installer `.exe`.

---

##  Installation & Usage

### 1. **Prepare AMD Driver Folder**
- Download official AMD Adrenalin driver (e.g., `amd-software-pro-24.5.1-win10-win11-64bit.exe`)
- Extract it to a folder like `C:\AMD\Drivers`

### 2. **Run the Patcher**
#### Option A: PowerShell (Admin)
```powershell
# Navigate to script folder
cd "G:\AMD_DriverMagic_PatchWinServer2022-2025"

# Execute
& .\AMD-INF-Patcher.ps1
```

#### Option B: Standalone EXE (Recommended)

```powershell
Downloade .exe version and run as admin...
```
Then double-click `AMD-INF-Patcher.exe` (auto-elevates).

### 3. **Patch Workflow**
1. **Browse** to your extracted AMD driver folder
2. **Select Target OS** → `Server2025` (default)
3. (Optional) Enable **Patch Adrenalin Manifest**
4. Click **Patch INF**
5. Run `setup.exe` from the patched folder

>  Use **Revert All** anytime to undo changes.

---

##  Safety & Redundancy

- **Atomic Backups**: Every modified file is backed up as `original.bak_<timestamp>_<8-char-SHA256>`
- **Session Isolation**: Each run uses a unique session ID (`yyyyMMdd_HHmmss`)
- **Non-Destructive**: Original files are never deleted—only renamed during revert
- **Log Auditing**: Full activity logged to `C:\RepairLogs\amd_inf_patch_*.log`
- **Dependency Checks**: Validates PowerShell version, admin rights, and log directory

---

##  Supported AMD Driver Structures

The patcher automatically detects INF files in:
- `\Display\WT6A_INF\`
- Any folder named `WT6A_INF`
- Files matching `u*.inf` (e.g., `u037113.inf`)

Manifest files are detected by:
- Filename: `InstallManifest.json`, `AppInstallerManifest.xml`, `manifest.json`
- Path: Any `Bin64` subdirectory

---


---

##  Disclaimer

- This tool **modifies driver installation files only**—it does **not** alter the Windows kernel or AMD binaries.
- Use at your own risk. Not affiliated with AMD or Microsoft.
- **Backup your system** before installing patched drivers.
- Some features (e.g., Radeon Anti-Lag, Boost) may not function on Server SKUs.

---

##  License

MIT License – Free for personal and commercial use.  
*Community-built. Not endorsed by AMD.*

---

## 💬 Community & Support

- **Reddit**: r/AMD_DriverMagic, r/homelab, r/WindowsServer
- **GitHub Issues**: (if published)
- **Discord**: Homelab & GPU Compute communities

> Made with ❤️ for server tinkerers pushing hardware beyond its limits.

---

**`AMD-INF-Patcher.ps1` – Because your EPYC deserves Radeon power.** 💥

https://github.com/user-attachments/assets/d86f150e-2bdc-4a9c-ad5d-4f6dffeaf94c

