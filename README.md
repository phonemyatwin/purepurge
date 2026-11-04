# PurePurge

**Zero-Trace Uninstaller for Ubuntu**

PurePurge deeply removes APT packages, Snaps, and Flatpaks — including residual configs, cached `.deb` files, PPA entries, signing keys, and per-user data directories — so uninstalled software leaves no trace on your system.

![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue)
![Ubuntu 22.04+](https://img.shields.io/badge/ubuntu-22.04%2B-orange)
![License: GPL-3.0](https://img.shields.io/badge/license-GPL--3.0-green)

---

## Features

| Feature | Details |
|---|---|
| **Unified scanner** | Discovers GUI applications across APT (`.desktop` → `dpkg -S` mapping), Snap (`snap list`), and Flatpak (`flatpak list`) |
| **Deep purge** | `apt-get purge --autoremove` + residual `rc` cleanup + PPA/repo removal + cache/config scrubbing |
| **Snap purge** | `snap remove --purge` + `~/snap/` and `/var/snap/` data wipe |
| **Flatpak purge** | `flatpak uninstall --delete-data` + `flatpak uninstall --unused` + `~/.var/app/` cleanup |
| **Safety whitelist** | Essential packages (`systemd`, `ubuntu-desktop`, `linux-image-*`, `core22`, etc.) are **never** removable |
| **Inspection modal** | Before confirming, review every file, config, repo entry, and exact shell command to be executed |
| **Single auth prompt** | All commands batched into one `pkexec bash` script — authenticate once via polkit |
| **Non-blocking UI** | Scanning and purging run on background `QThread`s; the PyQt6 GUI stays responsive |

---

## Project Structure

```
purepurge/
├── main.py                         # Entry point – wires UI ↔ scanner ↔ purger
├── com.purepurge.pkexec.policy     # Polkit policy for pkexec elevation
├── README.md
│
├── core/
│   ├── __init__.py
│   ├── safeguards.py               # Essential-package whitelist & filters
│   ├── scanner.py                  # APT / Snap / Flatpak application scanner
│   └── purger.py                   # Deep-removal command builder & executor
│
└── ui/
    ├── __init__.py
    ├── dashboard.py                # Main window (search, filters, app table)
    └── confirm_modal.py            # Inspection & confirmation dialog
```

---

## Prerequisites

- **Ubuntu 22.04+** (or any Debian-derivative with `dpkg`, `apt`, polkit)
- **Python 3.10+**
- **PyQt6**
- **polkit / pkexec** (pre-installed on Ubuntu Desktop)

---

## Installation

### 1. Clone & create a virtualenv

```bash
git clone https://github.com/purepurge/purepurge.git
cd purepurge

python3 -m venv venv
source venv/bin/activate
pip install PyQt6
```

### 2. Install the polkit policy

The policy file allows `pkexec` to run PurePurge's removal scripts with a standard password prompt instead of being rejected.

```bash
sudo cp com.purepurge.pkexec.policy /usr/share/polkit-1/actions/
```

> [!IMPORTANT]
> Without this step, clicking **Confirm Purge** will fail with a
> `pkexec` "not authorized" error. You only need to do this once.

### 3. (Optional) Create a `.desktop` launcher

```bash
cat > ~/.local/share/applications/purepurge.desktop << 'EOF'
[Desktop Entry]
Type=Application
Name=PurePurge
Comment=Zero-Trace Uninstaller for Ubuntu
Exec=bash -c "cd /path/to/purepurge && source venv/bin/activate && python main.py"
Icon=edit-delete
Terminal=false
Categories=System;PackageManager;
EOF
```

Replace `/path/to/purepurge` with the actual installation path.

---

## Usage

### Launch

```bash
cd purepurge
source venv/bin/activate
python main.py
```

### Workflow

1. **Scan** — On startup, PurePurge scans all three packaging systems in the background. A progress bar is shown until scanning completes.

2. **Search & filter** — Use the search bar to find apps by name or package ID. Click the **APT** / **Snap** / **Flatpak** tags to narrow by source.

3. **Select** — Click rows to select (Ctrl+Click or Shift+Click for multi-select). Essential system packages are highlighted in gold and cannot be selected for removal.

4. **Inspect** — Click **🗑 Purge Selected**. The confirmation modal opens with three tabs:
   - **Overview** — Summary of selected apps and trace counts
   - **Files & Configs** — Full tree of every file, config directory, repo entry, and cache file that will be deleted
   - **Commands** — Exact shell commands that will be executed via `pkexec`

5. **Confirm** — Click **Confirm Purge**. You will see a single polkit password prompt. A progress dialog tracks the operation. A result dialog shows success/failure details.

6. **Rescan** — The app list automatically refreshes after purging.

---

## Safety

> [!CAUTION]
> PurePurge performs **irreversible** deep removal. Always review the
> **Files & Configs** tab in the confirmation modal before proceeding.

### Safeguards whitelist

The following categories of packages are **hard-blocked** from removal:

| Category | Examples |
|---|---|
| Desktop meta-packages | `ubuntu-desktop`, `ubuntu-minimal`, `ubuntu-standard` |
| Init / boot / kernel | `systemd`, `grub-*`, `linux-image-*`, `linux-firmware*` |
| Core libraries | `libc6`, `libc-bin`, `libstdc++6` |
| Package management | `apt`, `dpkg`, `snapd`, `software-properties-common` |
| Shells & utilities | `bash`, `coreutils`, `sudo`, `login` |
| Snap runtimes | `bare`, `core`, `core18`–`core24`, `snapd` |
| Flatpak runtimes | `org.freedesktop.Platform`, `org.gnome.Platform`, etc. |

The full list is in [`core/safeguards.py`](core/safeguards.py). You can extend it by adding entries to the `ESSENTIAL_*` sets.

---

## Configuration

### Dry-run mode

All purger functions accept a `dry_run=True` parameter. To test without actually removing anything:

```python
from core.purger import purge_apt

result = purge_apt(["some-package"], dry_run=True)
print(result.commands_run)   # see what would execute
```

### Extending the whitelist

Edit [`core/safeguards.py`](core/safeguards.py) and add package names to the appropriate `ESSENTIAL_*` frozenset or glob tuple.

---

## Troubleshooting

| Problem | Solution |
|---|---|
| `pkexec` says "not authorized" | Install the polkit policy: `sudo cp com.purepurge.pkexec.policy /usr/share/polkit-1/actions/` |
| `ModuleNotFoundError: PyQt6` | Activate the venv: `source venv/bin/activate` |
| Snap/Flatpak tab is empty | The respective daemon may not be installed (`sudo apt install snapd` / `flatpak`) |
| Scan is slow | APT scan runs `dpkg -S` per `.desktop` file. This is normal on first run (~5–10 s). |
| GUI looks wrong on Wayland | Set `QT_QPA_PLATFORM=xcb` before launching, or upgrade to PyQt6 ≥ 6.5 |

---

## License

GPL-3.0 — see [LICENSE](LICENSE) for details.
