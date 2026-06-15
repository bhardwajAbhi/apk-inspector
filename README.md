# 📦 APK Inspector — Context Menu Tool for Ubuntu

A one-click APK analysis tool for malware researchers. Right-click any `.apk` file
in Nautilus (Ubuntu's file manager) and get a full parsed breakdown in seconds.

---

## ✨ What it shows

| Tab | Information |
|-----|-------------|
| 🗂 File Info | Filename, path, size, MD5, SHA-256 |
| 📋 Metadata | Package name, version, SDK targets, debuggable flag |
| 🔐 Permissions | All declared permissions, **dangerous ones highlighted in red** |
| 🧩 Components | Activity / Service / Receiver / Provider counts, launchable activity |
| 📁 APK Contents | DEX count, native libs, assets, MultiDex detection |
| ✍ Signing | apksigner output — v1/v2/v3/v4 scheme, verified status |
| 🏅 Certificate | Subject, issuer, validity dates, key size, SHA fingerprints |
| ⚙ Native Libs | All `.so` files with architecture (arm64-v8a, x86_64, etc.) |
| 🔍 Strings | Extracted URLs, IPs, emails, API keys, crypto addresses |

**Toolbar buttons:**
- **Open in JADX-GUI** — decompile and browse source code
- **Export to Text** — save a full report to any location
- **Copy SHA-256** — one-click hash copy for VirusTotal / reports
- **Click any row** — copies that value to clipboard

---

## 🛠 Tools Used

| Tool | Source | Purpose |
|------|--------|---------|
| `aapt` / `aapt2` | `sudo apt install aapt` | Metadata, permissions, components |
| `apksigner` | `sudo apt install apksigner` | Signature verification |
| `openssl` | Pre-installed on Ubuntu | Certificate parsing |
| `jadx-gui` | [github.com/skylot/jadx](https://github.com/skylot/jadx/releases) | Source decompilation |
| Python `zipfile` | Built-in | APK contents (ZIP format) |
| Python `hashlib` | Built-in | SHA-256, MD5 hashing |
| GTK3 (`python3-gi`) | `sudo apt install python3-gi` | GUI window |

---

## 🚀 Installation

```bash
# 1. Extract the zip and enter directory
unzip apk-inspector.zip
cd apk-inspector

# 2. Run installer
bash install.sh
```

The installer will:
- Copy the Python GUI to `~/.local/share/apk-inspector/`
- Install a Nautilus script to `~/.local/share/nautilus/scripts/`
- Install a file-manager action to `~/.local/share/file-manager/actions/`
- Register the APK MIME type
- Offer to install missing `apt` packages
- Reload Nautilus

---

## 📋 Manual Dependency Install

```bash
# Core tools
sudo apt install aapt apksigner openssl unzip python3-gi gir1.2-gtk-3.0

# JADX (optional but recommended for source decompilation)
# Download latest release from:
# https://github.com/skylot/jadx/releases
# Extract and symlink: sudo ln -s /opt/jadx/bin/jadx-gui /usr/local/bin/jadx-gui
```

---

## 🖱 Usage

1. Open **Files (Nautilus)** file manager
2. Navigate to your APK file
3. **Right-click** the `.apk` file
4. Select **Scripts → Get APK Details**

> **Note:** On newer Ubuntu (22.04+), custom actions may appear under the
> "Scripts" submenu. On some setups with `filemanager-actions` installed,
> it appears as a top-level entry.

---

## 🔧 Manual Testing

```bash
python3 ~/.local/share/apk-inspector/apk_inspector.py /path/to/sample.apk
```

---

## 📁 File Structure

```
apk-inspector/
├── install.sh                    ← Run this first
├── README.md                     ← This file
├── scripts/
│   ├── apk_inspector.py          ← Main GTK3 GUI app
│   └── Get APK Details           ← Nautilus script bridge
└── actions/
    └── apk-inspector.desktop     ← File-manager action definition
```

---

## 💡 Tips for Malware Analysis

- **Permissions tab**: Watch for `READ_SMS`, `SEND_SMS`, `BIND_ACCESSIBILITY_SERVICE`,
  `SYSTEM_ALERT_WINDOW`, `INSTALL_PACKAGES` — classic malware indicators.
- **Signing tab**: Unsigned or self-signed certs with `CN=Android Debug`
  suggest sideloaded/repackaged APKs.
- **Debuggable flag**: `android:debuggable=true` in production apps is suspicious.
- **MultiDex**: Multiple DEX files can indicate code obfuscation or large apps.
- **Native Libs**: Unexpected `.so` files in unusual ABIs may contain shellcode.
- **Strings tab**: Hardcoded C2 URLs, API keys, or suspicious domains.
- Export the report and paste the SHA-256 directly into VirusTotal or MalwareBazaar.

---

## 🔄 Uninstall

```bash
rm -rf ~/.local/share/apk-inspector
rm -f  ~/.local/share/nautilus/scripts/"Get APK Details"
rm -f  ~/.local/share/file-manager/actions/apk-inspector.desktop
nautilus -q
```
