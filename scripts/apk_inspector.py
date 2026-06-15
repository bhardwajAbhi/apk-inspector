#!/usr/bin/env python3
"""
APK Inspector - Malware Analysis Context Menu Tool
Parses APK files using aapt, apksigner, unzip and displays results in a GTK3 GUI.
"""

import sys
import os
import subprocess
import hashlib
import zipfile
import re
import threading
import datetime
import gi

gi.require_version("Gtk", "3.0")
gi.require_version("Pango", "1.0")
from gi.repository import Gtk, GLib, Pango, Gdk

# ──────────────────────────────────────────────────────────────────────────────
# Helper: run a shell command, return (stdout, stderr, returncode)
# ──────────────────────────────────────────────────────────────────────────────
def run(cmd, timeout=30):
    try:
        r = subprocess.run(
            cmd, shell=True, capture_output=True, text=True,
            timeout=timeout, errors="replace"
        )
        return r.stdout.strip(), r.stderr.strip(), r.returncode
    except subprocess.TimeoutExpired:
        return "", "Command timed out", 1
    except Exception as e:
        return "", str(e), 1


def which(binary):
    out, _, rc = run(f"which {binary}")
    return out if rc == 0 else None


def file_sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def file_md5(path):
    h = hashlib.md5()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


# ──────────────────────────────────────────────────────────────────────────────
# APK Parsing Engine
# ──────────────────────────────────────────────────────────────────────────────
class APKParser:
    def __init__(self, apk_path):
        self.path = apk_path
        self.data = {}

    def parse_all(self, progress_cb=None):
        steps = [
            ("File Info",        self._parse_file_info),
            ("Basic Metadata",   self._parse_aapt),
            ("Permissions",      self._parse_permissions),
            ("Components",       self._parse_components),
            ("Signing Info",     self._parse_signing),
            ("Certificate",      self._parse_certificate),
            ("APK Contents",     self._parse_contents),
            ("Strings (quick)",  self._parse_strings),
            ("Native Libraries", self._parse_native_libs),
        ]
        for i, (label, fn) in enumerate(steps):
            if progress_cb:
                GLib.idle_add(progress_cb, label, i / len(steps))
            try:
                fn()
            except Exception as e:
                self.data[label] = {"Error": str(e)}
        if progress_cb:
            GLib.idle_add(progress_cb, "Done", 1.0)
        return self.data

    # ── File Info ──────────────────────────────────────────────────────────────
    def _parse_file_info(self):
        p = self.path
        stat = os.stat(p)
        size_bytes = stat.st_size
        size_mb = size_bytes / (1024 * 1024)
        mtime = datetime.datetime.fromtimestamp(stat.st_mtime).strftime("%Y-%m-%d %H:%M:%S")

        self.data["File Info"] = {
            "Filename":   os.path.basename(p),
            "Full Path":  p,
            "Size":       f"{size_bytes:,} bytes  ({size_mb:.2f} MB)",
            "Modified":   mtime,
            "MD5":        file_md5(p),
            "SHA-256":    file_sha256(p),
        }

    # ── aapt dump badging ──────────────────────────────────────────────────────
    def _parse_aapt(self):
        aapt = which("aapt") or which("aapt2")
        if not aapt:
            self.data["Basic Metadata"] = {"Warning": "aapt/aapt2 not found. Install build-tools."}
            return

        cmd = f'"{aapt}" dump badging "{self.path}" 2>/dev/null'
        out, _, _ = run(cmd, timeout=30)

        def g(pattern):
            m = re.search(pattern, out)
            return m.group(1).strip() if m else "—"

        # multi-value patterns
        def gall(pattern):
            return list(set(re.findall(pattern, out))) or ["—"]

        meta = {
            "Package Name":          g(r"package: name='([^']+)'"),
            "Version Code":          g(r"versionCode='([^']+)'"),
            "Version Name":          g(r"versionName='([^']+)'"),
            "Min SDK Version":       g(r"sdkVersion:'(\d+)'"),
            "Target SDK Version":    g(r"targetSdkVersion:'(\d+)'"),
            "App Label":             g(r"application-label(?:-en)?:'([^']+)'"),
            "Supports Screens":      g(r"supports-screens: '([^']+)'"),
            "Densities":             g(r"densities: '([^']+)'"),
            "ABIs (native code)":    ", ".join(gall(r"native-code: '([^']+)'")),
            "Uses-Feature":          "; ".join(gall(r"uses-feature(?:-not-required)?:'([^']+)'")),
            "Uses-Library":          "; ".join(gall(r"uses-library(?:-not-required)?:'([^']+)'")),
            "Debuggable":            "YES ⚠" if "application-debuggable" in out else "No",
            "Test Only":             "YES ⚠" if "testOnly" in out else "No",
        }
        self.data["Basic Metadata"] = meta

    # ── Permissions ───────────────────────────────────────────────────────────
    def _parse_permissions(self):
        aapt = which("aapt") or which("aapt2")
        if not aapt:
            self.data["Permissions"] = {}
            return
        out, _, _ = run(f'"{aapt}" dump badging "{self.path}" 2>/dev/null', timeout=30)

        perms = sorted(set(re.findall(r"uses-permission(?:-sdk-\d+)?:\s*name='([^']+)'", out)))

        # Flag dangerous ones
        DANGEROUS = {
            "READ_CONTACTS", "WRITE_CONTACTS", "READ_CALL_LOG", "WRITE_CALL_LOG",
            "CAMERA", "RECORD_AUDIO", "READ_SMS", "SEND_SMS", "RECEIVE_SMS",
            "READ_PHONE_STATE", "CALL_PHONE", "READ_EXTERNAL_STORAGE",
            "WRITE_EXTERNAL_STORAGE", "ACCESS_FINE_LOCATION", "ACCESS_COARSE_LOCATION",
            "PROCESS_OUTGOING_CALLS", "GET_ACCOUNTS", "USE_BIOMETRIC",
            "USE_FINGERPRINT", "BIND_ACCESSIBILITY_SERVICE", "BIND_DEVICE_ADMIN",
            "INSTALL_PACKAGES", "DELETE_PACKAGES", "MOUNT_UNMOUNT_FILESYSTEMS",
            "PACKAGE_USAGE_STATS", "REQUEST_INSTALL_PACKAGES", "INTERNET",
            "READ_PHONE_NUMBERS", "MANAGE_EXTERNAL_STORAGE", "QUERY_ALL_PACKAGES",
            "CHANGE_NETWORK_STATE", "SYSTEM_ALERT_WINDOW", "RECEIVE_BOOT_COMPLETED",
        }
        result = {}
        for p in perms:
            short = p.replace("android.permission.", "")
            flag = " 🚨 DANGEROUS" if short in DANGEROUS else ""
            result[short] = p + flag
        self.data["Permissions"] = result

    # ── Components (Activities, Services, etc.) ───────────────────────────────
    def _parse_components(self):
        aapt = which("aapt") or which("aapt2")
        if not aapt:
            self.data["Components"] = {}
            return
        out, _, _ = run(f'"{aapt}" dump xmltree "{self.path}" AndroidManifest.xml 2>/dev/null', timeout=30)

        def extract(tag):
            return sorted(set(re.findall(rf'A: android:name\(0x[0-9a-f]+\)="({tag}[^"]+)"', out)))

        # Fallback: try unzip + xmllint
        components = {}
        activities = extract(r'[A-Za-z]')  # broad match, filtered below
        # More targeted extraction
        def extract_components_from_aapt_badging():
            out2, _, _ = run(f'"{aapt}" dump badging "{self.path}" 2>/dev/null', timeout=30)
            acts = re.findall(r"launchable-activity: name='([^']+)'", out2)
            return acts

        launchable = extract_components_from_aapt_badging()

        # Extract from manifest XML tree
        acts     = re.findall(r"E: activity \(", out)
        services = re.findall(r"E: service \(", out)
        recvs    = re.findall(r"E: receiver \(", out)
        provs    = re.findall(r"E: provider \(", out)

        # Get names from xmltree
        all_names = re.findall(r'A: android:name\(0x[0-9a-f]+\)="([^"]+)"', out)

        components = {
            "Activity Count":  str(len(acts)),
            "Service Count":   str(len(services)),
            "Receiver Count":  str(len(recvs)),
            "Provider Count":  str(len(provs)),
            "Launchable Activity": launchable[0] if launchable else "—",
        }
        self.data["Components"] = components

        # Sub-section: all component names
        self.data["Component Names"] = {n: "" for n in all_names[:150]}

    # ── Signing Info (apksigner) ──────────────────────────────────────────────
    def _parse_signing(self):
        apksigner = which("apksigner")
        if not apksigner:
            # Try Android SDK location
            for loc in [
                os.path.expanduser("~/Android/Sdk/build-tools"),
                "/opt/android-sdk/build-tools",
            ]:
                if os.path.isdir(loc):
                    # find latest
                    versions = sorted(os.listdir(loc))
                    if versions:
                        candidate = os.path.join(loc, versions[-1], "apksigner")
                        if os.path.isfile(candidate):
                            apksigner = candidate
                            break

        if not apksigner:
            self.data["Signing Info"] = {"Warning": "apksigner not found. Install android-sdk-build-tools."}
            return

        out, err, rc = run(f'"{apksigner}" verify --verbose --print-certs "{self.path}" 2>&1', timeout=30)
        full = out + err

        info = {
            "Signature Schemes": ", ".join(re.findall(r"Verified using (v\d) scheme", full)) or "—",
            "Verified":          "✅ YES" if "Verified using" in full else "❌ NO",
            "Warning":           "⚠ WARNING" if "WARNING" in full else "None",
        }

        # Certificate details from apksigner
        for line in full.splitlines():
            for key in ["Subject", "Issuer", "Valid from", "Valid until", "SHA-256 digest"]:
                if key.lower() in line.lower():
                    val = line.split(":", 1)[-1].strip()
                    info[key] = val

        self.data["Signing Info"] = info

    # ── Certificate (keytool / openssl) ───────────────────────────────────────
    def _parse_certificate(self):
        # Extract META-INF/*.RSA or *.DSA or *.EC
        cert_info = {}
        try:
            with zipfile.ZipFile(self.path, "r") as z:
                cert_files = [n for n in z.namelist()
                              if re.match(r"META-INF/.*\.(RSA|DSA|EC|SF|MF)$", n, re.I)]
                cert_info["Cert Files in META-INF"] = ", ".join(cert_files) or "—"

                # Extract and inspect the cert
                for cf in cert_files:
                    if cf.upper().endswith((".RSA", ".DSA", ".EC")):
                        cert_bytes = z.read(cf)
                        # Write to tmp and run openssl
                        tmp = f"/tmp/apk_cert_{os.getpid()}.der"
                        with open(tmp, "wb") as f:
                            f.write(cert_bytes)
                        out, _, rc = run(f"openssl pkcs7 -inform DER -in '{tmp}' -print_certs -text 2>/dev/null | head -60")
                        if rc == 0 and out:
                            # Extract key fields
                            for line in out.splitlines():
                                stripped = line.strip()
                                if stripped.startswith("Subject:"):
                                    cert_info["Subject"] = stripped.replace("Subject:", "").strip()
                                elif stripped.startswith("Issuer:"):
                                    cert_info["Issuer"] = stripped.replace("Issuer:", "").strip()
                                elif "Not Before" in stripped:
                                    cert_info["Valid From"] = stripped.split(":", 1)[-1].strip()
                                elif "Not After" in stripped:
                                    cert_info["Valid Until"] = stripped.split(":", 1)[-1].strip()
                                elif "Public Key Algorithm" in stripped:
                                    cert_info["Key Algorithm"] = stripped.split(":", 1)[-1].strip()
                                elif "RSA Public-Key" in stripped or "Public-Key" in stripped:
                                    cert_info["Key Size"] = stripped
                                elif "SHA256 Fingerprint" in stripped or "SHA-256" in stripped:
                                    cert_info["SHA-256 Fingerprint"] = stripped.split("=", 1)[-1].strip()
                                elif "SHA1 Fingerprint" in stripped or "SHA-1" in stripped:
                                    cert_info["SHA-1 Fingerprint"] = stripped.split("=", 1)[-1].strip()
                        try:
                            os.unlink(tmp)
                        except Exception:
                            pass
                        break
        except Exception as e:
            cert_info["Error"] = str(e)

        self.data["Certificate"] = cert_info

    # ── APK Contents (file list) ──────────────────────────────────────────────
    def _parse_contents(self):
        try:
            with zipfile.ZipFile(self.path, "r") as z:
                names = z.namelist()
                total = len(names)
                dex_files    = [n for n in names if n.endswith(".dex")]
                so_files     = [n for n in names if n.endswith(".so")]
                asset_files  = [n for n in names if n.startswith("assets/")]
                res_files    = [n for n in names if n.startswith("res/")]

                contents = {
                    "Total Files":        str(total),
                    "DEX Files":          f"{len(dex_files)} — " + ", ".join(dex_files[:5]),
                    "Native .so Files":   f"{len(so_files)}",
                    "Assets":             str(len(asset_files)),
                    "Resources":          str(len(res_files)),
                    "Has classes.dex":    "✅ Yes" if "classes.dex" in names else "❌ No",
                    "Has classes2.dex":   "✅ Yes (MultiDex)" if "classes2.dex" in names else "No",
                    "Has classes3.dex":   "✅ Yes" if "classes3.dex" in names else "No",
                    "Has resources.arsc": "✅ Yes" if "resources.arsc" in names else "❌ No",
                    "Has AndroidManifest.xml": "✅ Yes" if "AndroidManifest.xml" in names else "❌ No",
                }
                self.data["APK Contents"] = contents
                self.data["Native Libraries (.so)"] = {n: "" for n in so_files}
        except Exception as e:
            self.data["APK Contents"] = {"Error": str(e)}

    # ── Native Libraries ──────────────────────────────────────────────────────
    def _parse_native_libs(self):
        try:
            with zipfile.ZipFile(self.path, "r") as z:
                so_files = sorted([n for n in z.namelist() if n.endswith(".so")])
                info = {}
                for s in so_files:
                    zi = z.getinfo(s)
                    info[os.path.basename(s)] = f"  arch: {s.split('/')[1] if '/' in s else '?'}  |  size: {zi.file_size:,} bytes"
                self.data["Native Libraries"] = info if info else {"(none)": ""}
        except Exception as e:
            self.data["Native Libraries"] = {"Error": str(e)}

    # ── Strings extraction (quick) ─────────────────────────────────────────────
    def _parse_strings(self):
        interesting = []
        patterns = {
            "URLs / IPs":   re.compile(r'https?://[^\s\'"<>]{5,100}|(?:\d{1,3}\.){3}\d{1,3}(?::\d+)?'),
            "Emails":       re.compile(r'[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}'),
            "Crypto Addr":  re.compile(r'\b(1[A-HJ-NP-Za-km-z1-9]{25,34}|0x[a-fA-F0-9]{40})\b'),
            "SDK Keys":     re.compile(r'(?i)(api[_-]?key|apikey|secret|token|password|passwd)\s*[=:]\s*["\']?([A-Za-z0-9_\-/+]{8,50})'),
        }

        try:
            with zipfile.ZipFile(self.path, "r") as z:
                # Read classes.dex and strings.xml
                for fname in ["classes.dex", "res/values/strings.xml"]:
                    if fname in z.namelist():
                        raw = z.read(fname)
                        text = raw.decode("utf-8", errors="replace")
                        for label, pat in patterns.items():
                            matches = list(set(pat.findall(text)))[:20]
                            if matches:
                                key = f"[{label}] in {fname}"
                                self.data.setdefault("Interesting Strings", {})[key] = \
                                    "\n".join(str(m) for m in matches)
        except Exception as e:
            self.data.setdefault("Interesting Strings", {})["Error"] = str(e)

        if "Interesting Strings" not in self.data:
            self.data["Interesting Strings"] = {"(none found)": ""}


# ──────────────────────────────────────────────────────────────────────────────
# GTK3 GUI
# ──────────────────────────────────────────────────────────────────────────────
class APKInspectorWindow(Gtk.Window):
    ACCENT   = "#1E88E5"   # blue
    DANGER   = "#E53935"   # red
    WARN     = "#F57C00"   # orange
    SUCCESS  = "#43A047"   # green
    BG_DARK  = "#1A1A2E"
    BG_MID   = "#16213E"
    BG_CARD  = "#0F3460"
    FG_MAIN  = "#E0E0E0"
    FG_DIM   = "#9E9E9E"

    def __init__(self, apk_path):
        super().__init__(title=f"APK Inspector — {os.path.basename(apk_path)}")
        self.apk_path = apk_path
        self.parsed_data = {}

        self.set_default_size(1000, 720)
        self.set_border_width(0)
        self._apply_css()

        # ── Layout ──────────────────────────────────────────────────────────
        vbox = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=0)
        self.add(vbox)

        # Header bar
        header = self._make_header()
        vbox.pack_start(header, False, False, 0)

        # Progress bar (shown during loading)
        self.progress_bar = Gtk.ProgressBar()
        self.progress_bar.set_text("Parsing APK…")
        self.progress_bar.set_show_text(True)
        self.progress_bar.get_style_context().add_class("progress-bar")
        vbox.pack_start(self.progress_bar, False, False, 0)

        # Notebook (tabs)
        self.notebook = Gtk.Notebook()
        self.notebook.set_tab_pos(Gtk.PositionType.LEFT)
        self.notebook.get_style_context().add_class("notebook")
        vbox.pack_start(self.notebook, True, True, 0)

        # Bottom toolbar
        toolbar = self._make_toolbar()
        vbox.pack_start(toolbar, False, False, 0)

        self.show_all()
        self.progress_bar.hide()

        # Start parsing in background
        self._start_parsing()

    def _apply_css(self):
        css = f"""
        window {{
            background-color: {self.BG_DARK};
        }}
        .header-bar {{
            background-color: #0D1B2A;
            padding: 10px 16px;
            border-bottom: 2px solid {self.ACCENT};
        }}
        .header-title {{
            font-size: 16px;
            font-weight: bold;
            color: {self.ACCENT};
        }}
        .header-sub {{
            font-size: 11px;
            color: {self.FG_DIM};
        }}
        notebook tab {{
            padding: 8px 14px;
            min-width: 160px;
            color: {self.FG_DIM};
            background-color: {self.BG_MID};
            border-radius: 4px 0 0 4px;
            margin: 2px 0;
        }}
        notebook tab:checked {{
            color: #FFFFFF;
            background-color: {self.BG_CARD};
            border-left: 3px solid {self.ACCENT};
        }}
        notebook > header {{
            background-color: {self.BG_MID};
            border-right: 1px solid #333;
        }}
        .card {{
            background-color: {self.BG_CARD};
            border-radius: 6px;
            padding: 4px;
            margin: 6px;
        }}
        treeview {{
            background-color: {self.BG_MID};
            color: {self.FG_MAIN};
            font-family: monospace;
            font-size: 12px;
        }}
        treeview:selected {{
            background-color: {self.ACCENT};
            color: white;
        }}
        treeview header button {{
            background-color: {self.BG_CARD};
            color: {self.ACCENT};
            font-weight: bold;
            border: none;
            padding: 4px;
        }}
        .toolbar-bottom {{
            background-color: #0D1B2A;
            padding: 8px 12px;
            border-top: 1px solid #333;
        }}
        .btn-primary {{
            background-color: {self.ACCENT};
            color: white;
            border-radius: 4px;
            padding: 4px 14px;
            border: none;
            font-weight: bold;
        }}
        .btn-primary:hover {{
            background-color: #1565C0;
        }}
        .btn-secondary {{
            background-color: #37474F;
            color: white;
            border-radius: 4px;
            padding: 4px 14px;
            border: none;
        }}
        .btn-danger {{
            background-color: {self.DANGER};
            color: white;
            border-radius: 4px;
            padding: 4px 14px;
            border: none;
            font-weight: bold;
        }}
        .status-ok   {{ color: {self.SUCCESS}; font-weight: bold; }}
        .status-warn {{ color: {self.WARN};    font-weight: bold; }}
        .status-bad  {{ color: {self.DANGER};  font-weight: bold; }}
        scrolledwindow {{ background-color: {self.BG_MID}; }}
        label {{ color: {self.FG_MAIN}; }}
        progressbar trough {{ background-color: #333; }}
        progressbar progress {{ background-color: {self.ACCENT}; }}
        """
        provider = Gtk.CssProvider()
        provider.load_from_data(css.encode())
        Gtk.StyleContext.add_provider_for_screen(
            Gdk.Screen.get_default(), provider,
            Gtk.STYLE_PROVIDER_PRIORITY_APPLICATION
        )

    def _make_header(self):
        box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=10)
        box.get_style_context().add_class("header-bar")

        # Icon placeholder
        icon_label = Gtk.Label(label="📦")
        icon_label.set_markup('<span size="xx-large">📦</span>')
        box.pack_start(icon_label, False, False, 0)

        info_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=2)
        title = Gtk.Label(label=f"APK Inspector")
        title.get_style_context().add_class("header-title")
        title.set_halign(Gtk.Align.START)

        sub = Gtk.Label(label=os.path.basename(self.apk_path))
        sub.get_style_context().add_class("header-sub")
        sub.set_halign(Gtk.Align.START)

        info_box.pack_start(title, False, False, 0)
        info_box.pack_start(sub, False, False, 0)
        box.pack_start(info_box, True, True, 0)

        return box

    def _make_toolbar(self):
        box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        box.get_style_context().add_class("toolbar-bottom")
        box.set_border_width(4)

        btn_jadx = Gtk.Button(label="⚙  Open in JADX-GUI")
        btn_jadx.get_style_context().add_class("btn-primary")
        btn_jadx.connect("clicked", self._on_open_jadx)

        btn_export = Gtk.Button(label="💾  Export to Text")
        btn_export.get_style_context().add_class("btn-secondary")
        btn_export.connect("clicked", self._on_export)

        btn_copy_hash = Gtk.Button(label="📋  Copy SHA-256")
        btn_copy_hash.get_style_context().add_class("btn-secondary")
        btn_copy_hash.connect("clicked", self._on_copy_hash)

        self.status_label = Gtk.Label(label="Parsing…")
        self.status_label.get_style_context().add_class("status-warn")

        box.pack_start(btn_jadx, False, False, 0)
        box.pack_start(btn_export, False, False, 0)
        box.pack_start(btn_copy_hash, False, False, 0)
        box.pack_end(self.status_label, False, False, 0)

        return box

    # ── Parsing ───────────────────────────────────────────────────────────────
    def _start_parsing(self):
        self.progress_bar.show()
        self.progress_bar.set_fraction(0)

        def worker():
            parser = APKParser(self.apk_path)
            parser.parse_all(progress_cb=self._update_progress)
            self.parsed_data = parser.data
            GLib.idle_add(self._build_tabs)

        t = threading.Thread(target=worker, daemon=True)
        t.start()

    def _update_progress(self, label, fraction):
        self.progress_bar.set_fraction(fraction)
        self.progress_bar.set_text(f"Parsing: {label}")
        return False

    # ── Tab Building ──────────────────────────────────────────────────────────
    def _build_tabs(self):
        self.progress_bar.hide()
        GLib.idle_add(self.status_label.set_text, "✅ Parsed")
        self.status_label.get_style_context().remove_class("status-warn")
        self.status_label.get_style_context().add_class("status-ok")

        TAB_ICONS = {
            "File Info":            "🗂  File Info",
            "Basic Metadata":       "📋 Metadata",
            "Permissions":          "🔐 Permissions",
            "Components":           "🧩 Components",
            "Component Names":      "   ↳ Names",
            "APK Contents":         "📁 Contents",
            "Signing Info":         "✍  Signing",
            "Certificate":          "🏅 Certificate",
            "Native Libraries":     "⚙  Native Libs",
            "Interesting Strings":  "🔍 Strings",
        }

        for section_key, tab_label in TAB_ICONS.items():
            if section_key not in self.parsed_data:
                continue
            data = self.parsed_data[section_key]
            page = self._make_data_page(data, section_key)
            label_widget = Gtk.Label(label=tab_label)
            label_widget.set_halign(Gtk.Align.START)
            self.notebook.append_page(page, label_widget)

        self.notebook.show_all()
        return False

    def _make_data_page(self, data, section):
        sw = Gtk.ScrolledWindow()
        sw.set_policy(Gtk.PolicyType.AUTOMATIC, Gtk.PolicyType.AUTOMATIC)

        if not data:
            lbl = Gtk.Label(label="No data found.")
            lbl.set_margin_top(20)
            sw.add(lbl)
            return sw

        # TreeView with 2 columns: Key | Value
        store = Gtk.ListStore(str, str, str)  # key, value, row_color

        DANGEROUS_COLOR = "#FF5252"
        WARNING_COLOR   = "#FFA726"
        NORMAL_COLOR    = self.FG_MAIN

        for k, v in data.items():
            color = NORMAL_COLOR
            display_v = str(v)
            if "🚨" in display_v or "DANGEROUS" in display_v:
                color = DANGEROUS_COLOR
            elif "⚠" in display_v or "WARNING" in display_v or "YES ⚠" in display_v:
                color = WARNING_COLOR
            elif "Error" in k or "Error" in display_v:
                color = DANGEROUS_COLOR
            store.append([str(k), display_v, color])

        tv = Gtk.TreeView(model=store)
        tv.set_grid_lines(Gtk.TreeViewGridLines.HORIZONTAL)
        tv.set_rules_hint(True)
        tv.get_style_context().add_class("data-view")

        # Column: Key
        col_key = Gtk.TreeViewColumn("Property")
        col_key.set_min_width(220)
        col_key.set_resizable(True)
        cell_key = Gtk.CellRendererText()
        cell_key.set_property("foreground", self.ACCENT)
        cell_key.set_property("weight", Pango.Weight.BOLD)
        cell_key.set_property("xpad", 10)
        cell_key.set_property("ypad", 6)
        col_key.pack_start(cell_key, True)
        col_key.add_attribute(cell_key, "text", 0)

        # Column: Value
        col_val = Gtk.TreeViewColumn("Value")
        col_val.set_expand(True)
        col_val.set_resizable(True)
        cell_val = Gtk.CellRendererText()
        cell_val.set_property("xpad", 10)
        cell_val.set_property("ypad", 6)
        cell_val.set_property("ellipsize", Pango.EllipsizeMode.END)
        col_val.pack_start(cell_val, True)
        col_val.add_attribute(cell_val, "text", 1)
        col_val.add_attribute(cell_val, "foreground", 2)

        tv.append_column(col_key)
        tv.append_column(col_val)

        # Click to copy value
        tv.connect("row-activated", self._on_row_activated, store)

        sw.add(tv)
        return sw

    def _on_row_activated(self, tv, path, col, store):
        it = store.get_iter(path)
        val = store.get_value(it, 1)
        clipboard = Gtk.Clipboard.get(Gdk.SELECTION_CLIPBOARD)
        clipboard.set_text(val, -1)
        self.status_label.set_text(f"📋 Copied!")
        GLib.timeout_add(2000, lambda: self.status_label.set_text("✅ Parsed"))

    # ── Actions ───────────────────────────────────────────────────────────────
    def _on_open_jadx(self, btn):
        jadx_gui = which("jadx-gui") or "/opt/jadx/bin/jadx-gui"
        if not os.path.isfile(jadx_gui or ""):
            # Search common paths
            for p in ["/usr/local/bin/jadx-gui", os.path.expanduser("~/jadx/bin/jadx-gui"),
                      "/opt/jadx/bin/jadx-gui"]:
                if os.path.isfile(p):
                    jadx_gui = p
                    break

        if not jadx_gui or not os.path.isfile(jadx_gui):
            dialog = Gtk.MessageDialog(
                transient_for=self, flags=0,
                message_type=Gtk.MessageType.WARNING,
                buttons=Gtk.ButtonsType.OK,
                text="JADX-GUI not found"
            )
            dialog.format_secondary_text(
                "Install JADX from https://github.com/skylot/jadx/releases\n"
                "and place jadx-gui in your PATH."
            )
            dialog.run()
            dialog.destroy()
            return

        subprocess.Popen([jadx_gui, self.apk_path])

    def _on_export(self, btn):
        dialog = Gtk.FileChooserDialog(
            title="Export APK Details",
            parent=self,
            action=Gtk.FileChooserAction.SAVE
        )
        dialog.add_buttons(
            Gtk.STOCK_CANCEL, Gtk.ResponseType.CANCEL,
            Gtk.STOCK_SAVE,   Gtk.ResponseType.OK
        )
        apk_name = os.path.splitext(os.path.basename(self.apk_path))[0]
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        dialog.set_current_name(f"{apk_name}_apk_report_{timestamp}.txt")

        if dialog.run() == Gtk.ResponseType.OK:
            out_path = dialog.get_filename()
            self._write_report(out_path)
            self.status_label.set_text(f"✅ Exported!")
            GLib.timeout_add(3000, lambda: self.status_label.set_text("✅ Parsed"))

        dialog.destroy()

    def _write_report(self, out_path):
        lines = [
            "=" * 72,
            f"  APK INSPECTOR REPORT",
            f"  Generated: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            f"  File: {self.apk_path}",
            "=" * 72,
            "",
        ]
        for section, data in self.parsed_data.items():
            lines.append(f"\n{'─' * 60}")
            lines.append(f"  {section.upper()}")
            lines.append(f"{'─' * 60}")
            for k, v in data.items():
                lines.append(f"  {k:<35} {v}")
        lines.append("\n" + "=" * 72)
        with open(out_path, "w", encoding="utf-8") as f:
            f.write("\n".join(lines))

    def _on_copy_hash(self, btn):
        sha = self.parsed_data.get("File Info", {}).get("SHA-256", "")
        if sha:
            clipboard = Gtk.Clipboard.get(Gdk.SELECTION_CLIPBOARD)
            clipboard.set_text(sha, -1)
            self.status_label.set_text("📋 SHA-256 Copied!")
            GLib.timeout_add(2000, lambda: self.status_label.set_text("✅ Parsed"))


# ──────────────────────────────────────────────────────────────────────────────
# Entry point
# ──────────────────────────────────────────────────────────────────────────────
def main():
    # ── Safety guards ──────────────────────────────────────────────────────────
    # Must be called with exactly one APK path argument.
    # Nautilus may call scripts with no args on single-click preview — exit silently.
    if len(sys.argv) < 2:
        sys.exit(0)  # Silent exit — not called by right-click, do nothing

    apk_path = sys.argv[1]

    # Validate it's actually an APK file (not a folder, not a non-apk)
    if not os.path.isfile(apk_path):
        sys.exit(0)

    if not apk_path.lower().endswith(".apk"):
        sys.exit(0)

    # ── Detach from parent process ─────────────────────────────────────────────
    # This prevents Nautilus from waiting on us, which causes it to freeze/crash.
    # Double-fork: child becomes its own session leader, parent exits immediately.
    try:
        pid = os.fork()
        if pid > 0:
            # Parent exits immediately — Nautilus is freed
            os._exit(0)
    except AttributeError:
        pass  # os.fork not available (Windows) — skip

    # Redirect stdin/stdout/stderr so we don't hold Nautilus's file descriptors
    try:
        sys.stdin.close()
        devnull = open(os.devnull, "w")
        sys.stdout = devnull
        sys.stderr = devnull
    except Exception:
        pass

    # ── Launch GUI ─────────────────────────────────────────────────────────────
    try:
        win = APKInspectorWindow(apk_path)
        win.connect("destroy", Gtk.main_quit)
        Gtk.main()
    except Exception as e:
        # Last-resort: show a simple error dialog if GTK crashes at startup
        try:
            import subprocess
            subprocess.run(
                ["zenity", "--error", "--title=APK Inspector",
                 f"--text=Failed to start:\n{e}"],
                timeout=10
            )
        except Exception:
            pass
        sys.exit(1)


if __name__ == "__main__":
    main()
