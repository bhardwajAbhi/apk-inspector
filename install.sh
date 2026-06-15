#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════════════════════
#  APK Inspector — Installer Script
#  Ubuntu 20.04 / 22.04 / 24.04
# ═══════════════════════════════════════════════════════════════════════════════

set -e

RED='\033[0;31m'; YLW='\033[1;33m'; GRN='\033[0;32m'; BLU='\033[1;34m'; NC='\033[0m'
info()    { echo -e "${BLU}[INFO]${NC}  $*"; }
success() { echo -e "${GRN}[OK]${NC}    $*"; }
warn()    { echo -e "${YLW}[WARN]${NC}  $*"; }

INSTALL_DIR="$HOME/.local/share/apk-inspector"
NAUTILUS_SCRIPTS_DIR="$HOME/.local/share/nautilus/scripts"
NAUTILUS_SCRIPT="$NAUTILUS_SCRIPTS_DIR/Get APK Details"
ACTIONS_DIR="$HOME/.local/share/file-manager/actions"
NAUTILUS_EXT="$HOME/.local/share/nautilus-python/extensions/apk_inspector_nautilus.py"

echo ""
echo -e "${BLU}╔════════════════════════════════════════════╗${NC}"
echo -e "${BLU}║       APK Inspector — Installer v4         ║${NC}"
echo -e "${BLU}║   Malware Analysis Context Menu Tool       ║${NC}"
echo -e "${BLU}╚════════════════════════════════════════════╝${NC}"
echo ""

# ─── Step 1: Create directories ───────────────────────────────────────────────
info "Creating install directories…"
mkdir -p "$INSTALL_DIR" "$NAUTILUS_SCRIPTS_DIR"
success "Directories ready."

# ─── Step 2: Remove other integrations (keep Scripts submenu only) ─────────────
info "Removing file-manager actions and Nautilus extension (if present)…"
rm -f "$ACTIONS_DIR/apk-inspector.desktop"
rm -f "$HOME/.local/share/applications/apk-inspector.desktop"
rm -f "$NAUTILUS_EXT"
success "Legacy integrations removed."

# ─── Step 3: Copy core script ─────────────────────────────────────────────────
info "Installing core Python script to $INSTALL_DIR…"
SCRIPT_SRC="$(dirname "$0")/scripts/apk_inspector.py"
cp "$SCRIPT_SRC" "$INSTALL_DIR/apk_inspector.py"
chmod +x "$INSTALL_DIR/apk_inspector.py"
success "Core script installed."

# ─── Step 4: Install Nautilus Script (Scripts submenu) ────────────────────────
info "Installing Nautilus script (Scripts → Get APK Details)…"

cat > "$NAUTILUS_SCRIPT" << 'NSCRIPT'
#!/usr/bin/env bash
# APK Inspector — Nautilus Script
# Invoked via right-click → Scripts → Get APK Details

INSPECTOR="$HOME/.local/share/apk-inspector/apk_inspector.py"

if [[ -z "$NAUTILUS_SCRIPT_SELECTED_FILE_PATHS" ]]; then
    exit 0
fi

while IFS= read -r filepath; do
    [[ -z "$filepath" ]] && continue
    case "${filepath,,}" in
        *.apk) ;;
        *) continue ;;
    esac
    python3 "$INSPECTOR" "$filepath" &
    disown
done <<< "$NAUTILUS_SCRIPT_SELECTED_FILE_PATHS"
NSCRIPT

chmod +x "$NAUTILUS_SCRIPT"
success "Nautilus script installed."

# ─── Step 5: Register APK MIME type ───────────────────────────────────────────
info "Registering APK MIME type…"
mkdir -p "$HOME/.local/share/mime/packages"
cat > "$HOME/.local/share/mime/packages/android-apk.xml" << 'MIME'
<?xml version="1.0" encoding="UTF-8"?>
<mime-info xmlns="http://www.freedesktop.org/standards/shared-mime-info">
  <mime-type type="application/vnd.android.package-archive">
    <comment>Android Application Package</comment>
    <glob pattern="*.apk"/>
  </mime-type>
</mime-info>
MIME
update-mime-database "$HOME/.local/share/mime" 2>/dev/null || true
success "MIME type registered."

# ─── Step 6: Check dependencies ───────────────────────────────────────────────
echo ""
info "Checking dependencies…"
check_tool() {
    local name="$1" hint="$2"
    if command -v "$name" &>/dev/null; then
        success "$name — found"
    else
        warn "$name — NOT FOUND.  $hint"
    fi
}
check_tool python3   "sudo apt install python3"
check_tool aapt      "sudo apt install aapt"
check_tool apksigner "sudo apt install apksigner"
check_tool openssl   "sudo apt install openssl"
check_tool unzip     "sudo apt install unzip"
check_tool jadx-gui  "https://github.com/skylot/jadx/releases"
python3 -c "import gi; gi.require_version('Gtk','3.0'); from gi.repository import Gtk" 2>/dev/null \
    && success "python3-gi GTK3 — found" \
    || warn "python3-gi — NOT FOUND. Install: sudo apt install python3-gi gir1.2-gtk-3.0"

# ─── Step 7: Auto-install missing apt packages ────────────────────────────────
echo ""
read -rp "$(echo -e "${YLW}Install/verify apt packages? [y/N]:${NC} ")" choice
if [[ "$choice" =~ ^[Yy]$ ]]; then
    sudo apt install -y aapt apksigner python3-gi gir1.2-gtk-3.0 openssl unzip 2>/dev/null \
        || warn "Some packages failed — install manually if needed."
    success "Packages verified."
fi

# ─── Step 8: Reload Nautilus ──────────────────────────────────────────────────
echo ""
info "Reloading Nautilus…"
nautilus -q 2>/dev/null || pkill -x nautilus 2>/dev/null || true
sleep 1
success "Nautilus reloaded."

echo ""
echo -e "${GRN}╔══════════════════════════════════════════════════╗${NC}"
echo -e "${GRN}║           APK Inspector installed                ║${NC}"
echo -e "${GRN}╚══════════════════════════════════════════════════╝${NC}"
echo ""
echo -e "  ${YLW}How to use:${NC}"
echo -e "  1. Open Files (Nautilus)"
echo -e "  2. ${YLW}Right-click${NC} any .apk file"
echo -e "  3. Click ${BLU}Scripts → Get APK Details${NC}"
echo ""
echo -e "  ${YLW}Manual test:${NC}"
echo -e "  ${BLU}python3 ~/.local/share/apk-inspector/apk_inspector.py /path/to/file.apk${NC}"
echo ""
