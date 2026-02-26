#!/bin/bash
#===============================================================================
# BUILD CACHYOS + OMARCHY HYBRID INSTALLER ISO
#
# Creates an installer that:
# - Boots CachyOS live environment
# - Installs CachyOS base via pacstrap (online from mirror)
# - Installs Omarchy from embedded files (from local ISO)
#
# REQUIRES: Network connection for CachyOS packages during installation
#
# Usage: sudo ./build-online-iso.sh
#
# This script will automatically:
# - Install required build tools (xorriso, squashfs-tools)
# - Download CachyOS ISO from mirror if not present
# - Extract Omarchy from local omarchy*.iso (auto-detected)
#===============================================================================

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

log() { echo -e "${GREEN}[✓]${NC} $1"; }
warn() { echo -e "${YELLOW}[!]${NC} $1"; }
error() { echo -e "${RED}[✗]${NC} $1"; exit 1; }
info() { echo -e "${CYAN}[i]${NC} $1"; }

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
WORK_DIR="$SCRIPT_DIR/.online-build-$$"
OUTPUT_ISO="$SCRIPT_DIR/omacat-online-$(date +%Y.%m.%d).iso"

[[ $EUID -ne 0 ]] && error "Run as root: sudo $0"

#===============================================================================
# AUTO-SETUP: Install build dependencies
#===============================================================================

log "Checking build dependencies..."

# Install missing dependencies via pacman
missing=()
command -v xorriso &>/dev/null || missing+=(xorriso)
command -v unsquashfs &>/dev/null || missing+=(squashfs-tools)
command -v curl &>/dev/null || missing+=(curl)
command -v git &>/dev/null || missing+=(git)

if [[ ${#missing[@]} -gt 0 ]]; then
    log "Installing missing dependencies: ${missing[*]}"
    pacman -Sy --noconfirm --needed "${missing[@]}"
fi
log "Build dependencies OK"

#===============================================================================
# AUTO-SETUP: Extract Omarchy from local ISO
#===============================================================================

# Auto-detect Omarchy ISO in script directory
OMARCHY_ISO=$(find "$SCRIPT_DIR" -maxdepth 1 -name "omarchy*.iso" 2>/dev/null | head -1)

if [[ -z "$OMARCHY_ISO" ]]; then
    error "No Omarchy ISO found in $SCRIPT_DIR (looking for omarchy*.iso)"
fi

log "Found Omarchy ISO: $(basename "$OMARCHY_ISO")"

# Temp directories in script folder - will be cleaned up at end
OMARCHY_DIR="$SCRIPT_DIR/.omarchy-$$"
OMARCHY_MOUNT="$SCRIPT_DIR/.omarchy-mount-$$"

# Early cleanup trap for Omarchy extraction phase
cleanup_omarchy() {
    umount "$OMARCHY_MOUNT" 2>/dev/null || true
    rm -rf "$SCRIPT_DIR"/.omarchy-* 2>/dev/null || true
}
trap cleanup_omarchy EXIT

log "Extracting Omarchy from local ISO: $OMARCHY_ISO"

mkdir -p "$OMARCHY_MOUNT"
mount -o loop,ro "$OMARCHY_ISO" "$OMARCHY_MOUNT"

# Extract from squashfs in the ISO
if [[ -f "$OMARCHY_MOUNT/arch/x86_64/airootfs.sfs" ]]; then
    log "Extracting Omarchy squashfs..."
    OMARCHY_EXTRACT="$SCRIPT_DIR/.omarchy-extract-$$"
    unsquashfs -d "$OMARCHY_EXTRACT" "$OMARCHY_MOUNT/arch/x86_64/airootfs.sfs" > /dev/null

    # Find omarchy in extracted filesystem
    # Omarchy ISO stores files at /root/omarchy
    if [[ -d "$OMARCHY_EXTRACT/root/omarchy" ]]; then
        cp -r "$OMARCHY_EXTRACT/root/omarchy" "$OMARCHY_DIR"
    elif [[ -d "$OMARCHY_EXTRACT/root/.local/share/omarchy" ]]; then
        cp -r "$OMARCHY_EXTRACT/root/.local/share/omarchy" "$OMARCHY_DIR"
    elif [[ -d "$OMARCHY_EXTRACT/usr/share/omarchy" ]]; then
        cp -r "$OMARCHY_EXTRACT/usr/share/omarchy" "$OMARCHY_DIR"
    else
        OMARCHY_FOUND=$(find "$OMARCHY_EXTRACT" -type d -name "omarchy" 2>/dev/null | head -1)
        if [[ -n "$OMARCHY_FOUND" ]]; then
            cp -r "$OMARCHY_FOUND" "$OMARCHY_DIR"
        else
            umount "$OMARCHY_MOUNT" 2>/dev/null || true
            rm -rf "$OMARCHY_MOUNT" "$OMARCHY_EXTRACT"
            error "Could not find Omarchy files in ISO squashfs"
        fi
    fi
    log "Omarchy scripts extracted to $OMARCHY_DIR"

    # NOTE: We intentionally DO NOT extract packages from the Omarchy ISO.
    # The offline cached packages have older versions that conflict with
    # fresh CachyOS packages. All packages will be downloaded from online
    # mirrors to ensure version consistency.
    log "Skipping package extraction (all packages will be downloaded fresh)"

    rm -rf "$OMARCHY_EXTRACT"
else
    umount "$OMARCHY_MOUNT" 2>/dev/null || true
    rm -rf "$OMARCHY_MOUNT"
    error "No squashfs found in Omarchy ISO"
fi

umount "$OMARCHY_MOUNT"
rm -rf "$OMARCHY_MOUNT"
log "Omarchy extraction complete"

#===============================================================================
# AUTO-SETUP: Download CachyOS ISO if not present
#===============================================================================

CACHY_ISO=$(find "$SCRIPT_DIR" -maxdepth 1 -name "cachyos*.iso" 2>/dev/null | head -1)

if [[ -z "$CACHY_ISO" ]]; then
    log "CachyOS ISO not found. Downloading latest version..."

    # Get latest version from mirror directory
    CACHY_MIRROR="https://mirror.cachyos.org/ISO/desktop/"

    # Find latest version directory
    LATEST_VERSION=$(curl -sL "$CACHY_MIRROR" | grep -oP 'href="\K[0-9]+(?=/")' | sort -rn | head -1)

    if [[ -z "$LATEST_VERSION" ]]; then
        error "Could not determine latest CachyOS version. Please download manually from https://cachyos.org/download/"
    fi

    ISO_NAME="cachyos-desktop-linux-${LATEST_VERSION}.iso"
    ISO_URL="${CACHY_MIRROR}${LATEST_VERSION}/${ISO_NAME}"

    log "Downloading: $ISO_NAME"
    info "URL: $ISO_URL"
    info "This may take a while (ISO is ~2-3GB)..."

    if ! curl -L -o "$SCRIPT_DIR/$ISO_NAME" --progress-bar "$ISO_URL"; then
        error "Failed to download CachyOS ISO"
    fi

    CACHY_ISO="$SCRIPT_DIR/$ISO_NAME"
    log "Download complete: $ISO_NAME"
fi

log "CachyOS ISO: $(basename "$CACHY_ISO")"

#===============================================================================
# VERIFY REQUIREMENTS
#===============================================================================

# Final verification
for cmd in xorriso unsquashfs mksquashfs curl git; do
    command -v $cmd &>/dev/null || error "Missing required command: $cmd"
done

[[ ! -f "$CACHY_ISO" ]] && error "CachyOS ISO not found: $CACHY_ISO"
[[ ! -d "$OMARCHY_DIR" ]] && error "Omarchy directory not found: $OMARCHY_DIR"
[[ ! -d "$OMARCHY_DIR/default/plymouth" ]] && error "Omarchy Plymouth theme not found"

log "All requirements verified"

# Cleanup on exit
cleanup() {
    log "Cleaning up..."
    umount "$WORK_DIR/efi_mount" 2>/dev/null || true
    umount "$WORK_DIR/cachy_mount" 2>/dev/null || true
    rm -rf "$WORK_DIR"
    # Clean up Omarchy extraction temp files
    rm -rf "$SCRIPT_DIR"/.omarchy-* 2>/dev/null || true
}
trap cleanup EXIT

mkdir -p "$WORK_DIR"/{cachy_mount,cachy_extract,newiso}

#===============================================================================
# EXTRACT CACHYOS ISO
#===============================================================================

log "Mounting CachyOS ISO..."
mount -o loop,ro "$CACHY_ISO" "$WORK_DIR/cachy_mount"

# Detect the original ISO label - we must use the same label for boot to work
# Try grubenv first (CachyOS style), then blkid
ORIG_ISO_LABEL=""
if [[ -f "$WORK_DIR/cachy_mount/boot/grub/grubenv" ]]; then
    ORIG_ISO_LABEL=$(grep -o 'ARCHISO_LABEL=[^ ]*' "$WORK_DIR/cachy_mount/boot/grub/grubenv" 2>/dev/null | cut -d= -f2 || true)
fi
if [[ -z "$ORIG_ISO_LABEL" ]]; then
    # Fallback to blkid
    ORIG_ISO_LABEL=$(blkid -s LABEL -o value "$CACHY_ISO" 2>/dev/null || true)
fi
if [[ -z "$ORIG_ISO_LABEL" ]]; then
    error "Could not detect ISO label from source CachyOS ISO"
fi
log "Detected original ISO label: $ORIG_ISO_LABEL"

log "Copying CachyOS ISO structure..."
cp -a "$WORK_DIR/cachy_mount/." "$WORK_DIR/newiso/"

# Update all boot config files to use the detected label
# The configs may have a different (timestamp) label hardcoded
# Convert all boot configs from UUID-based to label-based boot
# archisosearchuuid is semantically wrong when we rebuild the ISO (new UUID generated)
# Using archisolabel is reliable since we preserve the original volume label
log "Updating boot configs to use label: $ORIG_ISO_LABEL"

# Escape special characters in ISO label for sed replacement (/ & \ are problematic)
# Use | as sed delimiter to avoid issues with / in labels
ESCAPED_ISO_LABEL=$(printf '%s\n' "$ORIG_ISO_LABEL" | sed 's/[&/\]/\\&/g')
# Also create a safe filename version (replace any problematic chars with _)
SAFE_ISO_LABEL=$(printf '%s\n' "$ORIG_ISO_LABEL" | tr '/<>:"\|?*' '_')

find "$WORK_DIR/newiso" -type f \( -name "*.cfg" -o -name "*.conf" -o -name "grub.cfg" -o -name "loopback.cfg" \) 2>/dev/null | while read -r cfg; do
    # Replace any timestamp-style labels (YYYY-MM-DD-HH-MM-SS-XX format)
    sed -i "s|archisolabel=[0-9]\{4\}-[0-9]\{2\}-[0-9]\{2\}-[0-9]\{2\}-[0-9]\{2\}-[0-9]\{2\}-[0-9]\{2\}|archisolabel=$ESCAPED_ISO_LABEL|g" "$cfg"
    # Also replace in LABEL= format
    sed -i "s|LABEL=[0-9]\{4\}-[0-9]\{2\}-[0-9]\{2\}-[0-9]\{2\}-[0-9]\{2\}-[0-9]\{2\}-[0-9]\{2\}|LABEL=$ESCAPED_ISO_LABEL|g" "$cfg"
    # CRITICAL: Convert archisosearchuuid to archisolabel (UUID changes on rebuild, label doesn't)
    # This replaces the parameter name AND value to use label-based lookup
    sed -i "s|archisosearchuuid=[^ ]*|archisolabel=$ESCAPED_ISO_LABEL|g" "$cfg"
done

# Create .label marker file for label-based boot (replacing .uuid approach)
# The initramfs looks for these marker files to identify the correct ISO
log "Creating label marker files..."
for search_dir in "$WORK_DIR/newiso" "$WORK_DIR/newiso/boot" "$WORK_DIR/newiso/arch/x86_64"; do
    if [[ -d "$search_dir" ]]; then
        # Remove any existing .uuid files (no longer used)
        rm -f "$search_dir"/*.uuid 2>/dev/null || true
        # Create .label marker file (use safe filename version)
        touch "$search_dir/${SAFE_ISO_LABEL}.label" 2>/dev/null || true
    fi
done
log "Label marker files created for: $ORIG_ISO_LABEL"

log "Extracting CachyOS squashfs (this takes a few minutes)..."
unsquashfs -d "$WORK_DIR/cachy_extract" "$WORK_DIR/cachy_mount/arch/x86_64/airootfs.sfs"

#===============================================================================
# COPY OMARCHY INTO ISO (full copy for offline install)
#===============================================================================

log "Copying full Omarchy into ISO for offline installation..."
mkdir -p "$WORK_DIR/cachy_extract/root/omarchy-assets"
cp -r "$OMARCHY_DIR" "$WORK_DIR/cachy_extract/root/omarchy-assets/omarchy"
# Ensure all scripts have execute permissions (can be lost during extraction/copy)
chmod +x "$WORK_DIR/cachy_extract/root/omarchy-assets/omarchy/bin/"* 2>/dev/null || true
chmod +x "$WORK_DIR/cachy_extract/root/omarchy-assets/omarchy/install.sh" 2>/dev/null || true
find "$WORK_DIR/cachy_extract/root/omarchy-assets/omarchy" -name "*.sh" -exec chmod +x {} \; 2>/dev/null || true
log "Full Omarchy copied to ISO (with execute permissions)"

# NOTE: No offline packages are included - all packages download from online mirrors
# This avoids version conflicts between cached packages and fresh CachyOS base
log "All packages will be downloaded from online mirrors during installation"

# Also copy Plymouth theme to expected location
if [[ -d "$OMARCHY_DIR/default/plymouth" ]]; then
    mkdir -p "$WORK_DIR/cachy_extract/root/omarchy-assets/plymouth"
    cp -r "$OMARCHY_DIR/default/plymouth/"* "$WORK_DIR/cachy_extract/root/omarchy-assets/plymouth/"
    log "Plymouth theme copied"
fi

# Copy Limine config if available
if [[ -d "$OMARCHY_DIR/default/limine" ]]; then
    mkdir -p "$WORK_DIR/cachy_extract/root/omarchy-assets/limine"
    cp -r "$OMARCHY_DIR/default/limine/"* "$WORK_DIR/cachy_extract/root/omarchy-assets/limine/"
    log "Limine config copied"
fi

# Extract CachyOS keyring files directly from the CachyOS ISO's squashfs
# This ensures we always have the correct keyring for the CachyOS version being used
# The keyring files are already in the extracted squashfs at /usr/share/pacman/keyrings/
log "Extracting CachyOS keyring files from ISO..."
if [[ -d "$WORK_DIR/cachy_extract/usr/share/pacman/keyrings" ]]; then
    mkdir -p "$WORK_DIR/cachy_extract/root/omarchy-assets/cachyos-keyring"
    cp "$WORK_DIR/cachy_extract/usr/share/pacman/keyrings/cachyos"* \
       "$WORK_DIR/cachy_extract/root/omarchy-assets/cachyos-keyring/" 2>/dev/null || true
    if [[ -f "$WORK_DIR/cachy_extract/root/omarchy-assets/cachyos-keyring/cachyos.gpg" ]]; then
        log "CachyOS keyring files extracted from ISO"
    else
        warn "CachyOS keyring files not found in ISO squashfs"
    fi
else
    warn "Pacman keyrings directory not found in extracted squashfs"
fi

#===============================================================================
# CREATE ONLINE INSTALLER SCRIPT
#===============================================================================

log "Creating online installer..."

cat > "$WORK_DIR/cachy_extract/root/omacat-install.sh" << 'INSTALLER'
#!/bin/bash
#===============================================================================
# OMACAT ONLINE INSTALLER
# Installs CachyOS + Omarchy (requires network)
#===============================================================================

set -e

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'

log() { echo -e "${GREEN}[✓]${NC} $1"; }
warn() { echo -e "${YELLOW}[!]${NC} $1"; }
error() { echo -e "${RED}[✗]${NC} $1"; exit 1; }
info() { echo -e "${CYAN}[i]${NC} $1"; }

header() {
    echo ""
    echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${BOLD}  $1${NC}"
    echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo ""
}

cleanup_and_exit() {
    warn "Installation cancelled. Cleaning up..."
    # Kill any processes using /mnt
    fuser -km /mnt 2>/dev/null || true
    sleep 1
    # Unmount specific mounts first
    umount /mnt/boot 2>/dev/null || true
    umount /mnt/var/tmp 2>/dev/null || true
    umount /mnt/var/cache/pacman/pkg 2>/dev/null || true
    umount /mnt/var/log 2>/dev/null || true
    umount /mnt/home 2>/dev/null || true
    # Try normal unmount, fall back to lazy
    if ! umount -R /mnt 2>/dev/null; then
        umount -lR /mnt 2>/dev/null || true
    fi
    cryptsetup close cryptroot 2>/dev/null || true
    exit 1
}

#===============================================================================
# NETWORK SETUP FUNCTIONS
#===============================================================================

check_network() {
    # Test actual HTTPS connectivity to mirrors (not ICMP which may be blocked)
    # Try multiple mirrors in case one is down
    curl -sf --connect-timeout 5 --max-time 10 -o /dev/null \
        https://geo.mirror.pkgbuild.com/ 2>/dev/null && return 0
    curl -sf --connect-timeout 5 --max-time 10 -o /dev/null \
        https://mirror.cachyos.org/ 2>/dev/null && return 0
    curl -sf --connect-timeout 5 --max-time 10 -o /dev/null \
        https://archlinux.org/ 2>/dev/null && return 0
    return 1
}

setup_wifi() {
    header "WIFI SETUP"

    # Make sure WiFi is unblocked and powered on
    rfkill unblock wifi 2>/dev/null || true

    # Check for wireless interface
    WIFI_IFACE=$(iw dev 2>/dev/null | awk '$1=="Interface"{print $2}' | head -1)

    if [[ -z "$WIFI_IFACE" ]]; then
        warn "No WiFi interface found. Please use ethernet."
        return 1
    fi

    log "WiFi interface: $WIFI_IFACE"

    # Start IWD if not running
    systemctl start iwd 2>/dev/null || true
    sleep 2

    echo ""
    echo "Scanning for networks..."
    echo ""

    # Scan and list networks using iwctl
    iwctl station "$WIFI_IFACE" scan 2>/dev/null
    sleep 3

    # Get list of networks
    echo "Available WiFi networks:"
    echo ""
    iwctl station "$WIFI_IFACE" get-networks 2>/dev/null | head -20
    echo ""

    read -p "Enter WiFi network name (SSID): " WIFI_SSID
    [[ -z "$WIFI_SSID" ]] && return 1

    read -s -p "Enter WiFi password: " WIFI_PASS
    echo ""

    echo ""
    log "Connecting to $WIFI_SSID..."

    # Connect using iwctl
    iwctl --passphrase "$WIFI_PASS" station "$WIFI_IFACE" connect "$WIFI_SSID" 2>/dev/null

    # Wait for WiFi link to establish
    sleep 3

    # Request IP address via DHCP
    log "Requesting IP address..."
    if command -v dhcpcd &>/dev/null; then
        dhcpcd "$WIFI_IFACE" 2>/dev/null &
    elif command -v dhclient &>/dev/null; then
        dhclient "$WIFI_IFACE" 2>/dev/null &
    fi

    # Wait for connection
    for i in {1..15}; do
        sleep 1
        if check_network; then
            log "Connected to WiFi!"
            return 0
        fi
        echo -n "."
    done

    echo ""
    warn "WiFi connection failed. Please try again."
    return 1
}

setup_network() {
    header "NETWORK SETUP"

    # Check if already connected (ethernet)
    if check_network; then
        log "Network already connected (ethernet or existing WiFi)"
        return 0
    fi

    echo "No network connection detected."
    echo ""
    echo "Options:"
    echo "  1) Setup WiFi"
    echo "  2) I'll connect ethernet now (wait and retry)"
    echo "  3) Exit to shell (configure manually)"
    echo ""
    read -p "Select option [1]: " NET_CHOICE
    NET_CHOICE=${NET_CHOICE:-1}

    case "$NET_CHOICE" in
        1)
            while ! setup_wifi; do
                echo ""
                read -p "Try WiFi setup again? (Y/n): " retry
                [[ "$retry" =~ ^[Nn]$ ]] && break
            done
            ;;
        2)
            echo ""
            echo "Please connect ethernet cable now..."
            echo "Waiting for connection..."
            for i in {1..30}; do
                sleep 2
                if check_network; then
                    log "Network connected!"
                    return 0
                fi
                echo -n "."
            done
            echo ""
            warn "Still no connection."
            ;;
        3)
            echo ""
            echo "Exiting to shell. Connect to network manually, then run:"
            echo "  /root/omacat-install.sh"
            echo ""
            rm -f /tmp/omacat-install.lock  # Allow autostart on next login
            exit 0
            ;;
    esac

    # Final check
    if ! check_network; then
        error "No network connection. Cannot continue with online install."
    fi

    log "Network connected!"
}

#===============================================================================
# MIRROR RELIABILITY FUNCTIONS
#===============================================================================

# List of known-good fallback mirrors (geographically distributed)
FALLBACK_MIRRORS=(
    "https://geo.mirror.pkgbuild.com"
    "https://mirror.rackspace.com/archlinux"
    "https://mirrors.kernel.org/archlinux"
    "https://mirrors.mit.edu/archlinux"
    "https://mirror.leaseweb.net/archlinux"
)

FALLBACK_CACHY_MIRRORS=(
    "https://mirror.cachyos.org/repo"
)

# Probe mirrors and return first reachable one
probe_mirrors() {
    local mirrors=("$@")
    for mirror in "${mirrors[@]}"; do
        if curl -sfI --connect-timeout 5 --max-time 10 "$mirror" &>/dev/null; then
            echo "$mirror"
            return 0
        fi
    done
    return 1
}

# Preflight check: verify mirrors are reachable before starting install
preflight_mirror_check() {
    header "VERIFYING MIRROR ACCESS"

    log "Probing Arch Linux mirrors..."
    local arch_mirror
    arch_mirror=$(probe_mirrors "${FALLBACK_MIRRORS[@]}")
    if [[ -n "$arch_mirror" ]]; then
        log "Arch mirror reachable: $arch_mirror"
    else
        warn "No Arch mirrors responding - install may fail"
        echo ""
        read -p "Continue anyway? (y/N): " continue_anyway
        [[ ! "$continue_anyway" =~ ^[Yy]$ ]] && { rm -f /tmp/omacat-install.lock; exit 1; }
    fi

    log "Probing CachyOS mirrors..."
    local cachy_mirror
    cachy_mirror=$(probe_mirrors "${FALLBACK_CACHY_MIRRORS[@]}")
    if [[ -n "$cachy_mirror" ]]; then
        log "CachyOS mirror reachable: $cachy_mirror"
    else
        warn "No CachyOS mirrors responding - CachyOS packages may fail"
    fi

    log "Mirror preflight check complete"
}

# Swap to fallback mirrorlist
use_fallback_mirrors() {
    warn "Swapping to fallback mirrorlist..."
    cat > /etc/pacman.d/mirrorlist << 'FALLBACK'
# Emergency fallback mirrors
Server = https://geo.mirror.pkgbuild.com/$repo/os/$arch
Server = https://mirror.rackspace.com/archlinux/$repo/os/$arch
Server = https://mirrors.kernel.org/archlinux/$repo/os/$arch
Server = https://mirrors.mit.edu/archlinux/$repo/os/$arch
Server = https://mirror.leaseweb.net/archlinux/$repo/os/$arch
FALLBACK
    log "Fallback mirrorlist activated"
}

# Retry wrapper for critical network operations
# Usage: retry_cmd <max_attempts> <delay_seconds> <command...>
retry_cmd() {
    local max_attempts=$1
    local delay=$2
    shift 2
    local cmd=("$@")

    local attempt=1
    while [[ $attempt -le $max_attempts ]]; do
        if "${cmd[@]}"; then
            return 0
        fi

        if [[ $attempt -lt $max_attempts ]]; then
            warn "Attempt $attempt/$max_attempts failed, retrying in ${delay}s..."
            sleep "$delay"
            # Increase delay for next attempt (simple backoff)
            delay=$((delay + 5))
        fi
        ((attempt++))
    done

    return 1
}

# Wrapper for pacstrap with retry and fallback
pacstrap_with_retry() {
    local target=$1
    shift
    local packages=("$@")

    # Attempt 1: Normal pacstrap
    if pacstrap -K "$target" "${packages[@]}"; then
        return 0
    fi

    warn "pacstrap failed, retrying with mirror refresh..."
    sleep 5

    # Attempt 2: Refresh mirrors and retry
    pacman -Sy
    if pacstrap -K "$target" "${packages[@]}"; then
        return 0
    fi

    warn "pacstrap failed again, trying fallback mirrors..."
    sleep 5

    # Attempt 3: Use fallback mirrors
    use_fallback_mirrors
    pacman -Sy
    if pacstrap -K "$target" "${packages[@]}"; then
        return 0
    fi

    error "pacstrap failed after all retry attempts"
}

#===============================================================================
# WELCOME
#===============================================================================

clear
header "OMACAT ONLINE INSTALLER"

echo "This installer will set up:"
echo "  • CachyOS base with optimized kernel"
echo "  • Omarchy desktop (Hyprland)"
echo "  • LUKS2 disk encryption"
echo "  • Btrfs with snapshots"
echo ""
echo -e "${YELLOW}REQUIRES: Active network connection${NC}"
echo ""
echo "Options:"
echo "  1) Install (wipe entire disk)"
echo "  2) Exit to shell"
echo ""
read -p "Select option [1]: " MENU_CHOICE
MENU_CHOICE=${MENU_CHOICE:-1}

[[ "$MENU_CHOICE" == "2" ]] && { rm -f /tmp/omacat-install.lock; exit 0; }
[[ "$MENU_CHOICE" != "1" ]] && exec /root/omacat-install.sh

# Setup network connection
setup_network

# Verify mirrors are reachable before we start partitioning
preflight_mirror_check

#===============================================================================
# PRE-FLIGHT CHECKS
#===============================================================================

[[ ! -d /sys/firmware/efi ]] && error "UEFI mode required"

header "SELECT DRIVE"

echo "Available drives:"
echo ""
lsblk -d -o NAME,SIZE,MODEL | grep -E "^(nvme|sd|vd)"
echo ""

mapfile -t DRIVES < <(lsblk -d -n -o NAME,TRAN | awk '$2!="usb" {print $1}' | grep -E "^(nvme|sd|vd)")

if [[ ${#DRIVES[@]} -eq 1 ]]; then
    DRIVE="/dev/${DRIVES[0]}"
    info "Found: $DRIVE"
    read -p "Use this drive? (Y/n): " confirm
    [[ "$confirm" =~ ^[Nn]$ ]] && error "Cancelled"
else
    read -p "Enter drive (e.g., nvme0n1): " drive_input
    DRIVE="/dev/$drive_input"
fi

[[ ! -b "$DRIVE" ]] && error "Drive not found: $DRIVE"
[[ "$DRIVE" == *"nvme"* ]] && PART_PREFIX="${DRIVE}p" || PART_PREFIX="$DRIVE"

echo ""
echo -e "${RED}WARNING: ALL DATA ON $DRIVE WILL BE DESTROYED${NC}"
echo ""
read -p "Type 'yes' to confirm: " confirm
[[ "$confirm" != "yes" ]] && error "Cancelled"

#===============================================================================
# USER CONFIGURATION
#===============================================================================

header "USER SETUP"

while true; do
    read -p "Enter username: " USERNAME
    [[ "$USERNAME" =~ ^[a-z_][a-z0-9_-]*$ ]] && break
    warn "Invalid username. Use lowercase letters, numbers, underscore, hyphen."
done

read -p "Enter full name: " FULLNAME

while true; do
    read -s -p "Enter password: " USER_PASS; echo ""
    read -s -p "Confirm password: " USER_PASS2; echo ""
    [[ "$USER_PASS" == "$USER_PASS2" ]] && break
    warn "Passwords don't match"
done

read -p "Enter hostname [omacat]: " TARGET_HOSTNAME
TARGET_HOSTNAME=${TARGET_HOSTNAME:-omacat}

#===============================================================================
# DISK ENCRYPTION PASSWORD
#===============================================================================

header "DISK ENCRYPTION"

echo "Your disk will be encrypted with LUKS2."
echo ""

while true; do
    read -s -p "Enter LUKS encryption password: " LUKS_PASS; echo ""
    read -s -p "Confirm password: " LUKS_PASS2; echo ""
    [[ "$LUKS_PASS" == "$LUKS_PASS2" ]] && break
    warn "Passwords don't match"
done

#===============================================================================
# PARTITIONING
#===============================================================================

header "PARTITIONING DRIVE"

trap cleanup_and_exit ERR

log "Wiping partition table..."
sgdisk -Z "$DRIVE"
partprobe "$DRIVE"; sleep 2

log "Creating EFI partition (1GB)..."
sgdisk -n 1:0:+1G -t 1:ef00 -c 1:"EFI" "$DRIVE"

log "Creating root partition..."
sgdisk -n 2:0:0 -t 2:8300 -c 2:"Linux" "$DRIVE"

partprobe "$DRIVE"; udevadm settle; sleep 2

EFI_PART="${PART_PREFIX}1"
ROOT_PART="${PART_PREFIX}2"

log "Formatting EFI partition..."
mkfs.fat -F32 -n "EFI" "$EFI_PART"

#===============================================================================
# ENCRYPTION & FILESYSTEM
#===============================================================================

header "SETTING UP ENCRYPTION"

log "Formatting LUKS2..."
echo -n "$LUKS_PASS" | cryptsetup luksFormat --type luks2 \
    --cipher aes-xts-plain64 --key-size 512 --hash sha512 \
    --iter-time 5000 --key-file=- "$ROOT_PART"

log "Opening encrypted volume..."
echo -n "$LUKS_PASS" | cryptsetup open --key-file=- "$ROOT_PART" cryptroot
LUKS_UUID=$(blkid -s UUID -o value "$ROOT_PART")
[[ -z "$LUKS_UUID" ]] && error "Failed to get LUKS UUID - system would not boot"

log "Creating btrfs filesystem..."
mkfs.btrfs -f -L "OMACAT" /dev/mapper/cryptroot

log "Creating subvolumes..."
mount /dev/mapper/cryptroot /mnt
btrfs subvolume create /mnt/@
btrfs subvolume create /mnt/@home
btrfs subvolume create /mnt/@log
btrfs subvolume create /mnt/@pkg
btrfs subvolume create /mnt/@tmp
# NOTE: Do NOT create @snapshots - snapper will create .snapshots as nested subvolume in @
umount /mnt

log "Mounting filesystems..."
mount -o compress=zstd,subvol=@ /dev/mapper/cryptroot /mnt
mkdir -p /mnt/{home,var/log,var/cache/pacman/pkg,var/tmp,boot}
mount -o compress=zstd,subvol=@home /dev/mapper/cryptroot /mnt/home
mount -o compress=zstd,subvol=@log /dev/mapper/cryptroot /mnt/var/log
mount -o compress=zstd,subvol=@pkg /dev/mapper/cryptroot /mnt/var/cache/pacman/pkg
mount -o compress=zstd,subvol=@tmp /dev/mapper/cryptroot /mnt/var/tmp
# NOTE: Do NOT mount .snapshots - snapper creates it as nested subvolume in @
mount "$EFI_PART" /mnt/boot

#===============================================================================
# INSTALL BASE SYSTEM (ONLINE)
#===============================================================================

header "INSTALLING BASE SYSTEM (Online)"

# Use reflector to find the best mirrors for user's location
log "Setting up Arch mirrors..."

# First, set up minimal working mirrors so we can install reflector
# (chicken-and-egg: need mirrors to install reflector, need reflector for best mirrors)
cat > /etc/pacman.d/mirrorlist << 'BOOTSTRAP_MIRRORS'
# Bootstrap mirrors to install reflector
Server = https://geo.mirror.pkgbuild.com/$repo/os/$arch
Server = https://mirror.rackspace.com/archlinux/$repo/os/$arch
Server = https://mirrors.kernel.org/archlinux/$repo/os/$arch
BOOTSTRAP_MIRRORS

# Install reflector if not present
if ! command -v reflector &>/dev/null; then
    log "Installing reflector..."
    pacman -Sy --noconfirm reflector rsync
fi

# Try to auto-detect country, fallback to asking user
MIRROR_COUNTRY=""
if command -v curl &>/dev/null; then
    # Try to detect country from IP geolocation
    DETECTED_COUNTRY=$(curl -s --connect-timeout 5 "https://ipapi.co/country_name" 2>/dev/null || true)
    if [[ -n "$DETECTED_COUNTRY" && "$DETECTED_COUNTRY" != "Undefined" ]]; then
        info "Detected country: $DETECTED_COUNTRY"
        read -p "Use mirrors from $DETECTED_COUNTRY? (Y/n): " use_detected
        if [[ ! "$use_detected" =~ ^[Nn]$ ]]; then
            MIRROR_COUNTRY="$DETECTED_COUNTRY"
        fi
    fi
fi

if [[ -z "$MIRROR_COUNTRY" ]]; then
    echo ""
    echo "Enter your country for fastest mirrors (e.g., 'United Kingdom', 'Germany', 'United States')"
    echo "Leave blank to use worldwide mirrors."
    read -p "Country: " MIRROR_COUNTRY
fi

# Run reflector to get best mirrors
if [[ -n "$MIRROR_COUNTRY" ]]; then
    log "Finding fastest mirrors in $MIRROR_COUNTRY..."
    if reflector --country "$MIRROR_COUNTRY" --latest 20 --sort rate --protocol https --save /etc/pacman.d/mirrorlist 2>/dev/null; then
        log "Mirrors configured for $MIRROR_COUNTRY"
    else
        warn "Reflector failed for $MIRROR_COUNTRY, trying worldwide mirrors..."
        reflector --latest 20 --sort rate --protocol https --save /etc/pacman.d/mirrorlist 2>/dev/null || true
    fi
else
    log "Finding fastest worldwide mirrors..."
    reflector --latest 20 --sort rate --protocol https --save /etc/pacman.d/mirrorlist 2>/dev/null || true
fi

# Fallback to hardcoded mirrors if reflector failed
if [[ ! -s /etc/pacman.d/mirrorlist ]]; then
    warn "Reflector failed, using fallback mirrors..."
    cat > /etc/pacman.d/mirrorlist << 'ARCHMIRROR'
# Fallback Arch Linux mirrors
Server = https://geo.mirror.pkgbuild.com/$repo/os/$arch
Server = https://mirror.rackspace.com/archlinux/$repo/os/$arch
Server = https://mirrors.kernel.org/archlinux/$repo/os/$arch
Server = https://mirrors.mit.edu/archlinux/$repo/os/$arch
Server = https://mirror.leaseweb.net/archlinux/$repo/os/$arch
ARCHMIRROR
fi

log "Arch mirrors configured"

# Save country preference for first-boot installer
if [[ -n "$MIRROR_COUNTRY" ]]; then
    echo "$MIRROR_COUNTRY" > /tmp/omacat-mirror-country
fi

# Refresh package database with new mirrors (with retry)
log "Syncing package database..."
if ! retry_cmd 3 5 pacman -Sy; then
    warn "pacman -Sy failed, trying fallback mirrors..."
    use_fallback_mirrors
    retry_cmd 3 5 pacman -Sy || error "Failed to sync package database after all retries"
fi

log "Installing base packages..."
# Don't install kernel here - we'll install linux-cachyos after adding CachyOS repos
# This avoids having both standard linux and linux-cachyos installed
# Using pacstrap_with_retry for automatic retry and fallback on failure
pacstrap_with_retry /mnt base linux-firmware \
    btrfs-progs cryptsetup networkmanager iwd sudo nano vim \
    base-devel git wget curl \
    limine efibootmgr plymouth \
    pipewire pipewire-alsa pipewire-pulse pipewire-jack wireplumber \
    bluez bluez-utils \
    snapper \
    man-db man-pages texinfo

log "Generating fstab..."
genfstab -U /mnt >> /mnt/etc/fstab

# Copy working mirrorlist to installed system
log "Copying working mirrorlist to installed system..."
cp /etc/pacman.d/mirrorlist /mnt/etc/pacman.d/mirrorlist

# Copy country preference for first-boot reflector
if [[ -f /tmp/omacat-mirror-country ]]; then
    cp /tmp/omacat-mirror-country /mnt/etc/omacat-mirror-country
    log "Saved mirror country preference: $(cat /tmp/omacat-mirror-country)"
fi

# Copy embedded Omarchy files to target system for offline installation
log "Copying Omarchy files to installed system..."
if [[ -d /root/omarchy-assets ]]; then
    # Copy to /root for system-level access
    cp -r /root/omarchy-assets /mnt/root/
    log "Omarchy assets copied to /root"

    # Also copy to /opt for user access (readable by all)
    mkdir -p /mnt/opt/omarchy-assets
    cp -r /root/omarchy-assets/* /mnt/opt/omarchy-assets/
    chmod -R a+rX /mnt/opt/omarchy-assets
    log "Omarchy assets copied to /opt (user accessible)"

else
    warn "Omarchy assets not found in live environment"
fi

#===============================================================================
# CONFIGURE BASE SYSTEM
#===============================================================================

header "CONFIGURING SYSTEM"

log "Setting timezone..."
arch-chroot /mnt ln -sf /usr/share/zoneinfo/UTC /etc/localtime
arch-chroot /mnt hwclock --systohc

log "Setting locale..."
echo "en_US.UTF-8 UTF-8" > /mnt/etc/locale.gen
arch-chroot /mnt locale-gen
echo "LANG=en_US.UTF-8" > /mnt/etc/locale.conf

log "Setting console configuration..."
cat > /mnt/etc/vconsole.conf << 'VCONSOLE'
KEYMAP=us
FONT=ter-v16b
VCONSOLE

# Ensure terminus-font is installed for consolefont hook
arch-chroot /mnt pacman -S --noconfirm --needed terminus-font 2>/dev/null || \
    warn "terminus-font not installed, consolefont hook may show warnings"

log "Setting hostname..."
echo "$TARGET_HOSTNAME" > /mnt/etc/hostname
cat > /mnt/etc/hosts << HOSTS
127.0.0.1   localhost
::1         localhost
127.0.1.1   $TARGET_HOSTNAME.localdomain $TARGET_HOSTNAME
HOSTS

log "Creating user: $USERNAME"
if ! arch-chroot /mnt useradd -m -G wheel,video,audio,input -s /bin/bash "$USERNAME"; then
    error "Failed to create user $USERNAME"
fi
# Use printf with %s to avoid special character interpretation
if ! printf '%s:%s\n' "$USERNAME" "$USER_PASS" | arch-chroot /mnt chpasswd; then
    error "Failed to set password for $USERNAME"
fi
arch-chroot /mnt chfn -f "$FULLNAME" "$USERNAME" 2>/dev/null || true

log "Configuring sudo..."
# Permanent sudo config (requires password)
echo "%wheel ALL=(ALL:ALL) ALL" > /mnt/etc/sudoers.d/wheel
chmod 440 /mnt/etc/sudoers.d/wheel

# Temporary NOPASSWD for first-boot installer (will be removed after Omarchy installs)
echo "%wheel ALL=(ALL:ALL) NOPASSWD: ALL" > /mnt/etc/sudoers.d/first-boot-nopasswd
chmod 440 /mnt/etc/sudoers.d/first-boot-nopasswd

# Also set root password (same as user) for recovery
printf '%s:%s\n' "root" "$USER_PASS" | arch-chroot /mnt chpasswd

# Verify user is in wheel group
arch-chroot /mnt usermod -aG wheel "$USERNAME" 2>/dev/null || true

#===============================================================================
# CONFIGURE INITRAMFS FOR ENCRYPTION
#===============================================================================

header "CONFIGURING BOOT"

log "Configuring mkinitcpio for encryption..."
# Modify mkinitcpio.conf directly for maximum compatibility
# (conf.d support requires mkinitcpio 31+, not guaranteed on all systems)

# Ensure mkinitcpio is installed (may not be in CachyOS base)
if ! arch-chroot /mnt pacman -Q mkinitcpio &>/dev/null; then
    log "Installing mkinitcpio..."
    arch-chroot /mnt pacman -S --noconfirm --needed mkinitcpio
fi

# Remove CachyOS mkinitcpio.conf.d files that might override our HOOKS
# These can set sd-* hooks which conflict with our encrypt setup
if [[ -d /mnt/etc/mkinitcpio.conf.d ]]; then
    for conffile in /mnt/etc/mkinitcpio.conf.d/*.conf; do
        if [[ -f "$conffile" ]]; then
            if grep -qE "^HOOKS=|^HOOKS\+=" "$conffile" 2>/dev/null; then
                log "Removing conflicting mkinitcpio config: $(basename "$conffile")"
                rm -f "$conffile"
            fi
        fi
    done
fi

# Create mkinitcpio.conf if it doesn't exist (CachyOS may not include it)
if [[ ! -f /mnt/etc/mkinitcpio.conf ]]; then
    log "Creating mkinitcpio.conf (not present after pacstrap)..."
    cat > /mnt/etc/mkinitcpio.conf << 'MKINITCPIO'
# mkinitcpio.conf - generated by Omarchy installer
MODULES=(thunderbolt)
BINARIES=()
FILES=()
HOOKS=(base udev plymouth keyboard autodetect microcode modconf kms keymap consolefont block encrypt filesystems fsck)
MKINITCPIO
else
    # Backup original
    cp /mnt/etc/mkinitcpio.conf /mnt/etc/mkinitcpio.conf.bak

    # Set HOOKS with encrypt and plymouth support (order matters!)
    sed -i 's/^HOOKS=.*/HOOKS=(base udev plymouth keyboard autodetect microcode modconf kms keymap consolefont block encrypt filesystems fsck)/' /mnt/etc/mkinitcpio.conf

    # Add thunderbolt module support
    if grep -q "^MODULES=" /mnt/etc/mkinitcpio.conf; then
        # Append thunderbolt to existing MODULES line
        sed -i 's/^MODULES=(\(.*\))/MODULES=(\1 thunderbolt)/' /mnt/etc/mkinitcpio.conf
        # Clean up double spaces and empty parens
        sed -i 's/( /(/; s/  / /g' /mnt/etc/mkinitcpio.conf
    else
        echo "MODULES=(thunderbolt)" >> /mnt/etc/mkinitcpio.conf
    fi
fi

log "mkinitcpio.conf configured with encrypt hook and thunderbolt module"

# Setup Omarchy Plymouth theme
log "Installing Omarchy Plymouth theme..."
if [[ -d /root/omarchy-assets/plymouth ]]; then
    mkdir -p /mnt/usr/share/plymouth/themes/omarchy
    cp -r /root/omarchy-assets/plymouth/* /mnt/usr/share/plymouth/themes/omarchy/
    arch-chroot /mnt plymouth-set-default-theme omarchy
    log "Plymouth theme set to Omarchy"
else
    warn "Plymouth theme not found, using default"
fi

# NOTE: initramfs will be built later after kernel and GPU drivers are installed

#===============================================================================
# INSTALL BOOTLOADER (LIMINE)
#===============================================================================

header "INSTALLING BOOTLOADER"

log "Installing Limine bootloader..."

# Create base kernel command line for encryption (nvidia params added later if needed)
KERNEL_CMDLINE_BASE="cryptdevice=UUID=$LUKS_UUID:cryptroot root=/dev/mapper/cryptroot rootflags=subvol=@ quiet splash"

# Install Limine to EFI (BIOS install is optional, may fail on UEFI-only systems)
arch-chroot /mnt limine bios-install "$DRIVE" 2>/dev/null || info "Limine BIOS install skipped (UEFI-only system)"
mkdir -p /mnt/boot/EFI/BOOT
if [[ -f /mnt/usr/share/limine/BOOTX64.EFI ]]; then
    cp /mnt/usr/share/limine/BOOTX64.EFI /mnt/boot/EFI/BOOT/
    log "Limine EFI boot file installed"
else
    error "Limine EFI boot file not found - bootloader installation failed"
fi

# NOTE: limine.conf will be generated AFTER kernel packages are installed
# to ensure we know which kernels are available

# Create EFI boot entry
if arch-chroot /mnt efibootmgr --create --disk "$DRIVE" --part 1 --label "Omarchy" --loader "\\EFI\\BOOT\\BOOTX64.EFI" 2>/dev/null; then
    log "EFI boot entry created"
else
    info "EFI boot entry creation skipped (may already exist or not needed)"
fi

#===============================================================================
# ADD CACHYOS REPOS
#===============================================================================

header "DETECTING CPU ARCHITECTURE LEVEL"

# Ensure gcc is available for best CPU detection accuracy
if ! command -v gcc &>/dev/null; then
    warn "gcc not found in live environment; installing for CPU detection..."
    if command -v pacman &>/dev/null; then
        # Refresh package database with retries before installing gcc
        if ! retry_cmd 3 5 pacman -Sy; then
            warn "pacman -Sy failed; attempting gcc install anyway"
        fi
        if retry_cmd 3 5 pacman -S --noconfirm --needed gcc >/dev/null 2>&1; then
            log "gcc installed for CPU detection"
        else
            warn "Failed to install gcc; will rely on glibc detection if available"
        fi
    else
        warn "pacman not available; cannot install gcc"
    fi
fi

# If both gcc and glibc dynamic linker are unavailable, continue with baseline arch
if ! command -v gcc &>/dev/null && [[ ! -x /lib/ld-linux-x86-64.so.2 ]]; then
    warn "Neither gcc nor /lib/ld-linux-x86-64.so.2 available; falling back to baseline x86_64 repos"
fi

# Detect CPU microarchitecture level using glibc's dynamic linker and GCC
# This is authoritative - glibc is what actually loads optimized libraries at runtime
# This determines which CachyOS repositories to use for optimized packages.
# Priority: znver4 > v4 > v3 > baseline (znver4 is most optimized for AMD Zen 4/5)
detect_cpu_arch_level() {
    # Check for AMD Zen 4/5 first (uses GCC method from official CachyOS script)
    # znver4 repos are more optimized than generic v4 for these specific CPUs
    if command -v gcc &>/dev/null; then
        if gcc -march=native -Q --help=target 2>&1 | grep -q 'march.*znver[45]'; then
            echo "x86_64_znver4"
            return
        fi
    fi

    # Use glibc's dynamic linker to detect CPU microarchitecture level
    if [[ -x /lib/ld-linux-x86-64.so.2 ]]; then
        local support
        support=$(/lib/ld-linux-x86-64.so.2 --help 2>/dev/null | grep -E "x86-64-v[234]" || true)

        if echo "${support}" | grep -q "x86-64-v4.*supported"; then
            echo "x86_64_v4"
            return
        elif echo "${support}" | grep -q "x86-64-v3.*supported"; then
            echo "x86_64_v3"
            return
        fi
    fi

    # Fallback to baseline x86_64
    echo "x86_64"
}

DETECTED_ARCH=$(detect_cpu_arch_level)
log "Detected CPU architecture level: $DETECTED_ARCH"

# Determine which CachyOS repos to use based on CPU level
# znver4 -> cachyos-core-znver4, cachyos-extra-znver4 (AMD Zen 4/5 specific)
# v4 -> cachyos-core-v4, cachyos-extra-v4
# v3 -> cachyos-core-v3, cachyos-extra-v3
# x86_64 -> use Arch core/extra (CachyOS only provides tools repo)
case "$DETECTED_ARCH" in
    x86_64_znver4)
        CACHYOS_CORE_REPO="cachyos-core-znver4"
        CACHYOS_EXTRA_REPO="cachyos-extra-znver4"
        USE_CACHYOS_BASE=true
        log "Using CachyOS znver4 optimized repositories (AMD Zen 4/5)"
        ;;
    x86_64_v4)
        CACHYOS_CORE_REPO="cachyos-core-v4"
        CACHYOS_EXTRA_REPO="cachyos-extra-v4"
        USE_CACHYOS_BASE=true
        log "Using CachyOS v4 optimized repositories"
        ;;
    x86_64_v3)
        CACHYOS_CORE_REPO="cachyos-core-v3"
        CACHYOS_EXTRA_REPO="cachyos-extra-v3"
        USE_CACHYOS_BASE=true
        log "Using CachyOS v3 optimized repositories"
        ;;
    *)
        CACHYOS_CORE_REPO=""
        CACHYOS_EXTRA_REPO=""
        USE_CACHYOS_BASE=false
        log "CPU does not support v3/v4 - using Arch repos with CachyOS tools overlay"
        ;;
esac

header "ADDING CACHYOS REPOSITORIES"

#===============================================================================
# TWO-PHASE BOOTSTRAP FOR CACHYOS V4/V3 REPOS
#
# Problem: Keyring packages (archlinux-keyring, cachyos-keyring) are ONLY
# published for x86_64, NOT for x86_64_v3 or x86_64_v4. If we set Architecture
# to v4 before installing keyrings, pacman gets 404s and "Unrecognized archive".
#
# Solution: Two-phase bootstrap:
#   PHASE 1 (BOOTSTRAP): Architecture=x86_64, SigLevel=Never, install keyrings
#   PHASE 2 (PRODUCTION): Architecture=x86_64_v4, SigLevel=Required, full upgrade
#===============================================================================

#-------------------------------------------------------------------------------
# HELPER FUNCTIONS
#-------------------------------------------------------------------------------

write_pacman_conf_bootstrap() {
    # BOOTSTRAP MODE: x86_64 architecture, signatures disabled
    # Used only to install keyring packages before we can verify signatures
    # Uses dedicated bootstrap mirrorlist with HARDCODED paths (no $arch substitution)
    log "Writing pacman.conf (BOOTSTRAP: x86_64, SigLevel=Never)..."
    cat > /mnt/etc/pacman.conf << 'PACCONF'
[options]
HoldPkg = pacman glibc
Architecture = x86_64
Color
CheckSpace
ParallelDownloads = 10
DisableDownloadTimeout
SigLevel = Never
LocalFileSigLevel = Optional

# CachyOS base repo - keyrings ONLY exist at /repo/cachyos/x86_64/
# Must use dedicated bootstrap mirrorlist with hardcoded path
[cachyos]
Include = /etc/pacman.d/cachyos-bootstrap-mirrorlist

# Arch repos for gnupg and base dependencies
[core]
Include = /etc/pacman.d/mirrorlist

[extra]
Include = /etc/pacman.d/mirrorlist
PACCONF
}

write_pacman_conf_production() {
    # PRODUCTION MODE: signatures required, architecture-specific mirrorlists
    log "Writing pacman.conf (PRODUCTION: $DETECTED_ARCH, SigLevel=Required)..."

    if [[ "$USE_CACHYOS_BASE" == "true" ]]; then
        # CachyOS v4/v3 mode - per official CachyOS wiki "Optimized Repositories"
        # https://wiki.cachyos.org/features/optimized_repos/
        #
        # IMPORTANT: Standard Arch pacman doesn't understand $arch_v4 or $arch_v3
        # variables used in CachyOS's official mirrorlist packages. Therefore:
        #   - We use Architecture = auto (x86_64)
        #   - CachyOS v4 repos use mirrorlist with HARDCODED x86_64_v4 paths
        #   - CachyOS base repo uses mirrorlist with HARDCODED x86_64 paths
        #   - Arch repos use standard mirrorlist with $arch (= x86_64)
        #
        # Determine which mirrorlist to use based on detected architecture
        # NOTE: znver4 repos are served from x86_64_v4 path (same as v4), just different repo names
        local CACHYOS_OPTIMIZED_MIRRORLIST
        if [[ "$DETECTED_ARCH" == "x86_64_znver4" ]] || [[ "$DETECTED_ARCH" == "x86_64_v4" ]]; then
            CACHYOS_OPTIMIZED_MIRRORLIST="/etc/pacman.d/cachyos-v4-mirrorlist"
        else
            CACHYOS_OPTIMIZED_MIRRORLIST="/etc/pacman.d/cachyos-v3-mirrorlist"
        fi

        cat > /mnt/etc/pacman.conf << PACCONF
[options]
HoldPkg = pacman glibc
# Use auto (x86_64) - CachyOS mirrorlists have HARDCODED arch paths
Architecture = auto
Color
CheckSpace
ParallelDownloads = 10
DisableDownloadTimeout
SigLevel = Required DatabaseOptional
LocalFileSigLevel = Optional

# CachyOS optimized repos - MUST be listed ABOVE Arch repos
# These provide $DETECTED_ARCH-optimized builds that override Arch packages
# Mirrorlist has HARDCODED $DETECTED_ARCH paths (standard pacman doesn't support \$arch_v4)
[$CACHYOS_CORE_REPO]
Include = $CACHYOS_OPTIMIZED_MIRRORLIST

[$CACHYOS_EXTRA_REPO]
Include = $CACHYOS_OPTIMIZED_MIRRORLIST

# CachyOS base repo - tools, keyrings, kernels (x86_64 only, no v4 variant)
[cachyos]
Include = /etc/pacman.d/cachyos-x86_64-mirrorlist

# Arch repos - use standard Arch mirrorlist (\$arch = x86_64)
[core]
Include = /etc/pacman.d/mirrorlist

[extra]
Include = /etc/pacman.d/mirrorlist

# Multilib - Arch only (CachyOS does NOT provide multilib)
[multilib]
Include = /etc/pacman.d/mirrorlist
PACCONF
    else
        # Baseline x86_64 mode: Arch base + CachyOS tools overlay
        cat > /mnt/etc/pacman.conf << 'PACCONF'
[options]
HoldPkg = pacman glibc
Architecture = auto
Color
CheckSpace
ParallelDownloads = 10
DisableDownloadTimeout
SigLevel = Required DatabaseOptional
LocalFileSigLevel = Optional

# CachyOS tools overlay (kernels, chwd, etc.)
[cachyos]
Include = /etc/pacman.d/cachyos-x86_64-mirrorlist

# Arch base repos
[core]
Include = /etc/pacman.d/mirrorlist

[extra]
Include = /etc/pacman.d/mirrorlist

[multilib]
Include = /etc/pacman.d/mirrorlist
PACCONF
    fi
}

write_mirrorlists() {
    # Write CachyOS-specific mirrorlists with HARDCODED architecture paths
    #
    # CRITICAL: CachyOS's official mirrorlist package uses $arch_v4 / $arch_v3
    # which are CUSTOM pacman variables only available in CachyOS's patched pacman.
    # Standard Arch Linux pacman does NOT understand these variables.
    # Therefore we MUST hardcode the architecture in the URL paths.
    #
    # URL LAYOUT:
    #   - CachyOS mirrors: /repo/<arch>/$repo (e.g., /repo/x86_64_v4/cachyos-core-v4)
    #   - Arch mirrors:    /$repo/os/$arch    (e.g., /core/os/x86_64)
    #
    log "Writing CachyOS mirrorlists (hardcoded architectures for standard pacman)..."

    # x86_64 mirrorlist - for [cachyos] base repo (keyrings, tools, kernels)
    # This repo does NOT have v3/v4 variants - only exists at x86_64
    # Mirror order: primary mirror first, then geographic distribution
    cat > /mnt/etc/pacman.d/cachyos-x86_64-mirrorlist << 'EOF'
## CachyOS x86_64 mirrors (base repo: keyrings, tools, kernels)
## HARDCODED x86_64 - this repo only exists at x86_64
Server = https://mirror.cachyos.org/repo/x86_64/$repo
Server = https://us.cachyos.org/repo/x86_64/$repo
Server = https://at.cachyos.org/repo/x86_64/$repo
Server = https://mirror.lesviallon.fr/cachy/repo/x86_64/$repo
Server = https://mirrors.nju.edu.cn/cachyos/repo/x86_64/$repo
Server = https://mirror.funami.tech/cachy/x86_64/$repo
EOF

    # v4 mirrorlist - for [cachyos-core-v4], [cachyos-extra-v4], [cachyos-v4]
    # HARDCODED x86_64_v4 because standard pacman doesn't understand $arch_v4
    cat > /mnt/etc/pacman.d/cachyos-v4-mirrorlist << 'EOF'
## CachyOS x86_64_v4 mirrors (optimized repos)
## HARDCODED x86_64_v4 - standard pacman doesn't support $arch_v4 variable
Server = https://mirror.cachyos.org/repo/x86_64_v4/$repo
Server = https://us.cachyos.org/repo/x86_64_v4/$repo
Server = https://at.cachyos.org/repo/x86_64_v4/$repo
Server = https://mirror.lesviallon.fr/cachy/repo/x86_64_v4/$repo
Server = https://mirrors.nju.edu.cn/cachyos/repo/x86_64_v4/$repo
Server = https://mirror.funami.tech/cachy/x86_64_v4/$repo
EOF

    # NOTE: znver4 repos (cachyos-core-znver4, etc.) are served from the SAME x86_64_v4 path
    # as regular v4 repos - they just have different repo names. No separate mirrorlist needed.

    # v3 mirrorlist - for [cachyos-core-v3], [cachyos-extra-v3], [cachyos-v3]
    # HARDCODED x86_64_v3 because standard pacman doesn't understand $arch_v3
    cat > /mnt/etc/pacman.d/cachyos-v3-mirrorlist << 'EOF'
## CachyOS x86_64_v3 mirrors (optimized repos)
## HARDCODED x86_64_v3 - standard pacman doesn't support $arch_v3 variable
Server = https://mirror.cachyos.org/repo/x86_64_v3/$repo
Server = https://us.cachyos.org/repo/x86_64_v3/$repo
Server = https://at.cachyos.org/repo/x86_64_v3/$repo
Server = https://mirror.lesviallon.fr/cachy/repo/x86_64_v3/$repo
Server = https://mirrors.nju.edu.cn/cachyos/repo/x86_64_v3/$repo
Server = https://mirror.funami.tech/cachy/x86_64_v3/$repo
EOF

    # Bootstrap mirrorlist - x86_64, used during Phase 1 keyring install
    cat > /mnt/etc/pacman.d/cachyos-bootstrap-mirrorlist << 'EOF'
## CachyOS bootstrap mirror (x86_64 for keyring install)
Server = https://mirror.cachyos.org/repo/x86_64/$repo
EOF

    # NOTE: Arch repos (core, extra, multilib) use /etc/pacman.d/mirrorlist
    # which is managed by reflector/pacstrap - we do NOT modify it here.

    log "CachyOS mirrorlists written"
}

clear_pacman_databases() {
    log "Clearing pacman sync databases..."
    arch-chroot /mnt rm -f /var/lib/pacman/sync/*.db
    arch-chroot /mnt rm -f /var/lib/pacman/sync/*.db.sig
    arch-chroot /mnt rm -f /var/lib/pacman/sync/*.files
}

preflight_repo_check() {
    # Preflight sanity check: verify CachyOS mirror returns valid repo databases
    # Uses sandbox pacman sync to test without affecting the system
    log "Preflight check: Testing CachyOS repository access..."

    local TEST_URL="https://mirror.cachyos.org/repo/x86_64/cachyos/cachyos.db"
    local TMP_DIR="/tmp/pacman-preflight-$$"
    local TMP_DB="$TMP_DIR/cachyos.db"

    mkdir -p "$TMP_DIR"

    # Download the database file
    log "  Downloading: $TEST_URL"
    if ! curl -sfL --connect-timeout 15 --max-time 30 -o "$TMP_DB" "$TEST_URL" 2>/dev/null; then
        rm -rf "$TMP_DIR"
        error "PREFLIGHT FAILED: Cannot download from CachyOS mirror

    URL: $TEST_URL

    The installer requires network access to mirror.cachyos.org.
    Please check your internet connection and try again."
    fi

    # Check file size (valid .db should be >10KB, HTML error pages are ~1KB)
    local file_size
    file_size=$(stat -c%s "$TMP_DB" 2>/dev/null || echo "0")
    log "  Downloaded: ${file_size} bytes"

    if [[ "$file_size" -lt 10000 ]]; then
        rm -rf "$TMP_DIR"
        error "PREFLIGHT FAILED: Repository database too small (${file_size} bytes)

    URL: $TEST_URL
    Expected: >10KB (valid Zstandard archive)
    Got: ${file_size} bytes (likely HTML error page)

    The mirror may be returning an error page instead of the database."
    fi

    # Check file type (should be Zstandard or gzip compressed, NOT HTML)
    local file_type
    file_type=$(file -b "$TMP_DB" 2>/dev/null || echo "unknown")
    log "  File type: $file_type"

    if [[ "$file_type" == *"HTML"* ]] || [[ "$file_type" == *"ASCII"* ]] || [[ "$file_type" == *"text"* ]]; then
        rm -rf "$TMP_DIR"
        error "PREFLIGHT FAILED: Repository database is invalid

    URL: $TEST_URL
    File type: $file_type

    Expected Zstandard or gzip compressed data, got text/HTML.
    The mirror is returning an error page instead of the database."
    fi

    rm -rf "$TMP_DIR"
    log "  OK: Valid repository database"
    log "CachyOS mirror verified - proceeding with installation"
}

#===============================================================================
# PHASE 1: BOOTSTRAP (x86_64 mode)
#===============================================================================

header "PHASE 1: KEYRING BOOTSTRAP"

# Preflight: verify CDN is reachable before attempting any downloads
preflight_repo_check

log "Keyring packages only exist in x86_64 repos, not v3/v4."
log "Using x86_64 architecture temporarily for bootstrap..."

# Write mirrorlists (used by both phases)
write_mirrorlists

# Write bootstrap pacman.conf (x86_64, SigLevel=Never)
write_pacman_conf_bootstrap

# Clear any stale/corrupted databases from previous attempts
clear_pacman_databases

# Install gnupg first - required for pacman-key to work
# Without gnupg, pacman-key --init silently fails or hangs
log "Installing gnupg (required for pacman-key)..."
if ! arch-chroot /mnt pacman -Sy --noconfirm --needed gnupg; then
    error "CRITICAL: Failed to install gnupg. Cannot initialize keyrings."
fi

# Install keyring packages
# NOTE: cachyos-keyring may pull in cachyos-mirrorlist as a dependency,
# which would overwrite our CDN-only mirrorlist with defaults including broken mirrors.
log "Installing keyring packages..."
if ! arch-chroot /mnt pacman -S --noconfirm --needed archlinux-keyring cachyos-keyring; then
    error "CRITICAL: Failed to install keyrings. Cannot proceed."
fi
log "Keyring packages installed"

# Re-write CachyOS mirrorlists after keyring install
# The cachyos-mirrorlist package (dependency of cachyos-keyring) may have overwritten
# our CachyOS mirrorlists - restore them to known-working CDN paths
# NOTE: This only touches CachyOS mirrorlists, NOT Arch mirrorlist or repos
log "Re-applying CachyOS mirrorlists (CachyOS repos only, not Arch)..."
write_mirrorlists

# Initialize pacman keyring
log "Initializing pacman keyring..."
arch-chroot /mnt pacman-key --init || error "pacman-key --init failed"

# Populate keyrings with trusted keys
log "Populating keyrings..."
arch-chroot /mnt pacman-key --populate archlinux || error "Failed to populate archlinux keyring"
arch-chroot /mnt pacman-key --populate cachyos || error "Failed to populate cachyos keyring"
log "Keyrings initialized and populated successfully"

#===============================================================================
# PHASE 2: PRODUCTION (v4/v3 mode)
#===============================================================================

header "PHASE 2: CACHYOS $DETECTED_ARCH UPGRADE"

# Switch to production pacman.conf (target architecture, signatures required)
write_pacman_conf_production

# Ensure CachyOS mirrorlists are in place for Phase 2
# (may have been overwritten by cachyos-mirrorlist package in Phase 1)
# NOTE: Arch repos (core/extra/multilib) use standard Arch mirrorlist - untouched
write_mirrorlists

# Clear databases - must re-sync with new architecture
clear_pacman_databases

# Full system upgrade to CachyOS packages
if [[ "$USE_CACHYOS_BASE" == "true" ]]; then
    log "Upgrading system to CachyOS $DETECTED_ARCH packages..."
    log "This replaces Arch base packages with optimized CachyOS builds..."
else
    log "Upgrading system (Arch base + CachyOS tools)..."
fi

if ! retry_cmd 3 5 arch-chroot /mnt pacman -Syyu --noconfirm; then
    error "CRITICAL: System upgrade failed. Cannot continue."
fi
log "System upgrade complete"

# Re-apply CachyOS mirrorlists after system upgrade
# The cachyos-mirrorlist package may have been upgraded, overwriting our CachyOS lists
# NOTE: This only touches CachyOS mirrorlists, NOT Arch repos (core/extra/multilib)
write_mirrorlists

#===============================================================================
# SANITY CHECK: Verify repos, signatures, and critical packages
#===============================================================================

log "Running repository sanity checks..."

# Test that we can query packages from each repo type
# This verifies: mirrors work, signatures verify, databases are valid
SANITY_PACKAGES="cachyos-keyring"
if [[ "$USE_CACHYOS_BASE" == "true" ]]; then
    # v4/v3 mode: check CachyOS base packages + multilib
    SANITY_PACKAGES="cachyos-keyring glibc linux-cachyos lib32-glibc"
fi

for pkg in $SANITY_PACKAGES; do
    if ! arch-chroot /mnt pacman -Si "$pkg" &>/dev/null; then
        error "SANITY CHECK FAILED: Cannot query '$pkg'. Repos may be broken."
    fi
done
log "Repository sanity check passed: all critical packages queryable"

#===============================================================================
# ADD OMARCHY REPO AND INSTALL
#===============================================================================

header "INSTALLING OMARCHY (Online)"

log "Adding Omarchy repository..."
# Omarchy repo only provides x86_64 packages - hardcode arch to avoid issues
# when pacman Architecture is set to x86_64_v3 or x86_64_v4
cat >> /mnt/etc/pacman.conf << 'OMARCHY_REPO'

[omarchy]
SigLevel = Optional TrustAll
Server = https://pkgs.omarchy.org/stable/x86_64
OMARCHY_REPO

log "Syncing package databases (forced refresh)..."
if ! retry_cmd 3 5 arch-chroot /mnt pacman -Syy; then
    warn "pacman -Syy failed in chroot, this may cause package installation issues"
fi

# Install CachyOS kernel in two steps to avoid dependency resolution issues.
# The headers package pulls in LLVM toolchain (llvm-libs, clang, lld) which requires
# CachyOS repos to be fully synced. Installing kernel first ensures base deps are met.
# Arch kernel fallback is ONLY available when USE_CACHYOS_BASE=false (Arch repos enabled).
log "Installing CachyOS kernel..."
CACHYOS_KERNEL_INSTALLED=false
KERNEL_TYPE="cachyos"
if arch-chroot /mnt pacman -S --noconfirm --needed linux-cachyos; then
    log "CachyOS kernel installed"
    # Install headers separately - this pulls in LLVM toolchain
    log "Installing CachyOS kernel headers (includes LLVM toolchain)..."
    if arch-chroot /mnt pacman -S --noconfirm --needed linux-cachyos-headers; then
        log "CachyOS kernel headers installed successfully"
        CACHYOS_KERNEL_INSTALLED=true
    else
        warn "Kernel headers failed - DKMS modules (nvidia-dkms) won't build"
        warn "System will boot but may lack GPU drivers"
        CACHYOS_KERNEL_INSTALLED=true  # Kernel itself is installed, just not headers
    fi
else
    # Fallback to Arch kernel ONLY if Arch repos are enabled (non-v3/v4 mode)
    if [[ "$USE_CACHYOS_BASE" == "false" ]]; then
        warn "CachyOS kernel failed - trying Arch Linux kernel (Arch repos are enabled)..."
        if arch-chroot /mnt pacman -S --noconfirm --needed linux; then
            log "Arch Linux kernel installed"
            KERNEL_TYPE="arch"
            if arch-chroot /mnt pacman -S --noconfirm --needed linux-headers; then
                log "Arch Linux kernel headers installed"
                CACHYOS_KERNEL_INSTALLED=true
            else
                warn "Kernel headers failed - DKMS modules won't build"
                CACHYOS_KERNEL_INSTALLED=true
            fi
        else
            error "CRITICAL: No kernel could be installed! System will not boot."
        fi
    else
        # CachyOS v3/v4 mode - Arch repos are disabled, no fallback available
        error "CRITICAL: CachyOS kernel installation failed! Arch repos are disabled in $DETECTED_ARCH mode - no fallback available. System will not boot."
    fi
fi

log "Installing CachyOS settings..."
arch-chroot /mnt pacman -S --noconfirm --needed cachyos-settings 2>/dev/null || warn "cachyos-settings not available (optional)"

#===============================================================================
# AUTO-DETECT AND INSTALL GPU DRIVERS (CachyOS method using chwd)
# Based on: /var/lib/chwd/db/pci/graphic_drivers/profiles.toml
#===============================================================================

header "DETECTING AND INSTALLING GPU DRIVERS"

# Helper function to check if nvidia modules exist in the INSTALLED system
# This avoids using modinfo which checks the LIVE kernel version (uname -r)
# IMPORTANT: Only checks for actual module files, NOT package installation
# (nvidia-dkms can be installed but DKMS build may have failed)
check_nvidia_modules_installed() {
    local chroot_path="${1:-/mnt}"
    # Check each installed kernel's module directory for nvidia modules
    for kdir in "$chroot_path"/lib/modules/*/; do
        if [[ -d "$kdir" ]]; then
            # Look for nvidia.ko, nvidia.ko.zst, nvidia.ko.xz, etc.
            if find "$kdir" -name "nvidia.ko*" -type f 2>/dev/null | grep -q .; then
                return 0
            fi
        fi
    done
    # No fallback - package installation doesn't guarantee modules were built
    # DKMS can fail silently, so only trust actual module files
    return 1
}

# Detect GPU from live environment FIRST (hardware detection works here)
NVIDIA_DETECTED=false
AMD_DETECTED=false
INTEL_DETECTED=false
IS_LAPTOP=false

# Check for NVIDIA (vendor ID 10de, class IDs 0300/0302/0380)
# lspci -n format: "BUS CLASS: VENDOR:DEVICE" e.g., "01:00.0 0300: 10de:2684"
if lspci -n | grep -qE "(0300|0302|0380): 10de:"; then
    NVIDIA_DETECTED=true
    log "NVIDIA GPU detected"
fi

# Check for AMD (vendor ID 1002)
if lspci -n | grep -qE "(0300|0302|0380): 1002:"; then
    AMD_DETECTED=true
    log "AMD GPU detected"
fi

# Check for Intel (vendor ID 8086)
if lspci -n | grep -qE "(0300|0302): 8086:"; then
    INTEL_DETECTED=true
    log "Intel GPU detected"
fi

# Detect laptop (chassis types 8-11 are laptops/notebooks)
CHASSIS_TYPE=$(cat /sys/devices/virtual/dmi/id/chassis_type 2>/dev/null || echo "0")
if (( CHASSIS_TYPE >= 8 && CHASSIS_TYPE <= 11 )); then
    IS_LAPTOP=true
    log "Laptop detected (chassis type: $CHASSIS_TYPE)"
fi

# Install chwd (CachyOS Hardware Detection) into target system
log "Installing CachyOS hardware detection tool..."
arch-chroot /mnt pacman -S --noconfirm --needed chwd || warn "chwd installation had issues"

# Run chwd --autoconfigure for GPU driver installation
# Note: arch-chroot bind-mounts /sys so hardware detection works inside chroot
log "Running CachyOS hardware detection (chwd --autoconfigure)..."
CHWD_SUCCESS=true
CHWD_NVIDIA_OK=true
CHWD_AMD_OK=true
CHWD_INTEL_OK=true

# Ensure /sys is properly mounted in chroot for hardware detection
if ! mountpoint -q /mnt/sys 2>/dev/null; then
    mount --bind /sys /mnt/sys
fi

# Run chwd inside chroot (arch-chroot ensures /sys is accessible)
log "Running: arch-chroot /mnt chwd --autoconfigure"
if arch-chroot /mnt chwd --autoconfigure 2>&1 | tee /tmp/chwd-output.log; then
    log "chwd --autoconfigure completed"
else
    warn "chwd --autoconfigure returned non-zero exit code (may still have worked partially)"
fi

# Immediately verify chwd didn't create broken nvidia config
# chwd may detect nvidia hardware and create module config even if drivers fail to install
if [[ -f /mnt/etc/mkinitcpio.conf.d/10-chwd.conf ]]; then
    if grep -q "nvidia" /mnt/etc/mkinitcpio.conf.d/10-chwd.conf; then
        if ! check_nvidia_modules_installed /mnt; then
            warn "chwd created nvidia config but modules not found - removing invalid config"
            rm -f /mnt/etc/mkinitcpio.conf.d/10-chwd.conf
        fi
    fi
fi

# Verify chwd installed drivers for ALL detected GPUs (not just one)
if [[ "$NVIDIA_DETECTED" == "true" ]]; then
    if arch-chroot /mnt pacman -Q nvidia-utils &>/dev/null; then
        log "chwd successfully installed NVIDIA drivers"
    else
        warn "chwd did not install NVIDIA drivers"
        CHWD_NVIDIA_OK=false
        CHWD_SUCCESS=false
    fi
fi

if [[ "$AMD_DETECTED" == "true" ]]; then
    if arch-chroot /mnt pacman -Q vulkan-radeon &>/dev/null; then
        log "chwd successfully installed AMD drivers"
    else
        warn "chwd did not install AMD drivers"
        CHWD_AMD_OK=false
        CHWD_SUCCESS=false
    fi
fi

if [[ "$INTEL_DETECTED" == "true" ]]; then
    if arch-chroot /mnt pacman -Q vulkan-intel &>/dev/null; then
        log "chwd successfully installed Intel drivers"
    else
        warn "chwd did not install Intel drivers"
        CHWD_INTEL_OK=false
        CHWD_SUCCESS=false
    fi
fi

# If no GPUs detected, chwd succeeded (VM or fallback case)
if [[ "$NVIDIA_DETECTED" != "true" && "$AMD_DETECTED" != "true" && "$INTEL_DETECTED" != "true" ]]; then
    log "chwd completed (no dedicated GPU detected)"
fi

# Manual fallback if chwd didn't install expected drivers
if [[ "$CHWD_SUCCESS" != "true" ]]; then
    warn "chwd auto-configure incomplete, using manual driver installation (matching CachyOS profiles.toml)..."

    #---------------------------------------------------------------------------
    # NVIDIA Manual Installation (matches CachyOS nvidia-open-dkms profile)
    #---------------------------------------------------------------------------
    if [[ "$NVIDIA_DETECTED" == "true" && "$CHWD_NVIDIA_OK" != "true" ]]; then
        log "Installing NVIDIA drivers manually (CachyOS method)..."

        # Install userspace packages (from profiles.toml line 25)
        log "Installing NVIDIA userspace packages..."
        arch-chroot /mnt pacman -S --noconfirm --needed \
            nvidia-utils egl-wayland nvidia-settings \
            opencl-nvidia lib32-opencl-nvidia lib32-nvidia-utils \
            libva-nvidia-driver vulkan-icd-loader lib32-vulkan-icd-loader || \
            warn "Some NVIDIA userspace packages failed to install"

        # Install kernel modules - prefer pre-built over DKMS (from profiles.toml conditional_packages)
        log "Installing NVIDIA kernel modules..."
        NVIDIA_MODULES_INSTALLED=false

        # Check which linux-cachyos kernels are installed and get matching nvidia modules
        INSTALLED_KERNELS=$(arch-chroot /mnt pacman -Qqs "^linux-cachyos" 2>/dev/null | grep -v -E '(-headers|-zfs|-nvidia|-dbg)$' || true)

        for kernel in $INSTALLED_KERNELS; do
            # Try pre-built nvidia-open modules first (e.g., linux-cachyos-nvidia-open)
            if arch-chroot /mnt pacman -S --noconfirm --needed "${kernel}-nvidia-open" 2>/dev/null; then
                log "Installed ${kernel}-nvidia-open (pre-built module)"
                NVIDIA_MODULES_INSTALLED=true
            fi
        done

        # Fallback to nvidia-open-dkms if no pre-built modules available
        if [[ "$NVIDIA_MODULES_INSTALLED" != "true" ]]; then
            log "No pre-built modules available, trying nvidia-open-dkms..."
            if arch-chroot /mnt pacman -S --noconfirm --needed nvidia-open-dkms 2>/dev/null; then
                log "Installed nvidia-open-dkms"
                NVIDIA_MODULES_INSTALLED=true
            else
                warn "nvidia-open-dkms failed, trying nvidia-dkms as last resort..."
                arch-chroot /mnt pacman -S --noconfirm --needed nvidia-dkms 2>/dev/null && \
                    NVIDIA_MODULES_INSTALLED=true || \
                    warn "Could not install any NVIDIA kernel modules"
            fi
        fi

        # Create mkinitcpio config for early KMS ONLY if modules actually exist
        # Check if any nvidia module is available before creating config
        if check_nvidia_modules_installed /mnt; then
            log "Configuring NVIDIA early KMS..."
            mkdir -p /mnt/etc/mkinitcpio.conf.d
            cat > /mnt/etc/mkinitcpio.conf.d/10-chwd.conf << 'NVIDIA_MKINIT'
# This file is automatically generated by chwd. PLEASE DO NOT EDIT IT.
MODULES+=(nvidia nvidia_modeset nvidia_uvm nvidia_drm)
NVIDIA_MKINIT
        else
            warn "NVIDIA kernel modules not found - skipping mkinitcpio nvidia config"
            warn "System will use nouveau or software rendering"
        fi

        # Laptop-specific configuration (from profiles.toml post_install)
        if [[ "$IS_LAPTOP" == "true" ]]; then
            log "Configuring NVIDIA for laptop (hybrid graphics)..."
            arch-chroot /mnt pacman -S --noconfirm --needed nvidia-prime switcheroo-control || \
                warn "nvidia-prime/switcheroo-control installation failed"

            # Enable switcheroo-control service
            arch-chroot /mnt systemctl enable switcheroo-control 2>/dev/null || true

            # Create RTD3 workaround for discrete GPU (from profiles.toml)
            cat > /mnt/etc/profile.d/nvidia-rtd3-workaround.sh << 'NVIDIA_RTD3'
# This file is automatically generated by chwd. PLEASE DO NOT EDIT IT.
if [ -n "$(lspci -d "10de:*:0302")" ]; then
    export __EGL_VENDOR_LIBRARY_FILENAMES=/usr/share/glvnd/egl_vendor.d/50_mesa.json
fi
NVIDIA_RTD3

            # Create user environment generator for RTD3
            mkdir -p /mnt/usr/lib/systemd/user-environment-generators
            cat > /mnt/usr/lib/systemd/user-environment-generators/20-nvidia-rtd3-workaround << 'NVIDIA_RTD3_GEN'
#!/usr/bin/env sh
# This file is automatically generated by chwd. PLEASE DO NOT EDIT IT.
if [ -n "$(lspci -d "10de:*:0302")" ]; then
    echo "__EGL_VENDOR_LIBRARY_FILENAMES=/usr/share/glvnd/egl_vendor.d/50_mesa.json"
fi
NVIDIA_RTD3_GEN
            chmod 755 /mnt/usr/lib/systemd/user-environment-generators/20-nvidia-rtd3-workaround
        else
            # Desktop: configure VAAPI (from profiles.toml)
            echo "export LIBVA_DRIVER_NAME=nvidia" > /mnt/etc/profile.d/nvidia-vaapi.sh
        fi

        log "NVIDIA drivers installed"
    fi

    #---------------------------------------------------------------------------
    # AMD Manual Installation (matches CachyOS amd profile)
    #---------------------------------------------------------------------------
    if [[ "$AMD_DETECTED" == "true" && "$CHWD_AMD_OK" != "true" ]]; then
        log "Installing AMD drivers manually (CachyOS method)..."

        # Install packages (from profiles.toml line 299)
        arch-chroot /mnt pacman -S --noconfirm --needed \
            mesa lib32-mesa vulkan-radeon lib32-vulkan-radeon \
            xf86-video-amdgpu gst-plugin-va linux-firmware-amdgpu || \
            warn "Some AMD packages failed to install"

        # Install OpenCL if no NVIDIA card present (from profiles.toml conditional_packages)
        if [[ "$NVIDIA_DETECTED" != "true" ]]; then
            arch-chroot /mnt pacman -S --noconfirm --needed opencl-mesa lib32-opencl-mesa || true

            # Configure Rusticl for OpenCL (from profiles.toml post_install)
            # Note: For AMD+Intel hybrid, AMD (radeonsi) takes priority as dGPU
            echo "export RUSTICL_ENABLE=radeonsi" > /mnt/etc/profile.d/opencl.sh
            mkdir -p /mnt/etc/environment.d
            echo "RUSTICL_ENABLE=radeonsi" > /mnt/etc/environment.d/30-opencl.conf
        fi

        log "AMD drivers installed"
    fi

    #---------------------------------------------------------------------------
    # Intel Manual Installation (matches CachyOS intel profile)
    #---------------------------------------------------------------------------
    if [[ "$INTEL_DETECTED" == "true" && "$CHWD_INTEL_OK" != "true" ]]; then
        log "Installing Intel drivers manually (CachyOS method)..."

        # Install packages (from profiles.toml line 256)
        arch-chroot /mnt pacman -S --noconfirm --needed \
            mesa lib32-mesa vulkan-intel lib32-vulkan-intel \
            gst-plugin-va linux-firmware-intel intel-media-driver || \
            warn "Some Intel packages failed to install"

        # Install OpenCL if no NVIDIA card present AND no AMD card (AMD takes priority)
        if [[ "$NVIDIA_DETECTED" != "true" && "$AMD_DETECTED" != "true" ]]; then
            arch-chroot /mnt pacman -S --noconfirm --needed opencl-mesa lib32-opencl-mesa || true

            # Configure Rusticl for OpenCL (from profiles.toml post_install)
            # Only set Intel if no AMD dGPU present
            echo "export RUSTICL_ENABLE=iris" > /mnt/etc/profile.d/opencl.sh
            mkdir -p /mnt/etc/environment.d
            echo "RUSTICL_ENABLE=iris" > /mnt/etc/environment.d/30-opencl.conf
        elif [[ "$AMD_DETECTED" != "true" ]]; then
            # Intel-only system with NVIDIA - still install mesa OpenCL for Intel iGPU
            arch-chroot /mnt pacman -S --noconfirm --needed opencl-mesa lib32-opencl-mesa || true
        fi

        log "Intel drivers installed"
    fi
fi

# Fallback for VMs or unknown GPUs (matches CachyOS fallback profile)
if [[ "$NVIDIA_DETECTED" != "true" && "$AMD_DETECTED" != "true" && "$INTEL_DETECTED" != "true" ]]; then
    log "No dedicated GPU detected - installing fallback/VM drivers"
    arch-chroot /mnt pacman -S --noconfirm --needed mesa lib32-mesa vulkan-swrast xf86-video-vesa || true

    # Check if running in VM and install appropriate tools
    VM_TYPE=$(systemd-detect-virt 2>/dev/null || echo "none")
    case "$VM_TYPE" in
        oracle)
            log "VirtualBox detected - installing guest utils"
            arch-chroot /mnt pacman -S --noconfirm --needed virtualbox-guest-utils || true
            arch-chroot /mnt systemctl enable vboxservice.service 2>/dev/null || true
            ;;
        vmware)
            log "VMware detected - installing open-vm-tools"
            arch-chroot /mnt pacman -S --noconfirm --needed open-vm-tools xf86-input-vmmouse || true
            arch-chroot /mnt systemctl enable vmtoolsd.service 2>/dev/null || true
            ;;
        kvm|qemu)
            log "QEMU/KVM detected - installing guest agent"
            arch-chroot /mnt pacman -S --noconfirm --needed qemu-guest-agent spice-vdagent vulkan-virtio || true
            ;;
    esac
fi

# CRITICAL: Verify nvidia modules exist if referenced in mkinitcpio config
# chwd may have created 10-chwd.conf with nvidia modules even if they failed to install
# Also wait a moment for any DKMS builds to complete
if [[ "$NVIDIA_DETECTED" == "true" ]]; then
    log "Waiting for any DKMS builds to complete..."
    # Wait for DKMS lock file inside the chroot (more reliable than process detection)
    DKMS_WAIT=0
    DKMS_MAX_WAIT=600  # 10 minutes for NVIDIA DKMS builds on real hardware
    while [[ -f /mnt/var/lib/dkms/.lock ]] && [[ $DKMS_WAIT -lt $DKMS_MAX_WAIT ]]; do
        sleep 5
        ((DKMS_WAIT+=5))
        if (( DKMS_WAIT % 30 == 0 )); then
            log "  Still waiting for DKMS lock file... (${DKMS_WAIT}s)"
        fi
    done
    # Also check for any active dkms processes in chroot
    # Use [d]kms pattern to avoid pgrep matching itself
    while arch-chroot /mnt pgrep -f "[d]kms" &>/dev/null && [[ $DKMS_WAIT -lt $DKMS_MAX_WAIT ]]; do
        sleep 5
        ((DKMS_WAIT+=5))
        if (( DKMS_WAIT % 30 == 0 )); then
            log "  Still waiting for DKMS processes... (${DKMS_WAIT}s)"
        fi
    done
    sleep 3  # Extra buffer for module registration
    if [[ $DKMS_WAIT -ge $DKMS_MAX_WAIT ]]; then
        warn "DKMS wait timed out after 10 minutes"
    else
        log "DKMS builds completed (waited ${DKMS_WAIT}s)"
    fi
fi

NVIDIA_MODULES_AVAILABLE=false
if [[ -f /mnt/etc/mkinitcpio.conf.d/10-chwd.conf ]]; then
    if grep -q "nvidia" /mnt/etc/mkinitcpio.conf.d/10-chwd.conf; then
        # Check if modules are actually available (check installed kernels, not live kernel)
        if check_nvidia_modules_installed /mnt; then
            NVIDIA_MODULES_AVAILABLE=true
            log "NVIDIA modules verified in initramfs config"
        else
            warn "Removing invalid nvidia config from mkinitcpio (modules not installed)"
            rm -f /mnt/etc/mkinitcpio.conf.d/10-chwd.conf
        fi
    fi
fi

# Also check if nvidia modules exist even without chwd config (manual install case)
if [[ "$NVIDIA_DETECTED" == "true" ]] && [[ "$NVIDIA_MODULES_AVAILABLE" != "true" ]]; then
    if check_nvidia_modules_installed /mnt; then
        NVIDIA_MODULES_AVAILABLE=true
    fi
fi

# Set final kernel command line with NVIDIA parameters if needed
if [[ "$NVIDIA_MODULES_AVAILABLE" == "true" ]]; then
    KERNEL_CMDLINE="$KERNEL_CMDLINE_BASE nvidia-drm.modeset=1 nvidia-drm.fbdev=1"
    log "NVIDIA detected - added nvidia-drm.modeset=1 to kernel cmdline"
else
    KERNEL_CMDLINE="$KERNEL_CMDLINE_BASE"
fi

# Summary of GPU driver installation
log "GPU Driver Summary:"
if [[ "$NVIDIA_DETECTED" == "true" ]]; then
    if [[ "$NVIDIA_MODULES_AVAILABLE" == "true" ]]; then
        info "  NVIDIA: Drivers installed with early KMS"
    else
        warn "  NVIDIA: Hardware detected but drivers may not be fully installed"
    fi
fi
if [[ "$AMD_DETECTED" == "true" ]]; then
    if arch-chroot /mnt pacman -Q vulkan-radeon &>/dev/null; then
        info "  AMD: Drivers installed (vulkan-radeon)"
    else
        warn "  AMD: Hardware detected but vulkan-radeon not installed"
    fi
fi
if [[ "$INTEL_DETECTED" == "true" ]]; then
    if arch-chroot /mnt pacman -Q vulkan-intel &>/dev/null; then
        info "  Intel: Drivers installed (vulkan-intel)"
    else
        warn "  Intel: Hardware detected but vulkan-intel not installed"
    fi
fi
if [[ "$NVIDIA_DETECTED" != "true" && "$AMD_DETECTED" != "true" && "$INTEL_DETECTED" != "true" ]]; then
    info "  Fallback: Software rendering (mesa/swrast)"
fi

# Rebuild initramfs for CachyOS kernel (includes GPU modules now)
log "Rebuilding initramfs with GPU support..."
if ! arch-chroot /mnt mkinitcpio -P; then
    error "mkinitcpio failed - system will not boot without initramfs"
fi

#===============================================================================
# GENERATE LIMINE.CONF (after kernels are installed)
#===============================================================================

header "CONFIGURING BOOTLOADER"

# Generate machine-id if not exists (needed for limine-snapper-sync)
if [[ ! -f /mnt/etc/machine-id ]]; then
    arch-chroot /mnt systemd-machine-id-setup 2>/dev/null || uuidgen | tr -d '-' > /mnt/etc/machine-id
fi
MACHINE_ID=$(cat /mnt/etc/machine-id)

# Determine default kernel based on what was actually installed
if [[ "$CACHYOS_KERNEL_INSTALLED" == "true" ]] && [[ -f /mnt/boot/vmlinuz-linux-cachyos ]]; then
    log "CachyOS kernel found - setting as default"
    DEFAULT_KERNEL="linux-cachyos"
else
    log "Using standard Linux kernel as default"
    DEFAULT_KERNEL="linux"
fi

# Create limine.conf with proper nested format for limine-snapper-sync
log "Creating limine.conf..."
cat > /mnt/boot/limine.conf << LIMINE
# Omarchy Bootloader Config
timeout: 3
default_entry: 1
interface_branding: Omarchy
interface_branding_color: 2
hash_mismatch_panic: no

term_background: 1a1b26
backdrop: 1a1b26

# Terminal colors (Tokyo Night palette)
term_palette: 15161e;f7768e;9ece6a;e0af68;7aa2f7;bb9af7;7dcfff;a9b1d6
term_palette_bright: 414868;f7768e;9ece6a;e0af68;7aa2f7;bb9af7;7dcfff;c0caf5

# Text colors
term_foreground: c0caf5
term_foreground_bright: c0caf5
term_background_bright: 24283b

/+Omarchy
comment: Omarchy
comment: machine-id=$MACHINE_ID order-priority=50
LIMINE

# Add kernel entries based on what's actually installed (check BOTH kernel AND initramfs exist)
if [[ -f /mnt/boot/vmlinuz-linux-cachyos ]] && [[ -f /mnt/boot/initramfs-linux-cachyos.img ]]; then
    cat >> /mnt/boot/limine.conf << LIMINE_CACHYOS
  //linux-cachyos
  comment: CachyOS optimized kernel
  comment: kernel-id=linux-cachyos
  protocol: linux
  kernel_path: boot():/vmlinuz-linux-cachyos
  cmdline: $KERNEL_CMDLINE
  module_path: boot():/initramfs-linux-cachyos.img

LIMINE_CACHYOS
    log "Added linux-cachyos kernel entry"
fi

if [[ -f /mnt/boot/vmlinuz-linux ]] && [[ -f /mnt/boot/initramfs-linux.img ]]; then
    cat >> /mnt/boot/limine.conf << LIMINE_LINUX
  //linux
  comment: Standard Arch kernel
  comment: kernel-id=linux
  protocol: linux
  kernel_path: boot():/vmlinuz-linux
  cmdline: $KERNEL_CMDLINE
  module_path: boot():/initramfs-linux.img

LIMINE_LINUX
    log "Added linux kernel entry"
fi

# Add fallback entries ONLY if the fallback initramfs actually exists
if [[ -f /mnt/boot/vmlinuz-linux-cachyos ]] && [[ -f /mnt/boot/initramfs-linux-cachyos-fallback.img ]]; then
    cat >> /mnt/boot/limine.conf << LIMINE_CACHYOS_FB
  //linux-cachyos-fallback
  comment: CachyOS kernel (fallback initramfs)
  comment: kernel-id=linux-cachyos-fallback
  protocol: linux
  kernel_path: boot():/vmlinuz-linux-cachyos
  cmdline: $KERNEL_CMDLINE
  module_path: boot():/initramfs-linux-cachyos-fallback.img

LIMINE_CACHYOS_FB
    log "Added linux-cachyos-fallback entry"
fi

if [[ -f /mnt/boot/vmlinuz-linux ]] && [[ -f /mnt/boot/initramfs-linux-fallback.img ]]; then
    cat >> /mnt/boot/limine.conf << LIMINE_LINUX_FB
  //linux-fallback
  comment: Standard kernel (fallback initramfs)
  comment: kernel-id=linux-fallback
  protocol: linux
  kernel_path: boot():/vmlinuz-linux
  cmdline: $KERNEL_CMDLINE
  module_path: boot():/initramfs-linux-fallback.img
LIMINE_LINUX_FB
    log "Added linux-fallback entry"
fi

log "limine.conf created with available kernels"

# Verify at least one kernel entry was added
if ! grep -q "kernel_path:" /mnt/boot/limine.conf; then
    error "No bootable kernel found - limine.conf has no kernel entries"
fi

# Configure limine-snapper-sync
log "Configuring limine-snapper-sync..."
mkdir -p /mnt/etc
cat > /mnt/etc/limine-snapper-sync.conf << 'SNAPPER_CONF'
# Omarchy limine-snapper-sync configuration
TARGET_OS_NAME="Omarchy"
ESP_PATH="/boot"
MAX_SNAPSHOT_ENTRIES=8
LIMIT_USAGE_PERCENT=85
ROOT_SUBVOLUME_PATH="/@"
ROOT_SNAPSHOTS_PATH="/@/.snapshots"
RESTORE_METHOD=replace
SET_SNAPSHOT_AS_DEFAULT=no
SNAPSHOT_FORMAT_CHOICE=2
SNAPPER_CONF
log "limine-snapper-sync configured"

#===============================================================================
# CLONE OMARCHY AND INSTALL ALL PACKAGES
#===============================================================================

header "INSTALLING OMARCHY (Full Installation)"

# Install minimal packages needed for first boot + Omarchy installer
log "Installing packages for first boot..."
FIRST_BOOT_PKGS=(
    git
    base-devel
    alacritty
    sddm
    hyprland
    uwsm
    xdg-desktop-portal-hyprland
    xdg-desktop-portal-gtk
    polkit-kde-agent
    qt5-wayland
    qt6-wayland
    networkmanager
    limine-snapper-sync
    python-terminaltexteffects
)

for pkg in "${FIRST_BOOT_PKGS[@]}"; do
    if ! arch-chroot /mnt pacman -S --noconfirm --needed "$pkg"; then
        warn "Package '$pkg' failed to install"
    fi
done
log "First boot packages installation complete"

# Install yay for AUR packages (Omarchy needs this)
log "Installing yay AUR helper..."
if arch-chroot /mnt sudo -u "$USERNAME" bash -c '
    set -e
    cd /tmp
    rm -rf yay
    git clone https://aur.archlinux.org/yay.git
    cd yay
    makepkg -si --noconfirm
    cd ..
    rm -rf yay
'; then
    log "yay installed successfully"
else
    warn "yay installation failed - Omarchy will attempt to install it during first boot"
fi

#===============================================================================
# ENABLE SERVICES
#===============================================================================

header "ENABLING SERVICES"

log "Enabling services..."
# NOTE: SDDM is NOT enabled here - it will be enabled by the first-boot installer
# after Omarchy is fully installed. First boot uses TTY autologin instead.
arch-chroot /mnt systemctl enable NetworkManager 2>/dev/null || true
arch-chroot /mnt systemctl enable iwd 2>/dev/null || true
arch-chroot /mnt systemctl enable bluetooth 2>/dev/null || true

# Copy network credentials from live environment to installed system
# This ensures network works after reboot without re-configuration

# Copy NetworkManager connection profiles (WiFi AND wired connections)
# This is the primary method - NM profiles work reliably after reboot
if [[ -d /etc/NetworkManager/system-connections ]]; then
    mkdir -p /mnt/etc/NetworkManager/system-connections
    # Copy all connection profiles (wifi, ethernet, vpn, etc.)
    for conn in /etc/NetworkManager/system-connections/*; do
        if [[ -f "$conn" ]]; then
            cp -a "$conn" /mnt/etc/NetworkManager/system-connections/
            # Ensure autoconnect is enabled for copied connections
            connfile="/mnt/etc/NetworkManager/system-connections/$(basename "$conn")"
            if ! grep -q "^autoconnect=" "$connfile" 2>/dev/null; then
                sed -i '/^\[connection\]/a autoconnect=true' "$connfile" 2>/dev/null || true
            fi
        fi
    done
    chmod 600 /mnt/etc/NetworkManager/system-connections/* 2>/dev/null || true
    COPIED_CONNS=$(ls -1 /mnt/etc/NetworkManager/system-connections/ 2>/dev/null | wc -l)
    if [[ "$COPIED_CONNS" -gt 0 ]]; then
        log "NetworkManager profiles copied ($COPIED_CONNS connections)"
    fi
fi

# Also copy IWD credentials as backup (in case NM uses IWD backend)
if [[ -d /var/lib/iwd ]] && ls /var/lib/iwd/*.psk &>/dev/null 2>&1; then
    mkdir -p /mnt/var/lib/iwd
    cp -a /var/lib/iwd/*.psk /mnt/var/lib/iwd/ 2>/dev/null || true
    chmod 600 /mnt/var/lib/iwd/*.psk 2>/dev/null || true
    log "IWD WiFi credentials copied (backup)"
fi

# Ensure NetworkManager will wait for network on boot (helps with first-boot installer)
mkdir -p /mnt/etc/NetworkManager/conf.d
cat > /mnt/etc/NetworkManager/conf.d/10-wait-online.conf << 'NMWAIT'
[main]
# Wait for connection on boot - ensures network is ready for first-boot installer
autoconnect-retries-default=3
NMWAIT

# Enable NetworkManager-wait-online for services that need network
arch-chroot /mnt systemctl enable NetworkManager-wait-online.service 2>/dev/null || true
log "Network credentials and autoconnect configured"
# Use multi-user target for first boot (TTY-based installer)
arch-chroot /mnt systemctl set-default multi-user.target
log "Services enabled (SDDM will be enabled after Omarchy install)"

#===============================================================================
# CONFIGURE TTY AUTOLOGIN FOR FIRST BOOT
#===============================================================================

log "Configuring TTY autologin for first-boot installer..."

# Create autologin to TTY1 as the user (like patch-omarchy-dualboot.sh does for live env)
mkdir -p /mnt/etc/systemd/system/getty@tty1.service.d
cat > /mnt/etc/systemd/system/getty@tty1.service.d/autologin.conf << GETTY_AUTOLOGIN
[Service]
ExecStart=
ExecStart=-/sbin/agetty --autologin $USERNAME --noclear %I \$TERM
GETTY_AUTOLOGIN

log "TTY1 autologin configured for user: $USERNAME"

#===============================================================================
# PREPARE SDDM CONFIG (will be enabled after Omarchy install)
#===============================================================================

log "Preparing SDDM config (not enabled yet)..."
mkdir -p /mnt/etc/sddm.conf.d
cat > /mnt/etc/sddm.conf.d/autologin.conf << SDDM
[Autologin]
User=$USERNAME
Session=hyprland-uwsm
[Theme]
Current=breeze
SDDM
log "SDDM config prepared for post-install"

#===============================================================================
# CREATE CACHYOS-AWARE OMARCHY PACMAN CONFIGS
# Omarchy's default pacman configs only include Arch repos + [omarchy].
# We replace them with versions that also include CachyOS repos so that
# omarchy-refresh-pacman, install/post-install/pacman.sh, and future
# re-installs all preserve CachyOS optimized packages.
#===============================================================================

log "Creating CachyOS-aware pacman configs for Omarchy..."

# Determine CachyOS optimized mirrorlist path for this CPU
if [[ "$DETECTED_ARCH" == "x86_64_znver4" ]] || [[ "$DETECTED_ARCH" == "x86_64_v4" ]]; then
    CACHYOS_OPTIM_ML="/etc/pacman.d/cachyos-v4-mirrorlist"
else
    CACHYOS_OPTIM_ML="/etc/pacman.d/cachyos-v3-mirrorlist"
fi

# Function to generate a CachyOS-aware pacman.conf
# Args: $1 = omarchy channel (stable|edge), $2 = output file
generate_cachyos_pacman_conf() {
    local channel="$1" output="$2"

    # [options] section - no variable expansion needed
    cat > "$output" << 'PACCONF_OPTS'
# CachyOS + Omarchy pacman.conf - generated by omacat installer
# Includes CachyOS optimized repos alongside Arch repos

[options]
Color
ILoveCandy
VerbosePkgLists
HoldPkg = pacman glibc
Architecture = auto
CheckSpace
ParallelDownloads = 10
DisableDownloadTimeout
DownloadUser = alpm
SigLevel = Required DatabaseOptional
LocalFileSigLevel = Optional
PACCONF_OPTS

    # CachyOS optimized repos (v4/v3/znver4) - only if CPU supports it
    if [[ "$USE_CACHYOS_BASE" == "true" ]]; then
        cat >> "$output" << PACCONF_CACHY

# CachyOS $DETECTED_ARCH optimized repos - MUST be listed ABOVE Arch repos
# These provide optimized builds that override standard Arch packages
[$CACHYOS_CORE_REPO]
Include = $CACHYOS_OPTIM_ML

[$CACHYOS_EXTRA_REPO]
Include = $CACHYOS_OPTIM_ML
PACCONF_CACHY
    fi

    # CachyOS base repo + standard Arch repos - no expansion needed
    cat >> "$output" << 'PACCONF_REPOS'

# CachyOS base repo (keyrings, tools, kernels) - x86_64 only
[cachyos]
Include = /etc/pacman.d/cachyos-x86_64-mirrorlist

# Arch Linux repos
[core]
Include = /etc/pacman.d/mirrorlist

[extra]
Include = /etc/pacman.d/mirrorlist

[multilib]
Include = /etc/pacman.d/mirrorlist
PACCONF_REPOS

    # Omarchy repo - channel variable needs expansion
    cat >> "$output" << PACCONF_OMARCHY

[omarchy]
SigLevel = Optional TrustAll
Server = https://pkgs.omarchy.org/${channel}/\$arch
PACCONF_OMARCHY
}

# Overwrite Omarchy's default pacman configs with CachyOS-aware versions
generate_cachyos_pacman_conf "stable" "/mnt/opt/omarchy-assets/omarchy/default/pacman/pacman-stable.conf"
generate_cachyos_pacman_conf "edge" "/mnt/opt/omarchy-assets/omarchy/default/pacman/pacman-edge.conf"
log "Omarchy pacman configs now include CachyOS repos"

# Save backup copies to /etc/omacat/ for recovery
# These survive git pull of Omarchy source and can be used to restore
mkdir -p /mnt/etc/omacat
cp /mnt/opt/omarchy-assets/omarchy/default/pacman/pacman-stable.conf /mnt/etc/omacat/
cp /mnt/opt/omarchy-assets/omarchy/default/pacman/pacman-edge.conf /mnt/etc/omacat/
cp /mnt/etc/pacman.d/cachyos-*-mirrorlist /mnt/etc/omacat/ 2>/dev/null || true
log "Backup configs saved to /etc/omacat/"

# Create script to check and restore CachyOS repos if they go missing
# Can be called manually: sudo omacat-ensure-cachyos-repos [stable|edge]
mkdir -p /mnt/usr/local/bin
cat > /mnt/usr/local/bin/omacat-ensure-cachyos-repos << 'ENSURE_SCRIPT'
#!/bin/bash
# Ensure CachyOS repos are present in pacman.conf
# Called automatically by pacman hook, or run manually:
#   sudo omacat-ensure-cachyos-repos [stable|edge]

CHANNEL="${1:-stable}"
BACKUP="/etc/omacat/pacman-${CHANNEL}.conf"

[[ ! -f "$BACKUP" ]] && exit 0

if ! grep -q '\[cachyos\]' /etc/pacman.conf 2>/dev/null; then
    cp -f "$BACKUP" /etc/pacman.conf
    echo "omacat: Restored CachyOS repos to pacman.conf (${CHANNEL})"

    # Also update Omarchy defaults so omarchy-refresh-pacman stays correct
    for homedir in /home/*/; do
        omarchy_conf="${homedir}.local/share/omarchy/default/pacman/pacman-${CHANNEL}.conf"
        if [[ -d "$(dirname "$omarchy_conf")" ]]; then
            cp -f "$BACKUP" "$omarchy_conf" 2>/dev/null || true
        fi
    done
fi

# Also ensure CachyOS mirrorlist files exist
for ml in /etc/omacat/cachyos-*-mirrorlist; do
    [[ ! -f "$ml" ]] && continue
    target="/etc/pacman.d/$(basename "$ml")"
    if [[ ! -f "$target" ]]; then
        cp -f "$ml" "$target"
        echo "omacat: Restored $(basename "$ml")"
    fi
done
ENSURE_SCRIPT
chmod +x /mnt/usr/local/bin/omacat-ensure-cachyos-repos

# Create pacman hook to auto-preserve CachyOS repos after relevant package updates
mkdir -p /mnt/etc/pacman.d/hooks
cat > /mnt/etc/pacman.d/hooks/zz-preserve-cachyos-repos.hook << 'PRESERVE_HOOK'
[Trigger]
Operation = Install
Operation = Upgrade
Type = Package
Target = pacman
Target = cachyos-mirrorlist
Target = cachyos-settings
Target = cachyos-keyring

[Action]
Description = Ensuring CachyOS repos are preserved in pacman.conf...
When = PostTransaction
Exec = /usr/local/bin/omacat-ensure-cachyos-repos
PRESERVE_HOOK

log "CachyOS repo preservation hook installed"

# Create systemd path unit to watch /etc/pacman.conf for changes
# If CachyOS repos are removed (by any mechanism), auto-restore them
cat > /mnt/etc/systemd/system/omacat-pacman-guard.path << 'GUARD_PATH'
[Unit]
Description=Watch pacman.conf for CachyOS repo removal

[Path]
PathChanged=/etc/pacman.conf

[Install]
WantedBy=multi-user.target
GUARD_PATH

cat > /mnt/etc/systemd/system/omacat-pacman-guard.service << 'GUARD_SERVICE'
[Unit]
Description=Restore CachyOS repos to pacman.conf if missing

[Service]
Type=oneshot
ExecStart=/usr/local/bin/omacat-ensure-cachyos-repos
GUARD_SERVICE

# Enable the path watcher
arch-chroot /mnt systemctl enable omacat-pacman-guard.path 2>/dev/null || true
log "systemd pacman.conf watcher enabled"

# Save git post-merge hook template to /etc/omacat/
# This hook re-deploys CachyOS configs after Omarchy git pull,
# BEFORE migrations run (which may call omarchy-refresh-pacman).
# The first-boot script installs it into Omarchy's .git/hooks/ if present.
cat > /mnt/etc/omacat/git-post-merge-hook << 'GIT_HOOK'
#!/bin/bash
# Git post-merge hook: re-deploy CachyOS-aware pacman configs after Omarchy git pull
# omarchy-update does: git pull → omarchy-update-perform → omarchy-migrate
# Migrations may call omarchy-refresh-pacman which copies templates to /etc/pacman.conf
# This hook runs during git pull (BEFORE migrations), restoring CachyOS-aware templates

REPO_ROOT="$(git rev-parse --show-toplevel 2>/dev/null)"

# Re-deploy CachyOS-aware pacman configs
if [[ -f /etc/omacat/pacman-stable.conf ]]; then
    if [[ -n "$REPO_ROOT" && -d "$REPO_ROOT/default/pacman" ]]; then
        cp -f /etc/omacat/pacman-stable.conf "$REPO_ROOT/default/pacman/pacman-stable.conf" 2>/dev/null || true
        cp -f /etc/omacat/pacman-edge.conf "$REPO_ROOT/default/pacman/pacman-edge.conf" 2>/dev/null || true
    fi
fi

# Re-deploy CachyOS-aware kernel check (supports linux-cachyos package name)
if [[ -f /etc/omacat/omarchy-update-restart && -n "$REPO_ROOT" ]]; then
    cp -f /etc/omacat/omarchy-update-restart "$REPO_ROOT/bin/omarchy-update-restart" 2>/dev/null || true
    chmod +x "$REPO_ROOT/bin/omarchy-update-restart" 2>/dev/null || true
fi
GIT_HOOK
chmod +x /mnt/etc/omacat/git-post-merge-hook
log "Git post-merge hook template saved to /etc/omacat/"

#===============================================================================
# CREATE FIRST-BOOT OMARCHY INSTALLER
#===============================================================================

header "SETTING UP AUTOMATIC OMARCHY INSTALL"

log "Creating first-boot Omarchy installer..."

# Create first-boot Omarchy installer script
# Note: We use a heredoc with variable substitution for USERNAME and FULLNAME
cat > "/mnt/home/$USERNAME/install-omarchy.sh" << OMARCHY_INSTALLER
#!/bin/bash
# OMACAT First-Boot Omarchy Installer (runs automatically)

# Note: NOT using set -e so cleanup always runs even if there are errors

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'

# Prevent running multiple times simultaneously
LOCKFILE="/tmp/omarchy-install.lock"
if [[ -f "\$LOCKFILE" ]]; then
    exit 0
fi
touch "\$LOCKFILE"
trap "rm -f \$LOCKFILE" EXIT

clear
echo ""
echo -e "\${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\${NC}"
echo -e "\${BOLD}  OMACAT - Automatic Omarchy Installation\${NC}"
echo -e "\${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\${NC}"
echo ""

#-------------------------------------------------------------------------------
# NETWORK CHECK - Allow user to reconnect WiFi if needed
#-------------------------------------------------------------------------------

check_network() {
    curl -sf --connect-timeout 5 --max-time 10 -o /dev/null https://archlinux.org/ 2>/dev/null
}

setup_wifi() {
    echo ""
    echo -e "\${YELLOW}WiFi Setup\${NC}"
    echo ""

    # Unblock and start services
    sudo rfkill unblock wifi 2>/dev/null || true
    sudo systemctl start iwd 2>/dev/null || true
    sleep 2

    # Find WiFi interface
    WIFI_IFACE=\$(iw dev 2>/dev/null | awk '\$1=="Interface"{print \$2}' | head -1)
    if [[ -z "\$WIFI_IFACE" ]]; then
        echo -e "\${RED}No WiFi interface found. Please use ethernet.\${NC}"
        return 1
    fi

    echo "Scanning for networks..."
    iwctl station "\$WIFI_IFACE" scan 2>/dev/null
    sleep 3

    echo ""
    echo "Available WiFi networks:"
    iwctl station "\$WIFI_IFACE" get-networks 2>/dev/null | head -20
    echo ""

    read -p "Enter WiFi network name (SSID): " WIFI_SSID
    [[ -z "\$WIFI_SSID" ]] && return 1

    read -s -p "Enter WiFi password: " WIFI_PASS
    echo ""

    echo "Connecting to \$WIFI_SSID..."
    iwctl --passphrase "\$WIFI_PASS" station "\$WIFI_IFACE" connect "\$WIFI_SSID" 2>/dev/null
    sleep 3

    # Get IP via DHCP
    if command -v dhcpcd &>/dev/null; then
        sudo dhcpcd "\$WIFI_IFACE" 2>/dev/null &
    elif command -v dhclient &>/dev/null; then
        sudo dhclient "\$WIFI_IFACE" 2>/dev/null &
    fi

    # Wait for connection
    for i in {1..10}; do
        sleep 1
        if check_network; then
            echo -e "\${GREEN}Connected to WiFi!\${NC}"
            return 0
        fi
        echo -n "."
    done

    echo ""
    echo -e "\${RED}WiFi connection failed.\${NC}"
    return 1
}

# Check network and offer WiFi setup if not connected
if check_network; then
    echo -e "\${GREEN}[✓]\${NC} Network connected"
else
    echo -e "\${YELLOW}[!]\${NC} No network connection detected."
    echo ""
    echo "Options:"
    echo "  1) Setup WiFi"
    echo "  2) Continue anyway (may fail if git clone needed)"
    echo "  3) Exit to shell"
    echo ""
    read -p "Select option [1]: " NET_CHOICE
    NET_CHOICE=\${NET_CHOICE:-1}

    case "\$NET_CHOICE" in
        1)
            while ! setup_wifi; do
                read -p "Try again? (Y/n): " retry
                [[ "\$retry" =~ ^[Nn]\$ ]] && break
            done
            ;;
        2)
            echo -e "\${YELLOW}Continuing without network...\${NC}"
            ;;
        3)
            echo "Exiting. Run ~/install-omarchy.sh when ready."
            rm -f \$LOCKFILE
            exit 0
            ;;
    esac
fi

echo ""
echo "Your CachyOS base is ready. Installing Omarchy desktop..."
echo ""
echo "This will take several minutes. Please wait..."
echo ""

# Pre-configure git with user info from install
git config --global user.name "$FULLNAME"

# Copy Omarchy from embedded files (installed from ISO)
if [[ ! -d ~/.local/share/omarchy ]]; then
    echo "Copying Omarchy from local installation..."
    mkdir -p ~/.local/share
    if [[ -d /opt/omarchy-assets/omarchy ]]; then
        cp -r /opt/omarchy-assets/omarchy ~/.local/share/omarchy
        # Fix execute permissions on all scripts (lost during ISO copy)
        chmod +x ~/.local/share/omarchy/bin/* 2>/dev/null || true
        chmod +x ~/.local/share/omarchy/install.sh 2>/dev/null || true
        find ~/.local/share/omarchy -name "*.sh" -exec chmod +x {} \; 2>/dev/null || true
        echo "Omarchy copied from embedded files (permissions fixed)"
    else
        echo "ERROR: Omarchy files not found at /opt/omarchy-assets/omarchy"
        echo "Falling back to git clone..."
        git clone https://github.com/basecamp/omarchy.git ~/.local/share/omarchy
    fi
fi

cd ~/.local/share/omarchy || { echo "ERROR: Could not cd to omarchy directory"; exit 1; }

# Install git post-merge hook to preserve CachyOS configs during omarchy-update
# omarchy-update does: git pull → migrations → some migrations call omarchy-refresh-pacman
# The hook runs during git pull (BEFORE migrations), re-deploying CachyOS-aware templates
# so that omarchy-refresh-pacman copies the correct config to /etc/pacman.conf
if [[ -d .git/hooks ]] && [[ -f /etc/omacat/git-post-merge-hook ]]; then
    cp -f /etc/omacat/git-post-merge-hook .git/hooks/post-merge
    chmod +x .git/hooks/post-merge
    echo "Git post-merge hook installed (preserves CachyOS repos during omarchy-update)"
elif [[ -d .git ]]; then
    mkdir -p .git/hooks
    cp -f /etc/omacat/git-post-merge-hook .git/hooks/post-merge 2>/dev/null || true
    chmod +x .git/hooks/post-merge 2>/dev/null || true
    echo "Git post-merge hook installed"
fi

# Make CachyOS-specific modifications
echo "Applying CachyOS compatibility patches..."

# Remove guard.sh - checks for /etc/cachyos-release and blocks non-Vanilla-Arch installs
# On CachyOS this always fails and either blocks waiting for gum confirm or crashes install.sh
sed -i '/source \\\$OMARCHY_INSTALL\/preflight\/guard\.sh/d' install/preflight/all.sh 2>/dev/null || true

# Remove tldr to prevent conflict with tealdeer
sed -i '/^tldr\$/d' install/omarchy-base.packages 2>/dev/null || true

# Remove pacman.sh from preflight - keep CachyOS pacman config
sed -i '/run_logged \\\$OMARCHY_INSTALL\/preflight\/pacman\.sh/d' install/preflight/all.sh 2>/dev/null || true

# Remove nvidia.sh - GPU drivers already installed during base install
sed -i '/run_logged \\\$OMARCHY_INSTALL\/config\/hardware\/nvidia\.sh/d' install/config/all.sh 2>/dev/null || true

# Remove plymouth.sh - keep existing bootloader
sed -i '/run_logged \\\$OMARCHY_INSTALL\/login\/plymouth\.sh/d' install/login/all.sh 2>/dev/null || true

# Remove limine-snapper.sh - keep existing bootloader
sed -i '/run_logged \\\$OMARCHY_INSTALL\/login\/limine-snapper\.sh/d' install/login/all.sh 2>/dev/null || true

# Remove alt-bootloaders.sh
sed -i '/run_logged \\\$OMARCHY_INSTALL\/login\/alt-bootloaders\.sh/d' install/login/all.sh 2>/dev/null || true

# Remove pacman.sh from post-install - keep CachyOS config
sed -i '/run_logged \\\$OMARCHY_INSTALL\/post-install\/pacman\.sh/d' install/post-install/all.sh 2>/dev/null || true

# Fix kernel version check in update-restart for CachyOS kernel
# Original checks 'pacman -Q linux' which doesn't exist on CachyOS (we use linux-cachyos)
# Also fixes version comparison: uname -r returns '6.x.x-2-cachyos' but pacman returns '6.x.x-2'
cat > bin/omarchy-update-restart << 'UPDATE_RESTART'
#!/bin/bash

# Kernel reboot check - supports both linux and linux-cachyos
RUNNING=\$(uname -r)
if pacman -Q linux-cachyos &>/dev/null; then
    INSTALLED=\$(pacman -Q linux-cachyos | awk '{print \$2}')
    RUNNING_CLEAN=\$(echo "\$RUNNING" | sed 's/-cachyos\$//')
elif pacman -Q linux &>/dev/null; then
    INSTALLED=\$(pacman -Q linux | awk '{print \$2}')
    RUNNING_CLEAN=\$(echo "\$RUNNING" | sed 's/-arch/.arch/')
else
    INSTALLED="\$RUNNING"
    RUNNING_CLEAN="\$RUNNING"
fi

if [ "\$RUNNING_CLEAN" != "\$INSTALLED" ]; then
    gum confirm "Linux kernel has been updated. Reboot?" && omarchy-cmd-reboot
elif [ -f "\$HOME/.local/state/omarchy/reboot-required" ]; then
    gum confirm "Updates require reboot. Ready?" && omarchy-cmd-reboot
fi

for file in "\$HOME"/.local/state/omarchy/restart-*-required; do
    if [ -f "\$file" ]; then
        filename=\$(basename "\$file")
        service=\$(echo "\$filename" | sed 's/restart-\(.*\)-required/\1/')
        echo "Restarting \$service"
        omarchy-state clear "\$filename"
        omarchy-restart-"\$service"
    fi
done
UPDATE_RESTART
chmod +x bin/omarchy-update-restart

# Save patched update-restart to /etc/omacat/ so it survives omarchy-update (git pull)
sudo cp bin/omarchy-update-restart /etc/omacat/omarchy-update-restart 2>/dev/null || true

echo ""
echo "Running Omarchy installer..."
echo ""

# Patch all gum confirm calls to auto-confirm (prevents interactive Yes/No prompts)
echo "Patching gum confirm calls for unattended install..."
find . -name "*.sh" -exec sed -i 's/gum confirm.*/true/g' {} \; 2>/dev/null || true

# Run the Omarchy installer (don't exit on failure - we need cleanup to run)
chmod +x install.sh
if ./install.sh; then
    echo "Omarchy installer completed successfully"
else
    echo "Omarchy installer had some errors but continuing..."
fi

# Verify CachyOS repos survived Omarchy's install.sh
echo ""
echo "Verifying CachyOS repos in pacman.conf..."
if ! grep -q '\[cachyos\]' /etc/pacman.conf 2>/dev/null; then
    echo "CachyOS repos missing from pacman.conf - restoring..."
    if [[ -f /etc/omacat/pacman-stable.conf ]]; then
        sudo cp -f /etc/omacat/pacman-stable.conf /etc/pacman.conf
        echo "CachyOS repos restored from /etc/omacat/ backup"
    else
        echo "WARNING: No backup found at /etc/omacat/pacman-stable.conf"
        echo "CachyOS packages may not update correctly"
    fi
else
    echo "CachyOS repos verified in pacman.conf"
fi

# Re-deploy CachyOS-aware configs to Omarchy defaults
# (install.sh may have overwritten them via git operations)
if [[ -f /etc/omacat/pacman-stable.conf ]]; then
    cp -f /etc/omacat/pacman-stable.conf ~/.local/share/omarchy/default/pacman/pacman-stable.conf 2>/dev/null || true
    cp -f /etc/omacat/pacman-edge.conf ~/.local/share/omarchy/default/pacman/pacman-edge.conf 2>/dev/null || true
    echo "CachyOS-aware configs deployed to Omarchy defaults"
fi

# Note: User password was already set during base install (chpasswd)
# No need to re-prompt - Omarchy installer does not modify the password

# Fix PATH for Omarchy binaries (not persisted by Omarchy installer)
# Add directly to hyprland.conf since envs.conf isn't sourced
echo "" >> ~/.config/hypr/hyprland.conf
echo "# Omarchy bin path" >> ~/.config/hypr/hyprland.conf
echo 'env = PATH,\$HOME/.local/share/omarchy/bin:\$PATH' >> ~/.config/hypr/hyprland.conf

# Also add to bashrc for terminal access
if ! grep -q "omarchy/bin" ~/.bashrc 2>/dev/null; then
    echo "" >> ~/.bashrc
    echo '# Omarchy bin path' >> ~/.bashrc
    echo 'export PATH="\$HOME/.local/share/omarchy/bin:\$PATH"' >> ~/.bashrc
fi

# Configure snapper for btrfs snapshots
echo ""
echo "Configuring snapper for system snapshots..."

# Create snapper config for root - this creates .snapshots as nested subvolume
sudo snapper -c root create-config / || echo "snapper create-config had issues (may already exist)"

# Enable and start snapper services
sudo systemctl enable --now snapper-cleanup.timer
sudo systemctl enable --now snapper-timeline.timer
sudo systemctl enable --now limine-snapper-sync.service

# Create initial snapshot
echo "Creating initial snapshot..."
sudo snapper -c root create -d "Post-Omarchy install" || echo "Could not create initial snapshot"

# Sync snapshots to limine boot menu
echo "Syncing snapshots to boot menu..."
sudo limine-snapper-sync || echo "limine-snapper-sync had issues"

echo "Snapper configured with bootable snapshots"

# NOTE: Mirrors were already configured during base install and copied to the
# installed system. No need to run reflector again here - it can break working
# mirrors and cause install failures.

# Cleanup - remove ALL first-boot items after successful install
rm -f ~/install-omarchy.sh

# Remove bash_profile hook completely
# Our installer hook is exactly 4 lines, so if file is small and has our marker, delete it
# Otherwise, surgically remove just our lines to preserve user content
if [[ -f ~/.bash_profile ]]; then
    PROFILE_LINES=\$(wc -l < ~/.bash_profile)
    if grep -q 'First-boot Omarchy installer' ~/.bash_profile && [[ \$PROFILE_LINES -le 4 ]]; then
        # File only contains our installer hook - safe to delete entirely
        rm -f ~/.bash_profile
    elif grep -q 'First-boot Omarchy installer' ~/.bash_profile; then
        # Has other content plus our hook - remove just our lines
        sed -i '/First-boot Omarchy installer/d' ~/.bash_profile 2>/dev/null || true
        sed -i '/install-omarchy\.sh/d' ~/.bash_profile 2>/dev/null || true
        sed -i '/\[\[ -f ~\/install-omarchy\.sh/d' ~/.bash_profile 2>/dev/null || true
        sed -i '/^fi\$/d' ~/.bash_profile 2>/dev/null || true
        # Remove empty lines left behind
        sed -i '/^[[:space:]]*\$/d' ~/.bash_profile 2>/dev/null || true
    fi
fi

#===============================================================================
# POST-INSTALL FIXES (WiFi, CachyOS packages, system upgrade)
#===============================================================================

echo ""
echo "Applying post-install optimizations..."
echo ""

# --- WiFi Fix: iwd backend + route-metric ---
echo "Configuring WiFi (iwd backend)..."

# NetworkManager depends on wpa_supplicant on Arch/CachyOS; keep package but stop/disable service
if systemctl is-active --quiet wpa_supplicant 2>/dev/null; then
    sudo systemctl stop wpa_supplicant || true
fi
if systemctl is-enabled --quiet wpa_supplicant 2>/dev/null; then
    sudo systemctl disable wpa_supplicant || true
fi

# Enable and start iwd
if ! systemctl is-enabled --quiet iwd 2>/dev/null; then
    sudo systemctl enable iwd || true
fi
if ! systemctl is-active --quiet iwd 2>/dev/null; then
    sudo systemctl start iwd || true
fi

# Create iwd config for stable operation with NetworkManager
sudo mkdir -p /etc/iwd
if [[ ! -f /etc/iwd/main.conf ]]; then
    sudo tee /etc/iwd/main.conf > /dev/null << 'IWDCONF'
[General]
EnableNetworkConfiguration=false
UseDefaultInterface=true

[Network]
EnableIPv6=true
RoutePriorityOffset=100
IWDCONF
    echo "Created iwd config"
fi

# Ensure NetworkManager waits for iwd on boot
sudo mkdir -p /etc/systemd/system/NetworkManager.service.d
sudo tee /etc/systemd/system/NetworkManager.service.d/iwd.conf > /dev/null << 'NMIWDDROP'
[Unit]
After=iwd.service
Wants=iwd.service
NMIWDDROP
sudo systemctl daemon-reload

# Configure NetworkManager to use iwd backend
sudo mkdir -p /etc/NetworkManager/conf.d
sudo rm -f /etc/NetworkManager/conf.d/20-wifi-powersave-metric.conf
sudo tee /etc/NetworkManager/conf.d/20-wifi-iwd-backend.conf > /dev/null << 'NMCONF'
[device]
# Use iwd as the WiFi backend (Omarchy default)
wifi.backend=iwd

[connection]
# Disable WiFi power saving (can cause connectivity issues)
wifi.powersave=2

[connection-wifi-defaults]
match-device=type:wifi
ipv4.route-metric=50
ipv6.route-metric=50
NMCONF

# Restart NetworkManager to apply changes
sudo systemctl restart NetworkManager
sleep 2

# Fix existing WiFi connections route metrics
while IFS= read -r line; do
    [[ -z "\$line" ]] && continue
    conn_name=\$(echo "\$line" | sed 's/:802-11-wireless\$//' | sed 's/:wifi\$//')
    if [[ -n "\$conn_name" ]]; then
        sudo nmcli connection modify "\$conn_name" ipv4.route-metric 50 ipv6.route-metric 50 2>/dev/null && \
            echo "Set route-metric 50 for: \$conn_name" || true
    fi
done < <(nmcli -t -f NAME,TYPE connection show 2>/dev/null | grep -E ':(wifi|802-11-wireless)\$')

echo "WiFi configured: iwd backend with route-metric 50"

# --- CachyOS Package Optimizations ---
echo ""
echo "Installing CachyOS optimized packages..."

# Migrate zlib to zlib-ng-compat (faster compression)
if pacman -Q zlib &>/dev/null && ! pacman -Q zlib-ng-compat &>/dev/null; then
    echo "Migrating zlib -> zlib-ng-compat..."
    sudo pacman -S --noconfirm --ask=4 zlib-ng-compat || echo "zlib-ng migration had issues"
fi

# Migrate lib32-zlib if present
if pacman -Q lib32-zlib &>/dev/null && ! pacman -Q lib32-zlib-ng-compat &>/dev/null; then
    echo "Migrating lib32-zlib -> lib32-zlib-ng-compat..."
    sudo pacman -S --noconfirm --ask=4 lib32-zlib-ng-compat || echo "lib32-zlib-ng migration had issues"
fi

# Install cachyos-settings (includes ananicy-cpp for process scheduling)
if ! pacman -Q cachyos-settings &>/dev/null; then
    echo "Installing cachyos-settings..."
    if sudo pacman -S --noconfirm --ask=4 cachyos-settings; then
        sudo systemctl enable --now ananicy-cpp 2>/dev/null || true
        echo "cachyos-settings installed"
    fi
else
    echo "cachyos-settings already installed"
fi

# --- System Upgrade ---
echo ""
echo "Running system upgrade..."
sudo pacman -Syu --noconfirm || echo "System upgrade had some issues"

echo ""
echo "Post-install optimizations complete!"

# Remove temporary NOPASSWD sudo (back to password-required)
sudo rm -f /etc/sudoers.d/first-boot-nopasswd
# Remove TTY autologin override (SDDM will handle login now)
sudo rm -f /etc/systemd/system/getty@tty1.service.d/autologin.conf
sudo rmdir /etc/systemd/system/getty@tty1.service.d 2>/dev/null || true

# Enable SDDM and switch to graphical target for next boot
echo ""
echo "Enabling SDDM display manager..."
sudo systemctl enable sddm
sudo systemctl set-default graphical.target

echo ""
echo -e "\${GREEN}Omarchy installation complete!\${NC}"
echo ""
echo "System will reboot in 5 seconds to full Omarchy desktop..."
sleep 5
sudo reboot
OMARCHY_INSTALLER

chmod +x "/mnt/home/$USERNAME/install-omarchy.sh"
arch-chroot /mnt chown "$USERNAME:$USERNAME" "/home/$USERNAME/install-omarchy.sh"

# Create .bash_profile to auto-run installer on TTY login
# This is the same approach used by patch-omarchy-dualboot.sh for the live environment
cat > "/mnt/home/$USERNAME/.bash_profile" << 'BASH_PROFILE'
# First-boot Omarchy installer - will remove itself after running
if [[ -f ~/install-omarchy.sh ]] && [[ $(tty) == "/dev/tty1" ]]; then
    ~/install-omarchy.sh
fi
BASH_PROFILE

# Fix ownership of all user files
arch-chroot /mnt chown -R "$USERNAME:$USERNAME" "/home/$USERNAME"

log "Automatic first-boot Omarchy installer configured (TTY autologin + .bash_profile)"

# Note: Most services (cups, docker, ufw, etc.) will be enabled by Omarchy installer
# during first boot after packages are installed. We only enable services that
# are already installed from the base install.

# Add user to input group (for Hyprland input handling)
arch-chroot /mnt usermod -aG input "$USERNAME" 2>/dev/null || true

#===============================================================================
# CLEANUP
#===============================================================================

header "FINISHING UP"

trap - ERR

sync

# Kill any processes still using /mnt before unmounting
log "Cleaning up mount points..."
fuser -km /mnt 2>/dev/null || true
sleep 1

# Unmount in correct order - specific mounts first, then recursive
umount /mnt/boot 2>/dev/null || true
umount /mnt/var/tmp 2>/dev/null || true
umount /mnt/var/cache/pacman/pkg 2>/dev/null || true
umount /mnt/var/log 2>/dev/null || true
umount /mnt/home 2>/dev/null || true

# Final recursive unmount with lazy fallback
if ! umount -R /mnt 2>/dev/null; then
    warn "Normal unmount failed, trying lazy unmount..."
    umount -lR /mnt 2>/dev/null || true
fi

cryptsetup close cryptroot 2>/dev/null || true

#===============================================================================
# DONE
#===============================================================================

echo ""
echo -e "${GREEN}╔══════════════════════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║                                                              ║${NC}"
echo -e "${GREEN}║   OMACAT Base Installation Complete!                         ║${NC}"
echo -e "${GREEN}║                                                              ║${NC}"
echo -e "${GREEN}║   • CachyOS base with optimized kernel                       ║${NC}"
echo -e "${GREEN}║   • Limine bootloader with LUKS2 encryption                  ║${NC}"
echo -e "${GREEN}║   • Btrfs filesystem with snapshots                          ║${NC}"
echo -e "${GREEN}║                                                              ║${NC}"
echo -e "${GREEN}╚══════════════════════════════════════════════════════════════╝${NC}"
echo ""
echo "  Username: $USERNAME"
echo "  Hostname: $TARGET_HOSTNAME"
echo ""
echo -e "${CYAN}  AUTOMATIC NEXT STEP:${NC}"
echo ""
echo "  After reboot, the Omarchy desktop installation will"
echo "  start AUTOMATICALLY. Just wait for it to complete."
echo ""
echo "  You may be prompted for your sudo password during install."
echo ""
echo -e "${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${YELLOW}  ⚠  REMOVE THE USB DRIVE BEFORE REBOOTING  ⚠${NC}"
echo -e "${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""
read -p "Remove USB drive, then press Enter to reboot..." _
reboot
INSTALLER

chmod +x "$WORK_DIR/cachy_extract/root/omacat-install.sh"

#===============================================================================
# CONFIGURE AUTO-START
#===============================================================================

log "Configuring installer auto-start..."

# Disable SDDM in live environment
rm -f "$WORK_DIR/cachy_extract/etc/systemd/system/display-manager.service" 2>/dev/null || true

# Create autologin to TTY1 as root
mkdir -p "$WORK_DIR/cachy_extract/etc/systemd/system/getty@tty1.service.d"
cat > "$WORK_DIR/cachy_extract/etc/systemd/system/getty@tty1.service.d/autologin.conf" << 'EOF'
[Service]
ExecStart=
ExecStart=-/sbin/agetty --autologin root --noclear %I $TERM
EOF

# Auto-start installer with proper lockfile cleanup
cat > "$WORK_DIR/cachy_extract/root/.zlogin" << 'EOF'
if [[ $(tty) == "/dev/tty1" ]]; then
    LOCKFILE="/tmp/omacat-install.lock"
    if [[ ! -f "$LOCKFILE" ]]; then
        touch "$LOCKFILE"
        # Trap to ensure lockfile is removed on any exit (success, failure, or signal)
        trap 'rm -f "$LOCKFILE"' EXIT
        /root/omacat-install.sh
        # Note: trap will clean up lockfile automatically on exit
    fi
fi
EOF

cat > "$WORK_DIR/cachy_extract/root/.bash_profile" << 'EOF'
if [[ $(tty) == "/dev/tty1" ]]; then
    LOCKFILE="/tmp/omacat-install.lock"
    if [[ ! -f "$LOCKFILE" ]]; then
        touch "$LOCKFILE"
        # Trap to ensure lockfile is removed on any exit (success, failure, or signal)
        trap 'rm -f "$LOCKFILE"' EXIT
        /root/omacat-install.sh
        # Note: trap will clean up lockfile automatically on exit
    fi
fi
EOF

#===============================================================================
# REPACK SQUASHFS
#===============================================================================

log "Repacking squashfs..."
rm -f "$WORK_DIR/newiso/arch/x86_64/airootfs.sfs"
mksquashfs "$WORK_DIR/cachy_extract" "$WORK_DIR/newiso/arch/x86_64/airootfs.sfs" \
    -comp zstd -Xcompression-level 3

log "Updating checksum..."
cd "$WORK_DIR/newiso/arch/x86_64"
sha512sum airootfs.sfs > airootfs.sha512

#===============================================================================
# CREATE ISO
#===============================================================================

log "Creating ISO..."

# Use the label we detected from the original CachyOS ISO
ISO_LABEL="$ORIG_ISO_LABEL"
log "Using ISO label: $ISO_LABEL"

# Find EFI boot file (case-insensitive search)
EFI_BOOT=$(find "$WORK_DIR/newiso/EFI/BOOT" -iname "bootx64.efi" 2>/dev/null | head -1)
if [[ -n "$EFI_BOOT" ]]; then
    EFI_BOOT_REL="${EFI_BOOT#"$WORK_DIR"/newiso/}"
    log "Found EFI boot: $EFI_BOOT_REL"
else
    warn "No EFI boot file found"
    EFI_BOOT_REL="EFI/BOOT/BOOTx64.EFI"
fi

# Create EFI boot image for hybrid ISO
log "Creating EFI boot image..."
EFI_IMG_PATH="$WORK_DIR/efiboot.img"
# Calculate size needed for EFI partition (EFI files + padding)
# FAT32 requires minimum ~33MB, so ensure we meet that threshold with margin
EFI_SIZE=$(du -sk "$WORK_DIR/newiso/EFI" 2>/dev/null | cut -f1)
EFI_SIZE=$((EFI_SIZE + 4096))  # Add 4MB padding for filesystem overhead
# FAT32 needs at least 33MB to be valid; use 36MB minimum for safety margin
[[ $EFI_SIZE -lt 36864 ]] && EFI_SIZE=36864
dd if=/dev/zero of="$EFI_IMG_PATH" bs=1K count=$EFI_SIZE 2>/dev/null
# Use FAT32 for maximum UEFI firmware compatibility
# Fall back to FAT16 if FAT32 fails (should not happen with 36MB+ image)
if ! mkfs.fat -F 32 "$EFI_IMG_PATH" >/dev/null 2>&1; then
    warn "FAT32 format failed, falling back to FAT16"
    mkfs.fat -F 16 "$EFI_IMG_PATH" >/dev/null 2>&1 || error "Failed to format EFI image"
fi
# Mount and copy EFI files
mkdir -p "$WORK_DIR/efi_mount"
mount -o loop "$EFI_IMG_PATH" "$WORK_DIR/efi_mount"
cp -r "$WORK_DIR/newiso/EFI" "$WORK_DIR/efi_mount/"
umount "$WORK_DIR/efi_mount"
# Copy efiboot.img into ISO structure
mkdir -p "$WORK_DIR/newiso/EFI/archiso"
cp "$EFI_IMG_PATH" "$WORK_DIR/newiso/EFI/archiso/efiboot.img"

# Build ISO
if [[ -f "$WORK_DIR/newiso/boot/syslinux/isolinux.bin" ]]; then
    xorriso -as mkisofs \
        -iso-level 3 \
        -full-iso9660-filenames \
        -volid "$ISO_LABEL" \
        -eltorito-boot boot/syslinux/isolinux.bin \
        -eltorito-catalog boot/syslinux/boot.cat \
        -no-emul-boot \
        -boot-load-size 4 \
        -boot-info-table \
        -isohybrid-mbr "$WORK_DIR/newiso/boot/syslinux/isohdpfx.bin" \
        -eltorito-alt-boot \
        -e EFI/archiso/efiboot.img \
        -no-emul-boot \
        -isohybrid-gpt-basdat \
        -o "$OUTPUT_ISO" \
        "$WORK_DIR/newiso"
else
    # UEFI-only boot
    xorriso -as mkisofs \
        -iso-level 3 \
        -full-iso9660-filenames \
        -volid "$ISO_LABEL" \
        -e EFI/archiso/efiboot.img \
        -no-emul-boot \
        -isohybrid-gpt-basdat \
        -o "$OUTPUT_ISO" \
        "$WORK_DIR/newiso"
fi

#===============================================================================
# DONE
#===============================================================================

echo ""
echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${GREEN}  SUCCESS!${NC}"
echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""
echo "  Created: $OUTPUT_ISO"
echo "  Size:    $(du -h "$OUTPUT_ISO" | cut -f1)"
echo ""
echo "  This ISO requires NETWORK for CachyOS packages during installation."
echo "  It will install:"
echo "    • CachyOS base (pacstrap - from online mirrors)"
echo "    • Omarchy desktop (from embedded files - local ISO)"
echo ""
