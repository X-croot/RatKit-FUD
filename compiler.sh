#!/usr/bin/env bash
set -euo pipefail

GREEN="\033[1;32m"
YELLOW="\033[1;33m"
RED="\033[1;31m"
BLUE="\033[1;34m"
CYAN="\033[1;36m"
RESET="\033[0m"
BOLD="\033[1m"
NC="\033[0m"

printf "${YELLOW}"
cat <<'ART'
 ▄████▄   ▒█████   ███▄ ▄███▓ ██▓███   ██▓ ██▓    ▓█████  ██▀███
▒██▀ ▀█  ▒██▒  ██▒▓██▒▀█▀ ██▒▓██░  ██▒▓██▒▓██▒    ▓█   ▀ ▓██ ▒ ██▒
▒▓█    ▄ ▒██░  ██▒▓██    ▓██░▓██░ ██▓▒▒██▒▒██░    ▒███   ▓██ ░▄█ ▒
▒▓▓▄ ▄██▒▒██   ██░▒██    ▒██ ▒██▄█▓▒ ▒░██░▒██░    ▒▓█  ▄ ▒██▀▀█▄
▒ ▓███▀ ░░ ████▓▒░▒██▒   ░██▒▒██▒ ░  ░░██░░██████▒░▒████▒░██▓ ▒██▒
░ ░▒ ▒  ░░ ▒░▒░▒░ ░ ▒░   ░  ░▒▓▒░ ░  ░░▓  ░ ▒░▓  ░░░ ▒░ ░░ ▒▓ ░▒▓░
  ░  ▒     ░ ▒ ▒░ ░  ░      ░░▒ ░      ▒ ░░ ░ ▒  ░ ░ ░  ░  ░▒ ░ ▒░
░        ░ ░ ░ ▒  ░      ░   ░░        ▒ ░  ░ ░      ░     ░░   ░
░ ░          ░ ░         ░             ░      ░  ░   ░  ░   ░
░                                         By https://github.com/X-croot
ART
printf "${RESET}"

log_info()  { echo -e "${BLUE}[*]${NC} $1"; }
log_ok()    { echo -e "${GREEN}[+]${NC} $1"; }
log_warn()  { echo -e "${YELLOW}[-]${NC} $1"; }
log_error() { echo -e "${RED}[!]${NC} $1"; }

CPP_FILES=(*.cpp)

if [ ${#CPP_FILES[@]} -eq 0 ]; then
  log_error "No .cpp files found!"
  exit 1
fi

echo
log_info "Available .cpp files:"
echo -e "${CYAN}────────────────────────────────────────────${NC}"
printf "${BOLD}%-5s %-40s${NC}\n" "ID" "File Name"
echo -e "${CYAN}────────────────────────────────────────────${NC}"

i=1
for f in "${CPP_FILES[@]}"; do
  printf "%-5s %-40s\n" "$i" "$f"
  ((i++))
done
echo -e "${CYAN}────────────────────────────────────────────${NC}"
echo

read -rp "Select file to compile [1-${#CPP_FILES[@]}]: " choice

if ! [[ "$choice" =~ ^[0-9]+$ ]] || [ "$choice" -lt 1 ] || [ "$choice" -gt ${#CPP_FILES[@]} ]; then
  log_error "Invalid selection!"
  exit 1
fi

SRC="${CPP_FILES[$((choice-1))]}"
OUT="${SRC%.cpp}.exe"
CC="${CROSS_COMPILE:-x86_64-w64-mingw32-g++}"
VCPKG_DIR="${HOME}/.vcpkg"
PKG="openssl:x64-mingw-static"

log_info "Source:   $SRC"
log_info "Output:   $OUT"
log_info "Compiler: $CC"

if ! command -v "$CC" >/dev/null 2>&1; then
  log_warn "mingw-w64 not found, installing..."
  if command -v apt-get >/dev/null 2>&1; then
    sudo apt-get update && sudo apt-get install -y mingw-w64
  elif command -v dnf >/dev/null 2>&1; then
    sudo dnf install -y mingw64-gcc
  elif command -v pacman >/dev/null 2>&1; then
    sudo pacman -S --noconfirm mingw-w64-gcc
  else
    log_error "Automatic mingw installation not supported."
    exit 1
  fi
  log_ok "mingw-w64 installed."
fi

if ! command -v git >/dev/null 2>&1; then
  log_warn "git not found, installing..."
  if command -v apt-get >/dev/null 2>&1; then
    sudo apt-get install -y git
  elif command -v dnf >/dev/null 2>&1; then
    sudo dnf install -y git
  elif command -v pacman >/dev/null 2>&1; then
    sudo pacman -S --noconfirm git
  fi
  log_ok "git installed."
fi

if [ ! -d "$VCPKG_DIR" ]; then
  log_info "Setting up vcpkg..."
  git clone https://github.com/microsoft/vcpkg.git "$VCPKG_DIR"
  "$VCPKG_DIR/bootstrap-vcpkg.sh"
  log_ok "vcpkg installed."
fi

if ! "$VCPKG_DIR/vcpkg" list | grep -q "$PKG"; then
  log_info "Installing OpenSSL via vcpkg..."
  "$VCPKG_DIR/vcpkg" install "$PKG"
  log_ok "OpenSSL installed."
fi

OPENSSL_ROOT="$VCPKG_DIR/installed/x64-mingw-static"
INCLUDE_DIR="$OPENSSL_ROOT/include"
LIB_DIR="$OPENSSL_ROOT/lib"

if [ ! -d "$INCLUDE_DIR/openssl" ]; then
  log_error "OpenSSL headers not found at $INCLUDE_DIR"
  exit 1
fi

log_info "Compiling..."
"$CC" "$SRC" \
  -I"$INCLUDE_DIR" \
  -L"$LIB_DIR" \
  -static -mwindows -static-libgcc -static-libstdc++ \
  -Wl,-Bstatic -lssl -lcrypto -lpthread \
  -Wl,-Bstatic -lws2_32 -lcrypt32 -lbcrypt -ladvapi32 \
  -O2 \
  -o "$OUT"

log_ok "Build complete: $OUT"
