#!/bin/bash
# eBPF Hunter v4.0 — Auto-installer
# Ubuntu/Debian-д зориулсан
# Хэрэглэх: sudo bash install.sh

set -e

echo "╔══════════════════════════════════════╗"
echo "║  eBPF Hunter v4.0  —  Installer      ║"
echo "╚══════════════════════════════════════╝"
echo ""

# Root шалгах
if [[ $EUID -ne 0 ]]; then
  echo "[!] Root эрх шаардлагатай: sudo bash install.sh"
  exit 1
fi

# OS шалгах
if ! grep -qi "ubuntu\|debian" /etc/os-release 2>/dev/null; then
  echo "[!] Ubuntu/Debian зориулсан. Бусад distro-д гар аар суулгана уу."
fi

# Kernel version шалгах
KVER=$(uname -r | cut -d. -f1-2 | tr -d '.')
if [[ "$KVER" -lt 415 ]]; then
  echo "[!] Kernel 4.15+ шаардлагатай. Одоогийн: $(uname -r)"
  exit 1
fi

echo "[1/4] Package шинэчилж байна..."
apt-get update -qq

echo "[2/4] BCC tools суулгаж байна..."
apt-get install -y -qq \
  bpfcc-tools \
  python3-bpfcc \
  linux-headers-$(uname -r) \
  python3-psutil \
  python3-pip 2>/dev/null || true

# Хэрэв python3-bpfcc байхгүй бол pip-ийн bcc
python3 -c "from bcc import BPF" 2>/dev/null || {
  echo "    pip-аар bcc суулгаж байна..."
  pip3 install bcc --quiet
}

echo "[3/4] psutil шалгаж байна..."
python3 -c "import psutil" 2>/dev/null || pip3 install psutil --quiet

echo "[4/4] Суулгалт шалгаж байна..."
python3 -c "from bcc import BPF; import psutil; print('[OK] Бүх dependency бэлэн')"

echo ""
echo "══════════════════════════════════════════"
echo "  Суулгалт амжилттай!"
echo ""
echo "  Ажиллуулах:"
echo "    sudo python3 ebpf_rwx_hunter.py"
echo ""
echo "  Dashboard:"
echo "    http://localhost:8765"
echo ""
echo "  Тусламж:"
echo "    sudo python3 ebpf_rwx_hunter.py --help"
echo "══════════════════════════════════════════"
