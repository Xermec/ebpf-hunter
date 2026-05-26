#!/bin/bash
# eBPF Hunter v4.0 — Sample Runner
# Hunter тусдаа terminal-д ажиллаж байх үед энэ script-ыг ажиллуулна
# Хэрэглэх: sudo bash run_samples.sh [sample_id]
#   sudo bash run_samples.sh       → бүх 10 sample
#   sudo bash run_samples.sh 03    → зөвхөн sample 03
#   sudo bash run_samples.sh 03 07 → sample 03, 07

set -e

SAMPLES_DIR="${SAMPLES_DIR:-/opt/samples}"
C2_HOST="${C2_HOST:-10.52.1.66}"
C2_PORT="${C2_PORT:-4444}"
WAIT_AFTER="${WAIT_AFTER:-5}"   # sample дараа хэдэн секунд хүлээх

# Өнгүүд
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[0;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'

echo -e "${BOLD}╔══════════════════════════════════════════════╗${NC}"
echo -e "${BOLD}║  eBPF Hunter — Sample Runner                 ║${NC}"
echo -e "${BOLD}╚══════════════════════════════════════════════╝${NC}"
echo ""
echo -e "  Samples dir : ${CYAN}$SAMPLES_DIR${NC}"
echo -e "  C2 host     : ${CYAN}$C2_HOST:$C2_PORT${NC}"
echo -e "  Dashboard   : ${CYAN}http://localhost:8765${NC}"
echo ""

# Root шалгах
if [[ $EUID -ne 0 ]]; then
    echo -e "${RED}[!] Root эрх шаардлагатай: sudo bash run_samples.sh${NC}"
    exit 1
fi

# Samples dir шалгах
if [[ ! -d "$SAMPLES_DIR" ]]; then
    echo -e "${RED}[!] Samples directory олдсонгүй: $SAMPLES_DIR${NC}"
    echo    "    Нөгөө серверүүдээс хуулна уу:"
    echo    "    scp -r root@10.52.1.57:/opt/samples /opt/samples"
    exit 1
fi

# Hunter ажиллаж байгаа эсэхийг шалгах
if ! pgrep -f "ebpf_rwx_hunter.py" > /dev/null 2>&1; then
    echo -e "${YELLOW}[!] ebpf_rwx_hunter.py ажиллаж байхгүй байна!${NC}"
    echo    "    Өөр terminal дээр: sudo python3 ebpf_rwx_hunter.py"
    echo ""
    read -p "Үргэлжлүүлэх үү? (y/N): " confirm
    [[ "$confirm" =~ ^[Yy]$ ]] || exit 1
fi

# Cleanup function
cleanup_sample() {
    echo -e "  ${YELLOW}↩ Cleanup...${NC}"
    # Process-уудыг kill
    pkill -f "custom_implant" 2>/dev/null || true
    pkill -f "xor_implant" 2>/dev/null || true
    pkill -f "mprot_implant" 2>/dev/null || true
    pkill -f "memfd_loader" 2>/dev/null || true
    pkill -f "py_inject" 2>/dev/null || true
    pkill -f "xmrig_fake" 2>/dev/null || true
    pkill -f "sample02" 2>/dev/null || true
    # /tmp файлуудыг устгах
    rm -f /tmp/custom_implant_* /tmp/xor_implant_* /tmp/mprot_implant_*
    rm -f /tmp/py_inject_* /tmp/xmrig_fake_* /tmp/sample02_*
    rm -f /tmp/cron_backup_*
    # Crontab-ийг сэргээх (хэрэв dirty болсон бол)
    crontab -l 2>/dev/null | grep -v "/dev/tcp/" | crontab - 2>/dev/null || true
    sleep 1
}

# Sample бэлдэх: C/C++ source compile
prepare_sample() {
    local sid="$1"
    local dir="$SAMPLES_DIR/$sid"

    case $sid in
        03)
            if [[ ! -f "$dir/loader" ]]; then
                echo -e "  ${CYAN}↳ loader.c compile хийж байна...${NC}"
                gcc "$dir/loader.c" -o "$dir/loader" -z execstack 2>&1 | head -5
            fi
            ;;
        04)
            if [[ ! -f "$dir/xor_loader" ]]; then
                echo -e "  ${CYAN}↳ xor_loader.c compile хийж байна...${NC}"
                gcc "$dir/xor_loader.c" -o "$dir/xor_loader" -z execstack 2>&1 | head -5
            fi
            ;;
        05)
            if [[ ! -f "$dir/mprotect_loader" ]]; then
                echo -e "  ${CYAN}↳ mprotect_loader.c compile хийж байна...${NC}"
                gcc "$dir/mprotect_loader.c" -o "$dir/mprotect_loader" 2>&1 | head -5
            fi
            ;;
        06)
            if [[ ! -f "$dir/memfd_loader" ]]; then
                echo -e "  ${CYAN}↳ memfd_loader.c compile хийж байна...${NC}"
                gcc "$dir/memfd_loader.c" -o "$dir/memfd_loader" 2>&1 | head -5
            fi
            if [[ ! -f "$dir/payload.elf" ]]; then
                echo -e "  ${YELLOW}  ⚠ payload.elf байхгүй — sample 06 алгасана${NC}"
                return 1
            fi
            ;;
        02)
            if [[ ! -f "$dir/payload.elf" ]]; then
                echo -e "  ${YELLOW}  ⚠ payload.elf байхгүй — sample 02 алгасана${NC}"
                return 1
            fi
            ;;
    esac
    return 0
}

# Тодорхой sample ажиллуулах
run_sample() {
    local sid="$1"
    local dir="$SAMPLES_DIR/$sid"
    local run_sh="$dir/run.sh"

    echo ""
    echo -e "${BOLD}────────────────────────────────────────────${NC}"

    # Sample нэр
    case $sid in
        01) name="EICAR test file" ;;
        02) name="Static x64 ELF (msfvenom)" ;;
        03) name="RWX shellcode loader" ;;
        04) name="XOR-encoded shellcode" ;;
        05) name="mprotect-based loader" ;;
        06) name="Reflective ELF (memfd_create)" ;;
        07) name="Python ctypes injector" ;;
        08) name="Bash reverse shell" ;;
        09) name="Crypto miner stub" ;;
        10) name="Cron persistence + reverse shell" ;;
        *)  name="Unknown" ;;
    esac

    echo -e "${BOLD}▶ Sample ${sid}: ${name}${NC}"

    if [[ ! -f "$run_sh" ]]; then
        echo -e "  ${RED}✗ run.sh олдсонгүй: $run_sh${NC}"
        return
    fi

    # Compile шаардлагатай sample-уудыг бэлдэх
    prepare_sample "$sid" || return

    # C2 host/port-ыг run.sh дотор шинэчлэх (зөвхөн temp copy-д)
    local tmp_run="/tmp/run_sample_${sid}_$$.sh"
    sed "s/10\.52\.1\.66/$C2_HOST/g; s/LPORT=4444/LPORT=$C2_PORT/g" \
        "$run_sh" > "$tmp_run"
    chmod +x "$tmp_run"

    echo -e "  ${CYAN}⏱ Ажиллуулж байна...${NC} (timeout 10s, wait ${WAIT_AFTER}s)"
    timeout 12 bash "$tmp_run" 2>&1 | head -5 &
    RUN_PID=$!

    # Hunter-ийн detect хийхэд хүлээх
    sleep "$WAIT_AFTER"

    # Cleanup
    kill "$RUN_PID" 2>/dev/null || true
    wait "$RUN_PID" 2>/dev/null || true
    rm -f "$tmp_run"
    cleanup_sample

    echo -e "  ${GREEN}✓ Sample ${sid} дууслаа → Dashboard шалгана уу${NC}"
    sleep 2
}

# Ямар sample-уудыг ажиллуулах
if [[ $# -gt 0 ]]; then
    SAMPLE_IDS=("$@")
else
    SAMPLE_IDS=(01 02 03 04 05 06 07 08 09 10)
fi

echo -e "Ажиллуулах sample-ууд: ${CYAN}${SAMPLE_IDS[*]}${NC}"
echo ""
read -p "Эхлүүлэх үү? (y/N): " go
[[ "$go" =~ ^[Yy]$ ]] || { echo "Цуцлагдлаа."; exit 0; }

# Run
for sid in "${SAMPLE_IDS[@]}"; do
    run_sample "$sid"
done

echo ""
echo -e "${BOLD}════════════════════════════════════════════${NC}"
echo -e "${GREEN}  Бүх sample дууслаа!${NC}"
echo -e "  Dashboard: ${CYAN}http://localhost:8765${NC}"
echo -e "${BOLD}════════════════════════════════════════════${NC}"
