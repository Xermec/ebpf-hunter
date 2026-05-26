#!/usr/bin/python3
# -*- coding: utf-8 -*-
"""
RWX Hunter v3.3 — Stable Multi-Vector
Зорилго: 7+ sample-ыг илрүүлэх, BPF code-ыг энгийн байлгаж тогтвортой ажиллуулах.

BPF tracepoints (kernel-side - энгийн):
  - mmap RWX
  - mprotect WRITE+EXEC
  - execve from /tmp /dev/shm  (string filter kernel-д)

Userspace polling (Python-аар):
  - Network connection scanner (psutil) - 4444 port watch
  - Crontab modification watcher
  - CPU spike monitor
  - Process tree scanner (memfd executions ажиглах)
"""

from bcc import BPF
import psutil
import os
import time
import threading
import warnings
warnings.filterwarnings("ignore", category=DeprecationWarning)

# --- ТОХИРГОО ---

SAMPLE_BIN_PATTERNS = [
    'custom_implant', 'xor_implant', 'mprot_implant',
    'sample02', 'xmrig_fake', 'eicar', 'py_inject',
    'memfd_loader', 'kworker',
]

JIT_EXE_PATTERNS = [
    '/usr/bin/java', '/usr/lib/jvm',
    '/usr/bin/node', '/usr/local/bin/node',
    '/usr/bin/ruby',
    '/usr/lib/chromium', '/usr/lib/firefox',
]

SUSPICIOUS_PATHS = ['/tmp/', '/dev/shm/', '/var/tmp/', '/run/user/']

SUSPICIOUS_PORTS = {4444, 1337, 5555, 6666, 7777, 8888, 9999, 31337, 4445, 2222}

TRUSTED_SYSTEM_PROCS = {
    'networkd-dispat', 'unattended-upgr', 'systemd', 'snapd',
    'dockerd', 'containerd', 'kubelet', 'wazuh-agent',
    'wazuh-modulesd', 'wazuh-execd', 'wazuh-syscheckd',
    'mfetpd', 'mfeespd', 'mfefwd', 'mvedr', 'mfemvedr', 'mvedrtrace',
    'masvc', 'macmnsvc', 'cma',
}

CPU_SUSTAINED_THRESHOLD = 80.0
CPU_SUSTAINED_DURATION = 3
NETWORK_POLL_INTERVAL = 0.5  # 500ms — connection-уудыг шалгах
PROCESS_SCAN_INTERVAL = 1.0  # 1 sec — sample процессууд шалгах

_alert_cache = {}
_alert_lock = threading.Lock()
ALERT_TTL = 60

def alert_once(key):
    now = time.time()
    with _alert_lock:
        last = _alert_cache.get(key, 0)
        if now - last < ALERT_TTL:
            return False
        _alert_cache[key] = now
        if len(_alert_cache) > 500:
            cutoff = now - ALERT_TTL
            for k in list(_alert_cache.keys()):
                if _alert_cache[k] < cutoff:
                    del _alert_cache[k]
        return True


def get_process_cmdline(pid):
    try:
        with open(f"/proc/{pid}/cmdline", "rb") as f:
            return f.read().replace(b"\x00", b" ").decode("utf-8", "replace").strip()
    except Exception:
        return ""


def get_process_exe(pid):
    try:
        return os.readlink(f"/proc/{pid}/exe")
    except Exception:
        return "Unknown/Exited"


def get_process_name(pid):
    try:
        with open(f"/proc/{pid}/comm", "r") as f:
            return f.read().strip()
    except Exception:
        return "unknown"


def get_network_activity(pid):
    connections = []
    try:
        proc = psutil.Process(pid)
        try:
            conns = proc.net_connections(kind='inet')
        except AttributeError:
            conns = proc.connections(kind='inet')
        for conn in conns:
            if conn.raddr:
                rip = conn.raddr.ip
                rport = conn.raddr.port
                if not rip.startswith('127.') and rip != '::1':
                    connections.append((rip, rport, conn.status))
    except (psutil.NoSuchProcess, psutil.AccessDenied):
        pass
    return connections


def is_jit_process(exe_path, cmdline):
    if not exe_path:
        return False
    cmd_lower = (cmdline or "").lower()
    for pat in SAMPLE_BIN_PATTERNS:
        if pat in cmd_lower:
            return False
    for pattern in JIT_EXE_PATTERNS:
        if exe_path.startswith(pattern):
            return True
    return False


def is_suspicious_path(path):
    if not path:
        return False
    for sp in SUSPICIOUS_PATHS:
        if path.startswith(sp):
            return True
    return False


def is_trusted_system(comm_name, exe_path):
    if comm_name in TRUSTED_SYSTEM_PROCS:
        return True
    return False


def analyze_threat(pid, process_name, exe_path, evidence,
                   source="SNAPSHOT", base_score=40, vector="RWX"):
    cmdline = get_process_cmdline(pid)
    score = base_score
    reasons = [f"[{vector}] {evidence}"]

    net_conns_raw = get_network_activity(pid) if pid > 0 else []
    net_conns = [(c[0], c[1]) for c in net_conns_raw if c[2] == 'ESTABLISHED']
    jit = is_jit_process(exe_path, cmdline)
    susp_path = is_suspicious_path(exe_path)
    trusted = is_trusted_system(process_name, exe_path)

    if trusted and vector in ("RWX", "MPROTECT"):
        return

    if jit and vector in ("RWX", "MPROTECT"):
        score -= 20
        reasons.append("JIT/Runtime process")

    if susp_path:
        score += 35
        reasons.append(f"Suspicious path: {exe_path}")

    try:
        real_exe = os.readlink(f"/proc/{pid}/exe")
        if "(deleted)" in real_exe:
            score += 25
            reasons.append("Executable deleted (in-memory loader)")
    except Exception:
        pass

    suspicious_conns = []
    for (rip, rport) in net_conns:
        if rport in SUSPICIOUS_PORTS:
            suspicious_conns.append(f"{rip}:{rport}")
            score += 40
            reasons.append(f"Suspicious port: {rip}:{rport}")
        else:
            score += 5

    if score >= 80:
        threat_level = "CRITICAL"
    elif score >= 55:
        threat_level = "HIGH"
    elif score >= 35:
        threat_level = "MEDIUM"
    else:
        threat_level = "INFO"

    if threat_level == "INFO":
        return

    sep = "=" * 55
    print(f"\n{sep}")
    print(f"  [{source}] {threat_level} ALERT")
    print(f"{sep}")
    print(f"  Vector  : {vector}")
    print(f"  Process : {process_name} (PID: {pid})")
    print(f"  Path    : {exe_path or 'Unknown'}")
    print(f"  Cmdline : {cmdline[:120]}")
    print(f"  Score   : {score}/100")
    if suspicious_conns:
        print(f"  [!!!] Suspicious C2 : {suspicious_conns}")
    print(f"  Reasons :")
    for r in reasons:
        print(f"    - {r}")
    print(f"{sep}", flush=True)


def scan_existing_rwx():
    print("[*] Snapshot scan...")
    found = 0
    for proc in psutil.process_iter(['pid', 'name', 'exe']):
        try:
            pid = proc.info['pid']
            if pid < 10 or pid == os.getpid():
                continue
            maps_path = f"/proc/{pid}/maps"
            if not os.path.exists(maps_path):
                continue
            with open(maps_path, 'r', errors='replace') as f:
                for line in f:
                    parts = line.split()
                    if len(parts) > 1 and 'rwx' in parts[1]:
                        analyze_threat(
                            pid, proc.info['name'], proc.info['exe'],
                            line.strip()[:80],
                            source="SNAPSHOT", base_score=40, vector="RWX"
                        )
                        found += 1
                        break
        except Exception:
            continue
    print(f"[*] Snapshot complete. {found} RWX found.\n")


# --- BPF PROGRAM (хамгийн энгийн!) ---
# Зөвхөн mmap, mprotect, execve. net/sock.h хэрэггүй.

bpf_program = r"""
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>

struct event_t {
    u32 pid;
    char comm[TASK_COMM_LEN];
    u8  vec;
    char extra[64];
};

BPF_PERF_OUTPUT(events);

// 1. mmap RWX
TRACEPOINT_PROBE(syscalls, sys_enter_mmap) {
    unsigned long prot = args->prot;
    if ((prot & 7) == 7) {
        struct event_t data = {};
        data.pid = bpf_get_current_pid_tgid() >> 32;
        bpf_get_current_comm(&data.comm, sizeof(data.comm));
        data.vec = 1;
        events.perf_submit(args, &data, sizeof(data));
    }
    return 0;
}

// 2. mprotect WRITE+EXEC
TRACEPOINT_PROBE(syscalls, sys_enter_mprotect) {
    unsigned long prot = args->prot;
    if ((prot & 6) == 6) {
        struct event_t data = {};
        data.pid = bpf_get_current_pid_tgid() >> 32;
        bpf_get_current_comm(&data.comm, sizeof(data.comm));
        data.vec = 2;
        events.perf_submit(args, &data, sizeof(data));
    }
    return 0;
}

// 3. execve from /tmp /dev/shm /var/tmp
TRACEPOINT_PROBE(syscalls, sys_enter_execve) {
    const char *filename = (const char *)args->filename;
    char fn[16] = {};
    bpf_probe_read_user_str(fn, sizeof(fn), filename);

    u8 match = 0;

    if (fn[0]=='/' && fn[1]=='t' && fn[2]=='m' && fn[3]=='p' && fn[4]=='/') {
        match = 1;
    }
    else if (fn[0]=='/' && fn[1]=='d' && fn[2]=='e' && fn[3]=='v' &&
             fn[4]=='/' && fn[5]=='s' && fn[6]=='h' && fn[7]=='m' && fn[8]=='/') {
        match = 1;
    }
    else if (fn[0]=='/' && fn[1]=='v' && fn[2]=='a' && fn[3]=='r' &&
             fn[4]=='/' && fn[5]=='t' && fn[6]=='m' && fn[7]=='p' && fn[8]=='/') {
        match = 1;
    }
    else if (fn[0]=='/' && fn[1]=='p' && fn[2]=='r' && fn[3]=='o' &&
             fn[4]=='c' && fn[5]=='/') {
        match = 2;  // memfd via /proc/.../fd/
    }

    if (match == 0) return 0;

    struct event_t data = {};
    data.pid = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    data.vec = (match == 1) ? 5 : 4;
    bpf_probe_read_user_str(data.extra, sizeof(data.extra), filename);
    events.perf_submit(args, &data, sizeof(data));
    return 0;
}
"""


def print_event(cpu, data, size):
    event = b["events"].event(data)
    pid = int(event.pid)
    process_name = event.comm.decode('utf-8', 'replace').strip('\x00')
    vec = int(event.vec)
    extra = event.extra.decode('utf-8', 'replace').strip('\x00') if hasattr(event, 'extra') else ""

    exe_path = get_process_exe(pid)

    if vec == 1:  # RWX mmap
        if process_name in TRUSTED_SYSTEM_PROCS:
            return
        if not alert_once(f"rwx_{pid}"):
            return
        analyze_threat(pid, process_name, exe_path,
                       "Dynamic mmap(RWX) via syscall",
                       source="REALTIME", base_score=40, vector="RWX")

    elif vec == 2:  # mprotect
        if process_name in TRUSTED_SYSTEM_PROCS:
            return
        if not alert_once(f"mprot_{pid}"):
            return
        analyze_threat(pid, process_name, exe_path,
                       "mprotect WRITE+EXEC (RW->RWX transition)",
                       source="REALTIME", base_score=45, vector="MPROTECT")

    elif vec == 4:  # /proc/.../fd/ exec — memfd
        if process_name in TRUSTED_SYSTEM_PROCS:
            return
        if "/fd/" not in extra:
            return
        if not alert_once(f"procfd_{pid}_{extra}"):
            return
        analyze_threat(pid, process_name, exe_path,
                       f"execve /proc/.../fd/ — fileless ELF: {extra}",
                       source="REALTIME", base_score=70, vector="MEMFD_EXEC")

    elif vec == 5:  # /tmp execve
        if process_name in TRUSTED_SYSTEM_PROCS:
            return
        # script-уудыг алгасах (shell нь /tmp-аас .sh ажиллуулах нь magadlaltai)
        if extra.endswith('.sh') or extra.endswith('.py'):
            return
        if not alert_once(f"tmpexec_{extra}"):
            return
        analyze_threat(pid, process_name, exe_path,
                       f"execve from suspicious path: {extra}",
                       source="REALTIME", base_score=45, vector="EXEC_TMP")


# --- USERSPACE WATCHERS ---

def network_watcher():
    """
    psutil-ээр бүх network connection-ыг 500ms тутамд скан хийж
    суспициус порт руу холбогдсон процесс илрүүлнэ.
    """
    while True:
        try:
            for conn in psutil.net_connections(kind='inet'):
                if not conn.raddr or not conn.pid:
                    continue
                rport = conn.raddr.port
                rip = conn.raddr.ip
                if rport not in SUSPICIOUS_PORTS:
                    continue
                if rip.startswith('127.') or rip == '::1':
                    continue

                pid = conn.pid
                try:
                    proc = psutil.Process(pid)
                    name = proc.name()
                    exe = proc.exe() if proc.exe() else ""
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue

                if name in TRUSTED_SYSTEM_PROCS:
                    continue

                if not alert_once(f"net_{pid}_{rip}_{rport}"):
                    continue

                analyze_threat(pid, name, exe,
                               f"Connection to suspicious port: {rip}:{rport} ({conn.status})",
                               source="NETWORK", base_score=60, vector="CONN_C2")
        except Exception:
            pass
        time.sleep(NETWORK_POLL_INTERVAL)


def crontab_watcher():
    """Crontab-уудыг 2 sec тутамд шалгана."""
    paths_to_watch = ["/var/spool/cron/crontabs", "/etc/cron.d", "/var/spool/cron"]
    last_state = {}

    for d in paths_to_watch:
        if not os.path.isdir(d):
            continue
        try:
            for f in os.listdir(d):
                full = os.path.join(d, f)
                last_state[full] = os.path.getmtime(full)
        except Exception:
            pass

    while True:
        time.sleep(2)
        for d in paths_to_watch:
            if not os.path.isdir(d):
                continue
            try:
                for f in os.listdir(d):
                    full = os.path.join(d, f)
                    try:
                        mtime = os.path.getmtime(full)
                    except Exception:
                        continue
                    prev = last_state.get(full)
                    if prev is None or mtime > prev:
                        last_state[full] = mtime
                        try:
                            with open(full, 'r', errors='replace') as fp:
                                content = fp.read()
                        except Exception:
                            content = ""
                        suspicious = any(p in content for p in
                                          ["/dev/tcp/", "bash -i", "nc -e", "mkfifo"])
                        if suspicious or prev is not None:
                            if not alert_once(f"cron_{full}"):
                                continue
                            analyze_threat(0, "crontab", full,
                                           f"Crontab modified: {full}",
                                           source="CRONTAB", base_score=55,
                                           vector="CRON")
            except Exception:
                continue


def cpu_watcher():
    """Sustained high CPU илрүүлэлт."""
    consecutive = 0
    psutil.cpu_percent(interval=None)
    for p in psutil.process_iter(["pid"]):
        try:
            p.cpu_percent(interval=None)
        except Exception:
            pass

    while True:
        time.sleep(2)
        cpu = psutil.cpu_percent(interval=None)
        if cpu > CPU_SUSTAINED_THRESHOLD:
            consecutive += 1
            if consecutive >= CPU_SUSTAINED_DURATION:
                top_pid = None
                top_cpu = 0
                top_name = ""
                top_exe = ""
                for proc in psutil.process_iter(["pid", "name", "exe"]):
                    try:
                        c = proc.cpu_percent(interval=None)
                        if c > top_cpu:
                            top_cpu = c
                            top_pid = proc.info['pid']
                            top_name = proc.info['name']
                            top_exe = proc.info.get('exe') or ""
                    except Exception:
                        continue

                if top_pid and alert_once(f"cpu_spike_{int(time.time()/30)}"):
                    analyze_threat(top_pid, top_name, top_exe,
                                   f"Sustained high CPU ({cpu:.0f}% for {CPU_SUSTAINED_DURATION*2}s)",
                                   source="CPU_MON", base_score=50, vector="CPU_SPIKE")
                consecutive = 0
        else:
            consecutive = 0


def memfd_watcher():
    """
    /proc/<pid>/maps дээр anon_inode:[memfd] тэмдэгт хайна.
    memfd_create-аас ажилладаг процессуудыг ингэж олно.
    """
    while True:
        try:
            for proc in psutil.process_iter(['pid', 'name', 'exe']):
                try:
                    pid = proc.info['pid']
                    if pid < 100 or pid == os.getpid():
                        continue
                    name = proc.info['name']
                    if name in TRUSTED_SYSTEM_PROCS:
                        continue

                    # /proc/<pid>/maps шалгах
                    maps_path = f"/proc/{pid}/maps"
                    if not os.path.exists(maps_path):
                        continue

                    with open(maps_path, 'r', errors='replace') as f:
                        content = f.read()

                    if 'memfd:' in content or '/memfd:' in content:
                        if not alert_once(f"memfd_proc_{pid}"):
                            continue
                        exe = proc.info.get('exe') or get_process_exe(pid)
                        analyze_threat(pid, name, exe,
                                       "Process running from memfd (fileless ELF)",
                                       source="MEMFD_SCAN", base_score=70,
                                       vector="MEMFD")
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
                except Exception:
                    continue
        except Exception:
            pass
        time.sleep(PROCESS_SCAN_INTERVAL)


if __name__ == "__main__":
    if os.geteuid() != 0:
        print("[!] Root erh shaardlagatai!")
        exit(1)

    scan_existing_rwx()

    # 4 background watcher
    threading.Thread(target=network_watcher, daemon=True).start()
    threading.Thread(target=crontab_watcher, daemon=True).start()
    threading.Thread(target=cpu_watcher, daemon=True).start()
    threading.Thread(target=memfd_watcher, daemon=True).start()

    print("[*] eBPF Real-time Monitor v3.3 ehellee")
    print("[*] BPF vectors: RWX, MPROTECT, EXEC_TMP, MEMFD_EXEC")
    print("[*] Userspace watchers: CONN_C2, CRON, CPU_SPIKE, MEMFD\n")

    b = BPF(text=bpf_program)
    b["events"].open_perf_buffer(print_event, page_cnt=64)

    while True:
        try:
            b.perf_buffer_poll(timeout=100)
        except KeyboardInterrupt:
            print("\n[*] Monitor zogson.")
            break
