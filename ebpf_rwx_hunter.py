#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
╔══════════════════════════════════════════════════════════════╗
║          eBPF RWX Hunter v4.0  —  Standalone Edition        ║
║  Linux kernel-level malware detection using eBPF tracepoints ║
║  GitHub: https://github.com/YOUR_USERNAME/ebpf-hunter        ║
╚══════════════════════════════════════════════════════════════╝

Detection Vectors (8):
  [BPF]  1. RWX mmap      — mmap(PROT_READ|WRITE|EXEC)
  [BPF]  2. MPROTECT      — mprotect(PROT_WRITE|EXEC)  RW→RWX
  [BPF]  3. EXEC_TMP      — execve from /tmp /dev/shm /var/tmp
  [BPF]  4. MEMFD_EXEC    — execve from /proc/self/fd/ (fileless)
  [USER] 5. CONN_C2       — connect() to suspicious port (psutil)
  [USER] 6. MEMFD_SCAN    — /proc/*/maps дотроос memfd: хайх
  [USER] 7. PYTHON_INJECT — Python-аас RWX mmap (JIT биш)
  [USER] 8. CRON          — crontab modification watcher
  [USER] 9. CPU_SPIKE     — sustained high CPU (crypto miner)

Хамрагдах sample-ууд (9/10):
  01 EICAR      — ❌ (signature-only, RWX биш)
  02 msfvenom   — ✅ EXEC_TMP
  03 RWX loader — ✅ RWX
  04 XOR loader — ✅ RWX
  05 mprotect   — ✅ MPROTECT
  06 memfd ELF  — ✅ MEMFD_SCAN + MEMFD_EXEC
  07 py ctypes  — ✅ PYTHON_INJECT
  08 bash shell — ✅ CONN_C2
  09 cpu miner  — ✅ CPU_SPIKE + EXEC_TMP
  10 cron perst — ✅ CRON + CONN_C2

Шаардлага:
  sudo apt install python3-bpfcc python3-psutil
  sudo python3 ebpf_rwx_hunter.py [--port 8765] [--c2-ports 4444,1337]
"""

import argparse
import json
import os
import signal
import sys
import threading
import time
import warnings

warnings.filterwarnings("ignore", category=DeprecationWarning)

try:
    from bcc import BPF
except ImportError:
    print("[!] bcc module олдсонгүй. Суулгах: sudo apt install python3-bpfcc")
    sys.exit(1)

try:
    import psutil
except ImportError:
    print("[!] psutil module олдсонгүй. Суулгах: pip3 install psutil")
    sys.exit(1)

# ─── ТОХИРГОО ───────────────────────────────────────────────────────────────

VERSION = "4.0.0"

# Default C2 ports — CLI-аас override хийж болно
DEFAULT_C2_PORTS = {4444, 1337, 5555, 6666, 7777, 8888, 9999, 31337, 4445, 2222}

SUSPICIOUS_PATHS = ['/tmp/', '/dev/shm/', '/var/tmp/', '/run/user/']

# JIT runtime — зөвхөн pure JIT (Python байхгүй!)
JIT_RUNTIMES = {
    '/usr/bin/java', '/usr/lib/jvm',
    '/usr/bin/node', '/usr/local/bin/node',
    '/usr/local/bin/node',
    '/usr/bin/ruby', '/usr/bin/perl',
    '/usr/lib/chromium', '/usr/lib/firefox',
    '/opt/google/chrome',
}

# Python-ыг JIT гэж үзэхгүй — python ctypes injection-ыг detect хийнэ
PYTHON_EXES = {
    '/usr/bin/python3', '/usr/bin/python',
    '/usr/local/bin/python3', '/usr/local/bin/python',
}

TRUSTED_SYSTEM_PROCS = {
    'systemd', 'systemd-journal', 'systemd-logind', 'systemd-network',
    'systemd-resolve', 'systemd-udevd', 'snapd', 'dockerd', 'containerd',
    'kubelet', 'wazuh-agent', 'wazuh-modulesd', 'wazuh-execd',
    'mfetpd', 'mfeespd', 'mfefwd', 'mvedr', 'mfemvedr', 'mvedrtrace',
    'masvc', 'macmnsvc', 'cma', 'dbus-daemon', 'NetworkManager',
    'unattended-upgr', 'packagekitd', 'polkitd',
}

CPU_SUSTAINED_THRESHOLD = 75.0
CPU_SUSTAINED_SECONDS = 6

NETWORK_POLL_INTERVAL = 0.5
MEMFD_SCAN_INTERVAL = 1.0
CRON_POLL_INTERVAL = 2.0
ALERT_TTL_SEC = 60

# ─── GLOBAL STATE ─────────────────────────────────────────────────────────────

_alert_cache: dict = {}
_alert_lock = threading.Lock()

# Alert queue — dashboard streamer-аас уншина
_alert_queue: list = []
_queue_lock = threading.Lock()

# Config (parse_args-аас override болно)
CONFIG = {
    "c2_ports": DEFAULT_C2_PORTS,
    "verbose": False,
    "log_file": None,
    "dashboard_port": None,
}


# ─── ALERT ENGINE ─────────────────────────────────────────────────────────────

def alert_once(key: str) -> bool:
    """TTL-тай dedup — нэг PID/event дахин ажиллахад detect хийнэ."""
    now = time.time()
    with _alert_lock:
        if now - _alert_cache.get(key, 0) < ALERT_TTL_SEC:
            return False
        _alert_cache[key] = now
        if len(_alert_cache) > 1000:
            cutoff = now - ALERT_TTL_SEC
            for k in list(_alert_cache):
                if _alert_cache[k] < cutoff:
                    del _alert_cache[k]
    return True


def emit_alert(vector: str, level: str, pid: int, process: str,
               exe: str, detail: str, score: int):
    """Alert хэвлэж log, queue-д нэмнэ."""
    ts = time.strftime("%H:%M:%S")
    sep = "═" * 58

    color = {
        "CRITICAL": "\033[91m",
        "HIGH":     "\033[93m",
        "MEDIUM":   "\033[33m",
    }.get(level, "\033[0m")
    reset = "\033[0m"

    msg = (
        f"\n{color}{sep}{reset}\n"
        f"  {color}[{ts}] {level} ALERT{reset}\n"
        f"  Vector  : {vector}\n"
        f"  Process : {process} (PID: {pid})\n"
        f"  Path    : {exe or 'Unknown'}\n"
        f"  Score   : {score}/100\n"
        f"  Detail  : {detail}\n"
        f"{color}{sep}{reset}"
    )
    print(msg, flush=True)

    # Log файл
    if CONFIG.get("log_file"):
        try:
            with open(CONFIG["log_file"], "a") as f:
                plain = (
                    f"[{ts}] {level} | {vector} | {process}({pid}) | "
                    f"score={score} | {detail}\n"
                )
                f.write(plain)
        except Exception:
            pass

    # Dashboard queue
    record = {
        "ts": ts,
        "vector": vector,
        "level": level,
        "pid": pid,
        "process": process,
        "exe": exe or "",
        "detail": detail[:120],
        "score": score,
    }
    with _queue_lock:
        _alert_queue.append(record)
        if len(_alert_queue) > 500:
            _alert_queue.pop(0)


def analyze_and_emit(pid: int, process_name: str, exe_path: str,
                     base_score: int, vector: str, evidence: str):
    """Score тооцоолж, threshold дээшилвэл alert илгээнэ."""
    score = base_score
    cmdline = _get_cmdline(pid)

    # Suspicious path
    if exe_path and any(exe_path.startswith(p) for p in SUSPICIOUS_PATHS):
        score += 35

    # Deleted executable
    try:
        real = os.readlink(f"/proc/{pid}/exe")
        if "(deleted)" in real:
            score += 25
    except Exception:
        pass

    # C2 connection
    try:
        proc = psutil.Process(pid)
        for c in _get_conns(proc):
            if c.raddr and c.raddr.port in CONFIG["c2_ports"]:
                score += 40
    except Exception:
        pass

    if score >= 80:
        level = "CRITICAL"
    elif score >= 55:
        level = "HIGH"
    elif score >= 35:
        level = "MEDIUM"
    else:
        return  # INFO — хэвлэхгүй

    emit_alert(vector, level, pid, process_name, exe_path, evidence, score)


# ─── HELPERS ──────────────────────────────────────────────────────────────────

def _get_cmdline(pid: int) -> str:
    try:
        with open(f"/proc/{pid}/cmdline", "rb") as f:
            return f.read().replace(b"\x00", b" ").decode("utf-8", "replace").strip()
    except Exception:
        return ""


def _get_exe(pid: int) -> str:
    try:
        return os.readlink(f"/proc/{pid}/exe")
    except Exception:
        return ""


def _get_conns(proc):
    try:
        return proc.net_connections(kind="inet")
    except AttributeError:
        return proc.connections(kind="inet")
    except Exception:
        return []


def _is_jit(exe_path: str) -> bool:
    """Python биш JIT-уудыг шалгана."""
    if not exe_path:
        return False
    for p in JIT_RUNTIMES:
        if exe_path.startswith(p):
            return True
    return False


def _is_python(exe_path: str) -> bool:
    for p in PYTHON_EXES:
        if exe_path.startswith(p):
            return True
    return False


def _is_trusted(comm: str, exe: str) -> bool:
    if comm in TRUSTED_SYSTEM_PROCS:
        return True
    if exe and (exe.startswith("/usr/lib/systemd") or exe.startswith("/lib/systemd")):
        return True
    return False


# ─── SNAPSHOT SCANNER ─────────────────────────────────────────────────────────

def scan_existing_rwx():
    """Startup дээр одоо ажиллаж байгаа RWX процессуудыг scan хийнэ."""
    print("[*] Snapshot scan хийж байна...", flush=True)
    found = 0
    for proc in psutil.process_iter(["pid", "name", "exe"]):
        try:
            pid = proc.info["pid"]
            if pid < 10 or pid == os.getpid():
                continue
            comm = proc.info["name"] or ""
            exe = proc.info["exe"] or ""
            if _is_trusted(comm, exe):
                continue

            maps = f"/proc/{pid}/maps"
            if not os.path.exists(maps):
                continue
            with open(maps, "r", errors="replace") as f:
                for line in f:
                    if len(line.split()) > 1 and "rwx" in line.split()[1]:
                        if not alert_once(f"snap_rwx_{pid}"):
                            break
                        analyze_and_emit(
                            pid, comm, exe,
                            base_score=40, vector="RWX",
                            evidence=f"Existing RWX mapping: {line.strip()[:60]}"
                        )
                        found += 1
                        break
        except Exception:
            continue
    print(f"[*] Snapshot дууслаа. {found} RWX mapping олдлоо.\n", flush=True)


# ─── BPF PROGRAM ──────────────────────────────────────────────────────────────

BPF_PROGRAM = r"""
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>

struct evt_t {
    u32 pid;
    char comm[TASK_COMM_LEN];
    u8  vec;        // 1=mmap_rwx 2=mprotect 3=exec_tmp 4=exec_proc_fd
    char path[64];
};

BPF_PERF_OUTPUT(events);

/* 1. mmap RWX */
TRACEPOINT_PROBE(syscalls, sys_enter_mmap) {
    if ((args->prot & 7) != 7) return 0;
    struct evt_t e = {};
    e.pid = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(&e.comm, sizeof(e.comm));
    e.vec = 1;
    events.perf_submit(args, &e, sizeof(e));
    return 0;
}

/* 2. mprotect WRITE+EXEC */
TRACEPOINT_PROBE(syscalls, sys_enter_mprotect) {
    if ((args->prot & 6) != 6) return 0;
    struct evt_t e = {};
    e.pid = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(&e.comm, sizeof(e.comm));
    e.vec = 2;
    events.perf_submit(args, &e, sizeof(e));
    return 0;
}

/* 3+4. execve — /tmp/  /dev/shm/  /var/tmp/  /proc/.../fd/ */
TRACEPOINT_PROBE(syscalls, sys_enter_execve) {
    char fn[16] = {};
    bpf_probe_read_user_str(fn, sizeof(fn), args->filename);

    u8 vec = 0;
    /* /tmp/ */
    if (fn[0]=='/' && fn[1]=='t' && fn[2]=='m' && fn[3]=='p' && fn[4]=='/') {
        vec = 3;
    }
    /* /dev/shm/ */
    else if (fn[0]=='/' && fn[1]=='d' && fn[2]=='e' && fn[3]=='v' &&
             fn[4]=='/' && fn[5]=='s' && fn[6]=='h' && fn[7]=='m') {
        vec = 3;
    }
    /* /var/tmp/ */
    else if (fn[0]=='/' && fn[1]=='v' && fn[2]=='a' && fn[3]=='r' &&
             fn[4]=='/' && fn[5]=='t' && fn[6]=='m' && fn[7]=='p') {
        vec = 3;
    }
    /* /proc/ — memfd fileless exec */
    else if (fn[0]=='/' && fn[1]=='p' && fn[2]=='r' && fn[3]=='o' &&
             fn[4]=='c' && fn[5]=='/') {
        vec = 4;
    }

    if (!vec) return 0;

    struct evt_t e = {};
    e.pid = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(&e.comm, sizeof(e.comm));
    e.vec = vec;
    bpf_probe_read_user_str(e.path, sizeof(e.path), args->filename);
    events.perf_submit(args, &e, sizeof(e));
    return 0;
}
"""


def _handle_bpf_event(cpu, data, size):
    """BPF perf event callback."""
    evt = b["events"].event(data)
    pid  = int(evt.pid)
    comm = evt.comm.decode("utf-8", "replace").strip("\x00")
    vec  = int(evt.vec)
    path = evt.path.decode("utf-8", "replace").strip("\x00") if hasattr(evt, "path") else ""

    if _is_trusted(comm, ""):
        return

    exe = _get_exe(pid)

    # ── Vector 1: mmap RWX ────────────────────────────────────────────────
    if vec == 1:
        # JIT: Java, Node, Ruby г.м. → алгасах
        if _is_jit(exe):
            return
        # Python → PYTHON_INJECT vector-аар тусдаа шалгана
        if _is_python(exe):
            _check_python_inject(pid, comm, exe)
            return
        if not alert_once(f"rwx_{pid}"):
            return
        analyze_and_emit(pid, comm, exe, 40, "RWX",
                         "mmap(PROT_READ|WRITE|EXEC) syscall")

    # ── Vector 2: mprotect WRITE+EXEC ─────────────────────────────────────
    elif vec == 2:
        if _is_trusted(comm, exe):
            return
        if _is_jit(exe):
            return
        if not alert_once(f"mprot_{pid}"):
            return
        analyze_and_emit(pid, comm, exe, 45, "MPROTECT",
                         "mprotect(PROT_WRITE|EXEC) — RW→RWX permission escalation")

    # ── Vector 3: execve from suspicious path ─────────────────────────────
    elif vec == 3:
        if _is_trusted(comm, exe):
            return
        # Shell script-уудыг алгасах (.sh, .py хэвийн)
        if path.endswith((".sh", ".bash")):
            return
        if not alert_once(f"exec_tmp_{path}"):
            return
        analyze_and_emit(pid, comm, exe, 45, "EXEC_TMP",
                         f"execve from suspicious path: {path}")

    # ── Vector 4: execve from /proc/.../fd/ (memfd fileless) ──────────────
    elif vec == 4:
        if _is_trusted(comm, exe):
            return
        if "/fd/" not in path:
            return
        if not alert_once(f"memfd_exec_{pid}_{path}"):
            return
        analyze_and_emit(pid, comm, exe, 70, "MEMFD_EXEC",
                         f"execve /proc/.../fd/ — fileless ELF execution: {path}")


def _check_python_inject(pid: int, comm: str, exe: str):
    """Python-аас RWX mmap хийвэл — cmdline шалган inject эсэхийг тодорхойло."""
    cmdline = _get_cmdline(pid)
    # Susp patterns: /tmp/ дотрох .py, inject/shellcode нэртэй
    INJECT_PATTERNS = [
        "/tmp/", "/dev/shm/", "inject", "shellcode", "implant",
        "payload", "reverse", "exploit",
    ]
    if any(p in cmdline.lower() for p in INJECT_PATTERNS):
        if not alert_once(f"py_inject_{pid}"):
            return
        emit_alert("PYTHON_INJECT", "HIGH", pid, comm, exe,
                   f"Python RWX mmap — suspicious cmdline: {cmdline[:80]}", 60)
    else:
        # Normal Python RWX (numpy, pytorch г.м.) — MEDIUM
        if not alert_once(f"py_rwx_{pid}"):
            return
        emit_alert("PYTHON_INJECT", "MEDIUM", pid, comm, exe,
                   f"Python mmap(RWX) — possible ctypes injection: {cmdline[:60]}", 45)


# ─── USERSPACE WATCHERS ───────────────────────────────────────────────────────

def network_watcher():
    """
    psutil.net_connections() 500ms тутамд scan — C2 port холболт.
    connect() BPF tracepoint-гүйгээр ч ажилладаг тул compile issue үгүй.
    """
    print("[*] Network watcher эхэллээ (C2 port monitor)", flush=True)
    while True:
        try:
            for conn in psutil.net_connections(kind="inet"):
                if not conn.raddr or not conn.pid:
                    continue
                rport = conn.raddr.port
                rip = conn.raddr.ip

                if rport not in CONFIG["c2_ports"]:
                    continue
                if rip.startswith("127.") or rip == "::1":
                    continue

                pid = conn.pid
                try:
                    proc = psutil.Process(pid)
                    comm = proc.name()
                    exe = proc.exe() if proc.is_running() else ""
                except Exception:
                    continue

                if _is_trusted(comm, exe):
                    continue

                key = f"net_{pid}_{rip}_{rport}"
                if not alert_once(key):
                    continue

                emit_alert(
                    "CONN_C2", "HIGH", pid, comm, exe,
                    f"Connection to suspicious port: {rip}:{rport} ({conn.status})",
                    score=65
                )
        except Exception:
            pass
        time.sleep(NETWORK_POLL_INTERVAL)


def memfd_watcher():
    """
    /proc/<pid>/maps-аас 'memfd:' хайна — fileless ELF-ийг илрүүлнэ.
    Sample 06 (memfd_create + execve) үүнд баригдана.
    """
    print("[*] memfd watcher эхэллээ (/proc/*/maps scan)", flush=True)
    while True:
        try:
            for proc in psutil.process_iter(["pid", "name", "exe"]):
                try:
                    pid  = proc.info["pid"]
                    comm = proc.info["name"] or ""
                    exe  = proc.info["exe"] or ""

                    if pid < 100 or pid == os.getpid():
                        continue
                    if _is_trusted(comm, exe):
                        continue
                    # systemd, snap г.м. legitimately use memfd
                    if exe.startswith(("/usr/lib/", "/lib/", "/snap/")):
                        continue

                    maps_path = f"/proc/{pid}/maps"
                    if not os.path.exists(maps_path):
                        continue

                    with open(maps_path, "r", errors="replace") as f:
                        content = f.read()

                    if "memfd:" not in content:
                        continue

                    if not alert_once(f"memfd_map_{pid}"):
                        continue

                    emit_alert(
                        "MEMFD_SCAN", "HIGH", pid, comm, exe,
                        "Process running from memfd anonymous FD — fileless ELF",
                        score=70
                    )
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
                except Exception:
                    continue
        except Exception:
            pass
        time.sleep(MEMFD_SCAN_INTERVAL)


def crontab_watcher():
    """
    Crontab файлуудыг 2 sec тутамд шалгана.
    Reverse shell pattern (/dev/tcp/, bash -i) илрүүлнэ.
    Sample 10 (Cron persistence) үүнд баригдана.
    """
    print("[*] Crontab watcher эхэллээ", flush=True)
    WATCH_DIRS = [
        "/var/spool/cron/crontabs",
        "/var/spool/cron",
        "/etc/cron.d",
        "/etc/cron.hourly",
        "/etc/cron.daily",
    ]
    SHELL_PATTERNS = ["/dev/tcp/", "bash -i", "nc -e", "mkfifo", "ncat ", "socat "]
    last_mtimes: dict = {}

    for d in WATCH_DIRS:
        if not os.path.isdir(d):
            continue
        try:
            for f in os.listdir(d):
                fp = os.path.join(d, f)
                last_mtimes[fp] = os.path.getmtime(fp)
        except Exception:
            pass

    while True:
        time.sleep(CRON_POLL_INTERVAL)
        for d in WATCH_DIRS:
            if not os.path.isdir(d):
                continue
            try:
                for f in os.listdir(d):
                    fp = os.path.join(d, f)
                    try:
                        mtime = os.path.getmtime(fp)
                    except Exception:
                        continue

                    prev = last_mtimes.get(fp)
                    if prev is not None and mtime <= prev:
                        continue

                    last_mtimes[fp] = mtime

                    try:
                        with open(fp, "r", errors="replace") as fh:
                            content = fh.read()
                    except Exception:
                        content = ""

                    has_shell = any(p in content for p in SHELL_PATTERNS)
                    is_new    = prev is None

                    if not (has_shell or (prev is not None and not is_new)):
                        continue

                    if not alert_once(f"cron_{fp}_{int(mtime)}"):
                        continue

                    score = 65 if has_shell else 40
                    emit_alert(
                        "CRON", "HIGH" if has_shell else "MEDIUM",
                        0, "crontab", fp,
                        f"Crontab modified: {fp}" +
                        (" — reverse shell pattern detected!" if has_shell else ""),
                        score=score
                    )
            except Exception:
                continue


def cpu_watcher():
    """
    Sustained high CPU (75%+ for 6s) — crypto miner simulation.
    Sample 09 (crypto miner stub) үүнд баригдана.
    """
    print("[*] CPU watcher эхэллээ", flush=True)
    psutil.cpu_percent(interval=None)
    # Baseline initialize
    for p in psutil.process_iter(["pid"]):
        try:
            p.cpu_percent(interval=None)
        except Exception:
            pass

    consecutive = 0
    while True:
        time.sleep(2)
        cpu = psutil.cpu_percent(interval=None)

        if cpu < CPU_SUSTAINED_THRESHOLD:
            consecutive = 0
            continue

        consecutive += 1
        if consecutive < CPU_SUSTAINED_SECONDS // 2:
            continue

        # Хамгийн их CPU авсан процесс
        top_pid, top_cpu, top_comm, top_exe = None, 0.0, "", ""
        for proc in psutil.process_iter(["pid", "name", "exe"]):
            try:
                c = proc.cpu_percent(interval=None)
                if c > top_cpu:
                    top_cpu   = c
                    top_pid   = proc.info["pid"]
                    top_comm  = proc.info["name"] or ""
                    top_exe   = proc.info["exe"] or ""
            except Exception:
                continue

        if top_pid and not _is_trusted(top_comm, top_exe):
            key = f"cpu_{top_pid}_{int(time.time() // 30)}"
            if alert_once(key):
                emit_alert(
                    "CPU_SPIKE", "HIGH", top_pid, top_comm, top_exe,
                    f"Sustained CPU {cpu:.0f}% for {consecutive * 2}s — "
                    f"possible crypto miner (top process: {top_comm} {top_cpu:.0f}%)",
                    score=55
                )
        consecutive = 0


# ─── LIGHTWEIGHT DASHBOARD ────────────────────────────────────────────────────

DASHBOARD_HTML = r"""<!DOCTYPE html>
<html lang="mn">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>eBPF Hunter — Live Dashboard</title>
<style>
:root {
  --bg: #06090d; --bg1: #0d1117; --bg2: #161b22;
  --teal: #3fb950; --red: #f85149; --amber: #d29922;
  --text: #e6edf3; --muted: #8b949e; --border: #30363d;
  --crit: #f85149; --high: #d29922; --med: #388bfd;
}
* { box-sizing: border-box; margin: 0; padding: 0; }
body { background: var(--bg); color: var(--text); font-family: 'Segoe UI', system-ui, sans-serif;
       font-size: 14px; line-height: 1.5; padding: 16px; }
.header { display: flex; align-items: center; justify-content: space-between;
          margin-bottom: 20px; padding-bottom: 12px; border-bottom: 1px solid var(--border); }
.logo { font-size: 20px; font-weight: 700; color: var(--teal); font-family: monospace; }
.logo span { color: var(--muted); font-size: 13px; font-weight: 400; margin-left: 8px; }
.status { display: flex; align-items: center; gap: 6px; font-size: 13px; }
.dot { width: 8px; height: 8px; border-radius: 50%; background: var(--teal);
       box-shadow: 0 0 6px var(--teal); animation: pulse 2s infinite; }
@keyframes pulse { 0%,100%{opacity:1} 50%{opacity:.4} }

.stats { display: grid; grid-template-columns: repeat(4,1fr); gap: 10px; margin-bottom: 16px; }
.stat { background: var(--bg1); border: 1px solid var(--border); border-radius: 8px; padding: 14px; }
.stat .num { font-size: 32px; font-weight: 700; font-family: monospace; color: var(--teal); }
.stat .lbl { font-size: 11px; color: var(--muted); text-transform: uppercase; letter-spacing: .5px; }

.vectors { display: grid; grid-template-columns: repeat(auto-fill, minmax(140px, 1fr));
           gap: 8px; margin-bottom: 16px; }
.vec-badge { background: var(--bg2); border: 1px solid var(--border); border-radius: 6px;
             padding: 8px 10px; font-size: 12px; display: flex; align-items: center; gap: 6px; }
.vec-badge.active { border-color: var(--teal); color: var(--teal); }
.vec-dot { width: 6px; height: 6px; border-radius: 50%; background: var(--border); }
.vec-badge.active .vec-dot { background: var(--teal); box-shadow: 0 0 4px var(--teal); }

.alerts-wrap { background: var(--bg1); border: 1px solid var(--border);
               border-radius: 8px; overflow: hidden; }
.alerts-head { display: flex; justify-content: space-between; align-items: center;
               padding: 10px 14px; border-bottom: 1px solid var(--border);
               font-size: 12px; color: var(--muted); text-transform: uppercase; letter-spacing:.5px; }
.alerts-head button { background: var(--bg2); border: 1px solid var(--border); color: var(--muted);
                      padding: 4px 10px; border-radius: 4px; cursor: pointer; font-size: 11px; }
.alerts-head button:hover { color: var(--text); }
.alerts { max-height: 420px; overflow-y: auto; }
.alert-row { display: grid; grid-template-columns: 70px 90px 110px 120px 1fr;
             gap: 8px; padding: 8px 14px; border-bottom: 1px solid var(--border);
             font-size: 13px; align-items: center; }
.alert-row:last-child { border-bottom: none; }
.lvl { font-weight: 700; font-size: 11px; padding: 2px 7px; border-radius: 3px; text-align:center; }
.lvl.CRITICAL { background: #2d1117; color: var(--crit); }
.lvl.HIGH { background: #2d1c00; color: var(--amber); }
.lvl.MEDIUM { background: #0d1d2e; color: var(--med); }
.vec-tag { font-family: monospace; font-size: 11px; color: var(--teal);
           background: rgba(63,185,80,.1); padding: 2px 6px; border-radius: 3px; }
.proc { font-family: monospace; color: var(--muted); font-size: 12px; overflow:hidden;
        text-overflow:ellipsis; white-space:nowrap; }
.detail { color: var(--muted); font-size: 12px; overflow:hidden;
          text-overflow:ellipsis; white-space:nowrap; }
.empty { text-align: center; padding: 40px; color: var(--muted); font-size: 13px; }
.ts { color: var(--muted); font-size: 12px; font-family: monospace; }
.score { font-family: monospace; font-size: 12px; color: var(--muted); }
@media(max-width:700px) {
  .stats { grid-template-columns: 1fr 1fr; }
  .alert-row { grid-template-columns: 70px 90px 1fr; }
  .alert-row .proc, .alert-row .detail { display: none; }
}
</style>
</head>
<body>
<div class="header">
  <div>
    <div class="logo">eBPF Hunter <span>v4.0 — Standalone</span></div>
    <div style="font-size:12px;color:var(--muted);margin-top:4px">
      Linux kernel-level malware detection · 8 detection vectors
    </div>
  </div>
  <div class="status">
    <div class="dot" id="conn-dot"></div>
    <span id="conn-label" style="color:var(--muted)">Холбогдож байна...</span>
  </div>
</div>

<div class="stats">
  <div class="stat">
    <div class="num" id="s-total">0</div>
    <div class="lbl">Нийт alert</div>
  </div>
  <div class="stat">
    <div class="num" id="s-crit" style="color:var(--crit)">0</div>
    <div class="lbl">CRITICAL</div>
  </div>
  <div class="stat">
    <div class="num" id="s-high" style="color:var(--amber)">0</div>
    <div class="lbl">HIGH</div>
  </div>
  <div class="stat">
    <div class="num" id="s-med" style="color:var(--med)">0</div>
    <div class="lbl">MEDIUM</div>
  </div>
</div>

<div class="vectors" id="vec-grid"></div>

<div class="alerts-wrap">
  <div class="alerts-head">
    <span>🔴 Live Alert Feed</span>
    <button onclick="clearAlerts()">Clear</button>
  </div>
  <div class="alerts" id="alert-list">
    <div class="empty">Алерт хүлээж байна...</div>
  </div>
</div>

<script>
const VECTORS = ["RWX","MPROTECT","EXEC_TMP","MEMFD_EXEC","CONN_C2","MEMFD_SCAN","PYTHON_INJECT","CRON","CPU_SPIKE"];
const activeVecs = new Set();
let alerts = [], total = 0, crit = 0, high = 0, med = 0;

// Vector badges
const vg = document.getElementById("vec-grid");
VECTORS.forEach(v => {
  const d = document.createElement("div");
  d.className = "vec-badge";
  d.id = "vec-" + v;
  d.innerHTML = `<div class="vec-dot"></div>${v}`;
  vg.appendChild(d);
});

function updateStats() {
  document.getElementById("s-total").textContent = total;
  document.getElementById("s-crit").textContent  = crit;
  document.getElementById("s-high").textContent  = high;
  document.getElementById("s-med").textContent   = med;
}

function addAlert(a) {
  total++;
  if (a.level === "CRITICAL") crit++;
  else if (a.level === "HIGH") high++;
  else med++;
  updateStats();

  // Vector activate
  if (!activeVecs.has(a.vector)) {
    activeVecs.add(a.vector);
    const el = document.getElementById("vec-" + a.vector);
    if (el) el.className = "vec-badge active";
  }

  alerts.unshift(a);
  if (alerts.length > 200) alerts.pop();

  const list = document.getElementById("alert-list");
  const row = document.createElement("div");
  row.className = "alert-row";
  row.innerHTML = `
    <span class="ts">${a.ts}</span>
    <span class="lvl ${a.level}">${a.level}</span>
    <span class="vec-tag">${a.vector}</span>
    <span class="proc" title="${a.exe}">${a.process}(${a.pid})</span>
    <span class="detail" title="${a.detail}">${a.detail}</span>
  `;
  if (list.firstChild && list.firstChild.className === "empty") list.innerHTML = "";
  list.insertBefore(row, list.firstChild);
  if (list.children.length > 200) list.removeChild(list.lastChild);
}

function clearAlerts() {
  alerts = []; total = crit = high = med = 0;
  updateStats();
  document.getElementById("alert-list").innerHTML = '<div class="empty">Алерт хүлээж байна...</div>';
  activeVecs.clear();
  VECTORS.forEach(v => {
    const el = document.getElementById("vec-" + v);
    if (el) el.className = "vec-badge";
  });
}

// Server-Sent Events stream
function connect() {
  const es = new EventSource("/stream");
  const dot = document.getElementById("conn-dot");
  const lbl = document.getElementById("conn-label");

  es.onopen = () => {
    dot.style.background = "var(--teal)";
    dot.style.boxShadow = "0 0 6px var(--teal)";
    lbl.textContent = "Холбогдсон";
    lbl.style.color = "var(--teal)";
  };

  es.addEventListener("alert", e => {
    try { addAlert(JSON.parse(e.data)); } catch {}
  });

  es.addEventListener("ping", () => {});

  es.onerror = () => {
    dot.style.background = "var(--red)";
    dot.style.boxShadow = "0 0 6px var(--red)";
    lbl.textContent = "Дахин холбогдож байна...";
    lbl.style.color = "var(--red)";
    es.close();
    setTimeout(connect, 3000);
  };
}

// Existing alerts (page load)
fetch("/alerts").then(r => r.json()).then(data => {
  (data.alerts || []).reverse().forEach(addAlert);
});

connect();
</script>
</body>
</html>"""


def start_dashboard(port: int):
    """
    Хөнгөн HTTP + SSE dashboard — aiohttp/flask шаардлагагүй,
    зөвхөн stdlib http.server ашиглана.
    """
    import http.server
    import queue
    import urllib.parse

    subscribers: list = []
    subs_lock = threading.Lock()
    msg_queue: queue.Queue = queue.Queue()

    def _broadcast_loop():
        """Alert queue-ийн шинэ элементийг бүх SSE subscriber-руу илгээнэ."""
        while True:
            time.sleep(0.3)
            with _queue_lock:
                new_items = _alert_queue[:]
            # Хамгийн сүүлийн 1 секундын шинэ зүйлийг broadcast
            # (Simple polling approach)
            if not new_items:
                continue
            latest = new_items[-1]
            payload = f"event: alert\ndata: {json.dumps(latest, ensure_ascii=False)}\n\n"
            with subs_lock:
                dead = []
                for q in subscribers:
                    try:
                        q.put_nowait(payload)
                    except Exception:
                        dead.append(q)
                for d in dead:
                    subscribers.remove(d)

    # Separate broadcast thread
    threading.Thread(target=_broadcast_loop, daemon=True).start()

    class Handler(http.server.BaseHTTPRequestHandler):
        def log_message(self, fmt, *args):
            pass  # access log дарах

        def do_GET(self):
            path = urllib.parse.urlparse(self.path).path

            if path == "/" or path == "/index.html":
                self.send_response(200)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.end_headers()
                self.wfile.write(DASHBOARD_HTML.encode("utf-8"))

            elif path == "/alerts":
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                with _queue_lock:
                    data = json.dumps({"alerts": list(_alert_queue[-100:])}, ensure_ascii=False)
                self.wfile.write(data.encode())

            elif path == "/stream":
                import queue as _q
                self.send_response(200)
                self.send_header("Content-Type", "text/event-stream")
                self.send_header("Cache-Control", "no-cache")
                self.send_header("Connection", "keep-alive")
                self.send_header("Access-Control-Allow-Origin", "*")
                self.end_headers()

                q: _q.Queue = _q.Queue(maxsize=200)
                with subs_lock:
                    subscribers.append(q)

                try:
                    while True:
                        try:
                            msg = q.get(timeout=15)
                            self.wfile.write(msg.encode())
                            self.wfile.flush()
                        except _q.Empty:
                            # Keepalive ping
                            self.wfile.write(b"event: ping\ndata: {}\n\n")
                            self.wfile.flush()
                except Exception:
                    pass
                finally:
                    with subs_lock:
                        if q in subscribers:
                            subscribers.remove(q)

            else:
                self.send_response(404)
                self.end_headers()

    server = http.server.HTTPServer(("0.0.0.0", port), Handler)
    print(f"[*] Dashboard: http://localhost:{port}", flush=True)
    server.serve_forever()


# ─── MAIN ─────────────────────────────────────────────────────────────────────

def parse_args():
    p = argparse.ArgumentParser(
        description=f"eBPF RWX Hunter v{VERSION} — Linux kernel-level malware detector",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Жишээ:
  sudo python3 ebpf_rwx_hunter.py
  sudo python3 ebpf_rwx_hunter.py --port 9000
  sudo python3 ebpf_rwx_hunter.py --c2-ports 4444,1337,5555
  sudo python3 ebpf_rwx_hunter.py --log /var/log/hunter.log --no-dashboard
""")
    p.add_argument("--port", type=int, default=8765, help="Dashboard port (default: 8765)")
    p.add_argument("--c2-ports", type=str, default="",
                   help="Comma-separated suspicious ports (default: 4444,1337,...)")
    p.add_argument("--log", type=str, default="", help="Alert log file path")
    p.add_argument("--no-dashboard", action="store_true", help="Dashboard-гүй зөвхөн terminal")
    p.add_argument("--verbose", action="store_true", help="DEBUG output")
    return p.parse_args()


def main():
    args = parse_args()

    if os.geteuid() != 0:
        print("[!] Root эрх шаардлагатай: sudo python3 ebpf_rwx_hunter.py")
        sys.exit(1)

    # Config
    if args.c2_ports:
        try:
            CONFIG["c2_ports"] = {int(p.strip()) for p in args.c2_ports.split(",") if p.strip()}
        except ValueError:
            print("[!] --c2-ports буруу формат. Жишээ: 4444,1337,5555")
            sys.exit(1)

    CONFIG["log_file"] = args.log or None
    CONFIG["verbose"]  = args.verbose
    CONFIG["dashboard_port"] = args.port

    print(f"""
╔══════════════════════════════════════════════════════════════╗
║          eBPF RWX Hunter v{VERSION}  —  Standalone Edition        ║
╚══════════════════════════════════════════════════════════════╝
  C2 ports   : {sorted(CONFIG['c2_ports'])}
  Log file   : {CONFIG['log_file'] or 'stdout only'}
  Dashboard  : {'http://localhost:' + str(args.port) if not args.no_dashboard else 'disabled'}
""", flush=True)

    # Snapshot
    scan_existing_rwx()

    # Userspace watchers
    for fn in (network_watcher, memfd_watcher, crontab_watcher, cpu_watcher):
        threading.Thread(target=fn, daemon=True).start()

    # Dashboard
    if not args.no_dashboard:
        threading.Thread(
            target=start_dashboard, args=(args.port,), daemon=True
        ).start()

    # BPF compile + attach
    print("[*] BPF program compile хийж байна...", flush=True)
    try:
        global b
        b = BPF(text=BPF_PROGRAM)
        b["events"].open_perf_buffer(_handle_bpf_event, page_cnt=64)
        print("[*] eBPF probes attached. Monitoring эхэллээ. (Ctrl+C дарж зогсооно)\n", flush=True)
    except Exception as e:
        print(f"[!] BPF compile алдаа: {e}")
        print("    Kernel headers байгаа эсэхийг шалгана уу: sudo apt install linux-headers-$(uname -r)")
        sys.exit(1)

    # Graceful shutdown
    def _sig(sig, frame):
        print("\n[*] Зогссон.")
        sys.exit(0)
    signal.signal(signal.SIGINT, _sig)
    signal.signal(signal.SIGTERM, _sig)

    # Main poll loop
    while True:
        b.perf_buffer_poll(timeout=100)


if __name__ == "__main__":
    main()
