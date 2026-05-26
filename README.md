# eBPF Hunter v0.2

> **Linux kernel-level malware detector** — eBPF tracepoint ашиглан in-memory shellcode, fileless execution, reverse shell болон persistence механизмуудыг real-time илрүүлнэ.

[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Python 3.10+](https://img.shields.io/badge/Python-3.10+-blue.svg)](https://python.org)
[![Kernel 5.15+](https://img.shields.io/badge/Kernel-5.15+-orange.svg)](https://kernel.org)
[![Ubuntu 22.04](https://img.shields.io/badge/Ubuntu-22.04-E95420.svg)](https://ubuntu.com)

---

## Хэрхэн ажилладаг вэ?

```
 Malware ажиллана
       │
       ▼
  Linux Kernel  ──── eBPF tracepoint hook ────► ebpf_rwx_hunter.py
  (syscall layer)                                      │
                                                ┌──────┴───────┐
                                                │   Alert!     │
                                                │  Terminal    │
                                                │  Dashboard   │
                                                └──────────────┘
```

eBPF Hunter нь **kernel syscall** дээр hook тавьдаг тул:
- Userspace-ийн bypass **боломжгүй**
- Encoding, obfuscation-ыг **тойрч гарах боломжгүй**
- JVM, runtime дахин compile (JIT) **false-positive бага**

---

## Detection Vectors (9)

| # | Vector | Арга | Илрүүлэх зүйл | Sample |
|:-:|--------|------|----------------|--------|
| 1 | **RWX** | BPF mmap | `mmap(PROT_READ\|WRITE\|EXEC)` | Shellcode loader |
| 2 | **MPROTECT** | BPF mprotect | RW→RWX permission escalation | Staged loader |
| 3 | **EXEC_TMP** | BPF execve | Execute from `/tmp` `/dev/shm` | Dropper |
| 4 | **MEMFD_EXEC** | BPF execve | `/proc/self/fd/N` fileless exec | Fileless ELF |
| 5 | **CONN_C2** | psutil poll | Suspicious port connection | Reverse shell |
| 6 | **MEMFD_SCAN** | /proc/maps | `memfd:` pattern in memory | Fileless ELF |
| 7 | **PYTHON_INJECT** | BPF+cmdline | Python ctypes RWX mmap | LOTL injection |
| 8 | **CRON** | File watcher | Crontab reverse shell pattern | Persistence |
| 9 | **CPU_SPIKE** | psutil | Sustained 75%+ CPU load | Crypto miner |

---

## Quick Start

```bash
# 1. Clone
git clone https://github.com/YOUR_USERNAME/ebpf-hunter.git
cd ebpf-hunter

# 2. Суулгах (Ubuntu/Debian)
sudo bash install.sh

# 3. Ажиллуулах — Terminal 1
sudo python3 ebpf_rwx_hunter.py
```

Dashboard: **http://localhost:8765** эсвэл **http://SERVER_IP:8765**

> ⚠️ Hunter ажиллаж байх үед dashboard **автоматаар** хүртэх боломжтой.
> Гаднаас нэвтрэхийн тулд firewall-д 8765 порт нээх хэрэгтэй: `sudo ufw allow 8765`

### Detection тестлэх

```bash
# Terminal 2 — hunter ажиллаж байх үед
sudo bash test_hunter.sh
```

6 тест ажилна — Terminal 1 дээр alert харагдах ёстой.

---

## Системийн шаардлага

| Шаардлага | Хамгийн бага | Санал болгох |
|---|---|---|
| OS | Ubuntu 20.04 | Ubuntu 22.04 LTS |
| Kernel | 4.15 | **5.15+** |
| Python | 3.8 | **3.10+** |
| BCC | 0.20 | **0.30+** |
| RAM | 64 MB | 128 MB |
| CPU overhead | ~0.5% | ~1% |

---

## Гар аар суулгах

```bash
# Ubuntu 22.04
sudo apt update
sudo apt install -y bpfcc-tools python3-bpfcc python3-psutil \
                    linux-headers-$(uname -r)

# Python psutil (хэрэв байхгүй бол)
pip3 install psutil
```

---

## Хэрэглэх заавар

```bash
# Үндсэн ажиллуулалт
sudo python3 ebpf_rwx_hunter.py

# Dashboard port өөрчлөх
sudo python3 ebpf_rwx_hunter.py --port 9000

# C2 port жагсаалт нэмэх
sudo python3 ebpf_rwx_hunter.py --c2-ports 4444,1337,8080,9001

# Alert log файлд хадгалах
sudo python3 ebpf_rwx_hunter.py --log /var/log/ebpf_hunter.log

# Dashboard-гүй зөвхөн terminal
sudo python3 ebpf_rwx_hunter.py --no-dashboard

# Бүх тохиргооны тусламж
sudo python3 ebpf_rwx_hunter.py --help
```

---

## Dashboard харагдах байдал

```
╔══════════════════════════════════════════════════════════════╗
║  eBPF Hunter v4.0 — Live Dashboard      ● Холбогдсон        ║
╠══════════════════════════════════════════════════════════════╣
║  Нийт: 7    CRITICAL: 2    HIGH: 4    MEDIUM: 1             ║
╠══════════════════════════════════════════════════════════════╣
║  [●RWX] [●MPROTECT] [●EXEC_TMP] [MEMFD_EXEC] [●CONN_C2]    ║
║  [●MEMFD_SCAN] [●PYTHON_INJECT] [●CRON] [●CPU_SPIKE]        ║
╠══════════════════════════════════════════════════════════════╣
║  12:03:15  CRITICAL  RWX          loader(1234)   mmap RWX   ║
║  12:03:40  HIGH      MPROTECT     mprot(1456)    RW→RWX     ║
║  12:04:15  HIGH      CONN_C2      bash(1789)     :4444      ║
╚══════════════════════════════════════════════════════════════╝
```

---

## Score тооцоолол

```
Үндсэн detection score:
  mmap/mprotect RWX         +40
  /tmp /dev/shm path        +35
  Deleted executable        +25
  C2 port connection        +40
  JIT runtime (Java/Node)   -20

Score → Alert level:
  ≥ 80   CRITICAL
  ≥ 55   HIGH
  ≥ 35   MEDIUM
  < 35   INFO (хэвлэхгүй)
```

---

## Туршилтын үр дүн (лабораторийн орчин)

| Sample | Техник | MITRE | Илрүүлэгдсэн эсэх | Vector |
|--------|--------|-------|:-:|--------|
| EICAR | Signature | N/A | ❌ | (signature-only) |
| msfvenom ELF | Static binary | T1059 | ✅ | EXEC_TMP |
| RWX shellcode | In-memory | T1620 | ✅ | RWX |
| XOR-encoded | Obfuscation | T1027 | ✅ | RWX |
| mprotect | RW→RWX | T1055 | ✅ | MPROTECT |
| memfd fileless | Fileless | T1620 | ✅ | MEMFD_SCAN |
| Python ctypes | LOTL | T1059.006 | ✅ | PYTHON_INJECT |
| Bash /dev/tcp | Reverse shell | T1059.004 | ✅ | CONN_C2 |
| Crypto miner | Resource abuse | T1496 | ✅ | CPU_SPIKE |
| Cron persistence | Persistence | T1053.003 | ✅ | CRON |

**9/10 detection rate** (EICAR нь signature-only, RWX vector байхгүй)

---

## Харьцуулалт

| Метрик | eBPF Hunter | Commercial EDR |
|--------|:-----------:|:--------------:|
| Detection rate | 9/10 (90%) | 2/10 (20%) |
| Avg latency | ~1500 ms | ~5000 ms |
| Idle CPU | **~0.5%** | ~25% |
| Idle RAM | **~50 MB** | ~1200 MB |
| Bypass-able | **No** | Yes (encoding) |
| Cost | **Free** | $$$ |

---

## Wazuh интеграци (нэмэлт)

Хэрэв Wazuh SIEM ашиглаж байгаа бол `/var/log/ebpf_hunter.log`-г monitor хийж болно:

```xml
<!-- /var/ossec/etc/ossec.conf дотор -->
<localfile>
  <log_format>syslog</log_format>
  <location>/var/log/ebpf_hunter.log</location>
</localfile>
```

```bash
sudo python3 ebpf_rwx_hunter.py --log /var/log/ebpf_hunter.log
```

---

## Хязгаарлалт

- EICAR-ыг илрүүлэхгүй (signature-only, RWX operation байхгүй)
- `systemd` scope-оос ажиллах процессуудад trust хийдэг
- Production орчинд false-positive тохируулах шаардлагатай (`TRUSTED_SYSTEM_PROCS`)

---

## Гэмт хэргийн хариуцлага

> ⚠️ **Зөвхөн эрдэм шинжилгээ, боловсрол, зөвшөөрөлтэй penetration testing-д хэрэглэнэ.**  
> Жинхэнэ системд зөвшөөрөлгүй ашиглах нь хууль зөрчих болно.

---

## Эх сурвалж

- [MITRE ATT&CK Framework](https://attack.mitre.org/)
- [BCC Tools](https://github.com/iovisor/bcc)
- [eBPF.io Documentation](https://ebpf.io/)
- [Linux Kernel Tracepoints](https://www.kernel.org/doc/html/latest/trace/tracepoints.html)

---

## Лиценз

[MIT License](LICENSE) — эрдэм шинжилгээ, боловсролын зориулалтаар чөлөөтэй ашиглаж болно.

---

> **Дипломын ажил:** eBPF технологид суурилсан Linux хяналтын систем — 2026
