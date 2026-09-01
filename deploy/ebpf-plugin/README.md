# CyberSheppard — Sensore eBPF (plugin opt-in)

Sensore kernel-level **opzionale** che colma i blind-spot di auditd/Laurel emersi in
purple-team (vedi ADR-0001, decisione: eBPF **minimale opt-in**, non nel core).

## Cosa cattura (che auditd/Laurel non vede)
- **Lettura di file credenziali via io_uring** — `security_file_open` scatta anche per le
  open in contesto worker io_uring, con attribuzione processo/uid (auditd: 0 record).
- **Accesso da processi root/daemon** — l'hook è indipendente dall'auid (blind-spot execve).
- **Injection ptrace/process_vm_writev** — `security_ptrace_access_check`.

## Come funziona
`bpftrace` (programma `watch.bt`) → `collector.py` formatta eventi JSON e li immette nello
stream eventi che il `dog-agent` già inoltra → `security_events` → detector **R21**
(eBPF Credential Access, T1003) e **R22** (Process Injection ptrace, T1055).

## Requisiti target
Kernel con BTF (`/sys/kernel/btf/vmlinux`) e `CONFIG_KPROBES=y` (Debian 13 / kernel 6.x: ok).

## Installazione (opt-in — DISATTIVO di default)
```bash
sudo ./install-ebpf.sh
sudo systemctl enable --now cybersheppard-ebpf   # attiva quando vuoi il sensore
```

## Due forme (ADR-0001)
- **Path B — binario CO-RE/libbpf (produzione)**: `core/` contiene il sorttorgente. Si builda su
  una macchina con toolchain (`clang llvm libbpf-dev bpftool libelf-dev zlib1g-dev`), libbpf
  linkato **staticamente** → binario autonomo (solo libc/libelf/libz base-system), **niente
  bpftrace/llvm sul target**. `run-sensor.sh` lo preferisce se presente.
  ```bash
  cd core && make BTF=/percorso/al/btf/del/target BPFTOOL=/usr/sbin/bpftool
  # copiare core/ebpf_sensor accanto a install-ebpf.sh e poi ./install-ebpf.sh
  ```
- **Path A — collector bpftrace (MVP/fallback)**: `watch.bt` + `collector.py`; usato se il
  binario CO-RE non è presente (richiede `bpftrace` sul target).

Entrambe emettono gli stessi eventi → detector R21/R22 invariati.

## Note
- I lettori legittimi di `shadow` (PAM: `unix_chkpwd`, `sshd`, `su`, …) sono esclusi dai
  detector per ridurre il rumore. Gli hook LSM sono di **sola osservazione** (ritornano sempre
  0, non bloccano mai le operazioni).
