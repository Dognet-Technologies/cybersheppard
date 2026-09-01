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

## Note
- MVP basato su bpftrace; la forma di produzione (binario CO-RE/libbpf, senza runtime pesante
  sul target) è la naturale evoluzione (ADR-0001, Path B).
- I lettori legittimi di `shadow` (PAM: `unix_chkpwd`, `sshd`, `su`, …) sono esclusi dai
  detector per ridurre il rumore.
