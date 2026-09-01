#!/usr/bin/env bash
# ============================================================================
# CyberSheppard — Sensore eBPF OPT-IN (plugin)
# Colma i punti ciechi di auditd/Laurel verificati in purple-team:
#   - lettura di file credenziali via io_uring (auditd non la vede)
#   - accesso da processi root/daemon (blind-spot auid)
#   - injection via ptrace/process_vm_writev
# Hook LSM/kprobe: security_file_open, security_ptrace_access_check.
# NON abilitato di default: è una capacità premium opt-in (vedi ADR-0001).
# Requisiti target: kernel con BTF (/sys/kernel/btf/vmlinux) + CONFIG_KPROBES.
# ============================================================================
set -euo pipefail
HERE="$(dirname "$0")"

echo "[eBPF] verifica requisiti..."
[ -r /sys/kernel/btf/vmlinux ] || { echo "ERRORE: BTF assente — kernel non idoneo"; exit 1; }

echo "[eBPF] deploy file..."
mkdir -p /etc/cybersheppard/ebpf /opt/cybersheppard-ebpf
install -m 755 "$HERE/run-sensor.sh"  /opt/cybersheppard-ebpf/run-sensor.sh
install -m 644 "$HERE/cybersheppard-ebpf.service" /etc/systemd/system/cybersheppard-ebpf.service

# Produzione (Path B): se è presente il binario CO-RE pre-buildato, usa quello
# (nessuna dipendenza runtime pesante sul target).
if [ -x "$HERE/core/ebpf_sensor" ]; then
    echo "[eBPF] installo sensore CO-RE (produzione)"
    install -m 755 "$HERE/core/ebpf_sensor" /opt/cybersheppard-ebpf/ebpf_sensor
else
    echo "[eBPF] binario CO-RE assente → fallback bpftrace (MVP); installo bpftrace..."
    export DEBIAN_FRONTEND=noninteractive
    command -v bpftrace >/dev/null || apt-get install -y -qq bpftrace
    install -m 644 "$HERE/watch.bt"     /etc/cybersheppard/ebpf/watch.bt
    install -m 755 "$HERE/collector.py" /opt/cybersheppard-ebpf/collector.py
fi
systemctl daemon-reload

echo "[eBPF] installato (DISATTIVO). Per attivare l'opt-in:"
echo "         systemctl enable --now cybersheppard-ebpf"
echo "       Verifica: systemctl status cybersheppard-ebpf ; journalctl -u cybersheppard-ebpf"
