#!/bin/sh
# Avvia il sensore eBPF: preferisce il binario CO-RE (produzione, nessun runtime
# pesante); fallback al collector bpftrace (MVP) se il binario non è presente.
if [ -x /opt/cybersheppard-ebpf/ebpf_sensor ]; then
    exec /opt/cybersheppard-ebpf/ebpf_sensor
else
    exec /usr/bin/python3 /opt/cybersheppard-ebpf/collector.py
fi
