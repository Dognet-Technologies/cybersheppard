#!/usr/bin/env python3
# CyberSheppard — collector del sensore eBPF (opt-in).
# Supervisiona bpftrace (watch.bt), formatta le sue righe in eventi JSON "flat"
# e li immette nello stream eventi che il dog-agent inoltra al server.
# Robusto: se bpftrace muore, viene riavviato.
import subprocess, json, sys, datetime, os, time

BT = "/etc/cybersheppard/ebpf/watch.bt"
SINK = os.environ.get("EBPF_SINK", "/var/log/laurel/audit.log")

def now():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()

def emit(evt):
    try:
        with open(SINK, "a") as f:
            f.write(json.dumps(evt) + "\n")
    except Exception as e:
        print(f"[ebpf] sink err: {e}", file=sys.stderr, flush=True)

def run_once():
    # stdbuf -oL forza il line-buffering di bpftrace verso la pipe.
    p = subprocess.Popen(
        ["stdbuf", "-oL", "bpftrace", BT],
        stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True, bufsize=1,
    )
    print(f"[ebpf] bpftrace avviato pid={p.pid}", file=sys.stderr, flush=True)
    for line in p.stdout:
        line = line.strip()
        if line.startswith("FOPEN|"):
            _, ns, pid, comm, uid, name = line.split("|", 5)
            emit({"type": "EBPF_CRED_ACCESS", "time": now(), "comm": comm, "exe": comm,
                  "pid": int(pid), "uid": uid, "name": name, "key": "ebpf_credread",
                  "res": "success", "sensor": "ebpf"})
        elif line.startswith("PTRACE|"):
            _, ns, pid, comm, uid, child = line.split("|", 5)
            emit({"type": "EBPF_PTRACE", "time": now(), "comm": comm, "exe": comm,
                  "pid": int(pid), "uid": uid, "key": "ebpf_ptrace", "res": "success",
                  "target_pid": child, "sensor": "ebpf"})
    return p.wait()

def main():
    print("[cybersheppard-ebpf] collector avviato", file=sys.stderr, flush=True)
    while True:
        try:
            rc = run_once()
            print(f"[ebpf] bpftrace terminato (rc={rc}), riavvio tra 3s", file=sys.stderr, flush=True)
        except Exception as e:
            print(f"[ebpf] errore: {e}", file=sys.stderr, flush=True)
        time.sleep(3)

if __name__ == "__main__":
    main()
