// CyberSheppard — loader userspace del sensore eBPF CO-RE.
// Carica/attacca il programma BPF, consuma gli eventi dal ring buffer e li
// immette come JSON "flat" nello stream che il dog-agent inoltra (stesso formato
// del collector bpftrace → detector R21/R22 invariati).
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <time.h>
#include <errno.h>
#include <bpf/libbpf.h>
#include "ebpf_sensor.h"
#include "ebpf_sensor.skel.h"

static volatile int exiting;
static const char *sink;

static void on_sig(int s) { (void)s; exiting = 1; }

static void iso_now(char *buf, size_t n)
{
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    struct tm tm;
    gmtime_r(&ts.tv_sec, &tm);
    char base[32];
    strftime(base, sizeof(base), "%Y-%m-%dT%H:%M:%S", &tm);
    snprintf(buf, n, "%s.%06ldZ", base, ts.tv_nsec / 1000);
}

static int handle_event(void *ctx, void *data, size_t sz)
{
    (void)ctx; (void)sz;
    struct ebpf_event *e = data;
    FILE *f = fopen(sink, "a");
    if (!f) return 0;
    char ts[48];
    iso_now(ts, sizeof(ts));
    if (e->kind == EBPF_KIND_FILE) {
        fprintf(f,
            "{\"type\":\"EBPF_CRED_ACCESS\",\"time\":\"%s\",\"comm\":\"%s\",\"exe\":\"%s\","
            "\"pid\":%u,\"uid\":\"%u\",\"name\":\"%s\",\"key\":\"ebpf_credread\","
            "\"res\":\"success\",\"sensor\":\"ebpf\"}\n",
            ts, e->comm, e->comm, e->pid, e->uid, e->name);
    } else {
        fprintf(f,
            "{\"type\":\"EBPF_PTRACE\",\"time\":\"%s\",\"comm\":\"%s\",\"exe\":\"%s\","
            "\"pid\":%u,\"uid\":\"%u\",\"key\":\"ebpf_ptrace\",\"res\":\"success\","
            "\"target_pid\":\"%u\",\"sensor\":\"ebpf\"}\n",
            ts, e->comm, e->comm, e->pid, e->uid, e->target_pid);
    }
    fclose(f);
    return 0;
}

int main(int argc, char **argv)
{
    sink = getenv("EBPF_SINK");
    if (!sink) sink = "/var/log/laurel/audit.log";
    (void)argc; (void)argv;

    signal(SIGINT, on_sig);
    signal(SIGTERM, on_sig);

    struct ebpf_sensor_bpf *skel = ebpf_sensor_bpf__open_and_load();
    if (!skel) { fprintf(stderr, "open_and_load fallito\n"); return 1; }
    if (ebpf_sensor_bpf__attach(skel)) {
        fprintf(stderr, "attach fallito (BPF-LSM attivo? 'bpf' in /sys/kernel/security/lsm)\n");
        ebpf_sensor_bpf__destroy(skel);
        return 1;
    }

    struct ring_buffer *rb = ring_buffer__new(bpf_map__fd(skel->maps.rb), handle_event, NULL, NULL);
    if (!rb) { fprintf(stderr, "ring_buffer__new fallito\n"); ebpf_sensor_bpf__destroy(skel); return 1; }

    fprintf(stderr, "[cybersheppard-ebpf] sensore CO-RE avviato (sink=%s)\n", sink);
    while (!exiting) {
        int err = ring_buffer__poll(rb, 200 /*ms*/);
        if (err < 0 && err != -EINTR) { fprintf(stderr, "poll err %d\n", err); break; }
    }
    ring_buffer__free(rb);
    ebpf_sensor_bpf__destroy(skel);
    return 0;
}
