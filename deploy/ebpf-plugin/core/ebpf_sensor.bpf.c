// CyberSheppard — sensore eBPF CO-RE (Path B, ADR-0001).
// Sostituisce l'MVP bpftrace con un programma libbpf CO-RE: nessun runtime pesante
// sul target, portabile tra kernel via BTF. Hook LSM (bpf è negli LSM attivi):
//   - file_open: apertura di file credenziali (cattura anche io_uring / root)
//   - ptrace_access_check: solo PTRACE_MODE_ATTACH (injection)
// È un sensore di SOLA OSSERVAZIONE: gli hook ritornano sempre 0 (mai deny).
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include "ebpf_sensor.h"

char LICENSE[] SEC("license") = "GPL";

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} rb SEC(".maps");

#define PTRACE_MODE_ATTACH 0x02

static __always_inline int streq(const char *a, const char *b, int n)
{
    for (int i = 0; i < n; i++) {
        if (a[i] != b[i]) return 0;
        if (a[i] == '\0') return 1;
    }
    return 1;
}

static __always_inline int is_cred_name(const char *s)
{
    return streq(s, "shadow", 7) || streq(s, "gshadow", 8) || streq(s, "shadow-", 8) ||
           streq(s, "id_rsa", 7) || streq(s, "id_ed25519", 11) || streq(s, "id_dsa", 7) ||
           streq(s, "authorized_keys", 16) || streq(s, ".pgpass", 8) || streq(s, "sudoers", 8);
}

SEC("lsm/file_open")
int BPF_PROG(on_file_open, struct file *file)
{
    char name[EBPF_NAME_LEN] = {};
    const unsigned char *nm = BPF_CORE_READ(file, f_path.dentry, d_name.name);
    bpf_probe_read_kernel_str(name, sizeof(name), nm);
    if (!is_cred_name(name))
        return 0;

    struct ebpf_event *e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (!e)
        return 0;
    e->kind = EBPF_KIND_FILE;
    e->pid = bpf_get_current_pid_tgid() >> 32;
    e->uid = bpf_get_current_uid_gid() & 0xffffffff;
    e->target_pid = 0;
    bpf_get_current_comm(&e->comm, sizeof(e->comm));
    __builtin_memcpy(e->name, name, sizeof(e->name));
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("lsm/ptrace_access_check")
int BPF_PROG(on_ptrace, struct task_struct *child, unsigned int mode)
{
    if (!(mode & PTRACE_MODE_ATTACH))
        return 0;

    struct ebpf_event *e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (!e)
        return 0;
    e->kind = EBPF_KIND_PTRACE;
    e->pid = bpf_get_current_pid_tgid() >> 32;
    e->uid = bpf_get_current_uid_gid() & 0xffffffff;
    e->target_pid = BPF_CORE_READ(child, pid);
    bpf_get_current_comm(&e->comm, sizeof(e->comm));
    e->name[0] = '\0';
    bpf_ringbuf_submit(e, 0);
    return 0;
}
