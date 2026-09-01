/* CyberSheppard — sensore eBPF CO-RE: struct evento condivisa BPF/userspace. */
#ifndef EBPF_SENSOR_H
#define EBPF_SENSOR_H

#define EBPF_KIND_FILE   1
#define EBPF_KIND_PTRACE 2

#define EBPF_NAME_LEN 64
#define EBPF_COMM_LEN 16

struct ebpf_event {
    unsigned int  pid;
    unsigned int  uid;
    unsigned int  target_pid;   /* solo ptrace */
    unsigned char kind;         /* EBPF_KIND_* */
    char          comm[EBPF_COMM_LEN];
    char          name[EBPF_NAME_LEN]; /* basename file (file_open) */
};

#endif
