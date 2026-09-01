# CyberSheppard — build del sensore eBPF CO-RE (Path B, ADR-0001).
# Requisiti host: clang, llvm (llvm-strip), bpftool, libbpf-dev, libelf-dev, zlib1g-dev.
#   sudo apt install -y clang llvm libbpf-dev bpftool libelf-dev zlib1g-dev
#
# BTF: per CO-RE si genera vmlinux.h da un BTF. Idealmente quello del TARGET
# (kernel 6.12): copiare /sys/kernel/btf/vmlinux dal target e passare BTF=...
# Default: BTF del sistema di build.
BTF     ?= /sys/kernel/btf/vmlinux
CLANG   ?= clang
BPFTOOL ?= bpftool
ARCH    ?= x86
CFLAGS  ?= -g -O2 -Wall

all: ebpf_sensor

vmlinux.h:
	$(BPFTOOL) btf dump file $(BTF) format c > vmlinux.h

ebpf_sensor.bpf.o: ebpf_sensor.bpf.c ebpf_sensor.h vmlinux.h
	$(CLANG) $(CFLAGS) -target bpf -D__TARGET_ARCH_$(ARCH) -I. -c ebpf_sensor.bpf.c -o $@
	llvm-strip -g $@

ebpf_sensor.skel.h: ebpf_sensor.bpf.o
	$(BPFTOOL) gen skeleton ebpf_sensor.bpf.o > ebpf_sensor.skel.h

# libbpf linkato STATICAMENTE (libbpf.a) → binario autonomo sul target (nessun
# bisogno di libbpf1). libelf/libz restano dinamici (presenti nel base system).
LIBBPF_A ?= /usr/lib/x86_64-linux-gnu/libbpf.a
ebpf_sensor: ebpf_sensor.c ebpf_sensor.skel.h ebpf_sensor.h
	$(CLANG) $(CFLAGS) -I. ebpf_sensor.c $(LIBBPF_A) -lelf -lz -o ebpf_sensor

clean:
	rm -f ebpf_sensor ebpf_sensor.bpf.o ebpf_sensor.skel.h vmlinux.h

.PHONY: all clean
