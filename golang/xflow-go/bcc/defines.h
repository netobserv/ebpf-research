#ifndef DEFINES_H
#define DEFINES_H

#include <vmlinux.h>

#define TC_ACT_OK 0
#define TC_ACT_SHOT 2

#define PIN_GLOBAL_NS 2
#define LIBBPF_PIN_BY_NAME 1

#define ETH_P_IP 0x0800

typedef struct flow_counters_t {
    __u32 packets;
    __u64 bytes;
    __u64 flow_start_ns;
    __u64 flow_end_ns;
} __attribute__((packed)) flow_counters;

typedef struct flow_id_t {
    __u32 saddr;
    __u32 daddr;
    __be16 sport;
    __be16 dport;
    __u8 protocol;
    __u16 interface;
} __attribute__((packed)) flow_id;

#define bpf_htons(x)                   \
    ((u16)((((u16)(x)&0xff00U) >> 8) | \
           (((u16)(x)&0x00ffU) << 8)))

#define bpf_htonl(x)                        \
    ((u32)((((u32)(x)&0xff000000U) >> 24) | \
           (((u32)(x)&0x00ff0000U) >> 8) |  \
           (((u32)(x)&0x0000ff00U) << 8) |  \
           (((u32)(x)&0x000000ffU) << 24)))

/* ELF map definition */
struct bpf_elf_map {
    __u32 type;
    __u32 size_key;
    __u32 size_value;
    __u32 max_elem;
    __u32 flags;
    __u32 id;
    __u32 pinning;
    __u32 inner_id;
    __u32 inner_idx;
};

#endif // DEFINES_H