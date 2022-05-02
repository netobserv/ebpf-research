//#include "../../headers/linux/bpf.h"
#include <linux/bpf.h>
#include <linux/in.h>
#include <linux/if_packet.h>
#include <linux/if_vlan.h>
#include <linux/ip.h>
#include <linux/if_ether.h>
#include <linux/ipv6.h>
#include <linux/icmp.h>
#include <linux/icmpv6.h>
#include <linux/udp.h>
#include <linux/tcp.h>

#include <linux/pkt_cls.h>
#include <iproute2/bpf_elf.h>
//#include <bpf/bpf_helper_defs.h>
#include <stdbool.h>
#include <linux/if_ether.h>
#define MAX_ENTRIES 1000

//flags
#define TCP_FIN_FLAG 0x1
#define DIR_EGRESS_FLAG 0x10 

typedef struct flow_metrics_t {
	__u32 packets;
	__u64 bytes;
	__u64 flow_start_ts;
    __u64 last_pkt_ts;
	__u32 flags;  // Could be used to indicate certain things
} __attribute__((packed)) flow_metrics;

typedef struct flow_id_t {
	__u32 saddr;
	__u32 daddr;
	__be16 sport;
	__be16 dport;
	__u8  protocol;
} __attribute__((packed)) flow_id;


typedef struct flow_record_t {
	flow_id id;
	flow_metrics metrics;
} __attribute__((packed)) flow_record;
