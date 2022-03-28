#ifndef __COMMON_DEFINES_H
#define __COMMON_DEFINES_H

#include <sys/types.h>
//#include <net/if.h>
#include <linux/types.h>
#include <stdbool.h>
#define IFSIZE 16
struct config {
	__u32 xdp_flags;
	int ifindex;
	char *ifname;
	char ifname_buf[IFSIZE];
	int redirect_ifindex;
	char *redirect_ifname;
	char redirect_ifname_buf[IFSIZE];
	bool do_unload;
	bool reuse_maps;
	char pin_dir[512];
	char filename[512];
	char progsec[32];
	char src_mac[18];
	char dest_mac[18];
	__u16 xsk_bind_flags;
	int xsk_if_queue;
	bool xsk_poll_mode;
};
typedef struct flow_counters_t {
	__u32 packets;
	__u64 bytes;
	__u64 flow_start_ns;
	__u64 flow_end_ns;
	__u64 pkt_counter;
} __attribute__((packed)) flow_counters;

typedef struct flow_id_t {
	__u32 saddr;
	__u32 daddr;
	__be16 sport;
	__be16 dport;
	__u8  protocol;
	__u16 interface;
} __attribute__((packed)) flow_id;

typedef struct flow_def_t {
	__u32 saddr;
	__u32 daddr;
	__be16 sport;
	__be16 dport;
} __attribute__((packed)) flow_def;

typedef struct flow_id_seq_t {
	flow_def id;
	__be32 seq;
} __attribute__((packed)) flow_id_seq;


typedef struct flow_record_t {
	flow_id id;
	flow_counters counters;
} __attribute__((packed)) flow_record;

typedef struct packet_capture_config_t {
	__u32 interface;
	// TODO : Config
} __attribute__((packed)) packet_capture_config;


typedef struct timestamps_t {
    __u64 send_tstamp;
    __u32 rtt;
}__attribute__((packed)) timestamps;

typedef struct flow_report_t {
    __u32 avg_rtt;
    __u64 fct;
}__attribute__((packed)) flow_report;

/* Defined in common_params.o */
extern int verbose;

/* Exit return codes */
#define EXIT_OK 		 0 /* == EXIT_SUCCESS (stdlib.h) man exit(3) */
#define EXIT_FAIL		 1 /* == EXIT_FAILURE (stdlib.h) man exit(3) */
#define EXIT_FAIL_OPTION	 2
#define EXIT_FAIL_XDP		30
#define EXIT_FAIL_BPF		40

#endif /* __COMMON_DEFINES_H */
