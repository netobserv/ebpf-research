/*
    XFlow. A Flow-metric generator using TC.
    This program can be hooked on to TC egress hook to monitor outgoing packets from an interface.
*/
#include "xflow_global.h"

#include <linux/if_packet.h>
#include <linux/if_vlan.h>
#include <linux/ip.h>
#include <linux/pkt_cls.h>
// we are using tc to load in our ebpf program that will
// create maps for us and require structure bpf_elf_map
#include <iproute2/bpf_elf.h>
#include <bpf/bpf_helpers.h>

#include <bpf/bpf_endian.h>

#include "../common/parsing_helpers.h"
#include "../common/common_defines.h"
#include "../common/common_utils.h"



#define MYNAME "xflow_tc"

//#define BPF_MAP_TYPE_RINGBUF 28
#define bpf_tc_printk(fmt, ...) \
({ \
const char ____fmt[] = fmt; \
bpf_trace_printk(____fmt, sizeof(____fmt), \
##__VA_ARGS__); \
})


// struct {
//     __uint(type, BPF_MAP_TYPE_RINGBUF);
//     __uint(max_entries, 1 << 24);
// } flow_maps SEC(".maps");


// struct bpf_elf_map SEC("maps") rtt_map = {
//     .type        = BPF_MAP_TYPE_HASH,
//     .id          = 1,
//     .size_key    = sizeof(__be32), // sequence number
//     .size_value  = sizeof(__u64), // time
//     .pinning     = PIN_GLOBAL_NS,
//     .max_elem    = MAX_ENTRIES,
// };
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, flow_id);
    __type(value, flow_counters);
    __uint(max_entries, MAX_ENTRIES);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} xflow_metric_tc_map SEC(".maps");


SEC("xflow")
int xflow_start(struct __sk_buff *skb) {
    void *data_end = (void *)(long)skb->data_end;
    void *data = (void *)(long)skb->data;
    flow_id my_flow_id;
    int rc = TC_ACT_OK;
    int pkt_bytes = data_end - data;

    // Flow Metrics
    __u64 flow_start_time = 0;
    __u64 flow_end_time = 0;
    /* Get Flow ID : <sourceip, destip, sourceport, destport, protocol> */

    /* Get Eth header */
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) {
        bpf_tc_printk(MYNAME
                   " Dropping received packet that did not"
                   " contain full Ethernet header (data_end-data)=%d\n",
                   data_end - data);
        return rc;
    }
    if (eth->h_proto != bpf_htons(ETH_P_IP)) {
        // Non-IP packets, ignore for now
        return rc;
    }

    /* Get IP header */
    struct iphdr *iph = (struct iphdr *)(void *)(eth + 1);
    if ((void *)(iph + 1) > data_end) {
        bpf_tc_printk(MYNAME " Dropping received Ethernet packet"
                             " with proto=0x%x indicating IPv4, but it"
                             " did not contain full IPv4 header"
                             " (data_end-data)=%d\n",
                        bpf_ntohs(eth->h_proto), data_end - data);
        return rc;
    }
    my_flow_id.saddr = iph->saddr;
    my_flow_id.daddr = iph->daddr;
    my_flow_id.protocol = iph->protocol;
    my_flow_id.interface = (__u16)skb->ifindex;

    if (iph->protocol == IPPROTO_TCP) {
        struct tcphdr *tcph = (struct tcphdr *)(void *)(iph + 1);
        if (tcph + 1 > data_end) {
            bpf_tc_printk(MYNAME " Dropping received Ethernet+IPv4"
                                 " packet with proto=UDP, but it was too"
                                 " short to contain a full UDP header"
                                 " (data_end-data)=%d\n",
                        data_end - data);
            return rc;
        }

        my_flow_id.sport = tcph->source;
        my_flow_id.dport = tcph->dest;
        // if (tcph->syn) {
        //     flow_start_time = bpf_ktime_get_ns();
        // }
        //
        // if (tcph->fin) {
        //     flow_end_time = bpf_ktime_get_ns();
        // }

#ifdef EXTRA_DEBUG
        bpf_tc_printk(MYNAME " [tcp]: %d->%d, %d\n", key.sport, key.dport,
                   new_seq_num);
#endif
    } else if (iph->protocol == IPPROTO_UDP) {
        struct udphdr *udph = (struct udphdr *)(void *)(iph + 1);
        if (udph + 1 > data_end) {
            bpf_tc_printk(MYNAME " Dropping received Ethernet+IPv4"
                                 " packet with proto=UDP, but it was too"
                                 " short to contain a full UDP header"
                                 " (data_end-data)=%d\n",
                       data_end - data);
            return rc;
        }
        my_flow_id.sport = udph->source;
        my_flow_id.dport = udph->dest;

#ifdef EXTRA_DEBUG
        bpf_tc_printk(MYNAME " [udp]: %d->%d, %d\n", key.sport, key.dport,
                   new_seq_num);
#endif
    } else {
        // Not a normal TCP/UDP flow, Ignore sport/dport part of flow-id
        my_flow_id.sport = 0;
        my_flow_id.dport = 0;
    }
    //bpf_tc_printk(MYNAME " Recording packet size=%d, interface=%d", pkt_bytes, skb->ifindex);

    flow_counters *my_flow_counters =
        bpf_map_lookup_elem(&xflow_metric_tc_map, &my_flow_id);
    if (my_flow_counters != NULL) {
        my_flow_counters->packets += 1;
        my_flow_counters->bytes += pkt_bytes;
        if (flow_end_time != 0) {
            my_flow_counters->flow_end_ns = flow_end_time;
        }
        bpf_map_update_elem(&xflow_metric_tc_map, &my_flow_id, my_flow_counters, BPF_EXIST);
    } else {
        flow_counters new_flow_counter = {
            .packets = 1, .bytes=pkt_bytes};
        if (flow_start_time != 0) {
            new_flow_counter.flow_start_ns = flow_start_time;
        }
        int ret = bpf_map_update_elem(&xflow_metric_tc_map, &my_flow_id, &new_flow_counter,
                                      BPF_NOEXIST);
        if (ret < 0) {
            bpf_tc_printk(MYNAME "Map is full\n Work on eviction");
            /*
                Evicted entry can be sent to userspace via RingBuffer
            */
            return rc;
        }
    }
    return rc;
}
char _license[] SEC("license") = "GPL";
