/* 
    XFlow. A Flow-metric generator using eBPF/XDP
    This program can be hooked on to XDP using SKB/native to monitor incoming packets from an interface.
*/
#include "xflow_global.h"

#define MYNAME "xflow"


/* Below is old-style map definition . TODO: add ifdef to detect */ 

// struct bpf_map_def SEC("maps") xflow_map = {
// 	 .type        = BPF_MAP_TYPE_HASH,	
// 	 .key_size    = sizeof(flow_id),
// 	.value_size  = sizeof(flow_counters),
// 	.max_entries = MAX_ENTRIES,
// };


/* This Map should ideally be per-interface */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);	
    __type(key, flow_id);
    __type(value, flow_counters);
    __uint(max_entries, MAX_ENTRIES);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} xflow_metric_map SEC(".maps");

SEC("xflow")
int xflow_start(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    int pkt_bytes = data_end - data;
    flow_id my_flow_id;
    int action = XDP_PASS;

    // Flow Metrics
    __u64 flow_start_time = 0;
    __u64 flow_end_time = 0;
    /* Get Flow ID : <sourceip, destip, sourceport, destport, protocol> */

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) {
        bpf_printk(MYNAME
                   " Dropping received packet that did not"
                   " contain full Ethernet header (data_end-data)=%d\n",
                   data_end - data);
        action = XDP_DROP;
        goto out;
    }
    if (eth->h_proto != bpf_htons(ETH_P_IP)) {
        // Non-IP packets, ignore for now
        goto out;
    }
    
    /* Get IP header */
    struct iphdr *iph = (struct iphdr *)(void *)(eth + 1);
    if ((void *)(iph + 1) > data_end) {
        bpf_printk(MYNAME " Dropping received Ethernet packet"
                             " with proto=0x%x indicating IPv4, but it"
                             " did not contain full IPv4 header"
                             " (data_end-data)=%d\n",
                   bpf_ntohs(eth->h_proto), data_end - data);
        action = XDP_DROP;
        goto out;
    }
    my_flow_id.saddr = iph->saddr;
    my_flow_id.daddr = iph->daddr;
    my_flow_id.protocol = iph->protocol;
    my_flow_id.interface = (__u16)ctx->ingress_ifindex;
    if (iph->protocol == IPPROTO_TCP) {
        struct tcphdr *tcph = (struct tcphdr *)(void *)(iph + 1);
        if (tcph + 1 > data_end) {
            bpf_printk(MYNAME " Dropping received Ethernet+IPv4"
                                 " packet with proto=TCP, but it was too"
                                 " short to contain a full TCP header"
                                 " (data_end-data)=%d\n",
                       data_end - data);
            action = XDP_DROP;
            goto out;
        }

        my_flow_id.sport = tcph->source;
        my_flow_id.dport = tcph->dest;
        if (tcph->syn) {
            flow_start_time = bpf_ktime_get_ns();
        }

        if (tcph->fin) {
            flow_end_time = bpf_ktime_get_ns();
        }

#ifdef EXTRA_DEBUG
        bpf_printk(MYNAME " [tcp]: %d->%d, %d\n", key.sport, key.dport,
                   new_seq_num);
#endif
    } else if (iph->protocol == IPPROTO_UDP) {
        struct udphdr *udph = (struct udphdr *)(void *)(iph + 1);
        if (udph + 1 > data_end) {
            bpf_printk(MYNAME " Dropping received Ethernet+IPv4"
                                 " packet with proto=UDP, but it was too"
                                 " short to contain a full UDP header"
                                 " (data_end-data)=%d\n",
                       data_end - data);
            action = XDP_DROP;
            goto out;
        }
        my_flow_id.sport = udph->source;
        my_flow_id.dport = udph->dest;

#ifdef EXTRA_DEBUG
        bpf_printk(MYNAME " [udp]: %d->%d, %d\n", key.sport, key.dport,
                   new_seq_num);
#endif
    } else {
        // Not a normal TCP/UDP flow, Ignore sport/dport part of flow-id
        my_flow_id.sport = 0;
        my_flow_id.dport = 0;
    }

    flow_counters *my_flow_counters =
        bpf_map_lookup_elem(&xflow_metric_map, &my_flow_id);
    if (my_flow_counters != NULL) {
        my_flow_counters->packets += 1;
        my_flow_counters->bytes += pkt_bytes;
        if (flow_end_time != 0) {
            my_flow_counters->flow_end_ns = flow_end_time;
        }
        bpf_map_update_elem(&xflow_metric_map, &my_flow_id, my_flow_counters, BPF_EXIST);
    } else {
        flow_counters new_flow_counter = {
            .packets = 1, .bytes=pkt_bytes};
        if (flow_start_time != 0) {
            new_flow_counter.flow_start_ns = flow_start_time;
        }
        int ret = bpf_map_update_elem(&xflow_metric_map, &my_flow_id, &new_flow_counter,
                                      BPF_NOEXIST);
        if (ret < 0) {
            bpf_printk(MYNAME "Map is full\n Work on eviction");
            goto out;
        }
    }

    out:
        return xdp_stats_record_action(ctx, action);
}


char _license[] SEC("license") = "GPL";
