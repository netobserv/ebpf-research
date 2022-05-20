/*
    XFlow Metric. A Flow-metric generator using TC.

    This program can be hooked on to TC ingress/egress hook to monitor packets
    to/from an interface.

    Logic:
        1) Store flow information in a per-cpu hash map.
        2) Upon flow completion (tcp->fin event), evict the entry from map, and
           send to userspace through ringbuffer.
           Eviction for non-tcp flows need to done by userspace
        3) When the map is full, we have two choices:
                1) Send the new flow entry to userspace via ringbuffer,
                        until an entry is available.
                2) Send an existing flow entry (probably least recently used)
                        to userspace via ringbuffer, delete that entry, and add in the
                        new flow to the hash map.

                Ofcourse, 2nd step involves more manipulations and
                    state maintenance, and will it provide any performance benefit?
*/

#include "xflow_metric.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define MYNAME "xflow_metric"

//#define BPF_MAP_TYPE_RINGBUF 28
#define bpf_tc_printk(fmt, ...) \
({ \
const char ____fmt[] = fmt; \
bpf_trace_printk(____fmt, sizeof(____fmt), \
##__VA_ARGS__); \
})

// Common Ringbuffer as a conduit for ingress/egress maps to userspace
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);
} flow_records SEC(".maps");


struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_HASH);
    __type(key, flow_id);
    __type(value, flow_metrics);
    __uint(max_entries, MAX_ENTRIES);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} xflow_metric_map_ingress SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_HASH);
    __type(key, flow_id);
    __type(value, flow_metrics);
    __uint(max_entries, MAX_ENTRIES);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} xflow_metric_map_egress SEC(".maps");

static inline int record_ingress_packet(struct __sk_buff *skb) {
    void *data_end = (void *)(long)skb->data_end;
    void *data = (void *)(long)skb->data;
    flow_id my_flow_id;
    int rc = TC_ACT_OK;
    int pkt_bytes = data_end - data;

    __u64 current_time = bpf_ktime_get_ns();
    //bool tcp_start = false;
    bool tcp_end = false;

    flow_record *flow_event;
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
    //my_flow_id.interface = (__u16)skb->ifindex;

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
        //     tcp_start = true;
        // }

        if (tcph->fin) {
            tcp_end = true;
        }
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

    } else {
        // Not a normal TCP/UDP flow, Ignore sport/dport part of flow-id
        my_flow_id.sport = 0;
        my_flow_id.dport = 0;
    }
    //bpf_tc_printk(MYNAME " Recording packet size=%d, interface=%d", pkt_bytes, skb->ifindex);

    flow_metrics *my_flow_counters =
        bpf_map_lookup_elem(&xflow_metric_map_egress, &my_flow_id);
    if (my_flow_counters != NULL) {
        my_flow_counters->packets += 1;
        my_flow_counters->bytes += pkt_bytes;
        my_flow_counters->last_pkt_ts = current_time;
        if (tcp_end) {
            /* Need to evict the entry and send it via ring buffer */
            flow_event = bpf_ringbuf_reserve(&flow_records, sizeof(flow_record), 0);
            if (!flow_event) {
                bpf_tc_printk(MYNAME "Ring buf reserve failed");
                return rc;
            }
            flow_event->id = my_flow_id;
            flow_event->metrics.packets = my_flow_counters->packets;
            flow_event->metrics.bytes = my_flow_counters->bytes;
            flow_event->metrics.last_pkt_ts = my_flow_counters->last_pkt_ts;
            flow_event->metrics.flags = flow_event->metrics.flags | TCP_FIN_FLAG;
            bpf_ringbuf_submit(flow_event, 0);
            // Delete the entry from the map
            bpf_map_delete_elem(&xflow_metric_map_egress, &my_flow_id);
            bpf_tc_printk(MYNAME "Flow ended, Delete and send to Ringbuf");
        } else {
            bpf_map_update_elem(&xflow_metric_map_ingress, &my_flow_id, my_flow_counters, BPF_EXIST);
        }
    } else {
        flow_metrics new_flow_counter = {
            .packets = 1, .bytes=pkt_bytes};
        new_flow_counter.flow_start_ts = current_time;
        new_flow_counter.last_pkt_ts = current_time;
        int ret = bpf_map_update_elem(&xflow_metric_map_ingress, &my_flow_id, &new_flow_counter,
                                      BPF_NOEXIST);
        if (ret < 0) {
            /*
                When the map is full, we have two choices:
                    1) Send the new flow entry to userspace via ringbuffer,
                       until an entry is available.
                    2) Send an existing flow entry (probably least recently used)
                       to userspace via ringbuffer, delete that entry, and add in the
                       new flow to the hash map.

                Ofcourse, 2nd step involves more manipulations and
                       state maintenance, and will it provide any performance benefit?

            */

            flow_event = bpf_ringbuf_reserve(&flow_records, sizeof(flow_record), 0);
            if (!flow_event) {
                bpf_tc_printk(MYNAME "Ring buf reserve failed");
                return rc;
            }
            flow_event->id = my_flow_id;
            flow_event->metrics = new_flow_counter;
            bpf_ringbuf_submit(flow_event, 0);
            bpf_tc_printk(MYNAME "Map space for new flow not found, sending to ringbuf");
        }else {
            bpf_tc_printk(MYNAME "New flow created in Map");
        }
    }
    return rc;
}

static inline int record_egress_packet(struct __sk_buff *skb) {
    void *data_end = (void *)(long)skb->data_end;
    void *data = (void *)(long)skb->data;
    flow_id my_flow_id;
    int rc = TC_ACT_OK;
    int pkt_bytes = data_end - data;

    __u64 current_time = bpf_ktime_get_ns();
    //bool tcp_start = false;
    bool tcp_end = false;

    flow_record *flow_event;
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
    //my_flow_id.interface = (__u16)skb->ifindex;

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
        //     tcp_start = true;
        // }

        if (tcph->fin) {
            tcp_end = true;
        }
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

    } else {
        // Not a normal TCP/UDP flow, Ignore sport/dport part of flow-id
        my_flow_id.sport = 0;
        my_flow_id.dport = 0;
    }
    //bpf_tc_printk(MYNAME " Recording packet size=%d, interface=%d", pkt_bytes, skb->ifindex);

    flow_metrics *my_flow_counters =
        bpf_map_lookup_elem(&xflow_metric_map_egress, &my_flow_id);
    if (my_flow_counters != NULL) {
        my_flow_counters->packets += 1;
        my_flow_counters->bytes += pkt_bytes;
        my_flow_counters->last_pkt_ts = current_time;
        if (tcp_end) {
            /* Need to evict the entry and send it via ring buffer */
            flow_event = bpf_ringbuf_reserve(&flow_records, sizeof(flow_record), 0);
            if (!flow_event) {
                bpf_tc_printk(MYNAME "Ring buf reserve failed");
                return rc;
            }
            flow_event->id = my_flow_id;
            flow_event->metrics.packets = my_flow_counters->packets;
            flow_event->metrics.bytes = my_flow_counters->bytes;
            flow_event->metrics.last_pkt_ts = my_flow_counters->last_pkt_ts;
            flow_event->metrics.flags = flow_event->metrics.flags | TCP_FIN_FLAG;
            flow_event->metrics.flags = flow_event->metrics.flags | DIR_EGRESS_FLAG;
            bpf_ringbuf_submit(flow_event, 0);
            // Delete the entry from the map
            bpf_map_delete_elem(&xflow_metric_map_egress, &my_flow_id);
            bpf_tc_printk(MYNAME "Flow ended, Delete and send to Ringbuf");
        } else {
            bpf_map_update_elem(&xflow_metric_map_egress, &my_flow_id, my_flow_counters, BPF_EXIST);
        }
    } else {
        flow_metrics new_flow_counter = {
            .packets = 1, .bytes=pkt_bytes};
        new_flow_counter.flow_start_ts = current_time;
        new_flow_counter.last_pkt_ts = current_time;
        int ret = bpf_map_update_elem(&xflow_metric_map_egress, &my_flow_id, &new_flow_counter,
                                      BPF_NOEXIST);
        if (ret < 0) {
            /*
                When the map is full, we have two choices:
                    1) Send the new flow entry to userspace via ringbuffer,
                       until an entry is available.
                    2) Send an existing flow entry (probably least recently used)
                       to userspace via ringbuffer, delete that entry, and add in the
                       new flow to the hash map.

                Ofcourse, 2nd step involves more manipulations and
                       state maintenance, and will it provide any performance benefit?

            */

            flow_event = bpf_ringbuf_reserve(&flow_records, sizeof(flow_record), 0);
            if (!flow_event) {
                bpf_tc_printk(MYNAME "Ring buf reserve failed");
                return rc;
            }
            flow_event->id = my_flow_id;
            flow_event->metrics = new_flow_counter;
            bpf_ringbuf_submit(flow_event, 0);
            bpf_tc_printk(MYNAME "Map space for new flow not found, sending to ringbuf");
        }else {
            bpf_tc_printk(MYNAME "New flow created in Map");
        }
    }
    return rc;
}
SEC("xflow_tc_ingress")
int xflow_metric_ingress(struct __sk_buff *skb) {
    return record_ingress_packet(skb);
}

SEC("xflow_tc_egress")
int xflow_metric_egress(struct __sk_buff *skb) {
    return record_egress_packet(skb);
}
char _license[] SEC("license") = "GPL";
