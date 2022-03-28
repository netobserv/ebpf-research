/*
    An ebpf tc program to calculate avg-RTT for flows based on the TCP Seq/ACK
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



#define MYNAME "xflow_rtt"

//#define BPF_MAP_TYPE_RINGBUF 28
#define bpf_tc_printk(fmt, ...) \
({ \
const char ____fmt[] = fmt; \
bpf_trace_printk(____fmt, sizeof(____fmt), \
##__VA_ARGS__); \
})


struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, flow_id_seq);
    __type(value, timestamps);
    __uint(max_entries, MAX_ENTRIES);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} flow_seq_timestamp_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, flow_def);
    __type(value, flow_report); // avg rtt
    __uint(max_entries, MAX_ENTRIES);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} flow_report_map SEC(".maps");

/*
Flow_id -> sample
Maintain avg rtt per-flow
*/




SEC("xflow_rtt_egress")
int xflow_egress(struct __sk_buff *skb) {
    void *data_end = (void *)(long)skb->data_end;
    void *data = (void *)(long)skb->data;
    int rc = TC_ACT_OK;
    int ret = 0;
    timestamps seq_timestamps;
    flow_id_seq my_flow_id_seq;
    flow_def my_flow_id;

    /* Get Eth header */
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) {
        return rc;
    }
    if (eth->h_proto != bpf_htons(ETH_P_IP)) {
        // Non-IP packets, ignore for now
        return rc;
    }

    /* Get IP header */
    struct iphdr *iph = (struct iphdr *)(void *)(eth + 1);
    if ((void *)(iph + 1) > data_end) {
        return rc;
    }


    if (iph->protocol == IPPROTO_TCP) {
        struct tcphdr *tcph = (struct tcphdr *)(void *)(iph + 1);
        if (tcph + 1 > data_end) {
            return rc;
        }
        my_flow_id.saddr = iph->saddr;
        my_flow_id.daddr = iph->daddr;
        my_flow_id.sport = tcph->source;
        my_flow_id.dport = tcph->dest;

        my_flow_id_seq.id = my_flow_id;
        my_flow_id_seq.seq = tcph->seq;
        //__u64 timestamp = skb->timestamp;
        //__be32 seq = tcph->seq;

        seq_timestamps.send_tstamp = bpf_ktime_get_ns();//skb->tstamp; //bpf_ktime_get_ns();//
        seq_timestamps.rtt = 0;
        //seq_timestamps.id = 0;
        timestamps *test = bpf_map_lookup_elem(&flow_seq_timestamp_map, &my_flow_id_seq);
        if (test == NULL) {
            ret = bpf_map_update_elem(&flow_seq_timestamp_map, &my_flow_id_seq, &seq_timestamps, BPF_NOEXIST);
            if (ret < 0) {
                bpf_tc_printk("Egress: Map is full\n Work on eviction..%d", ret);
                return rc;
            } else {
                //bpf_tc_printk("Egress: seq=%u, send_tstamp=%lu\n", my_flow_id_seq.seq, seq_timestamps.send_tstamp);
            }
        }


    }
    //bpf_tc_printk(MYNAME " Recording packet size=%d, interface=%d", pkt_bytes, skb->ifindex);

    return rc;
}

SEC("xflow_rtt_ingress")
int xflow_ingress(struct __sk_buff *skb) {
    void *data_end = (void *)(long)skb->data_end;
    void *data = (void *)(long)skb->data;
    int rc = TC_ACT_OK;
    //int pkt_bytes = data_end - data;
    flow_id_seq my_flow_id_seq;
    flow_def my_flow_id;
    flow_report my_report;

    /* Get Eth header */
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) {
        return rc;
    }
    if (eth->h_proto != bpf_htons(ETH_P_IP)) {
        // Non-IP packets, ignore for now
        return rc;
    }

    /* Get IP header */
    struct iphdr *iph = (struct iphdr *)(void *)(eth + 1);
    if ((void *)(iph + 1) > data_end) {
        return rc;
    }

    if (iph->protocol == IPPROTO_TCP) {
        struct tcphdr *tcph = (struct tcphdr *)(void *)(iph + 1);
        if (tcph + 1 > data_end) {
            return rc;
        }
        //__u64 timestamp = bpf_ktime_get_ns();
        if (tcph->ack == 1) {
            my_flow_id.saddr = iph->daddr;
            my_flow_id.daddr = iph->saddr;
            my_flow_id.sport = tcph->dest;
            my_flow_id.dport = tcph->source;

            my_flow_id_seq.id = my_flow_id;
            my_flow_id_seq.seq = tcph->ack_seq;
            //__be32 seq = tcph->ack_seq;
            //__u64 tstamp = skb->tstamp;
            //bpf_map_update_elem(&rtt_map, &seq, &tstamp, BPF_NOEXIST);
            timestamps *seq_timestamps = bpf_map_lookup_elem(&flow_seq_timestamp_map, &my_flow_id_seq);
            if (seq_timestamps != NULL) {
                //seq_timestamps->send_tstamp = seq_timestamps->send_tstamp;
                seq_timestamps->rtt = (__u32) (bpf_ktime_get_ns() - seq_timestamps->send_tstamp);//skb->tstamp;


                bpf_map_update_elem(&flow_seq_timestamp_map, &my_flow_id_seq, seq_timestamps, BPF_EXIST);
                //bpf_map_delete_elem(&flow_seq_timestamp_map, &my_flow_id);

                //bpf_tc_printk("Ingress: found seq=%u,  recv_tstamp=%lu, rtt=%u\n",
                //my_flow_id_seq.seq,
                //bpf_ktime_get_ns(),
                //seq_timestamps->rtt);

                // Next to maintain the RTT per-flow
                flow_report *report = bpf_map_lookup_elem(&flow_report_map, &my_flow_id);
                if (report != NULL) {
                    report->avg_rtt = (seq_timestamps->rtt + report->avg_rtt) / 2;
                    my_report.fct = 0;
                    bpf_map_update_elem(&flow_report_map, &my_flow_id, report, BPF_NOEXIST);
                } else {
                    my_report.avg_rtt = seq_timestamps->rtt;
                    my_report.fct = 0;
                    bpf_map_update_elem(&flow_report_map, &my_flow_id, &my_report, BPF_NOEXIST);
                }
            } else {
                //bpf_tc_printk("Ingress: Not found seq=%u \n", my_flow_id_seq.seq);
            }


        }

    }
    //bpf_tc_printk(MYNAME " Recording packet size=%d, interface=%d", pkt_bytes, skb->ifindex);

    return rc;
}
char _license[] SEC("license") = "GPL";
