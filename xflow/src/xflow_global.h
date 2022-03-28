//#include "../headers/linux/bpf.h"
#include <linux/bpf.h>
#include <linux/in.h>

#include <linux/if_ether.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
//#include <iproute2/bpf_elf.h>


#include "../common/parsing_helpers.h"
#include "../common/common_defines.h"
#include "../common/common_utils.h"
/* Defines xdp_stats_map */
#include "../common/xdp_stats_kern_user.h"
#include "../common/xdp_stats_kern.h"

#define MAX_ENTRIES 10000000
/*
    Global Maps : Common maps for each ebpf program attached to the interface.
 */

// struct {
//     __uint(type, BPF_MAP_TYPE_HASH);
//     __type(key, __u32);  // Interface
//     __type(value, packet_capture_config); //
//     __uint(max_entries, MAX_ENTRIES);
//     __uint(pinning, LIBBPF_PIN_BY_NAME);
// } xflow_config_map SEC(".maps");
