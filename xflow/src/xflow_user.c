/* SPDX-License-Identifier: GPL-2->0 */

/* NOTE:
 * We have used the veth index as primary key for this Poc, a more realistic
 * implementation should use the inner ip as the primary key instead*/
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <getopt.h>
#include <stdbool.h>
#include <math.h>
#include <locale.h>
#include <unistd.h>
#include <time.h>


#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include <net/if.h>
#include <linux/if_ether.h>
#include <linux/if_link.h> /* depend on kernel-headers installed */
#include <linux/bpf.h>


#include "../common/common_user_bpf_xdp.h"
#include "../common/common_params.h"
#include "../common/xdp_stats_kern_user.h"
#include "../common/common_defines.h"

#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

void  print_usage(){
  printf("./xflow_user -t <format type> -w <output file>\n");
}

const char *pin_base_dir =  "/sys/fs/bpf/xflow";

void get_ip_string(__u32 ip, char *ip_string) {
    unsigned char bytes[4];
    bytes[0] = ip & 0xFF;
    bytes[1] = (ip >> 8) & 0xFF;
    bytes[2] = (ip >> 16) & 0xFF;
    bytes[3] = (ip >> 24) & 0xFF;   
	//printf("%d.%d.%d.%d\n", bytes[0], bytes[1], bytes[2], bytes[3]);
    snprintf(ip_string, 32, "%d.%d.%d.%d", bytes[0], bytes[1], bytes[2], bytes[3]);   
}

int main(int argc, char **argv)
{
	
	int xflow_map_fd;
	flow_id flow_key = {};
	flow_id next_flow_key;
	flow_counters my_flow_counters;
	char map_name[] = "xflow_map";
	char saddr_string[32];
	char daddr_string[32];
	// if(parse_params(argc,argv)!=0){
	// 	fprintf(stderr, "ERR: parsing params\n");
	// 	return EXIT_FAIL_OPTION;
	// }

	/* Open the map for geneve config */
	xflow_map_fd = open_bpf_map_file(pin_base_dir, map_name, NULL);
	if (xflow_map_fd < 0) {
	  	fprintf(stderr,"ERR: opening map\n");
		return EXIT_FAIL_BPF;
	}

	printf("map dir: %s \n", pin_base_dir);

	/* Get the flow_maps iteratively using bpf_map_get_next_key() */
	/* TODO: Convert it into a known format */
	int entry=0;
	printf("####### Flow Counters from %s/%s #######\n", pin_base_dir, map_name);
	while (bpf_map_get_next_key(xflow_map_fd, &flow_key, &next_flow_key) == 0) {
		bpf_map_lookup_elem(xflow_map_fd, &next_flow_key, &my_flow_counters);
		get_ip_string(next_flow_key.saddr, saddr_string);
		get_ip_string(next_flow_key.daddr, daddr_string);
		printf("**** Entry : %d ****\n", entry);
		printf("Flow-id : src-ip %s -> dest-ip %s, proto:%d, sport:%d, dport:%d \n", 
			saddr_string, 
			daddr_string, 
			next_flow_key.protocol,
			next_flow_key.sport,
			next_flow_key.dport);
		printf("Counters : packets:%d ; bytes:%lld b\n", 
			my_flow_counters.packets,
			my_flow_counters.bytes);
		flow_key = next_flow_key;
		entry++;
	}
	printf("#######  #######\n");

	return EXIT_OK;
}
