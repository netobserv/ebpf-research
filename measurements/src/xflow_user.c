/*
	Xflow_user :
 */
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
#include <arpa/inet.h>
#include <net/if.h>

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
#include "../common/common_utils.h"

#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

#define MAXLEN 64
char iface[32];
unsigned int ifindex;
void  print_usage(){
	printf("./xflow_user -i <interface> \n");
}


static const struct option long_options[] = {
	{"interface", required_argument,       0,  'i' },
	{0,           0, NULL,  0   }
};

int parse_params(int argc, char *argv[]) {
    int opt= 0;
    int long_index =0;

    while ((opt = getopt_long(argc, argv,"i:",
                   long_options, &long_index )) != -1) {
      switch (opt) {
		  case 'i' :
		  	strncpy(iface, optarg, 32);
			ifindex = if_nametoindex(iface);
		  	break;
		  default:
		  	print_usage();
		  	exit(EXIT_FAILURE);
        }
    }
    return 0;
}

char xflow_pin_base_dir[MAXLEN] =  "/sys/fs/bpf/xflow/";
char xflow_tc_pin_base_dir[MAXLEN] =  "/sys/fs/bpf/tc/globals/";
char xdp_map_name[] = "xflow_metric_map";
char tc_map_name[] = "xflow_metric_tc_map";



int main(int argc, char **argv) {

	int xflow_xdp_metric_map_fd;
	int xflow_tc_metric_map_fd;

	flow_id flow_key = {};
	flow_id next_flow_key;
	flow_counters my_flow_counters;
	char saddr_string[32];
	char daddr_string[32];
	char proto_string[10];

	if(parse_params(argc,argv)!=0){
		fprintf(stderr, "ERR: parsing params\n");
		return EXIT_FAIL_OPTION;
	}

	strcat(xflow_pin_base_dir, iface);

	/* Open the map for xdp metrics */
	xflow_xdp_metric_map_fd = open_bpf_map_file(xflow_pin_base_dir, xdp_map_name, NULL);
	if (xflow_xdp_metric_map_fd < 0) {
	  	fprintf(stderr,"ERR: opening map\n");
		return EXIT_FAIL_BPF;
	}

	printf("map file: %s/%s \n", xflow_pin_base_dir, xdp_map_name);
	printf("map file: %s/%s \n", xflow_tc_pin_base_dir, tc_map_name);

	/* Get the flow_maps iteratively using bpf_map_get_next_key() */
	/* TODO: Convert it into a known format */
	printf("####### Incoming Flow Counters for interface %s(%d) #######\n", iface, ifindex);
	printf("Flow Start time  |  Flow End Time   | Protocol | Src IP Addr:Port  | Dst IP Addr:Port  |   Packets  |  Bytes     |\n");
	while (bpf_map_get_next_key(xflow_xdp_metric_map_fd, &flow_key, &next_flow_key) == 0) {
		bpf_map_lookup_elem(xflow_xdp_metric_map_fd, &next_flow_key, &my_flow_counters);
		get_ip_string(next_flow_key.saddr, saddr_string);
		get_ip_string(next_flow_key.daddr, daddr_string);
		get_proto_string(next_flow_key.protocol, proto_string);
		//printf("**** Entry : %d ****\n", entry);
		printf("%llu | %llu | %s | %s:%d | %s:%d | %d | %lld\n",
			my_flow_counters.flow_start_ns,
			my_flow_counters.flow_end_ns,
			proto_string,
			saddr_string,
			ntohs(next_flow_key.sport),
			daddr_string,
			ntohs(next_flow_key.dport),
			my_flow_counters.packets,
			my_flow_counters.bytes);
		flow_key = next_flow_key;
	}

	/* Open the map for xdp metrics */
	xflow_tc_metric_map_fd = open_bpf_map_file(xflow_tc_pin_base_dir, tc_map_name, NULL);
	if (xflow_tc_metric_map_fd < 0) {
	  	fprintf(stderr,"ERR: opening map\n");
		return EXIT_FAIL_BPF;
	}

	/* Get the flow_maps iteratively using bpf_map_get_next_key() */
	/* TODO: Convert it into a known format */
	printf("####### Outgoing Flow Counters for interface %s #######\n", iface);
	printf("Flow Start time  |  Flow End Time   | Protocol | Src IP Addr:Port  | Dst IP Addr:Port  |   Packets  |  Bytes     |\n");
	while (bpf_map_get_next_key(xflow_tc_metric_map_fd, &flow_key, &next_flow_key) == 0) {
		bpf_map_lookup_elem(xflow_tc_metric_map_fd, &next_flow_key, &my_flow_counters);

		if (next_flow_key.interface == ifindex) {

			get_ip_string(next_flow_key.saddr, saddr_string);
			get_ip_string(next_flow_key.daddr, daddr_string);
			get_proto_string(next_flow_key.protocol, proto_string);
			//printf("**** Entry : %d ****\n", entry);
			printf("%llu | %llu | %s |%s:%d | %s:%d | %d | %lld\n",
				my_flow_counters.flow_start_ns,
				my_flow_counters.flow_end_ns,
				proto_string,
				saddr_string,
				ntohs(next_flow_key.sport),
				daddr_string,
				ntohs(next_flow_key.dport),
				my_flow_counters.packets,
				my_flow_counters.bytes);
		}
		flow_key = next_flow_key;
	}
	printf("##############\n");
	return EXIT_OK;
}
