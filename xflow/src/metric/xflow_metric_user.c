/*
	Xflow_ringbuf_test_user : User-space program to load and consume the flow record entries of the ring-buffer
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
#include <signal.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <sys/resource.h>

#include <net/if.h>
#include <linux/if_ether.h>
#include <linux/if_link.h> /* depend on kernel-headers installed */
#include <linux/bpf.h>

// #include "../../common/common_user_bpf_xdp.h"
// #include "../../common/common_params.h"
// #include "../../common/xdp_stats_kern_user.h"
#include "xflow_metric.h"
//#include "../../common/common_utils.h"
#include "../../common/hashmap.h"

#ifndef PATH_MAX
#define PATH_MAX	4096
#endif

#define TASK_COMM_LEN 16
#define MAX_FILENAME_LEN 512
static volatile bool exiting = false;
struct bpf_tc_hook my_tc_hook;
struct bpf_tc_opts my_tc_opts;
char iface[32];
unsigned int ifindex;
uint64_t pkt_counter = 0;
struct hashmap *ongoing_flow_map;
struct hashmap *complete_flow_map;

char xflow_tc_pin_base_dir[] =  "/sys/fs/bpf/";
char xflow_egress_map_name[] = "xflow_metric_map_egress";
char xflow_ingress_map_name[] = "xflow_metric_map_ingress";

bool complete_update = false;
bool ongoing_update = false;

int xflow_tc_metric_ingress_map_fd;
int xflow_tc_metric_egress_map_fd;
int nr_cpus;

struct event {
    int pid;
    char comm[TASK_COMM_LEN];
    char filename[MAX_FILENAME_LEN];
};

static void tc_cleanup () {
    int err;
    //err = bpf_tc_detach(&my_tc_hook, &my_tc_opts);
    // if (err != 0) {
    //     fprintf(stderr, "Failed to detach, err=%s\n", strerror(err));
    //     return 1;
    // }
    err = bpf_tc_hook_destroy(&my_tc_hook);
    if (err != 0) {
        fprintf(stderr, "Failed to destroy tc hook, err=%s\n", strerror(err));
    }
    close(xflow_tc_metric_ingress_map_fd);
    close(xflow_tc_metric_egress_map_fd);
    printf("Destroyed hooks\n");

}
static void sig_handler(int sig) {
    printf("Cleaning up..\n");
    tc_cleanup();
    exiting = true;
}

void bump_memlock_rlimit(void) {
    struct rlimit rlim_new = {
        .rlim_cur = RLIM_INFINITY,
        .rlim_max = RLIM_INFINITY,
    };

    if (setrlimit(RLIMIT_MEMLOCK, &rlim_new))
    {
        fprintf(stderr, "Failed to increase RLIMIT_MEMLOCK limit!\n");
        exit(1);
    }
}

void get_ip_string2(__u32 ip, char *ip_string) {
    unsigned char bytes[4];
    bytes[0] = ip & 0xFF;
    bytes[1] = (ip >> 8) & 0xFF;
    bytes[2] = (ip >> 16) & 0xFF;
    bytes[3] = (ip >> 24) & 0xFF;
	//printf("%d.%d.%d.%d\n", bytes[0], bytes[1], bytes[2], bytes[3]);
    snprintf(ip_string, 32, "%d.%d.%d.%d", bytes[0], bytes[1], bytes[2], bytes[3]);
}

void get_proto_string2(__u8 proto, char *proto_string) {
	// TODO : Expand this based on https://en.wikipedia.org/wiki/List_of_IP_protocol_numbers
	switch(proto) {
		case 1:
			strcpy(proto_string, "ICMP");
			break;
		case 2:
			strcpy(proto_string, "IGMP");
			break;
		case 6:
			strcpy(proto_string, "TCP");
			break;
		case 17:
			strcpy(proto_string,"UDP");
			break;
		default:
			strcpy(proto_string,"---");
			break;
	}
}

int open_bpf_map_file2(const char *pin_dir,
		      const char *mapname,
		      struct bpf_map_info *info)
{
	char filename[PATH_MAX];
	int err, len, fd;
	__u32 info_len = sizeof(*info);

	len = snprintf(filename, PATH_MAX, "%s/%s", pin_dir, mapname);
	if (len < 0) {
		fprintf(stderr, "ERR: constructing full mapname path\n");
		return -1;
	}

	fd = bpf_obj_get(filename);
	if (fd < 0) {
		fprintf(stderr,
			"WARN: Failed to open bpf map file:%s err(%d):%s\n",
			filename, errno, strerror(errno));
		return fd;
	}

	if (info) {
		err = bpf_obj_get_info_by_fd(fd, info, &info_len);
		if (err) {
			fprintf(stderr, "ERR: %s() can't get info - %s\n",
				__func__,  strerror(errno));
			return -1;
		}
	}

	return fd;
}

static inline unsigned int bpf_num_possible_cpus(void)
{
	static const char *fcpu = "/sys/devices/system/cpu/possible";
	unsigned int start, end, possible_cpus = 0;
	char buff[128];
	FILE *fp;
	int n;

	fp = fopen(fcpu, "r");
	if (!fp) {
		printf("Failed to open %s: '%s'!\n", fcpu, strerror(errno));
		exit(1);
	}

	while (fgets(buff, sizeof(buff), fp)) {
		n = sscanf(buff, "%u-%u", &start, &end);
		if (n == 0) {
			printf("Failed to retrieve # possible CPUs!\n");
			exit(1);
		} else if (n == 1) {
			end = start;
		}
		possible_cpus = start == 0 ? end + 1 : 0;
		break;
	}
	fclose(fp);

	return possible_cpus;
}


int flow_compare(const void *a, const void *b, void *udata) {
    const flow_record *my_flow_record1 = a;
    const flow_record *my_flow_record2 = b;
    if (my_flow_record1->id.saddr == my_flow_record2->id.saddr &&
        my_flow_record1->id.daddr == my_flow_record2->id.daddr &&
        my_flow_record1->id.sport == my_flow_record2->id.sport &&
        my_flow_record1->id.dport == my_flow_record2->id.dport &&
        my_flow_record1->id.protocol == my_flow_record2->id.protocol) {
            return 0;
        } else {
            return 1;
        }

}

void print_flow_record(const flow_record* my_flow_record) {
    char saddr_string[32];
	char daddr_string[32];
	char proto_string[10];
	get_ip_string2(my_flow_record->id.saddr, saddr_string);
	get_ip_string2(my_flow_record->id.daddr, daddr_string);
	get_proto_string2(my_flow_record->id.protocol, proto_string);

	printf("%llu | %llu | %s | %s:%d | %s:%d | %d | %lld | %X\n",
		my_flow_record->metrics.flow_start_ts,
		my_flow_record->metrics.last_pkt_ts,
		proto_string,
		saddr_string,
		ntohs(my_flow_record->id.sport),
		daddr_string,
		ntohs(my_flow_record->id.dport),
		my_flow_record->metrics.packets,
		my_flow_record->metrics.bytes,
        my_flow_record->metrics.flags);
}

bool flow_iter(const void *item, void *udata) {
    const flow_record *my_flow_record = item;
    print_flow_record(my_flow_record);
    return true;
}

uint64_t flow_hash(const void *item, uint64_t seed0, uint64_t seed1) {
    const flow_record *my_flow_record = item;
    return hashmap_sip(&my_flow_record->id, sizeof(flow_id), seed0, seed1);
}

void aggregate_flow_entry (int map_fd, flow_record *my_flow_record) {
    __u64 sum_bytes = 0;
    __u32 sum_pkts = 0;
    __u64 flow_start_ts = 0;
    __u64 last_pkt_ts = 0;
    __u32 flags = 0;
    int i;
    flow_metrics my_flow_counters[nr_cpus];
    int rc = bpf_map_lookup_elem(map_fd, &my_flow_record->id, my_flow_counters);
    if (rc !=0) {
        return;
    }
    for (i = 0; i < nr_cpus; i++) {
        printf("CPU %d :[ %u, %lu, %lu, %lu]\n", i, my_flow_counters[i].packets,
          my_flow_counters[i].bytes,
          my_flow_counters[i].flow_start_ts,
          my_flow_counters[i].last_pkt_ts);
        sum_pkts  += my_flow_counters[i].packets;
        sum_bytes += my_flow_counters[i].bytes;
        if (my_flow_counters[i].flow_start_ts != 0) {
            flow_start_ts = my_flow_counters[i].flow_start_ts;
        }
        if (my_flow_counters[i].last_pkt_ts > last_pkt_ts) {
            last_pkt_ts = my_flow_counters[i].last_pkt_ts;
        }
        flags |= my_flow_counters[i].flags;
    }
    my_flow_record->metrics.packets = sum_pkts;
    my_flow_record->metrics.bytes = sum_bytes;
    my_flow_record->metrics.flow_start_ts = flow_start_ts;
    my_flow_record->metrics.last_pkt_ts = last_pkt_ts;

}

void scrub_flow_entry (flow_record *my_flow_record, flow_record *updated_flow_record, bool egress_direction, bool reverse) {
    if (!reverse) {
        // Reverse the flow id
        updated_flow_record->id.saddr = my_flow_record->id.daddr;
        updated_flow_record->id.daddr = my_flow_record->id.saddr;
        updated_flow_record->id.sport = my_flow_record->id.dport;
        updated_flow_record->id.dport = my_flow_record->id.sport;
        updated_flow_record->id.protocol = my_flow_record->id.protocol;
    } else {
        updated_flow_record->id.saddr = my_flow_record->id.saddr;
        updated_flow_record->id.daddr = my_flow_record->id.daddr;
        updated_flow_record->id.sport = my_flow_record->id.sport;
        updated_flow_record->id.dport = my_flow_record->id.dport;
        updated_flow_record->id.protocol = my_flow_record->id.protocol;
    }
    if (egress_direction) {
        aggregate_flow_entry(xflow_tc_metric_egress_map_fd, updated_flow_record);
    } else {
        aggregate_flow_entry(xflow_tc_metric_ingress_map_fd, updated_flow_record);
    }

}

int handle_flow_event(void *ctx, void *data, size_t data_sz) {
    /*
      Upon an entry regarding the flow from ringbuffer, there are two possibilities:
        1) TCP FIN Packet :
            In this case, perfom eviction of this flow from ingress and
            egress maps, and interim map in the userspace.
        2) Normal Packet coming to userspace because of insufficient space:
            Store this packet in a interim map at userspace
    */
    const flow_record *my_flow_record = data;
    flow_record updated_flow_record;
    if (my_flow_record->metrics.flags & TCP_FIN_FLAG == TCP_FIN_FLAG) {
        printf("Got a Fin Packet\n");
        // Consolidate flow info
        scrub_flow_entry(my_flow_record, &updated_flow_record, (bool)my_flow_record->metrics.flags & DIR_EGRESS_FLAG, false); //egress
        print_flow_record(my_flow_record);
        hashmap_set(complete_flow_map, my_flow_record);
        //hashmap_get(ongoing_flow_map, my_flow_record);
        complete_update = true;
    } else {
        hashmap_set(ongoing_flow_map, my_flow_record);
        ongoing_update = true;
    }


    return 0;
}

void DumpHex(const void* data, size_t size) {
	char ascii[17];
	size_t i, j;
	ascii[16] = '\0';
	for (i = 0; i < size; ++i) {
		printf("%02X ", ((unsigned char*)data)[i]);
		if (((unsigned char*)data)[i] >= ' ' && ((unsigned char*)data)[i] <= '~') {
			ascii[i % 16] = ((unsigned char*)data)[i];
		} else {
			ascii[i % 16] = '.';
		}
		if ((i+1) % 8 == 0 || i+1 == size) {
			printf(" ");
			if ((i+1) % 16 == 0) {
				printf("|  %s \n", ascii);
			} else if (i+1 == size) {
				ascii[(i+1) % 16] = '\0';
				if ((i+1) % 16 <= 8) {
					printf(" ");
				}
				for (j = (i+1) % 16; j < 16; ++j) {
					printf("   ");
				}
				printf("|  %s \n", ascii);
			}
		}
	}
}

#define CPUS 80

void monitor_map(void *arg) {
    char *map_name = arg;
    nr_cpus = libbpf_num_possible_cpus();
    char saddr_string[32];
	char daddr_string[32];
	char proto_string[10];
    int i;
    int map_fd;
    flow_metrics my_flow_counters[CPUS];

    if (strcmp(arg,"egress") == 0) {
        xflow_tc_metric_egress_map_fd = open_bpf_map_file(xflow_tc_pin_base_dir, xflow_egress_map_name, NULL);
        if (xflow_tc_metric_egress_map_fd < 0) {
            fprintf(stderr,"ERR: opening egress map\n");
            return;
        }
        map_fd = xflow_tc_metric_egress_map_fd;
    } else {
        xflow_tc_metric_ingress_map_fd = open_bpf_map_file(xflow_tc_pin_base_dir, xflow_egress_map_name, NULL);
        if (xflow_tc_metric_ingress_map_fd < 0) {
            fprintf(stderr,"ERR: opening ingress map\n");
            return;
        }
        map_fd = xflow_tc_metric_ingress_map_fd;
    }
    printf("map file: %s/%s \n", xflow_tc_pin_base_dir, map_name);

    /* Get the flow_maps iteratively using bpf_map_get_next_key() */
    /* TODO: Convert it into a known format */
    while (true) {
        flow_id flow_key = {};
    	flow_id next_flow_key;

        printf("####### Flow Counters for interface %s(%d) CPUs=%d #######\n", iface, ifindex, nr_cpus);
        printf("Flow Start time  |  Last Pkt Time   | Protocol | Src IP Addr:Port  | Dst IP Addr:Port  |   Packets  |  Bytes     |\n");
        while (bpf_map_get_next_key(map_fd, &flow_key, &next_flow_key) == 0) {
            //printf("%u, %u %d\n", next_flow_key.protocol, next_flow_key.daddr, nr_cpus);
            // printf("| %s | %s:%d | %s:%d|\n",
            // proto_string,
            // saddr_string,
            // ntohs(next_flow_key.sport),
            // daddr_string,
            // ntohs(next_flow_key.dport));
            __u64 sum_bytes = 0;
            __u32 sum_pkts = 0;
            __u64 flow_start_ts = 0;
            __u64 last_pkt_ts = 0;
            __u32 flags = 0;
        	int rc = bpf_map_lookup_elem(map_fd, &next_flow_key, my_flow_counters);
        	for (i = 0; i < nr_cpus; i++) {
                //printf("CPU %d :[ %u, %lu, %lu, %lu]\n", i, my_flow_counters[i].packets,
                 // my_flow_counters[i].bytes,
                 // my_flow_counters[i].flow_start_ts,
                 // my_flow_counters[i].last_pkt_ts);

                //DumpHex((void *)&my_flow_counters[i], sizeof(flow_metrics));

        		sum_pkts  += my_flow_counters[i].packets;
        		sum_bytes += my_flow_counters[i].bytes;
                if (my_flow_counters[i].flow_start_ts != 0) {
                    flow_start_ts = my_flow_counters[i].flow_start_ts;
                }
                if (my_flow_counters[i].last_pkt_ts > last_pkt_ts) {
                    last_pkt_ts = my_flow_counters[i].last_pkt_ts;
                }
                flags |= my_flow_counters[i].flags;
        	}
            get_ip_string2(next_flow_key.saddr, saddr_string);
            get_ip_string2(next_flow_key.daddr, daddr_string);
            get_proto_string2(next_flow_key.protocol, proto_string);
        	printf("| %llu | %llu | %s | %s:%d | %s:%d | %d | %lld | %X\n",
                flow_start_ts,
                last_pkt_ts,
        		proto_string,
        		saddr_string,
        		ntohs(next_flow_key.sport),
        		daddr_string,
        		ntohs(next_flow_key.dport),
        		sum_pkts,
        		sum_bytes,
                flags);
        	flow_key = next_flow_key;
        }

        sleep(5);
    }
}
void  print_usage(){
	printf("./xflow_ringbuf_test_user -i <interface> \n");
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

void *print_complete_flows( void *ptr )
{
    printf("Flow Start time  |  Flow End Time   | Protocol | Src IP Addr:Port  | Dst IP Addr:Port  |   Packets  |  Bytes     |\n");
    while (1) {
        if (complete_update == true) {
          hashmap_scan(complete_flow_map, flow_iter, NULL);
          complete_update = false;
        }
      sleep(1);
    }
}
int main(int argc, char *argv[])
{
    pthread_t flow_scan_thread;
    pthread_t monitor_ingress_map_thread;
    pthread_t monitor_egress_map_thread;
    const char *bpf_file = "xflow_metric.o";
    struct bpf_object *obj;
    int prog_fd = -1;
    int my_tc_prog_fd = -1;
    int buffer_map_fd = -1;
    struct bpf_program *prog;
    int err;
    //int interface_ifindex = 4;
    char error[32];

    if(parse_params(argc,argv)!=0){
  		fprintf(stderr, "ERR: parsing params\n");
  		return -1;
	   }
    ongoing_flow_map= hashmap_new(sizeof(flow_record), 0, 0, 0,
                                     flow_hash, flow_compare, NULL, NULL);
    complete_flow_map= hashmap_new(sizeof(flow_record), 0, 0, 0,
                                     flow_hash, flow_compare, NULL, NULL);

    printf("Running on interface idx-%d\n", index);

    memset(&my_tc_hook, 0, sizeof(my_tc_hook));
    my_tc_hook.sz = sizeof(my_tc_hook);
    my_tc_hook.ifindex = ifindex;
    my_tc_hook.attach_point = BPF_TC_EGRESS;

    err = bpf_tc_hook_create(&my_tc_hook);
    if (err != 0)
    {
        if (err == -17) {
            //tc_hook already exisits
        } else {
            libbpf_strerror(err, error, 32);
            fprintf(stderr, "Failed to create tc hook err=%d, %s\n", err, error);
            return 1;
        }
    }

    /* Bump RLIMIT_MEMLOCK to create BPF maps */
    bump_memlock_rlimit();

    /* Clean handling of Ctrl-C */
    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    err = bpf_prog_load(bpf_file, BPF_PROG_TYPE_SCHED_CLS, &obj, &prog_fd);
    if (err != 0) {
        fprintf(stderr, "Failed to load Program\n");
        return 1;
    }
    buffer_map_fd = bpf_object__find_map_fd_by_name(obj, "flow_records");

    struct ring_buffer *ring_buffer;

    ring_buffer = ring_buffer__new(buffer_map_fd, handle_flow_event, NULL, NULL);

    if (!ring_buffer) {
        fprintf(stderr, "failed to create ring buffer\n");
        return 1;
    }

    prog = bpf_object__find_program_by_title(obj, "xflow_tc_egress");
    if (!prog) {
        fprintf(stderr, "failed to find program title\n");
        return 1;
    }

    my_tc_prog_fd = bpf_program__fd(prog);
    if (my_tc_prog_fd <= 0) {
        fprintf(stderr, "ERR: bpf_program__fd failed\n");
        return 1;
    }

    memset(&my_tc_opts, 0, sizeof(my_tc_opts));
    my_tc_opts.sz = sizeof(my_tc_opts);
    my_tc_opts.prog_fd = my_tc_prog_fd;

    err = bpf_tc_attach(&my_tc_hook, &my_tc_opts);
    if (err != 0) {
        fprintf(stderr, "Failed to attach tc program\n");
        return 1;
    }
    printf("Attached %s program to tc hook point at ifindex:%d\n", bpf_file, ifindex);

    pthread_create(&flow_scan_thread, NULL, print_complete_flows, NULL);
    pthread_create(&monitor_egress_map_thread, NULL, monitor_map, "egress");
    //pthread_create(&monitor_ingress_map_thread, NULL, monitor_map, "ingress");

    while (!exiting)
    {
        err = ring_buffer__poll(ring_buffer, 1 /* timeout, ms */);
        /* Ctrl-C will cause -EINTR */
        if (err == -EINTR)
        {
            err = 0;
            break;
        }
        if (err < 0)
        {
            printf("Error polling ring buffer: %d\n", err);
            break;
        }
    }


    return 0;
}
