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
#include <stdint.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <sys/resource.h>

#include <net/if.h>
#include <linux/if_ether.h>
#include <linux/if_link.h> /* depend on kernel-headers installed */
#include <linux/bpf.h>

#include "../common/common_user_bpf_xdp.h"
#include "../common/common_params.h"
#include "../common/xdp_stats_kern_user.h"
#include "../common/common_defines.h"
#include "../common/common_utils.h"
#include "../common/hashmap.h"

#define TASK_COMM_LEN 16
#define MAX_FILENAME_LEN 512
#define TC_HOOK_EXISTS
static volatile bool exiting = false;
struct bpf_tc_hook my_egress_tc_hook;
struct bpf_tc_hook my_ingress_tc_hook;

struct bpf_tc_opts my_egress_tc_opts;
struct bpf_tc_opts my_ingress_tc_opts;

char iface[32];
unsigned int ifindex = 65535;
uint64_t pkt_counter = 0;
struct hashmap *flowmap;

char xflow_pin_base_dir[] =  "/sys/fs/bpf/";
char flow_seq_timestamp_map_name[] = "flow_seq_timestamp_map";
char flow_report_map_name[] = "flow_report_map";

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
    err = bpf_tc_hook_destroy(&my_egress_tc_hook);
    if (err != 0) {
        fprintf(stderr, "Failed to destroy tc hook, err=%s\n", strerror(err));
    }
    err = bpf_tc_hook_destroy(&my_ingress_tc_hook);
    if (err != 0) {
        fprintf(stderr, "Failed to destroy tc hook, err=%s\n", strerror(err));
    }
    printf("Destroyed hooks\n");

}
static void sig_handler(int sig) {
    printf("Cleaning up..\n");
    tc_cleanup();
    exiting = true;
    exit(1);
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

int flow_compare(const void *a, const void *b, void *udata) {
    const flow_record *my_flow_record1 = a;
    const flow_record *my_flow_record2 = b;
    if (my_flow_record1->id.saddr == my_flow_record2->id.saddr &&
        my_flow_record1->id.daddr == my_flow_record2->id.daddr &&
        my_flow_record1->id.sport == my_flow_record2->id.sport &&
        my_flow_record1->id.dport == my_flow_record2->id.dport &&
        my_flow_record1->id.protocol == my_flow_record2->id.protocol &&
        my_flow_record1->id.interface == my_flow_record2->id.interface) {
            return 0;
        } else {
            return 1;
        }

}

bool flow_iter(const void *item, void *udata) {
    const flow_record *my_flow_record = item;
    char saddr_string[32];
	char daddr_string[32];
	char proto_string[10];
	get_ip_string(my_flow_record->id.saddr, saddr_string);
	get_ip_string(my_flow_record->id.daddr, daddr_string);
	get_proto_string(my_flow_record->id.protocol, proto_string);

	printf("%llu | %llu | %llu | %s | %s:%d | %s:%d | %d | %lld\n",
        my_flow_record->counters.pkt_counter,
		my_flow_record->counters.flow_start_ns,
		my_flow_record->counters.flow_end_ns,
		proto_string,
		saddr_string,
		ntohs(my_flow_record->id.sport),
		daddr_string,
		ntohs(my_flow_record->id.dport),
		my_flow_record->counters.packets,
		my_flow_record->counters.bytes);
    return true;
}

uint64_t flow_hash(const void *item, uint64_t seed0, uint64_t seed1) {
    const flow_record *my_flow_record = item;
    return hashmap_sip(&my_flow_record->id, sizeof(flow_id), seed0, seed1);
}


int handle_event(void *ctx, void *data, size_t data_sz) {
    //printf("handle_event\n");

    const flow_record *my_flow_record = data;

    hashmap_set(flowmap, my_flow_record);
    pkt_counter++;

    // if (my_flow_record->counters.pkt_counter - pkt_counter != 1) {
    //     printf("Potential Drop!!\n");
    // }
    // pkt_counter = my_flow_record->counters.pkt_counter;
    //printf("%lu.. %lu\n", my_flow_record->counters.pkt_counter, pkt_counter);

    return 0;
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

void dump_flow_seq_timestamp() {
    int flow_seq_timestamp_map;
    flow_id_seq flow_key = {};
	flow_id_seq next_flow_key;
    timestamps seq_timestamps;

    char saddr_string[32];
    char daddr_string[32];
    flow_seq_timestamp_map = open_bpf_map_file(xflow_pin_base_dir, flow_seq_timestamp_map_name, NULL);
    if (flow_seq_timestamp_map < 0) {
        fprintf(stderr,"ERR: opening map\n");
        return EXIT_FAIL_BPF;
    }
    printf("------------------------------------------------------------------------------------------\n");
    printf("| Src IP Addr:Port  |  Dst IP Addr:Port  |     Seq       |   Send Timestamp   |   RTT  |\n");
    printf("------------------------------------------------------------------------------------------\n");
    while (bpf_map_get_next_key(flow_seq_timestamp_map, &flow_key, &next_flow_key) == 0) {
        bpf_map_lookup_elem(flow_seq_timestamp_map, &next_flow_key, &seq_timestamps);
        get_ip_string(next_flow_key.id.saddr, saddr_string);
        get_ip_string(next_flow_key.id.daddr, daddr_string);
        printf("| %s:%d | %s:%d | %u | %llu | %u |\n",
            saddr_string,
            ntohs(next_flow_key.id.sport),
            daddr_string,
            ntohs(next_flow_key.id.dport),
            ntohl(next_flow_key.seq),
            seq_timestamps.send_tstamp,
            seq_timestamps.rtt);
        flow_key = next_flow_key;
    }
}

void dump_flow_reports() {
    int flow_seq_timestamp_map;
    flow_id_seq flow_key = {};
	flow_id_seq next_flow_key;
    flow_report my_flow_report;

    char saddr_string[32];
    char daddr_string[32];
    flow_seq_timestamp_map = open_bpf_map_file(xflow_pin_base_dir, flow_report_map_name, NULL);
    if (flow_seq_timestamp_map < 0) {
        fprintf(stderr,"ERR: opening map\n");
        return EXIT_FAIL_BPF;
    }
    printf("------------------------------------------------------------------------------------------\n");
    printf("| Src IP Addr:Port  |  Dst IP Addr:Port  |     Avg RTT       |   FCT   |\n");
    printf("------------------------------------------------------------------------------------------\n");
    while (bpf_map_get_next_key(flow_seq_timestamp_map, &flow_key, &next_flow_key) == 0) {
        bpf_map_lookup_elem(flow_seq_timestamp_map, &next_flow_key, &my_flow_report);
        get_ip_string(next_flow_key.id.saddr, saddr_string);
        get_ip_string(next_flow_key.id.daddr, daddr_string);
        printf("| %s:%d | %s:%d | %u | %llu |\n",
            saddr_string,
            ntohs(next_flow_key.id.sport),
            daddr_string,
            ntohs(next_flow_key.id.dport),
            my_flow_report.avg_rtt,
            my_flow_report.fct);
        flow_key = next_flow_key;
    }
}

void *print_flows( void *ptr )
{
    while (1) {
        dump_flow_seq_timestamp();
        sleep(1);
        dump_flow_reports();
        sleep(1);
        // printf("------------------------------------------------------------------------------------------\n");
        // printf("| Src IP Addr:Port  |  Dst IP Addr:Port  |     Seq       |   Send Timestamp   |   RTT |\n");
        // printf("------------------------------------------------------------------------------------------\n");
    }
}


int main(int argc, char *argv[])
{
    pthread_t flow_scan_thread;
    const char *bpf_file = "xflow_rtt.o";
    struct bpf_object *obj;
    int prog_fd = -1;
    int my_egress_prog_fd = -1;
    int my_ingress_prog_fd = -1;

    int buffer_map_fd = -1;
    struct bpf_program *egress_prog;
    struct bpf_program *ingress_prog;

    int err;
    //int interface_ifindex = 4;
    char error[32];

    if(parse_params(argc,argv)!=0) {
  		fprintf(stderr, "ERR: parsing params\n");
  		return EXIT_FAIL_OPTION;
	}

    printf("Running on interface idx-%d\n", ifindex);

    memset(&my_egress_tc_hook, 0, sizeof(my_egress_tc_hook));
    my_egress_tc_hook.sz = sizeof(my_egress_tc_hook);
    my_egress_tc_hook.ifindex = ifindex;
    my_egress_tc_hook.attach_point = BPF_TC_EGRESS;

    memset(&my_ingress_tc_hook, 0, sizeof(my_ingress_tc_hook));
    my_ingress_tc_hook.sz = sizeof(my_ingress_tc_hook);
    my_ingress_tc_hook.ifindex = ifindex;
    my_ingress_tc_hook.attach_point = BPF_TC_INGRESS;

    err = bpf_tc_hook_create(&my_egress_tc_hook);
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

    err = bpf_tc_hook_create(&my_ingress_tc_hook);
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

    // Load egress/ingress sections

    egress_prog = bpf_object__find_program_by_title(obj, "xflow_rtt_egress");
    if (!egress_prog) {
        fprintf(stderr, "failed to find xflow_rtt_egress \n");
        return 1;
    }
    ingress_prog = bpf_object__find_program_by_title(obj, "xflow_rtt_ingress");
    if (!ingress_prog) {
        fprintf(stderr, "failed to find xflow_rtt_ingress\n");
        return 1;
    }

    my_egress_prog_fd = bpf_program__fd(egress_prog);
    if (my_egress_prog_fd <= 0) {
        fprintf(stderr, "ERR: bpf_program__fd egress failed\n");
        return 1;
    }
    my_ingress_prog_fd = bpf_program__fd(ingress_prog);
    if (my_ingress_prog_fd <= 0) {
        fprintf(stderr, "ERR: bpf_program__fd ingress failed\n");
        return 1;
    }

    memset(&my_egress_tc_opts, 0, sizeof(my_egress_tc_opts));
    my_egress_tc_opts.sz = sizeof(my_egress_tc_opts);
    my_egress_tc_opts.prog_fd = my_egress_prog_fd;

    memset(&my_ingress_tc_opts, 0, sizeof(my_ingress_tc_opts));
    my_ingress_tc_opts.sz = sizeof(my_ingress_tc_opts);
    my_ingress_tc_opts.prog_fd = my_ingress_prog_fd;

    err = bpf_tc_attach(&my_egress_tc_hook, &my_egress_tc_opts);
    if (err != 0) {
        fprintf(stderr, "Failed to attach tc program at egress\n");
        return 1;
    }

    err = bpf_tc_attach(&my_ingress_tc_hook, &my_ingress_tc_opts);
    if (err != 0) {
        fprintf(stderr, "Failed to attach tc program at ingress\n");
        return 1;
    }
    printf("Attached %s program to tc hook point at ifindex:%d\n", bpf_file, ifindex);

    pthread_create( &flow_scan_thread, NULL, print_flows, NULL);

    //pthread_join(flow_scan_thread, NULL);
    while (1) {
        sleep(1);
    }
    return 0;
}
