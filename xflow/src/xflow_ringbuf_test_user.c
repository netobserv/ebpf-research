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
struct bpf_tc_hook my_tc_hook;
struct bpf_tc_opts my_tc_opts;
char iface[32];
unsigned int ifindex;
uint64_t pkt_counter = 0;
struct hashmap *flowmap;


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

void *print_flows( void *ptr )
{
    printf("Flow Start time  |  Flow End Time   | Protocol | Src IP Addr:Port  | Dst IP Addr:Port  |   Packets  |  Bytes     |\n");
    while (1) {
      hashmap_scan(flowmap, flow_iter, NULL);
      printf("Total pkts received = %lu\n", pkt_counter);
      sleep(1);
    }
}
int main(int argc, char *argv[])
{
    pthread_t flow_scan_thread;
    const char *bpf_file = "xflow_ringbuf_test.o";
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
  		return EXIT_FAIL_OPTION;
	   }
    flowmap= hashmap_new(sizeof(flow_record), 0, 0, 0,
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

    ring_buffer = ring_buffer__new(buffer_map_fd, handle_event, NULL, NULL);

    if (!ring_buffer) {
        fprintf(stderr, "failed to create ring buffer\n");
        return 1;
    }

    prog = bpf_object__find_program_by_title(obj, "tc");
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

    pthread_create( &flow_scan_thread, NULL, print_flows, NULL);

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

// Skeleton method of attaching
// Involves additional step of creating skeleton.h file
// int main(int argc, char **argv)
// {
//     struct ring_buffer *rb = NULL;
// 	struct xflow_ringbuf_test *skel;
// 	int err;

// 	/* Clean handling of Ctrl-C */
// 	signal(SIGINT, sig_handler);
// 	signal(SIGTERM, sig_handler);

//     // skel = xflow_ringbuf_test__open();
//     // if (!skel) {
//     //     fprintf(stderr, "Failed to open skeleton\n");
// 	// 	return 1;
// 	// }

// 	// err = xflow_ringbuf_test__load(skel);
// 	// if (err != 0) {
//     //     fprintf(stderr, "Failed to open skeleton\n");
//     //     goto cleanup;
//     // }

// 	/* Load and verify BPF application */
// 	skel = xflow_ringbuf_test__open_and_load();
// 	if (!skel) {
// 		fprintf(stderr, "Failed to open and load BPF skeleton\n");
// 		return 1;
// 	}
//     printf("Opened and loaded xflow_ringbuf_test\n");
// 	/* Attach tracepoint */
// 	err = xflow_ringbuf_test__attach(skel);
// 	if (err) {
// 		fprintf(stderr, "Failed to attach BPF skeleton\n");
// 		goto cleanup;
// 	}
// 	/* Set up ring buffer polling */
// 	rb = ring_buffer__new(bpf_map__fd(skel->maps.flow_records), handle_event, NULL, NULL);
// 	if (!rb) {
// 		fprintf(stderr, "Failed to create ring buffer\n");
// 		goto cleanup;
// 	}

// 	/* Process events */
// 	printf("%-8s %-5s %-7s %-16s %s\n",
// 	       "TIME", "EVENT", "PID", "COMM", "FILENAME");
// 	while (!exiting) {
// 		err = ring_buffer__poll(rb, 100 /* timeout, ms */);
// 		/* Ctrl-C will cause -EINTR */
// 		if (err == -EINTR) {
// 			err = 0;
// 			break;
// 		}
// 		if (err < 0) {
// 			printf("Error polling ring buffer: %d\n", err);
// 			break;
// 		}
// 	}
// cleanup:
// 	ring_buffer__free(rb);
// 	xflow_ringbuf_test__destroy(skel);
//     return 0;
// }
