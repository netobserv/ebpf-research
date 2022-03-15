#include <stdio.h>
#include <string.h>     /* strerror */
#include <net/if.h>     /* IF_NAMESIZE */
#include <stdlib.h>     /* exit(3) */
#include <errno.h>

#include "common_utils.h"

void get_ip_string(__u32 ip, char *ip_string) {
    unsigned char bytes[4];
    bytes[0] = ip & 0xFF;
    bytes[1] = (ip >> 8) & 0xFF;
    bytes[2] = (ip >> 16) & 0xFF;
    bytes[3] = (ip >> 24) & 0xFF;   
	//printf("%d.%d.%d.%d\n", bytes[0], bytes[1], bytes[2], bytes[3]);
    snprintf(ip_string, 32, "%d.%d.%d.%d", bytes[0], bytes[1], bytes[2], bytes[3]);   
}

void get_proto_string(__u8 proto, char *proto_string) {
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