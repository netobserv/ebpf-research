#include <string.h>     /* strerror */
#include <net/if.h>     /* IF_NAMESIZE */
#include <stdlib.h>     /* exit(3) */
#include <errno.h>

#include "common_utils.h"

char * get_ip_string(__u32 ip) {
    unsigned char bytes[4];
    char ipstring[32];
    bytes[0] = ip & 0xFF;
    bytes[1] = (ip >> 8) & 0xFF;
    bytes[2] = (ip >> 16) & 0xFF;
    bytes[3] = (ip >> 24) & 0xFF;   
    snprintf(ipstring, "%d.%d.%d.%d", bytes[3], bytes[2], bytes[1], bytes[0]);   
}