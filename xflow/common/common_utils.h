/* Common function that with time should be moved to libbpf */
#ifndef __COMMON_UTILS_H
#define __COMMON_UTILS_H

#include <linux/types.h>

void get_ip_string(__u32 ip, char *ip_string);
void get_proto_string(__u8 proto, char *proto_string);

#endif /* __COMMON_UTILS_H */