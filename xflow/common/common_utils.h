/* Common function that with time should be moved to libbpf */
#ifndef __COMMON_UTILS_H
#define __COMMON_UTILS_H

#include <linux/types.h>

char * get_ip_string(__u32 ip);

#endif /* __COMMON_UTILS_H */