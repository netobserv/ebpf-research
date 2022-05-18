# SPDX-License-Identifier: (GPL-2.0 OR BSD-2-Clause)

XDP_TARGETS  := src/xflow_xdp src/xflow_hash src/xflow_ringbuf_test src/xflow_ringbuf_test2 src/xflow_rtt src/xflow_array src/xflow_perarray  src/metric/xflow_metric

USER_TARGETS := src/xflow_user src/xflow_ringbuf_test_user src/xflow_rtt_user src/metric/xflow_metric_user
USER_LIBS    := -lbpf -lm -lpthread

LIBBPF_DIR = ./libbpf/src/
COMMON_DIR = ./common

EXTRA_DEPS  += $(COMMON_DIR)/parsing_helpers.h

include $(COMMON_DIR)/common.mk
#COMMON_OBJS := $(COMMON_DIR)/common.o
