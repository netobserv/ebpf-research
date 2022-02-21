CLANG ?= clang
CFLAGS := -O2 -g -Wall -Werror $(CFLAGS)
CILIUM_EBPF_VERSION := v0.8.1
GOOS := linux
GOCMD ?= go

prereqs:
	@echo "### Test if prerequisites are met, and installing missing dependencies"
	test -f $($(GOCMD) env GOPATH)/bin/bpf2go || $(GOCMD) install github.com/cilium/ebpf/cmd/bpf2go@${CILIUM_EBPF_VERSION}

# $BPF_CLANG and BPF_CFLAGS is used in go:generate invocations.
generate: export BPF_CLANG := $(CLANG)
generate: export BPF_CFLAGS := $(CFLAGS)
generate: prereqs
	$(GOCMD) generate ./pkg/...

build:
	$(GOCMD) build -o xflow-go ./cmd

.PHONY: prereqs generate build
