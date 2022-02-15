LLC ?= llc
CLANG ?= clang
DOCKER_FILE ?= Dockerfile
DOCKER_EBPF_BUILDER_IMAGE ?= ebpf-builder
UID ?= $(shell id -u)
GID ?= $(shell id -g)

.PHONY: clean build-ebpf-docker-image docker-ebpf-build

all: clean docker-ebpf-build

ebpf-build: flow-gre.o flow.o

%.o: %.c
	$(CLANG) \
		-D__KERNEL__ -D__ASM_SYSREG_H -D__TARGET_ARCH_BPF -Wno-unused-value -Wno-pointer-sign \
		-Wno-compare-distinct-pointer-types \
		-Wno-gnu-variable-sized-type-not-at-end \
		-Wno-address-of-packed-member -Wno-tautological-compare \
		-Wno-compare-distinct-pointer-types -Wno-unknown-warning-option \
		-fno-stack-protector \
		-fno-jump-tables \
		-fno-common \
		-O2 -g -emit-llvm -c $< -o ebpf.bc
	$(LLC) -march=bpf -filetype=obj -mattr=dwarfris -o $@ ebpf.bc
	rm -f ebpf.bc

clean:
	rm -f ebpf/*.o

build-ebpf-docker-image:
	docker build -t $(DOCKER_EBPF_BUILDER_IMAGE) -f $(DOCKER_FILE) .

docker-ebpf-build: build-ebpf-docker-image
	docker run --rm \
		--env=UID=$(UID) \
		--env=GID=$(GID) \
		-v "$$PWD":/go/ebpf \
		--workdir=/go/ebpf \
		$(DOCKER_EBPF_BUILDER_IMAGE) \
		sh -c "make ebpf-build && chown -R $(UID):$(GID) ."

docker-ebpf-test:
	docker run --rm \
		--env=UID=$(UID) \
		--env=GID=$(GID) \
		-v "$$PWD":/go/ebpf \
		--workdir=/go/ebpf \
		$(DOCKER_EBPF_BUILDER_IMAGE) \
		sh -c "cd tests; go build -tags="ebpf" && sudo ./tests"

