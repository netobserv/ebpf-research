
VERSION?=0.1
GO?=go
BUILD_ID:=$(shell echo 0x$$(head -c20 /dev/urandom|od -An -tx1|tr -d ' \n'))
SKYDIVE_GITHUB:=github.com/skydive-project/skydive
SKYDIVE_PKG:=skydive-${VERSION}
SKYDIVE_PATH:=$(SKYDIVE_PKG)/src/$(SKYDIVE_GITHUB)/
SKYDIVE_GITHUB_VERSION:=$(SKYDIVE_GITHUB)/version.Version=${VERSION}
VERBOSE_FLAGS?=
VERBOSE?=true
ifeq ($(VERBOSE), true)
  VERBOSE_FLAGS+=-v
endif
BUILD_TAGS?=$(TAGS)

WITH_LXD?=true
WITH_OPENCONTRAIL?=true
WITH_LIBVIRT_GO?=true
WITH_EBPF_DOCKER_BUILDER?=true
WITH_VPP?=false
WITH_PACKETINJECT?=true

EXTRA_BUILD_TARGET=

ifeq ($(WITH_EBPF), true)
  BUILD_TAGS+=ebpf
  EXTRA_BUILD_TARGET+=.ebpf
endif

ifeq ($(WITH_PROF), true)
  BUILD_TAGS+=prof
endif

ifeq ($(WITH_SCALE), true)
  BUILD_TAGS+=scale
endif

ifeq ($(WITH_CDD), true)
  BUILD_TAGS+=cdd
endif


include .mk/ebpf.mk

.DEFAULT_GOAL := all

.PHONY: all install
all install: skydive

.PHONY: version
version:
	@echo -n ${VERSION}

define GOCOMPILE
CGO_CFLAGS_ALLOW='.*' CGO_LDFLAGS_ALLOW='.*' $(GO) $1 \
                -ldflags="${LDFLAGS} -B $(BUILD_ID) -X $(SKYDIVE_GITHUB_VERSION)" \
                ${GOFLAGS} -tags="${BUILD_TAGS}" ${VERBOSE_FLAGS} \
                ${SKYDIVE_GITHUB}
endef

.PHONY: .build
.build:
	$(call GOCOMPILE,build)

.PHONY: build
build: gopath moddownload genlocalfiles .build

.PHONY: .install
.install:
	$(call GOCOMPILE,install)

.PHONY: skydive
skydive: gopath moddownload genlocalfiles .install

.PHONY: skydive.clean
skydive.clean:
	go clean -i $(SKYDIVE_GITHUB)

.PHONY: moddownload
moddownload:
ifneq ($(OFFLINE), true)
	go mod download
endif

.PHONY: genlocalfiles
genlocalfiles: $(EXTRA_BUILD_TARGET) .proto .typescript .bindata .ovnmodel .gendecoder .easyjson .vppbinapi

.PHONY: touchlocalfiles
touchlocalfiles: .proto.touch .typescript.touch .bindata.touch .gendecoder.touch .easyjson.touch

.PHONY: clean
clean: skydive.clean test.functionals.clean contribs.clean .ebpf.clean .easyjson.clean .proto.clean .gendecoder.clean .ovnmodel.clean .typescript.clean .vppbinapi.clean swagger.clean
	go clean -i >/dev/null 2>&1 || true

.PHONY: docker
docker:
	docker build . -t $(DOCKER_IMAGE):$(DOCKER_TAG)

.PHONY: .ebpf
.ebpf: moddownload
ifeq ($(WITH_EBPF_DOCKER_BUILDER), true)
	$(MAKE) -C ebpf docker-ebpf-build
else
	$(MAKE) -C ebpf
endif

.PHONY: ebpf.test
ebpf.test: .ebpf ../ebpf/statics/bindata.go
	$(MAKE) -C ebpf ebpf-test

.PHONY: .ebpf.clean
.ebpf.clean:
	$(MAKE) -C ebpf clean
