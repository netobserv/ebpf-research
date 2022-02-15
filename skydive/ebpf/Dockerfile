FROM fedora:30
RUN dnf install -y kernel-devel make binutils golang go-bindata git cmake gcc g++ llvm clang
RUN mkdir -p /go
ENV GOPATH=/go
RUN go get github.com/iovisor/gobpf
RUN ls -la /go/src/github.com/iovisor/gobpf/elf/include/uapi/linux/bpf.h
RUN ls -la /go/src/github.com/iovisor/gobpf/elf/include/bpf_map.h

