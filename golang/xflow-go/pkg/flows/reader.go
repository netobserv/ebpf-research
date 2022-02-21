package flows

import (
	"errors"
	"fmt"
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"
	"github.com/vishvananda/netlink"
	"io/fs"
	"log"
	"os"
)

// $BPF_CLANG and $BPF_CFLAGS are set by the Makefile.
//go:generate bpf2go -cc $BPF_CLANG -cflags $BPF_CFLAGS bpf ../../bcc/xflow.c -- -I../../headers

const (
	qdiscType = "clsact"
)

func Start(stopCh <-chan os.Signal, interfaceName string) (*ebpf.Map, error) {
	objects := bpfObjects{}
	// Allow the current process to lock memory for eBPF resources.
	if err := rlimit.RemoveMemlock(); err != nil {
		return nil, fmt.Errorf("removing mem lock: %w", err)
	}
	// Load pre-compiled programs and maps into the kernel.
	if err := loadBpfObjects(&objects, nil); err != nil {
		return nil, fmt.Errorf("loading objects: %w", err)
	}
	ipvlan, err := netlink.LinkByName(interfaceName)
	if err != nil {
		return nil, fmt.Errorf("failed to lookup ipvlan device %q: %w", interfaceName, err)
	}
	qdiscAttrs := netlink.QdiscAttrs{
		LinkIndex: ipvlan.Attrs().Index,
		Handle:    netlink.MakeHandle(0xffff, 0),
		Parent:    netlink.HANDLE_CLSACT,
	}
	qdisc := &netlink.GenericQdisc{
		QdiscAttrs: qdiscAttrs,
		QdiscType:  qdiscType,
	}
	if err := netlink.QdiscAdd(qdisc); err != nil {
		if errors.Is(err, fs.ErrExist) {
			log.Printf("qdisc clsact already exists. Ignoring")
		} else {
			qdisc = nil
			return nil, fmt.Errorf("failed to create clsact qdisc on %q: %s %T", interfaceName, err)
		}
	}
	// Fetch events on egress
	egressAttrs := netlink.FilterAttrs{
		LinkIndex: ipvlan.Attrs().Index,
		Parent:    netlink.HANDLE_MIN_EGRESS,
		Handle:    netlink.MakeHandle(0, 1),
		Protocol:  3,
		Priority:  1,
	}
	egressFilter := &netlink.BpfFilter{
		FilterAttrs:  egressAttrs,
		Fd:           objects.XflowStart.FD(),
		Name:         "tc/xflow",
		DirectAction: true,
	}
	if err = netlink.FilterAdd(egressFilter); err != nil {
		if errors.Is(err, fs.ErrExist) {
			log.Printf("egress filter already exists. Ignoring")
		} else {
			return nil, fmt.Errorf("failed to create egress filter: %w", err)
		}
	}
	// Fetch events on ingress
	ingressAttrs := netlink.FilterAttrs{
		LinkIndex: ipvlan.Attrs().Index,
		Parent:    netlink.HANDLE_MIN_INGRESS,
		Handle:    netlink.MakeHandle(0, 1),
		Protocol:  3,
		Priority:  1,
	}
	ingressFilter := &netlink.BpfFilter{
		FilterAttrs:  ingressAttrs,
		Fd:           objects.XflowStart.FD(),
		Name:         "tc/xflow",
		DirectAction: true,
	}
	if err = netlink.FilterAdd(ingressFilter); err != nil {
		if errors.Is(err, fs.ErrExist) {
			log.Printf("ingress filter already exists. Ignoring")
		} else {
			return nil, fmt.Errorf("failed to create ingress filter: %w", err)
		}
	}

	go func() {
		<-stopCh
		if err := objects.Close(); err != nil {
			log.Println("error closing resources", err)
		}

		if qdisc != nil {
			if err := netlink.QdiscDel(qdisc); err != nil {
				log.Println("error closing resources", err)
			}
		}
		if egressFilter != nil {
			if err := netlink.FilterDel(egressFilter); err != nil {
				log.Println("error closing resources", err)
			}
		}
		if ingressFilter != nil {
			if err := netlink.FilterDel(ingressFilter); err != nil {
				log.Println("error closing resources", err)
			}
		}
	}()
	return objects.XflowMetricTcMap, nil
}
