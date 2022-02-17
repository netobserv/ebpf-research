package connect

import (
	"bytes"
	"errors"
	"fmt"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
	"github.com/vishvananda/netlink"
	"io"
	"io/fs"
	"log"
	"strings"
)

// $BPF_CLANG and $BPF_CFLAGS are set by the Makefile.
//go:generate bpf2go -cc $BPF_CLANG -cflags $BPF_CFLAGS bpf ../../bcc/flows.c -- -I../../headers

const (
	qdiscType = "clsact"
)

type Monitor struct {
	interfaceName string
	objects       bpfObjects
	qdisc         *netlink.GenericQdisc
	filter        *netlink.BpfFilter
	netEvents     *ringbuf.Reader
	stats         Registry
}

func NewMonitor(iface string) Monitor {
	return Monitor{
		interfaceName: iface,
		stats:         Registry{elements: map[statsKey]*Stats{}},
	}
}

func (m *Monitor) Start() error {
	// Allow the current process to lock memory for eBPF resources.
	if err := rlimit.RemoveMemlock(); err != nil {
		return fmt.Errorf("removing mem lock: %w", err)
	}
	// Load pre-compiled programs and maps into the kernel.
	if err := loadBpfObjects(&m.objects, nil); err != nil {
		return fmt.Errorf("loading objects: %w", err)
	}
	ipvlan, err := netlink.LinkByName(m.interfaceName)
	if err != nil {
		return fmt.Errorf("failed to lookup ipvlan device %q: %w", m.interfaceName, err)
	}
	qdiscAttrs := netlink.QdiscAttrs{
		LinkIndex: ipvlan.Attrs().Index,
		Handle:    netlink.MakeHandle(0xffff, 0),
		Parent:    netlink.HANDLE_CLSACT,
	}
	m.qdisc = &netlink.GenericQdisc{
		QdiscAttrs: qdiscAttrs,
		QdiscType:  qdiscType,
	}
	if err := netlink.QdiscAdd(m.qdisc); err != nil {
		if errors.Is(err, fs.ErrExist) {
			log.Printf("qdisc clsact already exists. Ignoring")
		} else {
			m.qdisc = nil
			return fmt.Errorf("failed to create clsact qdisc on %q: %s %T", m.interfaceName, err)
		}
	}
	filterAttrs := netlink.FilterAttrs{
		LinkIndex: ipvlan.Attrs().Index,
		Parent:    netlink.HANDLE_MIN_EGRESS,
		Handle:    netlink.MakeHandle(0, 1),
		Protocol:  3,
		Priority:  1,
	}
	m.filter = &netlink.BpfFilter{
		FilterAttrs:  filterAttrs,
		Fd:           m.objects.TcEgress.FD(),
		Name:         "tc/egress",
		DirectAction: true,
	}
	if err = netlink.FilterAdd(m.filter); err != nil {
		if errors.Is(err, fs.ErrExist) {
			log.Printf("cls_bpf filter already exists. Ignoring")
		} else {
			return fmt.Errorf("failed to create cls_bpf filter on %q: %w", m.interfaceName, err)
		}
	}
	if m.netEvents, err = ringbuf.NewReader(m.objects.bpfMaps.Egresses); err != nil {
		return fmt.Errorf("accessing to ringbuffer: %w", err)
	}

	go func() {
		for {
			event, err := m.netEvents.Read()
			if err != nil {
				if errors.Is(err, ringbuf.ErrClosed) {
					log.Println("Received signal, exiting..")
					return
				}
				log.Printf("reading from reader: %s", err)
				continue
			}
			// Parse the ringbuf event entry into an Event structure.
			rawSample, err := ReadRaw(bytes.NewBuffer(event.RawSample))
			if err != nil {
				log.Printf("reading ringbuf event: %s", err)
				continue
			}
			m.stats.Accum(rawSample)
		}
	}()
	return nil
}

func (m *Monitor) Stats() []*Stats {
	return m.stats.List()
}

func (m *Monitor) Stop() error {
	var errs []error
	doClose := func(o io.Closer) {
		if o == nil {
			return
		}
		if err := o.Close(); err != nil {
			errs = append(errs, err)
		}
	}
	doClose(m.netEvents)
	doClose(&m.objects)
	if m.qdisc != nil {
		if err := netlink.QdiscDel(m.qdisc); err != nil {
			errs = append(errs, err)
		}
	}
	if m.filter != nil {
		if err := netlink.FilterDel(m.filter); err != nil {
			errs = append(errs, err)
		}
	}
	if len(errs) == 0 {
		return nil
	}
	var errStrings []string
	for _, err := range errs {
		errStrings = append(errStrings, err.Error())
	}
	return errors.New("errors during close: " + strings.Join(errStrings, ", "))
}
