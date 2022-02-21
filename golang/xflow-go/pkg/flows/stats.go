package flows

import (
	"encoding/binary"
	"fmt"
	"net"
	"strconv"
)

type Protocol uint8
type RawIP uint32
type HumanBytes uint64

type FlowID struct {
	SrcIP    RawIP
	DstIP    RawIP
	SrcPort  uint16
	DstPort  uint16
	Protocol Protocol
	Iface    uint16
}

type FlowCounter struct {
	Packets uint32
	Bytes   HumanBytes
	StartNS uint64
	EndNS   uint64
}

func (proto Protocol) String() string {
	switch proto {
	case 0:
		return "IP"
	case 1:
		return "ICMP"
	case 2:
		return "IGMP"
	case 4:
		return "IPIP"
	case 6:
		return "TCP"
	case 8:
		return "EGP"
	case 12:
		return "PUP"
	case 17:
		return "UDP"
	case 22:
		return "IDP"
	case 29:
		return "TP"
	case 33:
		return "DCCP"
	case 41:
		return "IPV6"
	case 46:
		return "RSVP"
	case 136:
		return "UDPLITE"
	default:
		return "other"
	}
}

func (r RawIP) String() string {
	ip := make(net.IP, 4)
	binary.BigEndian.PutUint32(ip, uint32(r))
	return ip.String()
}

const (
	kibi = 1024
	mibi = kibi * 1024
	gibi = mibi * 1024
)

func (b HumanBytes) String() string {
	if b < kibi {
		return strconv.FormatUint(uint64(b), 10)
	}
	if b < mibi {
		return fmt.Sprintf("%.2f KiB", float64(b)/float64(kibi))
	}
	if b < gibi {
		return fmt.Sprintf("%.2f MiB", float64(b)/float64(mibi))
	}
	return fmt.Sprintf("%.2f MiB", float64(b)/float64(gibi))
}
