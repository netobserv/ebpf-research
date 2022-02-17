//go:build linux

package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"sort"
	"syscall"
	"time"

	"github.com/netobserv/ebpf-research/golang/tc-flows/pkg/connect"
)

var (
	interfaceName = flag.String("iface", "eth0", "interface to attach to")
	reportFreq    = flag.Duration("freq", 5*time.Second, "frequency of on-screen reporting")
)

func main() {
	flag.Parse()

	monitor := connect.NewMonitor(*interfaceName)
	if err := monitor.Start(); err != nil {
		log.Fatalf("starting monitor: %s", err)
	}

	go func() {
		for {
			time.Sleep(*reportFreq)
			fmt.Println("*** TOP TRAFFIC REPORT")
			stats := monitor.Stats()
			sort.SliceStable(stats, func(i, j int) bool {
				return stats[i].Bytes > stats[j].Bytes
			})
			for _, egress := range stats {
				fmt.Printf("\t- (%s)\t%s:%d\t->\t%s:%d\t(%d packets, %d bytes)\n",
					egress.Protocol,
					egress.SrcIP, egress.SrcPort,
					egress.DstIP, egress.DstPort,
					egress.Packets, egress.Bytes)
			}
		}
	}()

	// Subscribe to signals for terminating the program.
	stopper := make(chan os.Signal, 1)
	signal.Notify(stopper, os.Interrupt, syscall.SIGTERM)
	<-stopper
	log.Println("stopping server and closing resources")
	if err := monitor.Stop(); err != nil {
		log.Printf("error stopping server: %s", err)
	}
}
