package main

import (
	"fmt"
	"github.com/netobserv/ebpf-research/golang/xflow-go/pkg/flows"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"
)

func main() {
	// Subscribe to signals for terminating the program.
	stopper := make(chan os.Signal, 1)
	signal.Notify(stopper, os.Interrupt, syscall.SIGTERM)

	flm, err := flows.Start(stopper, "eth0")
	if err != nil {
		log.Println(err)
	}

	go func() {
		for {
			time.Sleep(2 * time.Second)
			fmt.Println("*********************************")
			key := flows.FlowID{}
			val := flows.FlowCounter{}
			iter := flm.Iterate()
			for iter.Next(&key, val) {
				fmt.Printf("%#v %#v\n", key, val)
			}

		}
	}()

	<-stopper
	log.Println("stopping server and closing resources")
	time.Sleep(2 * time.Second)
}
