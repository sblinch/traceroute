package main

import (
	"flag"
	"fmt"
	"net"
	"github.com/sblinch/traceroute"
	"context"
	"sync"
)

func printHop(hop traceroute.TracerouteHop) {
	addr := fmt.Sprintf("%v.%v.%v.%v", hop.Address[0], hop.Address[1], hop.Address[2], hop.Address[3])
	hostOrAddr := addr
	if hop.Host != "" {
		hostOrAddr = hop.Host
	}
	if hop.Success {
		fmt.Printf("%-3d %v (%v)  %v\n", hop.TTL, hostOrAddr, addr, hop.ElapsedTime)
	} else {
		fmt.Printf("%-3d *\n", hop.TTL)
	}
}

func main() {
	var m = flag.Int("m", traceroute.DEFAULT_MAX_HOPS, `Set the max time-to-live (max number of hops) used in outgoing probe packets (default is 64)`)
	var f = flag.Int("f", traceroute.DEFAULT_FIRST_HOP, `Set the first used time-to-live, e.g. the first hop (default is 1)`)
	var q = flag.Int("q", 1, `Set the number of probes per "ttl" to nqueries (default is one probe).`)

	flag.Parse()
	host := flag.Arg(0)
	options := traceroute.NewTracerouteOptions()
	options.Retries = *q - 1
	options.MaxHops = *m + 1
	options.FirstHop = *f

	ipAddr, err := net.ResolveIPAddr("ip", host)
	if err != nil {
		return
	}

	fmt.Printf("traceroute to %v (%v), %v hops max, %v byte packets\n", host, ipAddr, options.MaxHops, options.PacketSize)

	c := make(chan traceroute.TracerouteHop)

	wg := sync.WaitGroup{}
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			hop, ok := <-c
			if !ok {
				fmt.Println()
				return
			}
			printHop(hop)
		}
	}()

	_, err = traceroute.Traceroute(context.Background(), host, options, c)
	if err != nil {
		fmt.Printf("Error: ", err)
	}
	wg.Wait()
}
