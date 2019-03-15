// Package traceroute provides functions for executing a tracroute to a remote
// host.
package traceroute

import (
	"errors"
	"fmt"
	"net"
	"syscall"
	"time"
	"context"
	"sync"
)

const DEFAULT_PORT = 33434
const DEFAULT_MAX_HOPS = 64
const DEFAULT_FIRST_HOP = 1
const DEFAULT_TIMEOUT_MS = 500
const DEFAULT_RETRIES = 3
const DEFAULT_PACKET_SIZE = 52
const DEFAULT_RESOLVE_TIMEOUT_MS = 1000

// Return the first non-loopback address as a 4 byte IP address. This address
// is used for sending packets out.
func socketAddr() (addr [4]byte, err error) {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return
	}

	for _, a := range addrs {
		if ipnet, ok := a.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
			if len(ipnet.IP.To4()) == net.IPv4len {
				copy(addr[:], ipnet.IP.To4())
				return
			}
		}
	}
	err = errors.New("you do not appear to be connected to the Internet")
	return
}

// Given a host name convert it to a 4 byte IP address.
func destAddr(dest string) (destAddr [4]byte, err error) {
	addrs, err := net.LookupHost(dest)
	if err != nil {
		return
	}
	addr := addrs[0]

	ipAddr, err := net.ResolveIPAddr("ip", addr)
	if err != nil {
		return
	}
	copy(destAddr[:], ipAddr.IP.To4())
	return
}

// TracrouteOptions type
type TracerouteOptions struct {
	Port             int
	MaxHops          int
	FirstHop         int
	TimeoutMs        int
	Retries          int
	PacketSize       int
	ResolveTimeoutMs int
	ResolveHosts     bool
}

// Create a default options structure for a traceroute
func NewTracerouteOptions() *TracerouteOptions {
	return &TracerouteOptions{
		Port:             DEFAULT_PORT,
		MaxHops:          DEFAULT_MAX_HOPS,
		FirstHop:         DEFAULT_FIRST_HOP,
		TimeoutMs:        DEFAULT_TIMEOUT_MS,
		Retries:          DEFAULT_RETRIES,
		PacketSize:       DEFAULT_PACKET_SIZE,
		ResolveTimeoutMs: DEFAULT_RESOLVE_TIMEOUT_MS,
		ResolveHosts:     true,
	}
}

// TracerouteHop type
type TracerouteHop struct {
	Success     bool
	Address     [4]byte
	Host        string
	N           int
	ElapsedTime time.Duration
	TTL         int
}

func (hop *TracerouteHop) AddressString() string {
	return fmt.Sprintf("%v.%v.%v.%v", hop.Address[0], hop.Address[1], hop.Address[2], hop.Address[3])
}

func (hop *TracerouteHop) HostOrAddressString() string {
	hostOrAddr := hop.AddressString()
	if hop.Host != "" {
		hostOrAddr = hop.Host
	}
	return hostOrAddr
}

// TracerouteResult type
type TracerouteResult struct {
	DestinationAddress [4]byte
	Hops               []TracerouteHop
}

func notify(hop TracerouteHop, channels []chan TracerouteHop) {
	for _, c := range channels {
		c <- hop
	}
}

func closeNotify(channels []chan TracerouteHop) {
	for _, c := range channels {
		close(c)
	}
}

// Structure that wraps a file descriptor and only allows it to be closed once
type fdCloser struct {
	fd   int
	once sync.Once
}

// Closes the file descriptor if it's open, otherwise does nothing
func (c *fdCloser) Close() {
	c.once.Do(func() {
		syscall.Close(c.fd)
	})
}

// Resolves an IP address to a hostname and returns the first result; returns an empty string if no PTR record exists,
// or ctx is cancelled before resolution completes
func resolveHost(ctx context.Context, address string) string {
	currHost, err := net.DefaultResolver.LookupAddr(ctx, address)
	if err == nil {
		return currHost[0]
	} else {
		return ""
	}
}

// Waits for hops on resolverChan, then asynchronously resolves their IP addresses to hostname and then writes
// them to resolvedChan
func resolver(ctx context.Context, options *TracerouteOptions, resolverChan chan TracerouteHop, resolvedChan chan TracerouteHop) {
	resolveTimeout := time.Duration(options.ResolveTimeoutMs) * time.Millisecond

	wg := sync.WaitGroup{}
	for hop := range resolverChan {
		if hop.Success && options.ResolveHosts { // only need resolution if successful and ResolveHosts was requested
			wg.Add(1)
			go func(hopToResolve TracerouteHop) { // resolve asynchronously so that a slow DNS resolver doesn't slow down the traceroute
				defer wg.Done()

				rctx, _ := context.WithDeadline(ctx, time.Now().Add(resolveTimeout))
				hopToResolve.Host = resolveHost(rctx, hopToResolve.AddressString())
				resolvedChan <- hopToResolve
			}(hop)
		} else {
			resolvedChan <- hop
		}
	}

	wg.Wait()
	close(resolvedChan)
}

// Waits on recordChan for hops (which may arrive out of sequence), then reorders them sequentially, writes them to
// notifyChan, and records them to result
func recorder(result *TracerouteResult, recordChan chan TracerouteHop, notifyChan ...chan TracerouteHop) {
	expectedTTL := 1
	results := make(map[int]TracerouteHop)

	record := func(hop TracerouteHop) {
		result.Hops = append(result.Hops, hop)
		notify(hop, notifyChan)
	}

	maxTTL := 0
	for hop := range recordChan {
		if hop.TTL > maxTTL {
			maxTTL = hop.TTL
		}

		// if there is a gap between our last displayed hop and the current hop's TTL, see if we have queued the
		// hop(s) in the gap, and if so, record them
		for ttl := expectedTTL; ttl < hop.TTL; ttl++ {
			priorHop, ok := results[ttl]
			if ok {
				record(priorHop)
				delete(results, ttl)
				expectedTTL = ttl + 1
			} else {
				// if we're missing any hop, then stop and wait
				break
			}
		}
		// if this hop is now in sequence, record it
		if hop.TTL == expectedTTL {
			record(hop)
			expectedTTL++
		} else {
			// otherwise queue it to be recorded once we receive the hops before it
			results[hop.TTL] = hop
		}
	}

	// if the final hop we received is not the actual last hop, we need to iterate over the queued last hop(s) and
	// display them in order
	for ttl := expectedTTL; ttl <= maxTTL; ttl++ {
		priorHop, ok := results[ttl]
		if ok {
			record(priorHop)
		}
	}
}

// Traceroute uses the given dest (hostname) and options to execute a traceroute
// from your machine to the remote host.
//
// Outbound packets are UDP packets and inbound packets are ICMP.
//
// Terminates with an error if ctx is cancelled before completion.
//
// Returns a TracerouteResult which contains an array of hops. Each hop includes
// the elapsed time and its IP address.
func Traceroute(ctx context.Context, dest string, options *TracerouteOptions, c ...chan TracerouteHop) (result TracerouteResult, err error) {
	defer closeNotify(c)

	if options == nil {
		options = NewTracerouteOptions()
	}

	result.Hops = []TracerouteHop{}
	destAddr, err := destAddr(dest)
	result.DestinationAddress = destAddr
	socketAddr, err := socketAddr()
	if err != nil {
		return
	}

	timeoutMs := (int64)(options.TimeoutMs)
	tv := syscall.NsecToTimeval(1000 * 1000 * timeoutMs)

	// Set up the socket to receive inbound packets
	recvSocket, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_ICMP)
	if err != nil {
		return result, err
	}
	recvCloser := &fdCloser{fd: recvSocket}
	defer recvCloser.Close()

	// Set up the socket to send packets out.
	sendSocket, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_DGRAM, syscall.IPPROTO_UDP)
	if err != nil {
		return result, err
	}
	sendCloser := &fdCloser{fd: sendSocket}
	defer sendCloser.Close()

	// wrap the provided context so that we can signal our goroutines to terminate when we're done
	doneCtx, done := context.WithCancel(ctx)

	aborted := false
	wg := sync.WaitGroup{}

	// launch a goroutine to close the send/recv sockets when the context is cancelled; this will cause any
	// sendto/recvfrom calls in progress to exit with an error, and avoid waiting for them to block until they time out
	wg.Add(1)
	go func(aborted *bool) {
		defer wg.Done()
		select {
		case <-doneCtx.Done():
			sendCloser.Close()
			recvCloser.Close()
		}
		*aborted = true
		return
	}(&aborted)

	// allocate queues large enough for the worst-case scenario of MaxHops hops; we don't want these channels to block
	// as that would kill performance
	resolverChan := make(chan TracerouteHop, options.MaxHops)
	resolvedChan := make(chan TracerouteHop, options.MaxHops)

	// launch our asynchronous DNS resolver goroutine
	wg.Add(1)
	go func() {
		defer wg.Done()
		resolver(ctx, options, resolverChan, resolvedChan)
	}()

	// launch our asynchronous hop recorder goroutine
	wg.Add(1)
	go func() {
		defer wg.Done()
		recorder(&result, resolvedChan, c...)
	}()

	// Bind to the local socket to listen for ICMP packets
	syscall.Bind(recvSocket, &syscall.SockaddrInet4{Port: options.Port, Addr: socketAddr})

	// main traceroute loop
	retry := 0
	for ttl := options.FirstHop; ttl <= options.MaxHops; ttl++ {
		//log.Println("TTL: ", ttl)
		start := time.Now()

		// This sets the current hop TTL
		syscall.SetsockoptInt(sendSocket, 0x0, syscall.IP_TTL, ttl)
		// This sets the timeout to wait for a response from the remote host
		syscall.SetsockoptTimeval(recvSocket, syscall.SOL_SOCKET, syscall.SO_RCVTIMEO, &tv)

		// Send a single null byte UDP packet
		syscall.Sendto(sendSocket, []byte{0x0}, 0, &syscall.SockaddrInet4{Port: options.Port, Addr: destAddr})

		var p = make([]byte, options.PacketSize)
		n, from, err := syscall.Recvfrom(recvSocket, p, 0)
		elapsed := time.Since(start)
		if err == nil {
			currAddr := from.(*syscall.SockaddrInet4).Addr

			resolverChan <- TracerouteHop{Success: true, Address: currAddr, N: n, ElapsedTime: elapsed, TTL: ttl}

			retry = 0

			// if this reply is from our destination host, we are done
			if currAddr == destAddr {
				break
			}
		} else {
			// if Recvfrom returned an error, it's possible the context was cancelled and recvSocket was closed; if so,
			// aborted will be true
			if aborted {
				break
			}

			// optionally retry if requested, otherwise record an unsuccessful hop
			retry++
			if retry > options.Retries {
				resolverChan <- TracerouteHop{Success: false, TTL: ttl}
				retry = 0
			} else {
				ttl--
			}
		}
	}

	if (aborted) {
		err = errors.New("cancelled")
	} else {
		err = nil
	}

	// close our resolver channel to signal the resolver to exit
	close(resolverChan)

	// cancel our context to signal goroutines to exit
	done()

	// wait for any pending DNS queries
	wg.Wait()

	return result, err
}

// Simplified traceroute wrapper
func TracerouteSimple(dest string, c ...chan TracerouteHop) (result TracerouteResult, err error) {
	return Traceroute(context.Background(), dest, NewTracerouteOptions(), c...)
}
