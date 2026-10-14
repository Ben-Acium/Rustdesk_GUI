// Command rdprobe asks an hbbs rendezvous server whether the given peer IDs are
// online. It exists to validate the wire protocol independently of the web UI.
//
//	rdprobe -addr 127.0.0.1:21115 123456789 234567890
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/bjones/rustdeskgui/internal/rendezvous"
)

func main() {
	addr := flag.String("addr", "127.0.0.1:21115", "hbbs NAT port (base rendezvous port minus one)")
	timeout := flag.Duration("timeout", 10*time.Second, "overall query timeout")
	flag.Parse()

	peers := flag.Args()
	if len(peers) == 0 {
		fmt.Fprintln(os.Stderr, "usage: rdprobe [-addr host:port] <peer-id>...")
		os.Exit(2)
	}

	c := &rendezvous.Client{Addr: *addr, Timeout: *timeout}

	start := time.Now()
	states, err := c.Online(context.Background(), peers)
	elapsed := time.Since(start)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}

	online := 0
	for i, id := range peers {
		status := "offline"
		if states[i] {
			status = "ONLINE"
			online++
		}
		fmt.Printf("%-16s %s\n", id, status)
	}
	fmt.Printf("\n%d/%d online  (%s in %s)\n", online, len(peers), *addr, elapsed.Round(time.Millisecond))
}
