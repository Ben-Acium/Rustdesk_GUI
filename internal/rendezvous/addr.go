package rendezvous

import (
	"errors"
	"fmt"
	"net"
)

// ErrLoopbackAddr reports a rendezvous address that can never work.
//
// hbbs treats loopback connections on the NAT port specially: in
// handle_listener2 it checks the source address and hands loopback connections
// to an admin console handler instead of the rendezvous message path:
//
//	let ip = try_into_v4(addr).ip();
//	if ip.is_loopback() {
//	    tokio::spawn(async move { /* ... handles console commands */ });
//	    return;
//	}
//
// An OnlineRequest sent there is read as a console command, never answered, and
// the connection closes. The symptom is a bare EOF on every poll, so this is
// checked up front rather than left to be diagnosed at runtime.
var ErrLoopbackAddr = errors.New("hbbs ignores rendezvous requests from loopback addresses")

// ValidateAddr rejects an address hbbs cannot answer on.
//
// The returned error names a usable address, because the fix is almost always
// "use the host's LAN IP instead of 127.0.0.1".
func ValidateAddr(addr string) error {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return fmt.Errorf("rendezvous: %q is not a host:port address: %w", addr, err)
	}

	// A hostname that is not an IP literal is resolved at dial time; only
	// reject what we can be certain about here.
	ip := net.ParseIP(host)
	if ip == nil {
		if host == "localhost" {
			return loopbackError(addr, port)
		}
		return nil
	}
	if ip.IsLoopback() || ip.IsUnspecified() {
		return loopbackError(addr, port)
	}
	return nil
}

func loopbackError(addr, port string) error {
	hint := "use the host's LAN IP"
	if ip := OutboundIP(); ip != "" {
		hint = fmt.Sprintf("try %s:%s", ip, port)
	}
	return fmt.Errorf("rendezvous: %w: %s will never return device presence; %s",
		ErrLoopbackAddr, addr, hint)
}

// OutboundIP reports the local address the kernel would use to reach the
// internet, which on a single-homed host is the address hbbs will accept.
//
// The UDP "connection" only consults the routing table; no packets are sent.
// Returns "" when there is no default route or the result is unusable, so
// callers treat it as a hint rather than a value to depend on.
func OutboundIP() string {
	conn, err := net.Dial("udp", "192.0.2.1:80") // TEST-NET-1, never routed
	if err != nil {
		return ""
	}
	defer conn.Close()

	addr, ok := conn.LocalAddr().(*net.UDPAddr)
	if !ok || addr.IP.IsLoopback() || addr.IP.IsUnspecified() {
		return ""
	}
	return addr.IP.String()
}
