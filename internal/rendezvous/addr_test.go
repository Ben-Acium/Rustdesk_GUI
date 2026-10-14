package rendezvous

import (
	"errors"
	"strings"
	"testing"
)

// Loopback is always wrong for hbbs's NAT port: the server hands such
// connections to its console handler and never answers an OnlineRequest.
func TestValidateAddrRejectsLoopback(t *testing.T) {
	for _, addr := range []string{
		"127.0.0.1:21115",
		"127.0.0.53:21115",
		"[::1]:21115",
		"localhost:21115",
		"0.0.0.0:21115",
		"[::]:21115",
	} {
		err := ValidateAddr(addr)
		if err == nil {
			t.Errorf("ValidateAddr(%q) = nil, want an error", addr)
			continue
		}
		if !errors.Is(err, ErrLoopbackAddr) {
			t.Errorf("ValidateAddr(%q) error does not wrap ErrLoopbackAddr: %v", addr, err)
		}
		// The message has to name the port, since the fix is to swap only the host.
		if !strings.Contains(err.Error(), "21115") {
			t.Errorf("ValidateAddr(%q) error omits the port: %v", addr, err)
		}
	}
}

func TestValidateAddrAcceptsRoutableAddresses(t *testing.T) {
	for _, addr := range []string{
		"10.176.24.40:21115",
		"192.168.1.10:21115",
		"64.58.102.35:21115",
		"hbbs:21115", // Docker service name, resolved at dial time
		"[2001:db8::1]:21115",
	} {
		if err := ValidateAddr(addr); err != nil {
			t.Errorf("ValidateAddr(%q) = %v, want nil", addr, err)
		}
	}
}

func TestValidateAddrRejectsMalformed(t *testing.T) {
	for _, addr := range []string{"", "no-port", "10.0.0.1"} {
		if err := ValidateAddr(addr); err == nil {
			t.Errorf("ValidateAddr(%q) = nil, want an error", addr)
		}
	}
}

// OutboundIP is a hint, so it must never panic or return a loopback address;
// an empty string is a valid answer on a host with no default route.
func TestOutboundIPIsUsableOrEmpty(t *testing.T) {
	got := OutboundIP()
	if got == "" {
		t.Skip("no default route in this environment")
	}
	if strings.HasPrefix(got, "127.") || got == "::1" {
		t.Errorf("OutboundIP() = %q, want a non-loopback address or \"\"", got)
	}
}
