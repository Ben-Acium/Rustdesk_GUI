package rdns

import "testing"

// The filter's whole job is telling a name someone chose from filler a provider
// generated. These are real-world shapes, including the two seen on this
// deployment.
func TestIsNoise(t *testing.T) {
	cases := []struct {
		name string
		ptr  string
		ip   string
		want bool
	}{
		// Generated: the address is spelled out in the first label.
		{"verizon pool", "pool-71-113-27-25.rcmdva.east.verizon.net", "71.113.27.25", true},
		{"comcast hsd", "71-113-27-25.hsd1.ca.comcast.net", "71.113.27.25", true},
		{"dotted", "71.113.27.25.static.example.net", "71.113.27.25", true},
		{"zero padded", "071-113-027-025.dsl.example.net", "71.113.27.25", true},
		{"reversed octets", "25-27-113-71.rev.example.net", "71.113.27.25", true},
		{"bare address", "71.113.27.25", "71.113.27.25", true},
		{"unresolved reverse zone", "25.27.113.71.in-addr.arpa", "71.113.27.25", true},
		{"no underscore variant", "ip71-113-27-25.example.net", "71.113.27.25", true},

		// Chosen names, including ones that happen to contain digits.
		{"plain hostname", "eclipse", "10.176.24.40", false},
		{"lan fqdn", "eclipse.lan", "10.176.24.40", false},
		{"digits in name", "nas-box-2", "10.0.0.22", false},
		{"numbered host", "web01.internal", "10.0.0.5", false},
		{"year in name", "pc-2019.office", "10.0.0.7", false},
		// A digit run that is not the address must survive.
		{"unrelated digits", "host-12345.example.net", "71.113.27.25", false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := IsNoise(tc.ptr, tc.ip); got != tc.want {
				t.Errorf("IsNoise(%q, %q) = %v, want %v", tc.ptr, tc.ip, got, tc.want)
			}
		})
	}
}

func TestClean(t *testing.T) {
	cases := []struct {
		ptr, ip, want string
	}{
		// LookupAddr returns names with a trailing dot.
		{"eclipse.", "10.176.24.40", "eclipse"},
		{"  eclipse.lan.  ", "10.176.24.40", "eclipse.lan"},
		{"pool-71-113-27-25.rcmdva.east.verizon.net.", "71.113.27.25", ""},
		{"", "10.0.0.1", ""},
		{".", "10.0.0.1", ""},
	}
	for _, tc := range cases {
		if got := Clean(tc.ptr, tc.ip); got != tc.want {
			t.Errorf("Clean(%q, %q) = %q, want %q", tc.ptr, tc.ip, got, tc.want)
		}
	}
}

// A malformed IP must not make the filter throw away a perfectly good name.
func TestIsNoiseWithUnparseableIP(t *testing.T) {
	if IsNoise("eclipse", "not-an-ip") {
		t.Error("a good name was rejected because the IP was unparseable")
	}
}

func TestIsNoiseIPv6(t *testing.T) {
	if !IsNoise("2001-db8--1.static.example.net", "2001:db8::1") {
		t.Error("generated IPv6 record was not detected")
	}
	if IsNoise("eclipse.lan", "2001:db8::1") {
		t.Error("chosen name rejected for an IPv6 address")
	}
}

// An empty address must not trigger a lookup or a panic.
func TestLookupEmptyIP(t *testing.T) {
	if got := New().Lookup(t.Context(), ""); got != "" {
		t.Errorf("Lookup(\"\") = %q, want empty", got)
	}
}
