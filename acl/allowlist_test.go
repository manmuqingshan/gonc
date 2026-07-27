package acl

import (
	"context"
	"net"
	"os"
	"testing"
)

func loadACLForTest(t *testing.T, content string) *ACL {
	t.Helper()
	path, err := writeTempACL(content)
	if err != nil {
		t.Fatalf("write temp ACL: %v", err)
	}
	t.Cleanup(func() { _ = os.Remove(path) })

	loaded, err := LoadACL(path)
	if err != nil {
		t.Fatalf("load ACL: %v", err)
	}
	return loaded
}

func TestAllowInbound(t *testing.T) {
	loaded := loadACLForTest(t, `
[allow_inbound]
192.0.2.0/24
2001:db8::/32

[deny_inbound]
192.0.2.50
2001:db8::dead
`)

	tests := []struct {
		ip     string
		denied bool
	}{
		{ip: "192.0.2.1", denied: false},
		{ip: "192.0.2.50", denied: true},
		{ip: "198.51.100.1", denied: true},
		{ip: "2001:db8::1", denied: false},
		{ip: "2001:db8::dead", denied: true},
		{ip: "2001:db9::1", denied: true},
		{ip: "not-an-ip", denied: true},
	}
	for _, tt := range tests {
		t.Run(tt.ip, func(t *testing.T) {
			if got := loaded.ShouldDeny(tt.ip, "inbound"); got != tt.denied {
				t.Fatalf("ShouldDeny(%q, inbound) = %v; want %v", tt.ip, got, tt.denied)
			}
		})
	}

	if ACL_inbound_allow(loaded, &net.TCPAddr{IP: net.ParseIP("192.0.2.10"), Port: 49152}) != true {
		t.Fatal("allowlisted remote TCP address was denied")
	}
	if ACL_inbound_allow(loaded, &net.TCPAddr{IP: net.ParseIP("198.51.100.10"), Port: 49152}) != false {
		t.Fatal("non-allowlisted remote TCP address was allowed")
	}
	if ACL_inbound_allow(loaded, &net.IPAddr{IP: net.ParseIP("192.0.2.10")}) != false {
		t.Fatal("unparseable remote address must fail closed in allowlist mode")
	}
}

func TestAllowInboundEmptyAndLegacyModes(t *testing.T) {
	emptyAllowlist := loadACLForTest(t, "[allow_inbound]\n")
	if !emptyAllowlist.ShouldDeny("192.0.2.1", "inbound") {
		t.Fatal("empty allow_inbound section must deny every inbound IP")
	}

	legacy := loadACLForTest(t, `
[deny_inbound]
192.0.2.1
`)
	if !legacy.ShouldDeny("192.0.2.1", "inbound") {
		t.Fatal("legacy deny_inbound rule was not applied")
	}
	if legacy.ShouldDeny("198.51.100.1", "inbound") {
		t.Fatal("legacy deny-only mode must still allow unmatched IPs")
	}
	if !ACL_inbound_allow(legacy, &net.IPAddr{IP: net.ParseIP("198.51.100.1")}) {
		t.Fatal("legacy deny-only mode must retain fail-open address parsing")
	}
}

func TestAllowOutboundHostAndPortRanges(t *testing.T) {
	loaded := loadACLForTest(t, `
[allow_outbound]
example.com:443
example.com:8000-8002
192.0.2.10:1000-2000
192.0.2.10:2001-3000
192.0.2.20:443
[2001:db8::10]:53
bücher.example:443
blocked.example:443

[deny_outbound]
192.0.2.20
blocked.example
`)

	tests := []struct {
		name   string
		host   string
		port   int
		denied bool
	}{
		{name: "exact domain", host: "example.com", port: 443, denied: false},
		{name: "canonical domain", host: "EXAMPLE.COM.", port: 443, denied: false},
		{name: "wrong domain port", host: "example.com", port: 444, denied: true},
		{name: "domain range start", host: "example.com", port: 8000, denied: false},
		{name: "domain range end", host: "example.com", port: 8002, denied: false},
		{name: "domain range outside", host: "example.com", port: 8003, denied: true},
		{name: "merged IP ranges", host: "192.0.2.10", port: 2500, denied: false},
		{name: "IP range outside", host: "192.0.2.10", port: 3001, denied: true},
		{name: "IPv6", host: "2001:db8::10", port: 53, denied: false},
		{name: "Unicode domain", host: "BÜCHER.EXAMPLE.", port: 443, denied: false},
		{name: "unlisted host", host: "unlisted.example", port: 443, denied: true},
		{name: "deny IP wins", host: "192.0.2.20", port: 443, denied: true},
		{name: "deny domain wins", host: "blocked.example", port: 443, denied: true},
		{name: "invalid port", host: "example.com", port: 0, denied: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := loaded.ShouldDenyOutbound(tt.host, tt.port); got != tt.denied {
				t.Fatalf("ShouldDenyOutbound(%q, %d) = %v; want %v", tt.host, tt.port, got, tt.denied)
			}
		})
	}

	if loaded.ShouldDenyOutboundAddress("example.com:443") {
		t.Fatal("allowed host:port address was denied")
	}
	if !loaded.ShouldDenyOutboundAddress("example.com:444") {
		t.Fatal("unlisted host:port address was allowed")
	}
	if !loaded.ShouldDenyOutboundAddress("malformed-address") {
		t.Fatal("malformed address must be denied")
	}
}

func TestAllowOutboundEmptyAndLegacyModes(t *testing.T) {
	emptyAllowlist := loadACLForTest(t, "[allow_outbound]\n")
	if !emptyAllowlist.ShouldDenyOutbound("example.com", 443) {
		t.Fatal("empty allow_outbound section must deny every outbound endpoint")
	}

	legacy := loadACLForTest(t, `
[deny_outbound]
blocked.example
`)
	if !legacy.ShouldDenyOutbound("blocked.example", 443) {
		t.Fatal("legacy deny_outbound rule was not applied")
	}
	if legacy.ShouldDenyOutbound("example.com", 443) {
		t.Fatal("legacy deny-only mode must still allow unmatched endpoints")
	}
}

func TestAllowOutboundDeniedBeforeResolution(t *testing.T) {
	loaded := loadACLForTest(t, `
[allow_outbound]
127.0.0.1:1234
`)
	_, _, denied, err := ResolveAddrWithACL(context.Background(), loaded, "tcp", nil, "127.0.0.1:1235")
	if err == nil || !denied {
		t.Fatalf("ResolveAddrWithACL unlisted port: denied=%v err=%v; want ACL denial", denied, err)
	}
}

func TestInvalidAllowRulesFailLoading(t *testing.T) {
	tests := map[string]string{
		"inbound domain":            "[allow_inbound]\nexample.com\n",
		"inbound exception":         "[allow_inbound]\n!192.0.2.1\n",
		"outbound missing port":     "[allow_outbound]\nexample.com\n",
		"outbound zero port":        "[allow_outbound]\nexample.com:0\n",
		"outbound high port":        "[allow_outbound]\nexample.com:65536\n",
		"outbound reverse range":    "[allow_outbound]\nexample.com:9000-8000\n",
		"outbound wildcard":         "[allow_outbound]\n*.example.com:443\n",
		"outbound CIDR":             "[allow_outbound]\n192.0.2.0/24:443\n",
		"outbound unbracketed IPv6": "[allow_outbound]\n2001:db8::1:443\n",
		"outbound exception":        "[allow_outbound]\n!example.com:443\n",
	}

	for name, content := range tests {
		t.Run(name, func(t *testing.T) {
			path, err := writeTempACL(content)
			if err != nil {
				t.Fatalf("write temp ACL: %v", err)
			}
			defer os.Remove(path)
			if _, err := LoadACL(path); err == nil {
				t.Fatalf("LoadACL accepted invalid config:\n%s", content)
			}
		})
	}
}
