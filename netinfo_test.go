package samba

import (
	"net"
	"testing"
)

func TestEncodeInterfaceInfoShape(t *testing.T) {
	ifaces := []Iface{
		{Index: 1, Addr: mustIP(t, "127.0.0.1"), Speed: 100_000_000_000, Capability: IfaceCapRSS, Loopback: true},
		{Index: 2, Addr: mustIP(t, "10.0.0.5"), Speed: 25_000_000_000, Capability: IfaceCapRSS},
	}
	b := EncodeInterfaceInfo(ifaces)
	// Each entry is 24 bytes of header plus a 128-byte SOCKADDR_STORAGE = 152.
	if len(b) != 152*2 {
		t.Fatalf("length = %d, want %d", len(b), 152*2)
	}
	// The first Next points to the second entry.
	if got := le32(b[0:4]); got != 152 {
		t.Fatalf("next = %d, want 152", got)
	}
	// The last Next is zero.
	if got := le32(b[152:156]); got != 0 {
		t.Fatalf("last next = %d, want 0", got)
	}
	// First IfIndex.
	if got := le32(b[4:8]); got != 1 {
		t.Fatalf("ifindex = %d, want 1", got)
	}
	// LinkSpeed at offset 16, after Next/IfIndex/Capability/Reserved.
	if got := le64(b[16:24]); got != 100_000_000_000 {
		t.Fatalf("speed = %d", got)
	}
	// SOCKADDR family for an IPv4 address is 2 (AF_INET).
	if got := le16(b[24:26]); got != 2 {
		t.Fatalf("family = %d, want 2", got)
	}
}

func TestEncodeInterfaceInfoIPv6(t *testing.T) {
	b := EncodeInterfaceInfo([]Iface{{Index: 3, Addr: mustIP(t, "fe80::1"), Speed: 1, Capability: IfaceCapRSS}})
	if len(b) != 152 {
		t.Fatalf("length = %d", len(b))
	}
	if got := le16(b[24:26]); got != 23 {
		t.Fatalf("family = %d, want 23 (AF_INET6)", got)
	}
}

func TestEnumerateInterfacesHasLoopback(t *testing.T) {
	ifs := EnumerateInterfaces()
	found := false
	for _, i := range ifs {
		if i.Loopback {
			found = true
		}
		if i.Capability != IfaceCapRSS {
			t.Fatalf("interface %v must advertise RSS", i.Addr)
		}
		if i.Speed == 0 {
			t.Fatalf("interface %v must advertise a speed", i.Addr)
		}
	}
	if !found {
		t.Skip("no loopback interface in this environment")
	}
}

func mustIP(t *testing.T, s string) net.IP {
	t.Helper()
	ip := net.ParseIP(s)
	if ip == nil {
		t.Fatalf("bad IP %q", s)
	}
	return ip
}
