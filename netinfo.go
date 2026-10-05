package samba

import (
	"net"
	"os"
	"strconv"
	"strings"
)

// Network interface enumeration for SMB3 multichannel
// (FSCTL_QUERY_NETWORK_INTERFACE_INFO). The client uses the reported
// interfaces — their link speed and RSS capability — to decide how many
// channels (parallel connections) to open to the server.

// Interface capability bits.
const (
	IfaceCapRSS  uint32 = 0x0000_0001
	IfaceCapRDMA uint32 = 0x0000_0002
)

// Iface is one advertised network interface.
type Iface struct {
	Index uint32
	Addr  net.IP
	// Speed is the link speed in bits per second.
	Speed      uint64
	Capability uint32
	// Loopback is retained for diagnostics and the "don't advertise loopback"
	// policy in the FSCTL reply.
	Loopback bool
}

// linkSpeedBps reads /sys/class/net/<name>/speed (Mbps) and converts to
// bits/sec. It falls back to a high value so virtual and loopback interfaces
// still advertise as fast — multichannel is desirable on them for local and
// striped testing.
func linkSpeedBps(name string, loopback bool) uint64 {
	if raw, err := os.ReadFile("/sys/class/net/" + name + "/speed"); err == nil {
		if mbps, err := strconv.ParseInt(strings.TrimSpace(string(raw)), 10, 64); err == nil && mbps > 0 {
			return uint64(mbps) * 1_000_000
		}
	}
	if loopback {
		return 100_000_000_000
	}
	return 10_000_000_000
}

// EnumerateInterfaces returns the usable interfaces, including loopback so
// single-host multichannel testing works; real deployments pick the routable
// address.
func EnumerateInterfaces() []Iface {
	nics, err := net.Interfaces()
	if err != nil {
		return nil
	}
	var out []Iface
	for _, nic := range nics {
		if nic.Flags&net.FlagUp == 0 {
			continue
		}
		loopback := nic.Flags&net.FlagLoopback != 0
		addrs, err := nic.Addrs()
		if err != nil {
			continue
		}
		for _, a := range addrs {
			var ip net.IP
			switch v := a.(type) {
			case *net.IPNet:
				ip = v.IP
			case *net.IPAddr:
				ip = v.IP
			default:
				continue
			}
			if ip == nil {
				continue
			}
			out = append(out, Iface{
				Index:      uint32(nic.Index),
				Addr:       ip,
				Speed:      linkSpeedBps(nic.Name, loopback),
				Capability: IfaceCapRSS,
				Loopback:   loopback,
			})
		}
	}
	return out
}

// AdvertisedInterfaces applies the `advertise_only` filter — a list of
// addresses, empty meaning everything — to the host's interfaces. It is the set
// the server reports in NEGOTIATE and in FSCTL_QUERY_NETWORK_INTERFACE_INFO,
// and the CLI prints it for `--list-interfaces`.
func AdvertisedInterfaces(only []string) []Iface {
	ifaces := EnumerateInterfaces()
	if len(only) == 0 {
		return ifaces
	}
	want := make(map[string]bool, len(only))
	for _, ip := range only {
		want[ip] = true
	}
	kept := ifaces[:0]
	for _, i := range ifaces {
		if want[i.Addr.String()] {
			kept = append(kept, i)
		}
	}
	return kept
}

// EncodeInterfaceInfo encodes the interface list as a chain of
// NETWORK_INTERFACE_INFO structures (MS-SMB2 2.2.32.5) for the
// FSCTL_QUERY_NETWORK_INTERFACE_INFO reply.
func EncodeInterfaceInfo(ifaces []Iface) []byte {
	w := NewWriter(len(ifaces) * 152)
	entryOffsets := make([]int, 0, len(ifaces))
	for _, ifc := range ifaces {
		entryOffsets = append(entryOffsets, w.Len())
		w.U32(0) // Next, patched below
		w.U32(ifc.Index)
		w.U32(ifc.Capability)
		w.U32(0) // Reserved
		w.U64(ifc.Speed)
		// SOCKADDR_STORAGE (128 bytes): family + address.
		saStart := w.Len()
		if v4 := ifc.Addr.To4(); v4 != nil {
			w.U16(2) // AF_INET (Windows value, also Linux)
			w.U16(0) // port
			w.Bytes8(v4)
			w.Zeros(8) // sin_zero
		} else {
			w.U16(23) // AF_INET6 (Windows value)
			w.U16(0)  // port
			w.U32(0)  // flowinfo
			w.Bytes8(ifc.Addr.To16())
			w.U32(0) // scope id
		}
		// Pad SOCKADDR_STORAGE out to 128 bytes.
		w.Zeros(128 - (w.Len() - saStart))
	}
	// Patch Next offsets (the last stays 0).
	for i := 0; i+1 < len(entryOffsets); i++ {
		w.Patch32(entryOffsets[i], uint32(entryOffsets[i+1]-entryOffsets[i]))
	}
	return w.Bytes()
}
