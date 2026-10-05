//go:build !linux && !darwin && !freebsd && !openbsd && !netbsd && !dragonfly && !windows

package reuseport

import "syscall"

// available is false on the platforms outside the supported set: either they
// have no SO_REUSEPORT, or (Solaris, AIX) x/sys does not expose it. The caller is
// not left without a server — Listeners hands back a single socket and every
// worker accepts from it — so this is a degradation in *how* accepts are spread,
// not in whether they are.
func available() bool { return false }

// control is a no-op: there is no reuse option to set, so net.Listen's own
// defaults apply.
func control(network, address string, c syscall.RawConn) error { return nil }
