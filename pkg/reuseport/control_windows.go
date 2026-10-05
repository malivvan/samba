package reuseport

import (
	"syscall"

	"golang.org/x/sys/windows"
)

// available is false on Windows, and that is a security decision rather than a
// gap.
//
// Windows has no SO_REUSEPORT. What it has is SO_REUSEADDR, whose meaning is
// different from the Unix option of the same name: it lets a *second* socket
// forcibly bind an address that is already bound and listening, with unspecified
// results for who receives the connection. For a server whose entire purpose is
// to be reachable, allowing another process to steal its port is a downgrade, not
// portability — so this package never sets it, and Listeners returns a single
// shared socket for the workers to accept from.
func available() bool { return false }

// exclusiveAddrUse is SO_EXCLUSIVEADDRUSE, which winsock2.h defines as the
// complement of SO_REUSEADDR rather than as a value of its own:
//
//	#define SO_EXCLUSIVEADDRUSE ((int)(~SO_REUSEADDR))
//
// A wrong value fails the setsockopt below, which fails the bind loudly — the
// option cannot silently half-apply.
const exclusiveAddrUse = ^int(windows.SO_REUSEADDR)

// control asks for exclusive use of the address, which is the protection that
// makes up for not being able to share it.
//
// SO_EXCLUSIVEADDRUSE is Windows' answer to port hijacking: once a socket holds
// an address exclusively, no other socket can bind it, *including* one that asks
// for SO_REUSEADDR — which is exactly the attack the reuse option enables there.
// Microsoft's own guidance is that server applications should use it, and it is
// the reason this file is not simply empty.
//
// The failure is returned rather than ignored: on a server the port is the whole
// service, so a listener that could not be made exclusive is a listener an
// operator should hear about at startup, not discover later. The cost is
// Microsoft's documented caveat that a port held exclusively "cannot necessarily
// be reused immediately after socket closure" if connections were active; the
// shipped systemd unit restarts with a delay, which covers a restart.
func control(network, address string, c syscall.RawConn) error {
	var serr error
	if err := c.Control(func(fd uintptr) {
		serr = windows.SetsockoptInt(windows.Handle(fd), windows.SOL_SOCKET, exclusiveAddrUse, 1)
	}); err != nil {
		return err
	}
	return serr
}
