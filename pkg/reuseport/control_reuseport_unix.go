//go:build linux || darwin || freebsd || openbsd || netbsd || dragonfly

package reuseport

import (
	"syscall"

	"golang.org/x/sys/unix"
)

// available is true on the platforms whose SO_REUSEPORT has load-balancing
// semantics: a process (or, on Linux, a user) that binds the same address
// cooperatively gets a share of the incoming connections. The BSDs restrict a
// reuse group to sockets created by the same effective user, and Linux requires
// the flag on every socket in the group, so the option cannot be used by an
// unrelated process to take over the port.
//
// The build tag lists the platforms explicitly rather than saying `unix`,
// because the option is not exposed everywhere `unix` covers: Solaris has no
// SO_REUSEPORT this package can reach, and it must fall back to one shared
// socket rather than fail to build.
func available() bool { return true }

// control sets the socket options on a descriptor net.Listen has just created,
// before it is bound. SO_REUSEADDR is what actually rescues a restart from
// EADDRINUSE while old connections linger in TIME_WAIT (Go's net package sets it
// for TCP anyway — setting it here keeps the intent visible); SO_REUSEPORT is
// what lets every worker bind the same address.
//
// A kernel that does not implement SO_REUSEPORT at all (an ancient kernel, or a
// sandbox that filters the option) makes the bind fail, and Listeners then
// reports the error to the caller rather than silently degrading: the caller has
// a documented fallback for a platform *without* the facility, but a platform
// that has it and refuses to honour it is an error worth surfacing.
func control(network, address string, c syscall.RawConn) error {
	var serr error
	if err := c.Control(func(fd uintptr) {
		if err := unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_REUSEADDR, 1); err != nil {
			serr = err
			return
		}
		serr = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_REUSEPORT, 1)
	}); err != nil {
		return err
	}
	return serr
}
