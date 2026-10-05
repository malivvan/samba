//go:build freebsd || openbsd || netbsd || dragonfly

package watch

import "golang.org/x/sys/unix"

// openWatchFD opens a directory for kqueue. The BSDs have no O_EVTONLY, so the
// descriptor is an ordinary read-only one; the kernel does not read anything
// through it, it only uses it to name the vnode to watch.
//
// O_CLOEXEC keeps the descriptor out of any child process, and the flag is
// passed to open(2) rather than set afterwards so there is no window in which a
// concurrent spawn could inherit it.
func openWatchFD(path string) (int, error) {
	return unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC, 0)
}
