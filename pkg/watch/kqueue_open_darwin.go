//go:build darwin

package watch

import "golang.org/x/sys/unix"

// openWatchFD opens a directory for kqueue.
//
// macOS has a flag for exactly this: O_EVTONLY asks for a descriptor usable for
// event delivery without read access, so watching a directory the server's user
// may not read still works, and the kernel does not have to keep the vnode
// readable. Older systems that do not accept the flag fall back to a plain read
// descriptor.
func openWatchFD(path string) (int, error) {
	fd, err := unix.Open(path, unix.O_EVTONLY|unix.O_CLOEXEC, 0)
	if err != nil {
		return unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC, 0)
	}
	return fd, nil
}
