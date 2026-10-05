//go:build unix

package zerocopy

import (
	"errors"

	"golang.org/x/sys/unix"
)

// pollTimeoutMs bounds a single wait for the socket to become writable, so a
// stalled peer cannot delay unwinding a connection for long. The wait is
// repeated, and the caller's stall deadline is what finally gives up.
const pollTimeoutMs = 200

// waitWritable parks until the socket accepts more data.
//
// The descriptor is used directly rather than through the net.Conn write
// deadline, because the lock-free paths hand bytes to the kernel themselves and
// never call Conn.Write. A timeout is treated as success: the splice or sendfile
// is retried and re-checks the caller's stall deadline, which is what actually
// bounds the transfer.
func waitWritable(fd int) error {
	for {
		fds := []unix.PollFd{{Fd: int32(fd), Events: unix.POLLOUT}}
		n, err := unix.Poll(fds, pollTimeoutMs)
		switch {
		case err == nil && n > 0:
			return nil
		case err == nil:
			return nil // timeout: retry the transfer and re-check
		case errors.Is(err, unix.EINTR):
			continue
		default:
			return err
		}
	}
}

// unsupported reports whether err means "this kernel/host cannot do that
// syscall", as opposed to a transient condition. A seccomp filter, a container
// without the capability, or an old kernel is what produces these, and all of
// them call for the buffered fallback rather than a failed read.
func unsupported(err error) bool {
	return errors.Is(err, unix.ENOSYS) || errors.Is(err, unix.EINVAL) ||
		errors.Is(err, unix.EPERM) || errors.Is(err, unix.EOPNOTSUPP)
}
