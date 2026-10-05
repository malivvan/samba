//go:build unix && !linux

package zerocopy

import (
	"net"
	"os"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

// backend is what the operator-facing capability report prints, and what the
// README support table documents.
const backend = "sendfile"

// send moves n bytes from f at off into c with sendfile(2), which copies from
// the file's page cache to the socket in the kernel.
//
// Unlike splice(2) on Linux there is no pipe in the middle, so the explicit
// offset is the one passed to the syscall: the descriptor's own position is
// never consulted or advanced, which is what lets several channels of one
// session read the same handle concurrently.
func send(c net.Conn, f *os.File, off int64, n int, stall time.Duration) error {
	sc, ok := c.(syscall.Conn)
	if !ok {
		fallbacks.Add(1)
		return copyBuffered(c, f, off, n, stall)
	}
	raw, err := sc.SyscallConn()
	if err != nil {
		fallbacks.Add(1)
		return copyBuffered(c, f, off, n, stall)
	}
	srcFD := int(f.Fd())
	var (
		sent  int
		inner error
	)
	if cerr := raw.Control(func(sockFD uintptr) {
		fd := int(sockFD)
		sent, inner = pumpChunks(off, n, stall,
			func() error { return waitWritable(fd) },
			func(chunkOff int64, count int) (int, error) {
				return unix.Sendfile(fd, srcFD, &chunkOff, count)
			})
	}); cerr != nil {
		return cerr
	}
	// Nothing reached the wire and the kernel says it cannot do this (a sandbox
	// that filters sendfile, an old kernel): copy through userspace instead of
	// failing the read. Once a byte is on the wire the response length is fixed,
	// so there is no longer a safe way back.
	if inner != nil && sent == 0 && unsupported(inner) {
		fallbacks.Add(1)
		return copyBuffered(c, f, off, n, stall)
	}
	return inner
}
