//go:build unix && !linux

package zerocopy

import (
	"errors"
	"net"
	"os"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

// backend is what the operator-facing capability report prints, and what the
// README support table documents.
const backend = "sendfile"

// maxSendfileChunk bounds one sendfile(2) call. The count is an int in the
// syscall, so a chunk keeps a single call within range on a 32-bit target, and a
// bounded call gives the loop a chance to notice a stalled peer in between.
const maxSendfileChunk = 1 << 20

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
		sent, inner = sendfilePump(int(sockFD), srcFD, off, n, stall)
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

// sendfilePump moves n bytes from srcFD at off into sockFD, extending the stall
// deadline by every byte that moves so only a peer that stops making progress
// altogether is given up on.
//
// It returns how many bytes reached the socket.
func sendfilePump(sockFD, srcFD int, off int64, n int, stall time.Duration) (int, error) {
	deadline := time.Now().Add(stall)
	sent := 0
	// zeroProgress counts consecutive calls that reported success *and* moved
	// nothing, which is how "the send buffer is full" is told apart from "the
	// file ended": a full buffer makes progress after the wait, an ended file
	// never does.
	zeroProgress := 0
	for sent < n {
		if time.Now().After(deadline) {
			return sent, ErrStalled
		}
		want := min(n-sent, maxSendfileChunk)
		chunkOff := off + int64(sent)
		k, err := unix.Sendfile(sockFD, srcFD, &chunkOff, want)
		switch {
		case err == nil && k > 0:
			sent += k
			zeroProgress = 0
			deadline = time.Now().Add(stall)
		case err == nil:
			if zeroProgress++; zeroProgress >= 2 {
				// A writable socket that still accepts nothing: the file ended
				// before the promised byte count.
				return sent, ErrShort
			}
			if err := waitWritable(sockFD); err != nil {
				return sent, err
			}
		case errors.Is(err, unix.EINTR):
		case errors.Is(err, unix.EAGAIN) || errors.Is(err, unix.EWOULDBLOCK):
			if err := waitWritable(sockFD); err != nil {
				return sent, err
			}
		default:
			return sent, err
		}
	}
	return sent, nil
}
