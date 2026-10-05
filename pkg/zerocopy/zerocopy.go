// Package zerocopy moves a file's bytes to a connection without a userspace
// copy where the platform allows it, and with an honest, correct copy where it
// does not.
//
// # Contract
//
// Send delivers exactly n bytes from f at absolute offset off into c, using the
// kernel-mediated path this platform offers:
//
//   - Linux: splice(2), file → pipe → socket. The kernel moves page-cache pages;
//     the file's bytes never enter the server's address space.
//   - macOS and the BSDs: sendfile(2), file → socket.
//   - Windows and everything else: a buffered copy through a fixed-size buffer.
//
// Two properties hold on every platform, and they are the reason this is a
// package rather than a call to io.Copy at the call site:
//
//   - **The file's own offset is never touched.** SMB reads are addressed by
//     offset, and one handle can be read concurrently from several channels of a
//     session, so a transfer that advanced the descriptor's position would hand
//     the wrong bytes to a concurrent reader. Every path here uses positional
//     I/O or passes an explicit offset to the kernel.
//   - **A peer that stops reading cannot pin a goroutine, its connection slot
//     and its buffers forever.** Progress extends a deadline; no progress at all
//     for the caller's stall duration aborts the transfer with ErrStalled.
//
// The caller supplies the stall duration and the byte count it has already
// promised on the wire; the response header is written by the caller, which is
// why a short transfer is a fatal, connection-dropping error (ErrShort) rather
// than a partial success.
//
// Backend names the mechanism in use, for the operator-facing capability report
// and the README support table.
package zerocopy

import (
	"errors"
	"io"
	"net"
	"os"
	"sync/atomic"
	"time"
)

// Errors a caller must treat as fatal for the connection: the response header
// has already promised the byte count.
var (
	// ErrShort reports that the file ended before the promised byte count
	// arrived (it was truncated under us), so the response stream is unusable.
	ErrShort = errors.New("zerocopy: the transfer ended before the promised byte count")
	// ErrStalled reports a peer that made no progress at all for the stall
	// duration.
	ErrStalled = errors.New("zerocopy: the peer stalled during the transfer")
)

// fallbacks counts transfers that could not use the kernel copy path and were
// served by the buffered copy instead — a container whose seccomp filter blocks
// splice(2)/sendfile(2), a host out of descriptors for the pipe. It is exported
// so a silent downgrade cannot hide: an operator can see that the fast path is
// not being taken, and a test can see that the fallback was exercised.
var fallbacks atomic.Int64

// Fallbacks reports how many transfers took the buffered path on a platform that
// has a kernel path. It is always zero where the buffered copy *is* the
// implementation, because there is nothing to fall back from.
func Fallbacks() int64 { return fallbacks.Load() }

// Backend names the mechanism in use: "splice" (Linux), "sendfile" (macOS and
// the BSDs) or "buffered" (everywhere else). It is what the operator-facing
// capability report prints and what the README support table documents.
func Backend() string { return backend }

// bufferedChunk is the userspace buffer size on platforms with no kernel copy
// path. It is one typical page-cache read-ahead batch: large enough that the
// syscall count is negligible, small enough that the buffer is not worth
// pooling around.
const bufferedChunk = 128 << 10

// Send copies n bytes of f starting at off into c.
//
// It reports ErrShort if fewer than n bytes could be transferred (the caller has
// already promised n on the wire, so the connection must be dropped) and
// ErrStalled if the peer stopped making progress. Any other error is the
// operating system's.
func Send(c net.Conn, f *os.File, off int64, n int, stall time.Duration) error {
	if n <= 0 {
		return nil
	}
	return send(c, f, off, n, stall)
}

// copyBuffered is the portable path: positional reads from the file, writes to
// the connection, with the write deadline used as the stall guard. It is what
// every platform without a kernel copy path uses, and it is the reference the
// kernel paths have to match behaviourally.
func copyBuffered(c net.Conn, f *os.File, off int64, n int, stall time.Duration) error {
	buf := make([]byte, min(bufferedChunk, n))
	deadline := time.Now().Add(stall)
	written := 0
	for written < n {
		want := min(len(buf), n-written)
		rd, rerr := f.ReadAt(buf[:want], off+int64(written))
		if rd > 0 {
			for chunk := buf[:rd]; len(chunk) > 0; {
				if time.Now().After(deadline) {
					return ErrStalled
				}
				if err := c.SetWriteDeadline(deadline); err != nil {
					return err
				}
				k, werr := c.Write(chunk)
				if k > 0 {
					written += k
					chunk = chunk[k:]
					deadline = time.Now().Add(stall)
				}
				if werr != nil {
					_ = c.SetWriteDeadline(time.Time{})
					return werr
				}
				if k == 0 {
					return io.ErrShortWrite
				}
			}
		}
		if rerr != nil {
			// Short of the promise: the file shrank under us, which breaks the
			// response stream, or the read failed outright.
			if errors.Is(rerr, io.EOF) || rd < want {
				return ErrShort
			}
			return rerr
		}
		if rd == 0 {
			return ErrShort
		}
	}
	_ = c.SetWriteDeadline(time.Time{})
	return nil
}
