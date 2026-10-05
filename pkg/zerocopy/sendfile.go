//go:build unix

package zerocopy

import (
	"errors"
	"time"

	"golang.org/x/sys/unix"
)

// maxChunk bounds one kernel transfer call. The count is an int in the syscall,
// so a chunk keeps a single call within range on a 32-bit target, and a bounded
// call gives the loop a chance to notice a stalled peer in between.
const maxChunk = 1 << 20

// chunkSender moves up to count bytes starting at the absolute offset off, and
// reports how many it moved along with any error.
type chunkSender func(off int64, count int) (int, error)

// busy reports whether an error means "the socket is full, come back later"
// rather than "this transfer is over".
func busy(err error) bool {
	return errors.Is(err, unix.EAGAIN) || errors.Is(err, unix.EWOULDBLOCK)
}

// pumpChunks drives a file→socket transfer the kernel performs in chunks. It is
// the accounting core of the sendfile path, kept apart from the syscall for one
// reason: the accounting is the part that is easy to get wrong and hard to
// observe.
//
// The trap is that a partial transfer arrives *together with* an error. On macOS
// and the BSDs a non-blocking sendfile(2) queues what fits into the socket buffer
// and answers EAGAIN for the rest, with the in/out length set to what it queued —
// unlike Linux and Solaris, which answer (0, EAGAIN) and nothing else. Apple's
// man page states it ("may send fewer bytes than requested … the number of bytes
// successfully sent is returned via the len parameters and the error EAGAIN is
// returned"), and Go's own internal/poll records the same difference. A loop
// that counted bytes only when err == nil would lose them, and the result is not
// a slow transfer but a corrupt one: the next call would start from a stale
// offset, so the client would receive duplicate bytes inside a response whose
// length was already promised on the wire.
//
// The same platforms can also answer EAGAIN when they sent *everything* they were
// asked for, having found the socket buffer full before noticing they had run
// out of bytes. A full count with a busy error is therefore progress, not a
// retry.
//
// A *fatal* error is treated differently on purpose: the length is then not
// guaranteed to have been written at all, so its value may still be the count
// that went in. Counting it would fabricate a transfer that never happened, and
// the caller would believe a response had been delivered.
//
// The Linux splice path does not need any of this care, and it is worth saying
// why: its bytes live in a pipe between the two kernel calls, so nothing can
// leave the transfer without the pump having counted it. Here the return value
// *is* the only record of what reached the socket.
//
// wait is called when the socket is full; chunk is the platform's transfer.
func pumpChunks(base int64, n int, stall time.Duration, wait func() error, chunk chunkSender) (int, error) {
	deadline := time.Now().Add(stall)
	sent := 0
	// zeroProgress counts consecutive calls that reported no error *and* moved
	// nothing, which is how "the send buffer is full" is told apart from "the
	// file ended": a full buffer makes progress after the wait, an ended file
	// never does.
	zeroProgress := 0
	for sent < n {
		if time.Now().After(deadline) {
			return sent, ErrStalled
		}
		want := min(n-sent, maxChunk)
		k, err := chunk(base+int64(sent), want)
		// Progress is counted first, when it can be believed: a count of zero or
		// less, one larger than the call asked for, or one reported alongside a
		// fatal error is not something the kernel can be taken to have delivered,
		// and advancing the offset past bytes that never left would shorten the
		// response rather than lengthen it.
		if k > 0 && k <= want && (err == nil || busy(err) || errors.Is(err, unix.EINTR)) {
			sent += k
			zeroProgress = 0
			deadline = time.Now().Add(stall)
			continue
		}
		switch {
		case err == nil:
			if zeroProgress++; zeroProgress >= 2 {
				// A writable socket that still accepts nothing: the file ended
				// before the promised byte count.
				return sent, ErrShort
			}
			if werr := wait(); werr != nil {
				return sent, werr
			}
		case errors.Is(err, unix.EINTR):
			// Interrupted before it started; try again.
		case busy(err):
			if werr := wait(); werr != nil {
				return sent, werr
			}
		default:
			return sent, err
		}
	}
	return sent, nil
}
