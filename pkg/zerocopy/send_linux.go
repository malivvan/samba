//go:build linux

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
const backend = "splice"

// pipeTarget is the pipe size the splice path asks for. The kernel caps
// unprivileged sizing at /proc/sys/fs/pipe-max-size (1 MiB by default), so a
// read of the server's advertised maximum (smb2.go's MaxReadTarget, also 1 MiB)
// still fits in a single splice; a refusal is ignored and whatever capacity the
// pipe has is used.
const pipeTarget = 1 << 20

// send moves n bytes from f at off into c through a pipe, with the kernel doing
// both copies: file → pipe with splice(2), pipe → socket with splice(2).
//
// The pipe is what makes the offset explicit. sendfile(2) would be simpler, but
// it cannot take a bounded timeout, and the pipe gives the loop a place to stop
// between two kernel transfers, which is how a stalled peer is noticed.
func send(c net.Conn, f *os.File, off int64, n int, stall time.Duration) error {
	sc, ok := c.(syscall.Conn)
	if !ok {
		// No raw descriptor to hand to the kernel: copy through userspace.
		fallbacks.Add(1)
		return copyBuffered(c, f, off, n, stall)
	}
	raw, err := sc.SyscallConn()
	if err != nil {
		fallbacks.Add(1)
		return copyBuffered(c, f, off, n, stall)
	}
	var pipeFDs [2]int
	if err := unix.Pipe2(pipeFDs[:], unix.O_CLOEXEC|unix.O_NONBLOCK); err != nil {
		fallbacks.Add(1)
		return copyBuffered(c, f, off, n, stall)
	}
	pipeR, pipeW := pipeFDs[0], pipeFDs[1]
	defer unix.Close(pipeR)
	defer unix.Close(pipeW)
	// Ask for a pipe big enough to hold a whole read. A refusal is not worth a
	// fallback: the transfer still works, it just takes more splices.
	_, _ = unix.FcntlInt(uintptr(pipeR), unix.F_SETPIPE_SZ, pipeTarget)

	srcFD := int(f.Fd())
	var (
		sent  int
		inner error
	)
	if cerr := raw.Control(func(sockFD uintptr) {
		sent, inner = splicePump(int(sockFD), srcFD, pipeR, pipeW, off, n, stall)
	}); cerr != nil {
		return cerr
	}
	// Nothing reached the wire and the kernel says it cannot do this: fall back
	// to the buffered copy rather than failing a read on a host that simply
	// filters the syscall. Once a single byte is on the wire the response stream
	// has a length on it, so there is no longer a safe way back.
	if inner != nil && sent == 0 && unsupported(inner) {
		fallbacks.Add(1)
		return copyBuffered(c, f, off, n, stall)
	}
	return inner
}

// splicePump moves n bytes from srcFD at off through the pipe into sockFD,
// keeping the source offset explicit and the socket non-blocking. The stall
// deadline is extended by every byte that moves, so only a peer that stops
// making progress altogether is given up on.
//
// It returns how many bytes reached the socket, which is what decides whether a
// failure can still be recovered from by a userspace copy.
func splicePump(sockFD, srcFD, pipeR, pipeW int, off int64, n int, stall time.Duration) (int, error) {
	deadline := time.Now().Add(stall)
	capacity := pipeCapacity(pipeR)
	written := 0 // bytes moved out of the file
	queued := 0  // bytes currently sitting in the pipe
	sent := 0    // bytes handed to the socket
	for written < n || queued > 0 {
		if time.Now().After(deadline) {
			return sent, ErrStalled
		}
		// Top the pipe up while there is room and data left.
		if written < n && queued < capacity {
			want := min(n-written, capacity-queued)
			readOff := off + int64(written)
			k, err := unix.Splice(srcFD, &readOff, pipeW, nil, want, unix.SPLICE_F_MOVE)
			switch {
			case err == nil && k > 0:
				written += int(k)
				queued += int(k)
				continue
			case err == nil: // k == 0: the file ended
				if queued == 0 {
					return sent, ErrShort
				}
			case errors.Is(err, unix.EINTR):
				continue
			case errors.Is(err, unix.EAGAIN):
				// The pipe is full; drain it below and come back.
			default:
				return sent, err
			}
		}
		if queued == 0 {
			break
		}
		// Drain the pipe into the socket, waiting for writability as needed.
		k, err := unix.Splice(pipeR, nil, sockFD, nil, queued, unix.SPLICE_F_MOVE)
		switch {
		case err == nil && k > 0:
			queued -= int(k)
			sent += int(k)
			deadline = time.Now().Add(stall)
		case err == nil:
			return sent, ErrShort
		case errors.Is(err, unix.EINTR):
		case errors.Is(err, unix.EAGAIN):
			if err := waitWritable(sockFD); err != nil {
				return sent, err
			}
		default:
			return sent, err
		}
	}
	if written < n {
		return sent, ErrShort
	}
	return sent, nil
}

// pipeCapacity reports the pipe's byte capacity, falling back to the default
// Linux pipe size when the kernel will not say.
func pipeCapacity(fd int) int {
	sz, err := unix.FcntlInt(uintptr(fd), unix.F_GETPIPE_SZ, 0)
	if err != nil || sz <= 0 {
		return 64 * 1024
	}
	return sz
}
