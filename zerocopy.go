package samba

import (
	"errors"
	"io"
	"net"
	"os"

	"golang.org/x/sys/unix"
)

// Zero-copy READ data path.
//
// A large unsigned READ is answered without ever putting the file's bytes in
// userspace memory: the kernel moves page-cache pages into a pipe and from the
// pipe into the socket. That is the same shape the reference implementation
// used (file → pipe → socket), with two properties that matter here:
//
//   - the file is read at an *explicit* offset, so the handle's own position is
//     never disturbed. SMB reads are addressed by offset, and the same handle
//     can be read concurrently from several channels of one session, so the
//     sequential offset that sendfile(2)/splice(2)-via-io.Copy would advance is
//     unusable.
//   - waiting for the socket is done through poll(2) with a bounded timeout, so
//     a stalled peer cannot wedge connection teardown: the loop notices the
//     connection shutting down and unwinds.
//
// Everything else about the transfer (the response header, framing, credit
// accounting) is handled by the caller.

// zcPipeTarget is the maximum pipe size the server asks for. The kernel caps
// unprivileged sizing at /proc/sys/fs/pipe-max-size (1 MiB by default), so a
// 1 MiB read still fits in a single splice.
const zcPipeTarget = int(MaxReadTarget)

// errZeroCopyShort reports that the file ended before the promised byte count
// arrived. The response header has already been sent, so the caller must treat
// the connection as unusable.
var errZeroCopyShort = errors.New("samba: zero-copy read ended early")

// spliceFileToConn streams n bytes of f starting at off into tc. It reports an
// error if fewer than n bytes could be transferred.
func spliceFileToConn(tc *net.TCPConn, f *os.File, off int64, n int) error {
	if n <= 0 {
		return nil
	}
	raw, err := tc.SyscallConn()
	if err != nil {
		return err
	}
	var pipeFDs [2]int
	if err := unix.Pipe2(pipeFDs[:], unix.O_CLOEXEC|unix.O_NONBLOCK); err != nil {
		return err
	}
	pipeR, pipeW := pipeFDs[0], pipeFDs[1]
	defer unix.Close(pipeR)
	defer unix.Close(pipeW)
	// Ask for a pipe big enough to hold a whole read; ignore refusal and use
	// whatever capacity we got.
	if _, err := unix.FcntlInt(uintptr(pipeR), unix.F_SETPIPE_SZ, zcPipeTarget); err != nil {
		LogDebug("zerocopy: cannot size the pipe (%v); using the default", err)
	}

	srcFD := int(f.Fd())
	var inner error
	if cerr := raw.Control(func(sockFD uintptr) {
		inner = splicePump(int(sockFD), srcFD, pipeR, pipeW, off, n)
	}); cerr != nil {
		return cerr
	}
	return inner
}

// splicePump moves n bytes from srcFD at off through the pipe into sockFD,
// keeping both the source offset explicit and the socket non-blocking.
func splicePump(sockFD, srcFD, pipeR, pipeW int, off int64, n int) error {
	capacity := pipeCapacity(pipeR)
	written := 0 // bytes moved out of the file
	queued := 0  // bytes currently sitting in the pipe
	for written < n || queued > 0 {
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
					return io.ErrUnexpectedEOF
				}
			case errors.Is(err, unix.EINTR):
				continue
			case errors.Is(err, unix.EAGAIN):
				// The pipe is full; drain it below and come back.
			default:
				return err
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
		case err == nil:
			return errZeroCopyShort
		case errors.Is(err, unix.EINTR):
		case errors.Is(err, unix.EAGAIN):
			if err := waitWritable(sockFD); err != nil {
				return err
			}
		default:
			return err
		}
	}
	if written < n {
		return io.ErrUnexpectedEOF
	}
	return nil
}

// pipeCapacity reports the pipe's byte capacity.
func pipeCapacity(fd int) int {
	sz, err := unix.FcntlInt(uintptr(fd), unix.F_GETPIPE_SZ, 0)
	if err != nil || sz <= 0 {
		return 64 * 1024
	}
	return sz
}

// waitWritable parks until the socket accepts more data. The poll timeout is
// bounded so a stalled peer cannot delay connection teardown for long.
func waitWritable(fd int) error {
	for {
		fds := []unix.PollFd{{Fd: int32(fd), Events: unix.POLLOUT}}
		n, err := unix.Poll(fds, waitWritableTimeoutMs)
		switch {
		case err == nil && n > 0:
			return nil
		case err == nil:
			return nil // timeout: retry the splice and re-check
		case errors.Is(err, unix.EINTR):
			continue
		default:
			return err
		}
	}
}

// waitWritableTimeoutMs is the poll timeout used while draining the pipe.
const waitWritableTimeoutMs = 200
