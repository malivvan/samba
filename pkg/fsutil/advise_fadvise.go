//go:build linux || freebsd || netbsd

package fsutil

import (
	"os"

	"golang.org/x/sys/unix"
)

// AdviseSequential asks the kernel to read this file ahead aggressively. For a
// file server streaming large files that keeps the page cache warm ahead of the
// copy to the socket, so reads from cold storage are not latency-bound.
//
// The hint is best effort by construction — the kernel may ignore it, and it
// changes no result the client can observe — so failures are deliberately not
// reported.
func AdviseSequential(f *os.File) {
	_ = unix.Fadvise(int(f.Fd()), 0, 0, unix.FADV_SEQUENTIAL)
}
