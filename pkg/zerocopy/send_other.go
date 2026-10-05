//go:build !unix && !windows

package zerocopy

import (
	"net"
	"os"
	"time"
)

// backend is what the operator-facing capability report prints, and what the
// README support table documents. Platforms outside the supported set have no
// file-to-socket copy path this package can reach, so the buffered copy is the
// implementation rather than a fallback.
const backend = "buffered"

// send copies through a bounded userspace buffer.
func send(c net.Conn, f *os.File, off int64, n int, stall time.Duration) error {
	return copyBuffered(c, f, off, n, stall)
}
