package zerocopy

import (
	"net"
	"os"
	"time"
)

// backend is what the operator-facing capability report prints, and what the
// README support table documents.
//
// Windows has no sendfile(2). Its equivalent, TransmitFile, is not a substitute
// here: it applies the file offset rather than an explicit one, it is limited to
// 32-bit request sizes on some paths, and it cannot be bounded the way the
// splice and sendfile loops are. A read that must land at a client-chosen offset
// on a handle read concurrently from several session channels needs the
// positional path, so this platform uses the buffered copy.
const backend = "buffered"

// send copies through a bounded userspace buffer. The contract — exactly n bytes
// at an explicit offset, a stall deadline, and no disturbance of the descriptor's
// own position — is identical to the kernel paths; only the number of copies
// differs.
func send(c net.Conn, f *os.File, off int64, n int, stall time.Duration) error {
	return copyBuffered(c, f, off, n, stall)
}
