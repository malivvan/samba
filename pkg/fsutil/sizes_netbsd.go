//go:build netbsd

package fsutil

import (
	"os"

	"golang.org/x/sys/unix"
)

// NetBSD is the one Unix target with no usable statfs in x/sys/unix: its
// Statfs_t is a zero-length placeholder, because Go's NetBSD port reaches the
// old statfs(2) through libc. The modern statvfs(2) is available though, and it
// carries everything needed — a fragment size and the block counters.
func Sizes(f *os.File, _ string) (total, avail, free uint64, sectorsPerUnit, bytesPerSector uint32, err error) {
	var st unix.Statvfs_t
	if err = unix.Fstatvfs(int(f.Fd()), &st); err != nil {
		return 0, 0, 0, 0, 0, err
	}
	// The counters are explicitly widened: NetBSD's Statvfs_t uses 32-bit fields
	// on its 32-bit targets and 64-bit ones on its 64-bit targets.
	frsize := uint64(st.Frsize)
	if frsize == 0 {
		frsize = uint64(st.Bsize)
	}
	spu, bps := blockUnits(frsize)
	return uint64(st.Blocks), uint64(st.Bavail), uint64(st.Bfree), spu, bps, nil
}
