//go:build openbsd

package fsutil

import (
	"os"

	"golang.org/x/sys/unix"
)

// OpenBSD's struct statfs uses the newer f_-prefixed field names, and its
// f_bavail is signed.
func Sizes(f *os.File, _ string) (total, avail, free uint64, sectorsPerUnit, bytesPerSector uint32, err error) {
	var st unix.Statfs_t
	if err = unix.Fstatfs(int(f.Fd()), &st); err != nil {
		return 0, 0, 0, 0, 0, err
	}
	spu, bps := blockUnits(uint64(st.F_bsize))
	return st.F_blocks, negativeToZero(st.F_bavail), st.F_bfree, spu, bps, nil
}
