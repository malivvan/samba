//go:build linux

package fsutil

import (
	"os"

	"golang.org/x/sys/unix"
)

// Linux reports filesystem sizes through fstatfs, in units of the filesystem's
// fragment size (f_frsize). Reporting the fragment size as the allocation unit
// and 512 as the sector size is what makes the client's own free-space
// arithmetic come out right.
func Sizes(f *os.File, _ string) (total, avail, free uint64, sectorsPerUnit, bytesPerSector uint32, err error) {
	var st unix.Statfs_t
	if err = unix.Fstatfs(int(f.Fd()), &st); err != nil {
		return 0, 0, 0, 0, 0, err
	}
	frsize := uint64(st.Frsize)
	if frsize == 0 {
		frsize = uint64(st.Bsize)
	}
	spu, bps := blockUnits(frsize)
	return st.Blocks, st.Bavail, st.Bfree, spu, bps, nil
}
