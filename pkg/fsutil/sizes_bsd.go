//go:build darwin || freebsd || dragonfly

package fsutil

import (
	"os"

	"golang.org/x/sys/unix"
)

// The BSD statfs structure names its counters the same way on macOS, FreeBSD and
// DragonFly — only their signedness and width differ (Bsize is uint32 on
// macOS and uint64 on FreeBSD), which the explicit conversions absorb. The
// counters are expressed in units of f_bsize on all three.
func Sizes(f *os.File, _ string) (total, avail, free uint64, sectorsPerUnit, bytesPerSector uint32, err error) {
	var st unix.Statfs_t
	if err = unix.Fstatfs(int(f.Fd()), &st); err != nil {
		return 0, 0, 0, 0, 0, err
	}
	spu, bps := blockUnits(uint64(st.Bsize))
	return uint64(st.Blocks), negativeToZero(int64(st.Bavail)), negativeToZero(int64(st.Bfree)), spu, bps, nil
}
