//go:build linux

package fsutil

import (
	"os"
	"time"

	"golang.org/x/sys/unix"
)

// Linux updates the timestamps through the open descriptor itself: utimensat
// with AT_EMPTY_PATH applies to the file the descriptor refers to, which is the
// only way to time a file that has been unlinked since it was opened, and it is
// nanosecond-accurate. UTIME_OMIT is the kernel's own "leave this one alone",
// so an omitted timestamp never touches the file.
func SetTimes(f *os.File, t Times) error {
	ts := [2]unix.Timespec{
		timespecFromTime(t.Atime, t.OmitAtime),
		timespecFromTime(t.Mtime, t.OmitMtime),
	}
	if t.OmitAtime && t.OmitMtime {
		return nil
	}
	if err := unix.UtimesNanoAt(int(f.Fd()), "", ts[:], unix.AT_EMPTY_PATH); err != nil {
		return err
	}
	return nil
}

func timespecFromTime(tm time.Time, omit bool) unix.Timespec {
	if omit {
		return unix.Timespec{Nsec: unix.UTIME_OMIT}
	}
	return unix.NsecToTimespec(tm.UnixNano())
}
