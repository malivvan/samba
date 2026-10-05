//go:build darwin || freebsd || openbsd || netbsd || dragonfly

package fsutil

import (
	"os"

	"golang.org/x/sys/unix"
)

// The BSDs and macOS have no descriptor-relative utimensat carrying Linux's
// "operate on the descriptor itself" flag (AT_EMPTY_PATH), so the timestamps go
// through futimes(2), which is addressable only by descriptor and therefore
// still works on a file that has been unlinked since it was opened.
//
// Two consequences, both deliberate and both recorded in the README support
// table:
//
//   - Resolution is microseconds rather than nanoseconds. A client asking for a
//     nanosecond-precision timestamp gets it rounded; SMB clients round their
//     own timestamps to the nearest millisecond or worse in practice.
//   - futimes(2) always sets both timestamps, so an omitted one is filled in
//     from the value the file already has. That is a read-modify-write, racy in
//     principle against a concurrent writer on the same file; the window is one
//     syscall wide, and only a timestamp the client asked not to change is
//     affected.
func SetTimes(f *os.File, t Times) error {
	if t.OmitAtime && t.OmitMtime {
		return nil
	}
	if t.OmitAtime || t.OmitMtime {
		var st unix.Stat_t
		if err := unix.Fstat(int(f.Fd()), &st); err != nil {
			return err
		}
		if t.OmitAtime {
			t.Atime = clampTimespec(int64(st.Atim.Sec), int64(st.Atim.Nsec))
		}
		if t.OmitMtime {
			t.Mtime = clampTimespec(int64(st.Mtim.Sec), int64(st.Mtim.Nsec))
		}
	}
	tv := []unix.Timeval{
		unix.NsecToTimeval(t.Atime.UnixNano()),
		unix.NsecToTimeval(t.Mtime.UnixNano()),
	}
	return unix.Futimes(int(f.Fd()), tv)
}
