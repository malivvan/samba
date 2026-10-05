package fsutil

import (
	"os"

	"golang.org/x/sys/windows"
)

// Windows sets file timestamps by handle and expresses "leave this one
// unchanged" as a null pointer in the field, which maps exactly onto the SMB
// convention for an omitted timestamp: no read-modify-write is needed. The
// change time has no Windows equivalent and is left alone.
func SetTimes(f *os.File, t Times) error {
	h := windows.Handle(f.Fd())
	var atime, mtime *windows.Filetime
	if !t.OmitAtime {
		ft := windows.NsecToFiletime(t.Atime.UnixNano())
		atime = &ft
	}
	if !t.OmitMtime {
		ft := windows.NsecToFiletime(t.Mtime.UnixNano())
		mtime = &ft
	}
	if atime == nil && mtime == nil {
		return nil
	}
	return windows.SetFileTime(h, nil, atime, mtime)
}
