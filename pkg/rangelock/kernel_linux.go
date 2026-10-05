//go:build linux

package rangelock

import (
	"os"

	"golang.org/x/sys/unix"
)

// backend is what the operator-facing capability report prints, and what the
// README support table documents.
const backend = "OFD"

// kernelLock applies one range to the kernel's lock table.
//
// Linux is the one Unix target with open-file-description locks, which is
// exactly the semantics SMB needs: the lock belongs to the open file
// description, so two handles of one file conflict, and the lock is visible to
// every other process on the host. The non-waiting variant is used so the call
// can never block while the registry lock is held; a conflict comes back as
// EAGAIN/EACCES and is reported to the client as LOCK_NOT_GRANTED.
func kernelLock(f *os.File, start, length int64, kind Kind) error {
	fl := unix.Flock_t{Whence: 0 /* SEEK_SET */, Start: start, Len: length}
	switch kind {
	case Shared:
		fl.Type = unix.F_RDLCK
	case Exclusive:
		fl.Type = unix.F_WRLCK
	default:
		fl.Type = unix.F_UNLCK
	}
	return unix.FcntlFlock(f.Fd(), unix.F_OFD_SETLK, &fl)
}
