//go:build linux

package rangelock

import (
	"os"

	"golang.org/x/sys/unix"
)

// backend is what the operator-facing capability report prints, and what the
// README support table documents.
const backend = "OFD"

// kernelUpdate applies one logical change to the kernel's own lock table.
//
// Linux does not need the before/after sets: F_OFD_SETLK takes or releases exactly
// the range it is given and the kernel splits, merges and converts around it, so
// the operation is passed straight through. The parameters exist because a
// platform whose locks are exact-match objects (Windows) does need them — see
// planMirror.
func kernelUpdate(f *os.File, old, next []extent, want extent, kind Kind) error {
	start, length, ok := kernelRange(want)
	if !ok {
		// Beyond the largest offset a kernel lock can name. The registry is
		// authoritative for the protocol, so the range is simply not mirrored into
		// the kernel's table.
		return nil
	}
	err := kernelLock(f, start, length, kind)
	// A conflict is reported to the caller as one error, whichever table noticed
	// it: the kernel says "resource temporarily unavailable" or "permission
	// denied" for a range another process holds, and the registry says
	// ErrNotGranted for one another handle of this server holds. They mean the
	// same thing to a client.
	if isConflict(err) {
		return ErrNotGranted
	}
	return err
}

// kernelRelease releases the kernel's records for a handle that is going away.
// Each range is released with exactly the operation it was taken with, which is
// what the kernel expects on this platform too.
func kernelRelease(f *os.File, dropped []extent) {
	for _, e := range dropped {
		start, length, ok := kernelRange(e)
		if ok {
			_ = kernelLock(f, start, length, Unlock)
		}
	}
}

// resetKernel forgets every kernel record. Nothing is held outside the registry
// here, so there is nothing to forget.
func resetKernel() {}

// Degraded reports how many times this process gave up on mirroring a handle's
// locks into the kernel. It is always zero on this platform: the kernel performs
// the whole operation itself.
func Degraded() int64 { return 0 }

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
