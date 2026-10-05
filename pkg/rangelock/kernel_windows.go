package rangelock

import (
	"errors"
	"os"

	"golang.org/x/sys/windows"
)

// backend is what the operator-facing capability report prints, and what the
// README support table documents.
const backend = "LockFileEx"

// The two LockFileEx flags. x/sys/windows does not name them, and they are
// fixed Win32 values (they have been the same since the first release of the
// API):
//
//	LOCKFILE_FAIL_IMMEDIATELY  fail instead of waiting for the range
//	LOCKFILE_EXCLUSIVE_LOCK    take a write lock rather than a shared one
const (
	lockfileFailImmediately = 0x00000001
	lockfileExclusiveLock   = 0x00000002
)

// kernelLock applies one range to the kernel's lock table.
//
// Win32 byte-range locks are per handle, like SMB's, so unlike the POSIX-only
// Unix targets this platform can enforce a lock against other processes on the
// host as well as against other SMB clients. The non-waiting flag keeps the call
// from blocking while the registry lock is held.
func kernelLock(f *os.File, start, length int64, kind Kind) error {
	// The Overlapped structure carries the starting offset; the low/high pair
	// carries the length. The handle is not associated with a completion port,
	// which is the ordinary synchronous use of the API.
	ol := &windows.Overlapped{
		Offset:     uint32(start),
		OffsetHigh: uint32(uint64(start) >> 32),
	}
	low, high := uint32(length), uint32(uint64(length)>>32)
	if length == 0 {
		// Win32 has no "to the end of the file" shorthand: the maximum range is
		// how a whole-file lock is expressed.
		low, high = 0xFFFF_FFFF, 0xFFFF_FFFF
	}
	h := windows.Handle(f.Fd())
	if kind == Unlock {
		err := windows.UnlockFileEx(h, 0, low, high, ol)
		// POSIX and Windows disagree about unlocking a range that is not locked:
		// POSIX succeeds, Windows reports ERROR_NOT_LOCKED. The protocol follows
		// POSIX, so the difference is absorbed here rather than surfacing as a
		// spurious failure for an SMB client.
		if errors.Is(err, windows.ERROR_NOT_LOCKED) {
			return nil
		}
		return err
	}
	flags := uint32(lockfileFailImmediately)
	if kind == Exclusive {
		flags |= lockfileExclusiveLock
	}
	err := windows.LockFileEx(h, flags, 0, low, high, ol)
	// ERROR_LOCK_VIOLATION means a process outside this server holds the range.
	// It is reported as a refusal, the same answer an SMB client gets when the
	// conflict is another client's.
	if errors.Is(err, windows.ERROR_LOCK_VIOLATION) {
		return ErrNotGranted
	}
	return err
}
