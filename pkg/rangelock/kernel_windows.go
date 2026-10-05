package rangelock

import (
	"errors"
	"math"
	"os"
	"sync/atomic"

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

// maxLockOffset is the largest byte offset a Windows lock can name. A range whose
// offset plus length runs past it is refused outright with
// ERROR_INVALID_LOCK_RANGE, so nothing here may be expressed with an overflowing
// length — "to the end of the file" is bounded by this rather than by the largest
// length the API could encode.
const maxLockOffset = math.MaxInt64

// mirrors records, per handle, the *exact* ranges Windows currently has locked for
// it. It exists because Windows locks are exact-match objects: a range can only be
// released with the range it was taken with, so the server has to remember what it
// took rather than derive it from the registry — the registry's view changes by
// splitting and merging, which the kernel's cannot.
//
// Guarded by registry.mu: every reader runs inside apply or release, which hold it.
var mirrors = map[uintptr][]extent{}

// degraded counts the times this process gave up on mirroring a handle's locks
// into the kernel, after which that handle's locks are enforced between SMB
// clients only. It is reported by the capability report.
var degraded atomic.Int64

// Degraded reports how many times a handle's kernel mirror had to be abandoned.
func Degraded() int64 { return degraded.Load() }

// resetKernel forgets every mirrored range (the registry is being reset).
func resetKernel() { mirrors = map[uintptr][]extent{} }

// kernelUpdate applies one logical change to the kernel's own lock table.
//
// It cannot nudge the table the way Linux can — see planMirror for what Windows
// does and does not allow — so it releases exactly the objects that are in the way
// and then takes exactly the objects the registry wants in their place.
func kernelUpdate(f *os.File, old, next []extent, want extent, kind Kind) error {
	owner := f.Fd()
	mirror := mirrors[owner]
	region, release, acquire := planMirror(mirror, next, want)

	// Release first, always: taking a range this handle already holds is refused,
	// and releasing the overlapping objects is what makes room for the shape the
	// registry wants (a split, a merge, a conversion).
	for _, e := range release {
		// Best effort. The mirror records what was taken, so a release that does
		// not match means the mirror is already stale, and the acquire below will
		// report what actually cannot be taken.
		_ = unlockRange(f, e)
	}

	var (
		taken []extent
		err   error
	)
	for _, e := range acquire {
		if err = lockRange(f, e); err != nil {
			break
		}
		// A range Windows cannot be asked to hold — past the largest offset a lock
		// can name — is kept in the registry alone, so it is not recorded as
		// mirrored.
		if expressibleForKernel(e) {
			taken = append(taken, e)
		}
	}
	if err != nil {
		// Someone outside this server holds part of the region. Put the handle's
		// locks back the way they were, so the failure is not compounded by a
		// half-changed table, and report the refusal: the registry rolls back with
		// it.
		for _, e := range taken {
			_ = unlockRange(f, e)
		}
		for _, e := range release {
			if rerr := lockRange(f, e); rerr != nil {
				// The range was taken from under us, so this handle's kernel table
				// can no longer be trusted. Dropping the mirror is the safe
				// remainder: locks are still enforced between SMB clients, which is
				// the protocol's guarantee, and this handle simply stops appearing
				// to hold anything in the kernel.
				degraded.Add(1)
				delete(mirrors, owner)
				return err
			}
		}
		mirrors[owner] = mirror
		return err
	}

	// Everything outside the region is untouched; inside it, what was released is
	// replaced by what was taken.
	kept := make([]extent, 0, len(mirror))
	for _, m := range mirror {
		if !m.overlaps(region) {
			kept = append(kept, m)
		}
	}
	mirrors[owner] = append(kept, taken...)
	return nil
}

// kernelRelease releases the kernel's records for a handle that is going away.
//
// The ranges are the registry's, which are the exact objects this handle took:
// every successful update stores what it acquired, so the two agree. A range the
// kernel no longer has is not an error (unlockRange absorbs it), which keeps a
// teardown path from failing on a mirror that was already dropped.
func kernelRelease(f *os.File, dropped []extent) {
	for _, e := range dropped {
		_ = unlockRange(f, e)
	}
	delete(mirrors, f.Fd())
}

// windowsRange converts a range into the offset and the 32-bit length halves
// LockFileEx wants.
//
// The length for a range that runs to the end of the file is bounded by the
// largest offset the API accepts rather than by "as much as possible": the kernel
// sums (offset, length), and a sum that runs past the signed maximum is refused
// with ERROR_INVALID_LOCK_RANGE. The bound is still far beyond any file a volume
// can hold, so a "to the end of the file" lock covers everything that can exist.
func windowsRange(e extent) (start int64, low, high uint32, ok bool) {
	if !expressibleForKernel(e) {
		return 0, 0, 0, false
	}
	start = int64(e.start)
	length := maxLockOffset - start
	if e.end < toEnd {
		length = int64(e.end-e.start) + 1
	}
	return start, uint32(length), uint32(uint64(length) >> 32), true
}

// lockRange takes one exact range, reporting a conflict as ErrNotGranted.
func lockRange(f *os.File, e extent) error {
	start, low, high, ok := windowsRange(e)
	if !ok {
		return nil
	}
	flags := uint32(lockfileFailImmediately)
	if e.exclusive {
		flags |= lockfileExclusiveLock
	}
	err := windows.LockFileEx(windows.Handle(f.Fd()), flags, 0, low, high, overlappedAt(start))
	// ERROR_LOCK_VIOLATION means another handle holds the range. Another handle of
	// this server's is already excluded by the registry, so this is a process
	// outside it.
	if errors.Is(err, windows.ERROR_LOCK_VIOLATION) {
		return ErrNotGranted
	}
	return err
}

// unlockRange releases one exact range. Unlocking what is not locked is absorbed:
// it happens when the mirror is already stale, which is not something a caller can
// act on.
func unlockRange(f *os.File, e extent) error {
	start, low, high, ok := windowsRange(e)
	if !ok {
		return nil
	}
	err := windows.UnlockFileEx(windows.Handle(f.Fd()), 0, low, high, overlappedAt(start))
	if errors.Is(err, windows.ERROR_NOT_LOCKED) {
		return nil
	}
	return err
}

// overlappedAt carries a range's starting offset, which is how LockFileEx and
// UnlockFileEx name where a lock begins. The handle is not associated with a
// completion port, which is the ordinary synchronous use of the API.
func overlappedAt(start int64) *windows.Overlapped {
	return &windows.Overlapped{
		Offset:     uint32(start),
		OffsetHigh: uint32(uint64(start) >> 32),
	}
}
