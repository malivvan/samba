// Package fsutil is the portable filesystem-primitive layer for samba.
//
// Every call here has a native implementation on the platforms samba targets
// (Linux, macOS, the BSDs and Windows) and a documented, *honest* degradation
// where the platform has nothing equivalent. The rule the rest of the server
// relies on is: a call either does what it says on this platform, or it is a
// no-op / returns an error — it never silently invents a result that would
// make the server misbehave.
//
// The primitives are:
//
//   - Stat / Lstat / Fstat: file metadata, including the device and inode that
//     identify a file for leases and byte-range locks.
//   - FSSizes: the size of the filesystem backing an open file, as reported to
//     the client through FileFsSizeInformation.
//   - SetTimes / SetTimesValues: update a file's timestamps through its open
//     descriptor, with per-timestamp "leave unchanged" (the SMB behaviour when
//     a client sends 0 or all-ones).
//   - AdviseSequential: a read-ahead hint, best effort and ignorable.
//   - DirOpenFlags: the extra open(2) flags that make a descriptor a directory
//     descriptor where the platform has such a concept.
//
// Backend names the mechanism actually in use, for the operator-facing
// capability report and the README support table.
package fsutil

import (
	"errors"
	"math"
	"os"
	"time"
)

// ErrUnsupported reports a primitive the running platform cannot provide
// without cgo. Callers translate it into STATUS_NOT_SUPPORTED (or into a
// cautious fallback) rather than reporting an invented result.
var ErrUnsupported = errors.New("fsutil: not supported on this platform")

// Info is the portable subset of a file's metadata the SMB layer needs.
//
// Fields a platform cannot supply are filled with a documented stand-in rather
// than a zero: Times fall back to the modification time, Blocks to the size
// rounded up to 512-byte units, and Nlink to 1. Dev and Ino are zero only when
// the platform has no file identity at all, which is why lease and lock code
// treats a zero identity as "cannot key on this".
type Info struct {
	// Size is the file's size in bytes.
	Size int64
	// Mode is the file's mode and type bits.
	Mode os.FileMode
	// IsDir reports a directory.
	IsDir bool
	// Dev and Ino identify the file: the pair is stable for the file's lifetime
	// and unique within a share.
	Dev uint64
	Ino uint64
	// Nlink is the hard-link count.
	Nlink uint32
	// Blocks is the storage allocated, in 512-byte units (what `du` reports).
	Blocks int64
	// Atime, Mtime and Ctime are the access, modification and status-change
	// times. A platform that has no separate creation time reports Mtime.
	Atime time.Time
	Mtime time.Time
	Ctime time.Time
}

// Times is a pair of file timestamps where each may be absent, mirroring the
// SMB SET_INFO convention: a zero or all-ones FILETIME means "leave this one
// unchanged".
type Times struct {
	Atime time.Time
	Mtime time.Time
	// OmitAtime / OmitMtime mark a timestamp the caller does not want changed.
	OmitAtime bool
	OmitMtime bool
}

// MaxSectorsPerUnit bounds the sectors-per-allocation-unit value reported to
// the client. The field is 32 bits on the wire and a unit smaller than a
// sector would be meaningless, so anything outside 1..MaxSectorsPerUnit is
// clamped rather than passed through.
const MaxSectorsPerUnit = 1 << 20

// sectorSize is the byte size of a sector as reported in
// FileFsSizeInformation. Every target platform uses 512-byte sectors; the field
// exists so the value is stated once.
const sectorSize = 512

// blockUnits converts a filesystem fragment/block size into (sectors per
// allocation unit, bytes per sector). A filesystem may report a fragment size
// smaller than a sector (some report 0), which would make the client compute a
// nonsense free-space figure, so the result is clamped into range.
func blockUnits(frsize uint64) (sectorsPerUnit, bytesPerSector uint32) {
	if frsize < sectorSize {
		frsize = sectorSize
	}
	spu := frsize / sectorSize
	if spu > MaxSectorsPerUnit {
		spu = MaxSectorsPerUnit
	}
	return uint32(spu), sectorSize
}

// negativeToZero maps a signed filesystem counter onto the unsigned value the
// protocol uses, treating a negative count as empty rather than as an enormous
// positive one.
func negativeToZero(v int64) uint64 {
	if v < 0 {
		return 0
	}
	return uint64(v)
}

// clampTimespec returns a time from a Timespec-shaped pair, saturating the
// second count so a bogus on-disk value cannot overflow time.Unix.
func clampTimespec(sec, nsec int64) time.Time {
	if sec > math.MaxInt64/2 || sec < math.MinInt64/2 {
		return time.Time{}
	}
	if nsec < 0 || nsec >= int64(time.Second) {
		nsec = 0
	}
	return time.Unix(sec, nsec)
}
