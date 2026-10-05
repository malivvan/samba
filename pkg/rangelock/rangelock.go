// Package rangelock provides SMB-compatible byte-range locking.
//
// # Why there is more than one lock table
//
// SMB locking is per *open*, not per process: two handles of one file do not
// conflict with themselves, and a range locked through one handle is refused to
// another, even when both handles belong to the same server process. The kernel
// mechanisms differ in whether they can express that:
//
//   - Linux has open-file-description locks (F_OFD_SETLK). A lock belongs to the
//     open file description, so two handles of the same file genuinely conflict,
//     and the lock is also visible to every *other* process on the host.
//   - Windows has LockFileEx, which is per handle and likewise visible to other
//     processes on the host.
//   - macOS and the BSDs have only classic POSIX record locks (F_SETLK), where
//     locks belong to the *process*: two handles of one file never conflict,
//     and closing any descriptor of a file releases every lock the process
//     holds on it. That is the opposite of what SMB needs.
//
// So the authority for SMB semantics is an in-process registry, used on every
// platform: it is what makes a second handle's conflicting request fail, and
// what makes a handle's locks disappear when that handle closes. Where the
// kernel offers per-handle locks, one is taken as well, so a lock is also
// enforced against other processes on the host. Where it does not, no kernel
// lock is taken: a *process*-scoped lock would be actively wrong (it would
// release a sibling handle's lock on close), and unreliable protection that
// silently disappears is worse than none.
//
// # What that means for a deployment
//
// A lock is always enforced between SMB clients, on every platform. On Linux
// and Windows a lock is additionally enforced against local processes on the
// server touching the same files; on macOS and the BSDs it is not. That is the
// same caveat as Samba's "kernel oplocks" note, and it is the reason the README
// advises against mixing local and network access to one share.
//
// # Bounds
//
// The registry is heap the server owns, and the ranges in it are entirely
// client-controlled, so two limits apply: per handle and server-wide. A client
// that exceeds either is refused with ErrTooMany (STATUS_INSUFFICIENT_RESOURCES)
// rather than being allowed to grow the table without limit.
package rangelock

import (
	"errors"
	"math"
	"os"
	"sort"
	"sync"

	"github.com/malivvan/samba/pkg/fsutil"
)

// Kind selects the byte-range lock mode.
type Kind int

const (
	// Shared is a shared (read) lock: several handles may hold it at once.
	Shared Kind = iota
	// Exclusive is an exclusive (write) lock.
	Exclusive
	// Unlock releases a range.
	Unlock
)

// Errors the caller maps onto protocol statuses.
var (
	// ErrNotGranted reports a range another handle already holds.
	ErrNotGranted = errors.New("rangelock: the range is locked by another handle")
	// ErrTooMany reports that the registry's bounds were reached.
	ErrTooMany = errors.New("rangelock: too many locked ranges")
	// ErrNoWriteAccess reports an exclusive lock requested through a handle that
	// was not opened for writing.
	ErrNoWriteAccess = errors.New("rangelock: an exclusive lock requires a handle opened for writing")
)

// Backend names the kernel locking mechanism this platform contributes on top
// of the registry, for the operator-facing capability report and the README
// support table. It is one of "OFD" (Linux, per-handle and cross-process),
// "LockFileEx" (Windows, per-handle and cross-process) or "in-process" (the
// registry alone, so SMB clients only).
func Backend() string { return backend }

// Bounds on the registry.
//
// A LOCK request may carry up to 64 ranges, and a client may repeat it, so
// without these a peer could grow the server's lock table — and the kernel's,
// where one is used — until it ran out of memory. A real client locks the
// regions it is actively reading or writing and releases them; four thousand
// ranges on one handle is far past anything a genuine workload produces.
const (
	// MaxRangesPerHandle bounds the distinct ranges one handle may hold.
	MaxRangesPerHandle = 4096
	// MaxRangesTotal bounds the ranges held across every handle.
	MaxRangesTotal = 65536
)

// toEnd is the inclusive end of a range that runs to the end of the file, which
// is the protocol's reading of a zero length and the only way to say "and
// everything after".
const toEnd = ^uint64(0)

// extent is one locked byte range, inclusive of both ends and expressed in the
// wire's own 64-bit space.
//
// Using the unsigned wire values directly — rather than clamping them into the
// signed range a kernel offset can hold — is what keeps the arithmetic exact for
// every value a client can send: there is no offset that has to be reinterpreted,
// and no length that silently becomes zero.
type extent struct {
	start, end uint64
	exclusive  bool
}

// overlaps reports whether two ranges share at least one byte.
func (r extent) overlaps(o extent) bool { return r.start <= o.end && o.start <= r.end }

// extends reports whether r ends after o ends.
func (r extent) extends(o extent) bool { return r.end > o.end }

// kernelRange converts a range into the (offset, length) pair the kernel wants.
//
// A length of zero means "to the end of the file" to the kernel, which is how a
// range that reaches the top of the address space is passed. The second return
// value reports whether the range can be expressed at all: a start beyond the
// largest signed offset the kernel can be given cannot be, and that range is then
// kept in the registry alone.
func kernelRange(r extent) (start int64, length int64, ok bool) {
	if r.start > math.MaxInt64 {
		return 0, 0, false
	}
	if r.end >= toEnd {
		return int64(r.start), 0, true
	}
	return int64(r.start), int64(r.end-r.start) + 1, true
}

// fileKey identifies a file the way the filesystem does. Locks are per file, so
// two handles that reach the same inode through different names or shares must
// land on the same key.
type fileKey struct {
	dev, ino uint64
}

// normalizeRange turns a wire (offset, length) pair into a range. A zero length
// means "to the end of the file", and a length that would run past the top of the
// address space simply stops there — the one saturation the 64-bit space makes
// unavoidable, and the same thing the kernel does.
func normalizeRange(off, length uint64) extent {
	if length == 0 {
		return extent{start: off, end: toEnd}
	}
	end := off + length - 1 // inclusive
	if end < off {          // the addition wrapped: the range reaches the end
		end = toEnd
	}
	return extent{start: off, end: end}
}

// registry is the process-wide table of locks held by this server's handles.
type registry struct {
	mu sync.Mutex
	// files maps a file to the ranges held on it, per owning handle.
	files map[fileKey]map[uintptr][]extent
	// owners maps a handle back to the files it appears in, so releasing a
	// handle on close costs its own lock count rather than a scan of every file.
	owners map[uintptr]map[fileKey]struct{}
	// extents is the total number of ranges held, kept incrementally so the
	// server-wide bound can be checked without walking the table.
	extents int
}

var global = &registry{
	files:  make(map[fileKey]map[uintptr][]extent),
	owners: make(map[uintptr]map[fileKey]struct{}),
}

// apply records a change to the registry under the registry lock, running
// kernel inside that same critical section.
//
// Holding the lock across the kernel call is deliberate: the registry and the
// kernel's view must agree, and doing so is safe because every kernel lock here
// is taken with the non-waiting variant, so the call cannot block. The change is
// only recorded once the kernel has agreed to it, which is what stops a failed
// kernel lock from leaving a phantom range behind.
func (r *registry) apply(key fileKey, owner uintptr, want extent, unlock bool, kernel func() error) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	mine := r.files[key][owner]
	var next []extent
	if unlock {
		next = subtract(mine, want)
	} else {
		if err := r.conflicts(key, owner, want); err != nil {
			return err
		}
		// Re-locking a range the same handle already holds replaces whatever it
		// held there, which is what both POSIX and Windows do: a lock request
		// that overlaps an existing lock of the same owner overwrites it.
		next = coalesce(append(subtract(mine, want), want))
	}
	if len(next) > MaxRangesPerHandle || r.extents-len(mine)+len(next) > MaxRangesTotal {
		return ErrTooMany
	}
	if err := kernel(); err != nil {
		return err
	}
	r.commit(key, owner, next)
	return nil
}

// conflicts reports whether want overlaps a range held by a *different* handle
// in a way that cannot coexist: two shared locks coexist, anything involving an
// exclusive lock does not.
func (r *registry) conflicts(key fileKey, owner uintptr, want extent) error {
	for other, exts := range r.files[key] {
		if other == owner {
			continue
		}
		for _, e := range exts {
			if e.overlaps(want) && (e.exclusive || want.exclusive) {
				return ErrNotGranted
			}
		}
	}
	return nil
}

// commit installs next as the owner's ranges on key, keeping the counters and
// the reverse index in step and dropping empty buckets.
func (r *registry) commit(key fileKey, owner uintptr, next []extent) {
	before := len(r.files[key][owner])
	r.extents += len(next) - before
	if len(next) == 0 {
		if byOwner := r.files[key]; byOwner != nil {
			delete(byOwner, owner)
			if len(byOwner) == 0 {
				delete(r.files, key)
			}
		}
		if keys := r.owners[owner]; keys != nil {
			delete(keys, key)
			if len(keys) == 0 {
				delete(r.owners, owner)
			}
		}
		return
	}
	if r.files[key] == nil {
		r.files[key] = make(map[uintptr][]extent)
	}
	r.files[key][owner] = next
	if r.owners[owner] == nil {
		r.owners[owner] = make(map[fileKey]struct{})
	}
	r.owners[owner][key] = struct{}{}
}

// release drops every range held by a handle, calling kernel for each so the
// platform can release its own record of it. It is called when an SMB handle
// closes, because that is when the protocol says its locks are released.
//
// The kernel half matters even though the descriptor is about to close: an
// open-file-description lock (Linux) or a LockFileEx lock (Windows) is held by
// the *open file description*, not by this process, so it survives until the
// close actually happens — and a caller may release the locks of a handle it
// keeps open. Doing it explicitly also makes the behaviour identical on the
// platforms where the registry is the only table and nothing else would release
// anything.
func (r *registry) release(owner uintptr, kernel func(extent)) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for key := range r.owners[owner] {
		byOwner := r.files[key]
		for _, e := range byOwner[owner] {
			kernel(e)
		}
		r.extents -= len(byOwner[owner])
		delete(byOwner, owner)
		if len(byOwner) == 0 {
			delete(r.files, key)
		}
	}
	delete(r.owners, owner)
}

// subtract removes one range from an owner's ranges, splitting or truncating the
// ranges it cuts through. Partial unlocks are part of the protocol: a client that
// locks a whole file and then unlocks the middle of it still holds the two ends.
func subtract(exts []extent, cut extent) []extent {
	out := exts[:0]
	for _, e := range exts {
		if !e.overlaps(cut) {
			out = append(out, e)
			continue
		}
		if e.start < cut.start {
			out = append(out, extent{start: e.start, end: cut.start - 1, exclusive: e.exclusive})
		}
		if e.extends(cut) {
			out = append(out, extent{start: cut.end + 1, end: e.end, exclusive: e.exclusive})
		}
	}
	return out
}

// coalesce sorts ranges and merges the ones that touch, so that a client
// locking a file byte by byte does not fill the table with adjacent entries.
func coalesce(exts []extent) []extent {
	if len(exts) < 2 {
		return exts
	}
	sort.Slice(exts, func(i, j int) bool {
		if exts[i].start != exts[j].start {
			return exts[i].start < exts[j].start
		}
		return exts[i].end < exts[j].end
	})
	out := exts[:1]
	for _, e := range exts[1:] {
		last := &out[len(out)-1]
		// Only same-mode ranges merge: an exclusive range that overlaps a shared
		// one is a separate fact about the file. Touching ranges merge too — a
		// range's extent is just the set of bytes it covers.
		if e.exclusive == last.exclusive && (last.end == toEnd || e.start <= last.end+1) {
			if e.extends(*last) {
				last.end = e.end
			}
			continue
		}
		out = append(out, e)
	}
	return out
}

// Lock applies a byte-range lock to f.
//
// writeAccess reports whether the caller opened f for writing. An exclusive lock
// requires it on every platform: POSIX enforces that in the kernel, Windows does
// not, so requiring it here keeps one client's LOCK meaning the same thing
// whichever host serves it.
//
// The errors are ErrNotGranted for a range another handle holds, ErrTooMany at
// the registry's bounds, and the kernel's own error where a kernel lock was
// involved (EBADF for a closed descriptor, for instance).
func Lock(f *os.File, off, length uint64, kind Kind, writeAccess bool) error {
	if kind == Exclusive && !writeAccess {
		return ErrNoWriteAccess
	}
	dev, ino, err := fsutil.FileID(f)
	if err != nil {
		return err
	}
	key := fileKey{dev: dev, ino: ino}
	owner := f.Fd()
	want := normalizeRange(off, length)
	want.exclusive = kind == Exclusive
	unlock := kind == Unlock
	return global.apply(key, owner, want, unlock, func() error {
		start, kernelLen, ok := kernelRange(want)
		if !ok {
			// Beyond the largest offset a kernel lock can name. The registry is
			// authoritative for the protocol, so the range is simply not mirrored
			// into the kernel's table.
			return nil
		}
		err := kernelLock(f, start, kernelLen, kind)
		// A conflict is reported to the caller as one error, whichever table
		// noticed it: the kernel says "resource temporarily unavailable" or
		// "permission denied" for a range another process holds, and the registry
		// says ErrNotGranted for one another handle of this server holds. They
		// mean the same thing to a client. Which errno to look for is the
		// platform's business (see isConflict).
		if isConflict(err) {
			return ErrNotGranted
		}
		return err
	})
}

// Release drops every lock held through f and the kernel's own records of them.
// The caller invokes it when the handle closes; a handle's locks do not outlive
// it. A kernel release that fails is ignored: the descriptor is usually about to
// close, which releases whatever is left, and a lock that could not be released
// would be reported by the operation that tried, not by a teardown path.
func Release(f *os.File) {
	if f == nil {
		return
	}
	global.release(f.Fd(), func(e extent) {
		start, length, ok := kernelRange(e)
		if ok {
			_ = kernelLock(f, start, length, Unlock)
		}
	})
}

// ReleaseAll drops every lock the server holds. It exists for tests and for a
// last-resort reset; normal operation releases per handle.
func ReleaseAll() {
	global.mu.Lock()
	defer global.mu.Unlock()
	global.files = make(map[fileKey]map[uintptr][]extent)
	global.owners = make(map[uintptr]map[fileKey]struct{})
	global.extents = 0
}

// Count reports how many ranges the registry holds. Exposed for tests and for
// the operator-facing statistics.
func Count() int {
	global.mu.Lock()
	defer global.mu.Unlock()
	return global.extents
}
