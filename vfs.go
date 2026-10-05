package samba

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/malivvan/samba/pkg/fsutil"
	"github.com/malivvan/samba/pkg/rangelock"
)

// Filesystem layer: path resolution, open-handle table, metadata mapping.
//
// Handles wrap *os.File so the Go runtime owns descriptor lifetime, and all
// reads/writes use the positional ReadAt/WriteAt APIs, which are safe for
// concurrent use — the equivalent of the original's per-request `dup`+`pread`.

// DOS file attributes.
const (
	AttrReadonly  uint32 = 0x01
	AttrHidden    uint32 = 0x02
	AttrDirectory uint32 = 0x10
	AttrArchive   uint32 = 0x20
)

const epochDeltaSecs int64 = 11_644_473_600

// filetime converts a Unix timestamp to a Windows FILETIME (100ns ticks since
// 1601-01-01).
func filetime(sec, nsec int64) uint64 {
	if sec < -epochDeltaSecs {
		return 0
	}
	return uint64(sec+epochDeltaSecs)*10_000_000 + uint64(nsec)/100
}

// filetimeNow returns the current time as a Windows FILETIME.
func filetimeNow() uint64 {
	now := time.Now()
	return filetime(now.Unix(), int64(now.Nanosecond()))
}

// timeToFiletime converts a Go time to a Windows FILETIME.
func timeToFiletime(t time.Time) uint64 { return filetime(t.Unix(), int64(t.Nanosecond())) }

// Meta is the SMB-visible metadata of a file.
type Meta struct {
	Size   uint64
	Alloc  uint64
	Attrs  uint32
	Crtime uint64
	Atime  uint64
	Mtime  uint64
	Ctime  uint64
	Ino    uint64
	Nlink  uint32
	IsDir  bool
}

// metaFromInfo converts the portable file metadata into the SMB view of it.
//
// The kernel's own view is used rather than os.FileInfo's, because SMB exposes
// more than os.FileInfo carries: the allocated size, the link count and the
// access and change times. pkg/fsutil is where the platforms' differences are
// absorbed; by the time it gets here the values are already portable.
func metaFromInfo(info fsutil.Info) Meta {
	var attrs uint32
	if info.IsDir {
		attrs |= AttrDirectory
	}
	if info.Mode.Perm()&0o200 == 0 {
		attrs |= AttrReadonly
	}
	if attrs == 0 {
		attrs = AttrArchive
	}
	m := Meta{
		IsDir: info.IsDir,
		Attrs: attrs,
		Size:  uint64(info.Size),
		Ino:   info.Ino,
		Nlink: info.Nlink,
	}
	if info.Blocks > 0 {
		m.Alloc = uint64(info.Blocks) * 512
	} else if info.Size > 0 {
		m.Alloc = (uint64(info.Size) + 511) &^ 511
	}
	m.Mtime = timeToFiletime(info.Mtime)
	m.Atime = timeToFiletime(info.Atime)
	m.Ctime = timeToFiletime(info.Ctime)
	// No portable birth time; mtime is a sane stand-in for creation.
	m.Crtime = m.Mtime
	return m
}

// finalizeAttrs gives dotfiles the DOS hidden attribute, samba-style.
func finalizeAttrs(attrs uint32, leaf string) uint32 {
	if strings.HasPrefix(leaf, ".") && leaf != "." && leaf != ".." {
		return attrs | AttrHidden
	}
	return attrs
}

// statMeta stats path without following the final symlink's target semantics of
// the caller: it follows symlinks, like a normal open would.
func statMeta(path string) (Meta, error) {
	info, err := fsutil.StatPath(path)
	if err != nil {
		return Meta{}, err
	}
	return metaFromInfo(info), nil
}

// fstatMeta stats an open handle.
func fstatMeta(f *os.File) (Meta, error) {
	info, err := fsutil.StatFile(f)
	if err != nil {
		return Meta{}, err
	}
	return metaFromInfo(info), nil
}

// resolvePath maps a share-relative SMB name (backslash separators) to a host
// path. It rejects `..` traversal and embedded NULs, and returns the path plus
// the normalized relative name.
func resolvePath(root, smbName string) (string, string, uint32) {
	var parts []string
	var rel strings.Builder
	for _, comp := range strings.FieldsFunc(smbName, func(r rune) bool { return r == '\\' || r == '/' }) {
		switch comp {
		case "", ".":
			continue
		case "..":
			return "", "", StatusObjectNameInvalid
		}
		if strings.ContainsRune(comp, 0) {
			return "", "", StatusObjectNameInvalid
		}
		parts = append(parts, comp)
		if rel.Len() > 0 {
			rel.WriteByte('\\')
		}
		rel.WriteString(comp)
	}
	return filepath.Join(append([]string{root}, parts...)...), rel.String(), StatusSuccess
}

// openRaw opens path with an integer flag mask, so a caller can OR in
// fsutil.DirOpenFlags (the platform's "must be a directory" flag) on the
// platforms that have one.
func openRaw(path string, flags int, perm os.FileMode) (*os.File, error) {
	return os.OpenFile(path, flags, perm)
}

// pread reads from off, treating a short read at EOF as success (n < len(buf)
// with no error), matching the positional-read helper the protocol was written
// against.
func pread(f *os.File, buf []byte, off int64) (int, error) {
	n, err := f.ReadAt(buf, off)
	if err == io.EOF {
		err = nil
	}
	return n, err
}

// pwriteAll writes all of buf at off, looping over short writes.
func pwriteAll(f *os.File, buf []byte, off int64) error {
	for len(buf) > 0 {
		n, err := f.WriteAt(buf, off)
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrShortWrite
		}
		buf = buf[n:]
		off += int64(n)
	}
	return nil
}

// errnoOf extracts the Unix errno carried by err, defaulting to EIO.
func errnoOf(err error) syscall.Errno {
	if err == nil {
		return 0
	}
	var errno syscall.Errno
	if errors.As(err, &errno) {
		return errno
	}
	switch {
	case errors.Is(err, os.ErrNotExist):
		return syscall.ENOENT
	case errors.Is(err, os.ErrPermission):
		return syscall.EACCES
	case errors.Is(err, os.ErrExist):
		return syscall.EEXIST
	default:
		return syscall.EIO
	}
}

// Byte-range locks live in pkg/rangelock, which keeps the per-handle
// bookkeeping SMB needs and adds the kernel's own lock where the platform has a
// per-handle kind (Linux OFD, Windows LockFileEx). vfs.go does not wrap it: the
// LOCK handler calls it directly, because it is the caller that knows whether
// the handle was opened for writing — which is what an exclusive lock requires.

// DirEnt is one directory entry in a snapshot.
type DirEnt struct {
	Name string
	Meta Meta
}

// DirState is the resumable enumeration state of an open directory handle.
type DirState struct {
	Entries []DirEnt
	Pos     int
	Pattern string
}

// OpenFile is one open SMB handle.
type OpenFile struct {
	File *os.File
	Path string
	// Rel is the share-relative name with backslash separators ("" = share root).
	Rel           string
	Leaf          string
	ShareIdx      uint32
	IsDir         bool
	Writable      bool
	DeleteOnClose bool
	Dir           *DirState
	// HasLease records whether this handle holds a granted lease, and
	// LeaseIno is the inode it was granted on (for releasing it on CLOSE).
	HasLease bool
	LeaseIno uint64
	// LeaseKey is the client's lease key from this open's RqLs context, if any.
	// Recorded even when not granted, so a WRITE on this handle can exempt the
	// client's own lease from the break.
	LeaseKey *[16]byte
	// LeaseGranted is the lease state granted on this handle (0 = none). When it
	// includes handle-caching the lease persists past CLOSE.
	LeaseGranted uint32
	// refs counts operations using File without the session lock; dead is set
	// by close; closeOnce guarantees the descriptor is closed exactly once.
	refs      atomic.Int32
	dead      atomic.Bool
	closeOnce sync.Once
}

// use marks the handle as in use for an operation that runs without the session
// lock (a READ), and returns its file — or nil when the handle is already
// closed. The caller must call release when it is done.
//
// It exists because reads deliberately run with the session lock released, so
// that channels of one session can read in parallel; a CLOSE on another channel
// must therefore not pull the descriptor out from under them. use is called
// with the session lock held (the same lock close takes), so the reference
// count cannot race with a close.
func (o *OpenFile) use() *os.File {
	o.refs.Add(1)
	if o.dead.Load() {
		o.release()
		return nil
	}
	return o.File
}

// release drops a reference taken by use, closing the descriptor if that was
// the last one and the handle has been closed. An unmatched release (more
// releases than uses) is tolerated: the count is treated as "nothing
// outstanding" rather than being allowed to go negative, which would otherwise
// mean the descriptor never gets closed.
func (o *OpenFile) release() {
	if n := o.refs.Add(-1); n <= 0 && o.dead.Load() {
		o.closeFile()
	}
}

// close marks the handle closed and releases the descriptor once no in-flight
// reference is using it.
func (o *OpenFile) close() {
	o.dead.Store(true)
	if o.refs.Load() <= 0 {
		o.closeFile()
	}
}

// closeFile closes the descriptor exactly once. The File field is never cleared,
// so a reader that already copied the pointer keeps a usable (or cleanly
// closed) *os.File rather than a torn value.
func (o *OpenFile) closeFile() {
	if o.File != nil {
		o.closeOnce.Do(func() {
			// Locks do not outlive the handle that took them. On Linux and
			// Windows the kernel would release them with the descriptor, but on
			// the platforms where the process-wide registry is the only lock
			// table nothing would, so it is done explicitly everywhere.
			rangelock.Release(o.File)
			o.File.Close()
		})
	}
}

// dirSnapshot reads the full directory listing as a snapshot, including `.` and
// `..`, applying a case-insensitive single-name pattern filter when given.
func dirSnapshot(of *OpenFile, pattern string) ([]DirEnt, error) {
	selfMeta, err := fstatMeta(of.File)
	if err != nil {
		return nil, err
	}
	out := []DirEnt{
		{Name: ".", Meta: selfMeta},
		{Name: "..", Meta: selfMeta},
	}
	ents, err := os.ReadDir(of.Path)
	if err != nil {
		return nil, err
	}
	for _, ent := range ents {
		name := ent.Name()
		info, err := fsutil.LstatPath(filepath.Join(of.Path, name))
		if err != nil {
			continue
		}
		meta := metaFromInfo(info)
		meta.Attrs = finalizeAttrs(meta.Attrs, name)
		out = append(out, DirEnt{Name: name, Meta: meta})
	}
	if pattern != "" && pattern != "*" {
		filtered := out[:0]
		for _, e := range out {
			if matchPattern(pattern, e.Name) {
				filtered = append(filtered, e)
			}
		}
		out = filtered
	}
	return out, nil
}

const htIdxBits = 32

// HandleTable is a slab of open files. Ids are (generation << 32) | index and
// are never reused across a close, so a stale FileId from the client misses
// cleanly instead of aliasing a new handle.
type HandleTable struct {
	slots []*OpenFile
	gens  []uint32
	free  []int
}

// Insert stores of and returns its FileId.
func (t *HandleTable) Insert(of *OpenFile) uint64 {
	var idx int
	if n := len(t.free); n > 0 {
		idx = t.free[n-1]
		t.free = t.free[:n-1]
		t.slots[idx] = of
	} else {
		t.slots = append(t.slots, of)
		t.gens = append(t.gens, 1)
		idx = len(t.slots) - 1
	}
	return uint64(t.gens[idx])<<htIdxBits | uint64(idx)
}

func (t *HandleTable) slot(id uint64) (int, bool) {
	idx := int(id & 0xFFFF_FFFF)
	gen := uint32(id >> htIdxBits)
	if idx < 0 || idx >= len(t.slots) || t.gens[idx] != gen || t.slots[idx] == nil {
		return 0, false
	}
	return idx, true
}

// Len reports how many handles are open in the table.
func (t *HandleTable) Len() int { return len(t.slots) - len(t.free) }

// Get returns the open file for id.
func (t *HandleTable) Get(id uint64) (*OpenFile, bool) {
	idx, ok := t.slot(id)
	if !ok {
		return nil, false
	}
	return t.slots[idx], true
}

// Remove detaches and returns the open file for id.
func (t *HandleTable) Remove(id uint64) (*OpenFile, bool) {
	idx, ok := t.slot(id)
	if !ok {
		return nil, false
	}
	of := t.slots[idx]
	t.slots[idx] = nil
	t.gens[idx]++
	if t.gens[idx] == 0 {
		t.gens[idx] = 1
	}
	t.free = append(t.free, idx)
	return of, true
}

// CloseAll closes and drops every open handle (session teardown). The table is
// reset rather than merely emptied, so Len reports zero afterwards and every id
// handed out before the reset misses cleanly.
func (t *HandleTable) CloseAll() {
	for _, of := range t.slots {
		if of != nil {
			of.close()
		}
	}
	t.slots = nil
	t.gens = nil
	t.free = nil
}
