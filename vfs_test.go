package samba

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"syscall"
	"testing"

	"time"

	"github.com/malivvan/samba/pkg/fsutil"
	"github.com/malivvan/samba/pkg/rangelock"
)

func TestResolveRejectsTraversal(t *testing.T) {
	root := "/srv/data"
	if _, _, st := resolvePath(root, `..\etc\passwd`); st != StatusObjectNameInvalid {
		t.Fatalf("traversal must be rejected, got %#x", st)
	}
	if _, _, st := resolvePath(root, `a\..\..\b`); st != StatusObjectNameInvalid {
		t.Fatalf("nested traversal must be rejected, got %#x", st)
	}
	if _, _, st := resolvePath(root, "a\x00b"); st != StatusObjectNameInvalid {
		t.Fatalf("embedded NUL must be rejected, got %#x", st)
	}
	p, rel, st := resolvePath(root, `dir\sub\f.txt`)
	if st != StatusSuccess {
		t.Fatalf("resolve failed: %#x", st)
	}
	if p != "/srv/data/dir/sub/f.txt" {
		t.Fatalf("path = %q", p)
	}
	if rel != `dir\sub\f.txt` {
		t.Fatalf("rel = %q", rel)
	}
	p, rel, st = resolvePath(root, "")
	if st != StatusSuccess || p != root || rel != "" {
		t.Fatalf("root resolve = %q, %q, %#x", p, rel, st)
	}
}

func TestHandleTableGenerationSafety(t *testing.T) {
	var tbl HandleTable
	f, err := os.CreateTemp(t.TempDir(), "h")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	id := tbl.Insert(&OpenFile{File: f})
	if _, ok := tbl.Get(id); !ok {
		t.Fatal("fresh id must resolve")
	}
	if _, ok := tbl.Remove(id); !ok {
		t.Fatal("remove must succeed")
	}
	if _, ok := tbl.Get(id); ok {
		t.Fatal("a stale id must miss")
	}
	// A recycled slot must hand out a different id.
	id2 := tbl.Insert(&OpenFile{File: f})
	if id2 == id {
		t.Fatal("a recycled slot must not reuse the id")
	}
	if _, ok := tbl.Remove(id2); !ok {
		t.Fatal("second remove must succeed")
	}
}

func TestFiletimeEpoch(t *testing.T) {
	// 1970-01-01 → 116444736000000000.
	if got := filetime(0, 0); got != 116_444_736_000_000_000 {
		t.Fatalf("filetime(0,0) = %d", got)
	}
}

// TestFiletimeSentinels pins the two values SET_INFO uses for "leave this
// timestamp unchanged". They are what stop a client that sends only a
// modification time from having the access time reset, on every platform —
// pkg/fsutil expresses the omission in the way each one can.
func TestFiletimeSentinels(t *testing.T) {
	if !omitted(0) {
		t.Fatal(`a zero FILETIME must mean "leave unchanged"`)
	}
	if !omitted(^uint64(0)) {
		t.Fatal(`an all-ones FILETIME must mean "leave unchanged"`)
	}
	if omitted(1) {
		t.Fatal("a real FILETIME must not be treated as omitted")
	}
	// The epoch converts to the Unix epoch, and a fractional value keeps its
	// 100ns resolution.
	if got := filetimeToTime(116_444_736_000_000_000); !got.Equal(time.Unix(0, 0)) {
		t.Fatalf("the FILETIME epoch converted to %v", got)
	}
	if got := filetimeToTime(116_444_736_000_000_000 + 15_000_000); !got.Equal(time.Unix(1, 500_000_000)) {
		t.Fatalf("1.5s converted to %v", got)
	}
	if got := filetimeToTime(0); !got.IsZero() {
		t.Fatalf("the omitted sentinel converted to %v, want the zero time", got)
	}
}

func TestDirSnapshotPattern(t *testing.T) {
	dir := t.TempDir()
	for _, n := range []string{"a.txt", "b.txt", ".hidden"} {
		if err := os.WriteFile(filepath.Join(dir, n), []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	f, err := os.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	of := &OpenFile{File: f, Path: dir, IsDir: true}

	ents, err := dirSnapshot(of, "*")
	if err != nil {
		t.Fatal(err)
	}
	if len(ents) != 5 { // ".", "..", a.txt, b.txt, .hidden
		t.Fatalf("all-entries snapshot has %d entries: %+v", len(ents), ents)
	}
	// Dotfiles get the DOS hidden attribute.
	for _, e := range ents {
		if e.Name == ".hidden" && e.Meta.Attrs&AttrHidden == 0 {
			t.Fatal("dotfile must carry ATTR_HIDDEN")
		}
	}
	filtered, err := dirSnapshot(of, "A.TXT")
	if err != nil {
		t.Fatal(err)
	}
	if len(filtered) != 1 || filtered[0].Name != "a.txt" {
		t.Fatalf("pattern filter = %+v", filtered)
	}
}

func TestStatusFromErrno(t *testing.T) {
	cases := map[error]uint32{
		os.ErrNotExist:    StatusObjectNameNotFound,
		os.ErrPermission:  StatusAccessDenied,
		os.ErrExist:       StatusObjectNameCollision,
		syscall.EIO:       StatusIoDeviceError,
		syscall.ENOTEMPTY: StatusDirectoryNotEmpty,
	}
	for in, want := range cases {
		if got := statusFromErr(in); got != want {
			t.Errorf("statusFromErr(%v) = %#x, want %#x", in, got, want)
		}
	}
	if got := statusFromErr(nil); got != StatusSuccess {
		t.Errorf("statusFromErr(nil) = %#x", got)
	}
}

func TestMatchPattern(t *testing.T) {
	cases := []struct {
		pattern, name string
		want          bool
	}{
		// Exact, case-insensitive.
		{"a.txt", "a.txt", true},
		{"A.TXT", "a.txt", true},
		{"a.txt", "b.txt", false},
		// `*` matches any run, including empty and across the dot.
		{"*", "anything", true},
		{"*", ".hidden", true},
		{"*.txt", "a.txt", true},
		{"*.txt", "a.md", false},
		{"*.txt", ".txt", true},
		{"f1*", "f1.txt", true},
		{"f1*.txt", "f10.txt", true},
		{"f1*.txt", "f1.txt", true},
		{"f1*.txt", "f2.txt", false},
		{"f*1.txt", "f1.txt", true},
		{"f*1.txt", "f001.txt", true},
		{"*a*", "banana", true},
		{"*a*b*c*", "xaybzc", true},
		{"*z", "banana", false},
		// `?` matches exactly one character.
		{"f?.txt", "f1.txt", true},
		{"f?.txt", "f10.txt", false},
		{"???", "abc", true},
		{"???", "ab", false},
		// A trailing dot is not significant (DOS).
		{"*", "noext", true},
		{"*.", "noext", true},
		{"f*", "file.txt", true},
		// Consecutive stars behave.
		{"**", "anything", true},
		{"a**b", "ab", true},
		{"a**b", "axxxb", true},
		// Non-ASCII names match rune-wise.
		{"*.tö", "grüße.tö", true},
		{"gr??e.*", "grüße.tö", true},
	}
	for _, c := range cases {
		if got := matchPattern(c.pattern, c.name); got != c.want {
			t.Errorf("matchPattern(%q, %q) = %t, want %t", c.pattern, c.name, got, c.want)
		}
	}
}

func TestDirSnapshotWildcards(t *testing.T) {
	dir := t.TempDir()
	for _, n := range []string{"a.txt", "b.txt", "c.md", "notes", ".hidden"} {
		if err := os.WriteFile(filepath.Join(dir, n), []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	f, err := os.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	of := &OpenFile{File: f, Path: dir, IsDir: true}

	names := func(pattern string) []string {
		t.Helper()
		ents, err := dirSnapshot(of, pattern)
		if err != nil {
			t.Fatalf("snapshot(%q): %v", pattern, err)
		}
		var out []string
		for _, e := range ents {
			out = append(out, e.Name)
		}
		return out
	}
	// The unfiltered listing carries `.` and `..`.
	if got := names("*"); len(got) != 7 { // ., .., and the five files
		t.Fatalf("* = %v", got)
	}
	// A narrower pattern keeps only what matches — `.` and `..` included, which
	// is the same rule Windows applies.
	if got := names("*.txt"); len(got) != 2 || got[0] != "a.txt" || got[1] != "b.txt" {
		t.Fatalf("*.txt = %v", got)
	}
	if got := names("*.TXT"); len(got) != 2 {
		t.Fatalf("*.TXT (case-insensitive) = %v", got)
	}
	if got := names("?.md"); len(got) != 1 || got[0] != "c.md" {
		t.Fatalf("?.md = %v", got)
	}
	if got := names("a.txt"); len(got) != 1 || got[0] != "a.txt" {
		t.Fatalf("exact name = %v", got)
	}
	if got := names("n*"); len(got) != 1 || got[0] != "notes" {
		t.Fatalf("n* = %v", got)
	}
	if got := names("*hidden"); len(got) != 1 || got[0] != ".hidden" {
		t.Fatalf("*hidden = %v", got)
	}
	if got := names("nope*"); len(got) != 0 {
		t.Fatalf("no match = %v", got)
	}
}

func TestHandleTableCloseAll(t *testing.T) {
	dir := t.TempDir()
	var tbl HandleTable
	var files []*os.File
	for i := range 3 {
		f, err := os.CreateTemp(dir, "h")
		if err != nil {
			t.Fatal(err)
		}
		files = append(files, f)
		tbl.Insert(&OpenFile{File: f})
		if i == 1 {
			// Leave a permanently holey slot to exercise that branch.
			id := tbl.Insert(&OpenFile{File: f})
			tbl.Remove(id)
		}
	}
	if tbl.Len() != 3 {
		t.Fatalf("Len = %d, want 3", tbl.Len())
	}
	tbl.CloseAll()
	if tbl.Len() != 0 {
		t.Fatalf("Len = %d after CloseAll", tbl.Len())
	}
	for i, f := range files {
		if _, err := f.ReadAt(make([]byte, 1), 0); !errors.Is(err, fs.ErrClosed) {
			t.Fatalf("handle %d was not closed: %v", i, err)
		}
	}
	// CloseAll is idempotent.
	tbl.CloseAll()
}

func TestVfsFileOperations(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "f")

	// Opening a missing file fails with an errno.
	if _, err := openRaw(path, os.O_RDONLY, 0); err == nil {
		t.Fatal("opening a missing file must fail")
	}
	if _, err := statMeta(filepath.Join(dir, "missing")); err == nil {
		t.Fatal("statMeta on a missing path must fail")
	}

	f, err := openRaw(path, os.O_CREATE|os.O_RDWR, 0o644)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	// pwriteAll writes everything, even past a short-write boundary.
	data := make([]byte, 8192)
	for i := range data {
		data[i] = byte(i)
	}
	if err := pwriteAll(f, data, 0); err != nil {
		t.Fatalf("pwriteAll: %v", err)
	}
	// pread reads it back.
	got := make([]byte, len(data))
	n, err := pread(f, got, 0)
	if err != nil || n != len(data) {
		t.Fatalf("pread returned %d, %v", n, err)
	}
	if string(got) != string(data) {
		t.Fatal("pread returned different bytes")
	}
	// A read past EOF is a short read, not an error.
	if n, err := pread(f, make([]byte, 16), int64(len(data))+100); err != nil || n != 0 {
		t.Fatalf("pread past EOF = %d, %v", n, err)
	}
	// fstatMeta reports the size, and fsutil.Sizes reports a filesystem.
	m, err := fstatMeta(f)
	if err != nil {
		t.Fatal(err)
	}
	if m.Size != uint64(len(data)) || m.IsDir {
		t.Fatalf("meta = %+v", m)
	}
	total, avail, free, spu, bps, err := fsutil.Sizes(f, path)
	if err != nil {
		t.Fatalf("Sizes: %v", err)
	}
	if total == 0 || spu == 0 || bps != 512 || avail > total || free < avail {
		t.Fatalf("Sizes = %d/%d/%d/%d/%d", total, avail, free, spu, bps)
	}
	// fsync and AdviseSequential are best-effort.
	if err := f.Sync(); err != nil {
		t.Fatalf("sync: %v", err)
	}
	fsutil.AdviseSequential(f)
	// ftruncate shortens it.
	if err := f.Truncate(16); err != nil {
		t.Fatalf("truncate: %v", err)
	}
	if m, err := fstatMeta(f); err != nil || m.Size != 16 {
		t.Fatalf("size after truncate = %d (%v)", m.Size, err)
	}
	// A write on a read-only description fails.
	ro, err := openRaw(path, os.O_RDONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer ro.Close()
	if err := pwriteAll(ro, []byte("x"), 0); err == nil {
		t.Fatal("writing through a read-only descriptor must fail")
	}
}

func TestVfsRangeLock(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "locked")
	if err := os.WriteFile(path, make([]byte, 4096), 0o644); err != nil {
		t.Fatal(err)
	}
	// Exclusive (write) locks need writable descriptors, as POSIX requires.
	a, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	b, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()

	// A read-only descriptor can take a shared lock but not an exclusive one.
	ro, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer ro.Close()
	// The write-access rule is enforced from the handle's own record, not left to
	// the kernel: Windows would allow an exclusive lock through a read-only
	// handle, so passing writeAccess false here is what keeps the answer the same
	// on every platform.
	if err := rangelock.Lock(ro, 2000, 10, rangelock.Shared, false); err != nil {
		t.Fatalf("shared lock on a read-only descriptor: %v", err)
	}
	if err := rangelock.Lock(ro, 2000, 10, rangelock.Exclusive, false); !errors.Is(err, rangelock.ErrNoWriteAccess) {
		t.Fatalf("an exclusive lock on a read-only descriptor = %v, want ErrNoWriteAccess", err)
	}
	if err := rangelock.Lock(ro, 2000, 10, rangelock.Unlock, false); err != nil {
		t.Fatalf("unlock on a read-only descriptor: %v", err)
	}

	if err := rangelock.Lock(a, 0, 100, rangelock.Shared, true); err != nil {
		t.Fatalf("shared lock: %v", err)
	}
	if err := rangelock.Lock(b, 0, 100, rangelock.Shared, true); err != nil {
		t.Fatalf("second shared lock: %v", err)
	}
	if err := rangelock.Lock(a, 0, 100, rangelock.Exclusive, true); !errors.Is(err, rangelock.ErrNotGranted) {
		t.Fatalf("a conflicting exclusive lock = %v, want ErrNotGranted", err)
	}
	if err := rangelock.Lock(a, 0, 100, rangelock.Unlock, true); err != nil {
		t.Fatalf("unlock: %v", err)
	}
	if err := rangelock.Lock(b, 0, 100, rangelock.Unlock, true); err != nil {
		t.Fatalf("second unlock: %v", err)
	}
	if err := rangelock.Lock(a, 0, 100, rangelock.Exclusive, true); err != nil {
		t.Fatalf("exclusive lock after unlock: %v", err)
	}
	// A zero length means "to the end of the file".
	if err := rangelock.Lock(a, 0, 0, rangelock.Unlock, true); err != nil {
		t.Fatalf("whole-file unlock: %v", err)
	}
	// Locking an absurd range is clamped rather than overflowing.
	if err := rangelock.Lock(a, ^uint64(0), ^uint64(0), rangelock.Unlock, true); err != nil {
		t.Fatalf("clamped range: %v", err)
	}
	// Dropping every reference hands the ranges back.
	rangelock.Release(a)
	rangelock.Release(b)
	rangelock.Release(ro)
}

func TestVfsDirSnapshotErrors(t *testing.T) {
	dir := t.TempDir()
	f, err := os.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	// A handle whose path is gone cannot be snapshotted.
	of := &OpenFile{File: f, Path: filepath.Join(dir, "vanished"), IsDir: true}
	if _, err := dirSnapshot(of, "*"); err == nil {
		t.Fatal("snapshotting a missing directory must fail")
	}
	// A handle whose descriptor is closed cannot be stat'ed either.
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := dirSnapshot(of, "*"); err == nil {
		t.Fatal("snapshotting a closed handle must fail")
	}
}

func TestFiletimeBounds(t *testing.T) {
	// Times before the Windows epoch clamp to zero.
	if got := filetime(-epochDeltaSecs-1, 0); got != 0 {
		t.Fatalf("filetime before the epoch = %d", got)
	}
	// Sub-second precision is preserved at 100ns resolution.
	if got := filetime(0, 123_456_789); got != 116_444_736_000_000_000+1_234_567 {
		t.Fatalf("filetime(0, 123456789) = %d", got)
	}
	if got := filetime(-epochDeltaSecs, 0); got != 0 {
		t.Fatalf("filetime at the epoch = %d", got)
	}
}
