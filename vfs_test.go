package samba

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"

	"golang.org/x/sys/unix"
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

func TestFiletimeToTimespecSentinels(t *testing.T) {
	if got := filetimeToTimespec(0); got.Nsec != unix.UTIME_OMIT {
		t.Fatalf("0 must mean UTIME_OMIT, got %+v", got)
	}
	if got := filetimeToTimespec(^uint64(0)); got.Nsec != unix.UTIME_OMIT {
		t.Fatalf("all-ones must mean UTIME_OMIT, got %+v", got)
	}
	ts := filetimeToTimespec(116_444_736_000_000_000)
	if ts.Sec != 0 || ts.Nsec != 0 {
		t.Fatalf("epoch sentinel = %+v", ts)
	}
	ts = filetimeToTimespec(116_444_736_000_000_000 + 15_000_000)
	if ts.Sec != 1 || ts.Nsec != 500_000_000 {
		t.Fatalf("1.5s = %+v", ts)
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
