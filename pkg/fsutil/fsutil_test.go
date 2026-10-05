package fsutil

import (
	"math"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

// These tests run on every platform and are written around what each platform
// can actually do, so the differences stay documented rather than accidental:
// timestamps are compared with the coarse resolution the POSIX fallback has, and
// the file identity is required everywhere it exists.

// notWindows reports the platforms that have a descriptor-relative test that
// Windows cannot express.
func notWindows(t *testing.T) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("this assertion describes a Unix behaviour")
	}
}

func TestStatPathAndFileAgree(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "file.txt")
	if err := os.WriteFile(path, []byte("0123456789"), 0o644); err != nil {
		t.Fatal(err)
	}

	fromPath, err := StatPath(path)
	if err != nil {
		t.Fatalf("StatPath: %v", err)
	}
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	fromFile, err := StatFile(f)
	if err != nil {
		t.Fatalf("StatFile: %v", err)
	}

	if fromPath.Size != 10 || fromFile.Size != 10 {
		t.Fatalf("sizes reported as %d and %d, want 10", fromPath.Size, fromFile.Size)
	}
	if fromPath.IsDir || fromFile.IsDir {
		t.Fatal("a regular file was reported as a directory")
	}
	if fromPath.Mode.IsDir() || !strings.HasPrefix(fromPath.Mode.String(), "-rw") {
		t.Fatalf("mode %v does not describe a readable regular file", fromPath.Mode)
	}
	if fromPath.Ino == 0 || fromFile.Ino == 0 {
		t.Fatalf("file identity is missing: %d and %d", fromPath.Ino, fromFile.Ino)
	}
	if fromPath.Ino != fromFile.Ino {
		t.Fatalf("the two ways of asking disagreed: %d and %d", fromPath.Ino, fromFile.Ino)
	}
	if fromFile.Nlink == 0 {
		t.Fatal("the link count must be at least one")
	}
	// Nothing portable guarantees a creation time, but every target reports the
	// times it does have consistently.
	if fromFile.Mtime.IsZero() {
		t.Fatal("no modification time")
	}

	// The directory describes itself too.
	info, err := StatPath(dir)
	if err != nil {
		t.Fatalf("StatPath(dir): %v", err)
	}
	if !info.IsDir || !info.Mode.IsDir() {
		t.Fatalf("a directory was reported as %+v", info)
	}
}

func TestLstatDoesNotFollowTheFinalLink(t *testing.T) {
	notWindows(t)
	dir := t.TempDir()
	target := filepath.Join(dir, "target.txt")
	if err := os.WriteFile(target, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link")
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	viaLstat, err := LstatPath(link)
	if err != nil {
		t.Fatalf("LstatPath: %v", err)
	}
	if viaLstat.Mode&os.ModeSymlink == 0 {
		t.Fatalf("LstatPath followed the link: %v", viaLstat.Mode)
	}
	viaStat, err := StatPath(link)
	if err != nil {
		t.Fatalf("StatPath: %v", err)
	}
	if viaStat.Mode&os.ModeSymlink != 0 {
		t.Fatalf("StatPath did not follow the link: %v", viaStat.Mode)
	}
	if viaStat.Size != 1 {
		t.Fatalf("following the link reported size %d, want 1", viaStat.Size)
	}
}

func TestFileIDIsStableAndDistinct(t *testing.T) {
	dir := t.TempDir()
	a := filepath.Join(dir, "a")
	b := filepath.Join(dir, "b")
	for _, p := range []string{a, b} {
		if err := os.WriteFile(p, []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	fa, err := os.Open(a)
	if err != nil {
		t.Fatal(err)
	}
	defer fa.Close()
	fb, err := os.Open(b)
	if err != nil {
		t.Fatal(err)
	}
	defer fb.Close()

	da, ia, err := FileID(fa)
	if err != nil {
		t.Fatalf("FileID: %v", err)
	}
	// Asking twice gives the same answer: leases and locks key on it.
	da2, ia2, err := FileID(fa)
	if err != nil {
		t.Fatal(err)
	}
	if da != da2 || ia != ia2 {
		t.Fatalf("FileID changed between calls: (%d,%d) then (%d,%d)", da, ia, da2, ia2)
	}
	_, ib, err := FileID(fb)
	if err != nil {
		t.Fatal(err)
	}
	if ia == ib {
		t.Fatalf("two files share the identity (%d,%d)", da, ia)
	}
	// A closed descriptor cannot be identified, so a caller cannot go on to lock
	// or lease through it.
	closed, err := os.Open(a)
	if err != nil {
		t.Fatal(err)
	}
	closed.Close()
	if _, _, err := FileID(closed); err == nil {
		t.Fatal("identifying a closed descriptor must fail")
	}
}

func TestSetTimesUpdatesTheRequestedTimestamps(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "stamped")
	if err := os.WriteFile(path, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	f, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	// A second-level timestamp, because the POSIX fallback on macOS and the BSDs
	// has microsecond resolution and any filesystem may round further.
	want := time.Unix(1_000_000_000, 0).UTC()
	if err := SetTimes(f, Times{Atime: want, Mtime: want}); err != nil {
		t.Fatalf("SetTimes: %v", err)
	}
	got, err := StatFile(f)
	if err != nil {
		t.Fatal(err)
	}
	if delta := got.Mtime.Sub(want); delta > time.Second || delta < -time.Second {
		t.Fatalf("mtime = %v, want within a second of %v", got.Mtime, want)
	}

	// An omitted timestamp is left alone: SET_INFO updates one at a time, and a
	// client that sends 0 for a field must not have it reset to now.
	other := time.Unix(1_100_000_000, 0).UTC()
	if err := SetTimes(f, Times{Mtime: other, OmitAtime: true}); err != nil {
		t.Fatalf("SetTimes with an omitted access time: %v", err)
	}
	got, err = StatFile(f)
	if err != nil {
		t.Fatal(err)
	}
	if delta := got.Mtime.Sub(other); delta > time.Second || delta < -time.Second {
		t.Fatalf("mtime = %v, want within a second of %v", got.Mtime, other)
	}
	if delta := got.Atime.Sub(want); delta > time.Second || delta < -time.Second {
		t.Fatalf("the access time moved to %v, but it was omitted (want %v)", got.Atime, want)
	}

	// Asking for nothing at all is not an error and changes nothing.
	if err := SetTimes(f, Times{OmitAtime: true, OmitMtime: true}); err != nil {
		t.Fatalf("SetTimes with nothing to do: %v", err)
	}
}

func TestSizesDescribesTheFilesystem(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "space")
	if err := os.WriteFile(path, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	total, avail, free, spu, bps, err := Sizes(f, path)
	if err != nil {
		if err == ErrUnsupported {
			t.Skip("this platform has no filesystem-size call")
		}
		t.Fatalf("Sizes: %v", err)
	}
	if total == 0 {
		t.Fatal("a filesystem with no space at all")
	}
	if avail > total || free > total {
		t.Fatalf("free space exceeds total: %d available, %d free, %d total", avail, free, total)
	}
	if spu == 0 || spu > MaxSectorsPerUnit {
		t.Fatalf("sectors per allocation unit = %d", spu)
	}
	if bps == 0 {
		t.Fatal("bytes per sector = 0")
	}
	// The unit size the client multiplies out must be a plausible allocation
	// unit: a power-of-two sector count, at least one sector.
	if unit := uint64(spu) * uint64(bps); unit < 512 || unit > 64<<20 {
		t.Fatalf("allocation unit = %d bytes, which is not plausible", unit)
	}
}

func TestSizesReportsAClosedDescriptor(t *testing.T) {
	// The Unix implementations ask the descriptor, so a closed one cannot answer.
	notWindows(t)
	path := filepath.Join(t.TempDir(), "space")
	if err := os.WriteFile(path, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	f.Close()
	if _, _, _, _, _, err := Sizes(f, path); err == nil {
		t.Fatal("a closed descriptor must not report a filesystem")
	}
}

func TestDirOpenFlags(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "file")
	if err := os.WriteFile(path, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	// A directory opens with the flags.
	d, err := os.OpenFile(dir, os.O_RDONLY|DirOpenFlags, 0)
	if err != nil {
		t.Fatalf("opening a directory with DirOpenFlags: %v", err)
	}
	d.Close()
	if DirOpenFlags == 0 {
		if runtime.GOOS != "windows" && !strings.HasPrefix(runtime.GOOS, "plan9") {
			t.Fatalf("DirOpenFlags is zero on %s, which has O_DIRECTORY", runtime.GOOS)
		}
		return
	}
	// And a file does not, which is the fail-fast check the open path relies on.
	if f, err := os.OpenFile(path, os.O_RDONLY|DirOpenFlags, 0); err == nil {
		f.Close()
		t.Fatal("opening a regular file with DirOpenFlags must fail")
	}
}

func TestAdviseSequentialIsSafe(t *testing.T) {
	// A read-ahead hint is best effort on every platform, so the only contract is
	// that it never panics and never fails a caller — including on a closed
	// descriptor, where the syscall underneath cannot succeed.
	path := filepath.Join(t.TempDir(), "advise")
	if err := os.WriteFile(path, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	AdviseSequential(f)
	f.Close()
	AdviseSequential(f)
}

// TestBlockUnits pins the conversion the client's own free-space arithmetic
// depends on, including the clamps that stop a nonsense fragment size from
// becoming a nonsense unit size.
func TestBlockUnits(t *testing.T) {
	cases := []struct {
		frsize     uint64
		wantSPU    uint32
		wantSector uint32
	}{
		{0, 1, 512},   // a filesystem that would not say: one sector
		{1, 1, 512},   // smaller than a sector: rounded up
		{512, 1, 512}, // one sector
		{4096, 8, 512},
		{1 << 20, 2048, 512},
		{math.MaxUint64, MaxSectorsPerUnit, 512},
	}
	for _, c := range cases {
		spu, bps := blockUnits(c.frsize)
		if spu != c.wantSPU || bps != c.wantSector {
			t.Errorf("blockUnits(%d) = %d x %d, want %d x %d", c.frsize, spu, bps, c.wantSPU, c.wantSector)
		}
	}
}

func TestNegativeToZero(t *testing.T) {
	if got := negativeToZero(-1); got != 0 {
		t.Fatalf("negativeToZero(-1) = %d", got)
	}
	if got := negativeToZero(7); got != 7 {
		t.Fatalf("negativeToZero(7) = %d", got)
	}
}

func TestClampTimespec(t *testing.T) {
	if got := clampTimespec(1_000_000_000, 0); got.Unix() != 1_000_000_000 {
		t.Fatalf("clampTimespec = %v", got)
	}
	// An out-of-range second count becomes the zero time rather than an overflow.
	if got := clampTimespec(math.MaxInt64, 0); !got.IsZero() {
		t.Fatalf("an overflowing second count produced %v", got)
	}
	if got := clampTimespec(math.MinInt64, 0); !got.IsZero() {
		t.Fatalf("an underflowing second count produced %v", got)
	}
	// A nanosecond field outside its range is dropped, not passed on.
	if got := clampTimespec(0, int64(time.Second)); got.Nanosecond() != 0 {
		t.Fatalf("an out-of-range nanosecond field produced %v", got)
	}
	if got := clampTimespec(0, -1); got.Nanosecond() != 0 {
		t.Fatalf("a negative nanosecond field produced %v", got)
	}
}
