package rangelock

import (
	"errors"
	"math"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

// These tests run on every platform. The contract they check is the protocol's,
// not the kernel's, which is why they do not care which mechanism is underneath:
// two handles of one file conflict, one handle's overlapping request replaces its
// own, a partial unlock splits a range, and a handle's locks end with it.

// scratch creates a file and returns it opened twice, so that the two descriptors
// are what the registry keys on.
func scratch(t *testing.T) (path string, a, b *os.File) {
	t.Helper()
	ReleaseAll()
	t.Cleanup(ReleaseAll)
	path = filepath.Join(t.TempDir(), "file.bin")
	if err := os.WriteFile(path, make([]byte, 4096), 0o644); err != nil {
		t.Fatal(err)
	}
	var err error
	if a, err = os.OpenFile(path, os.O_RDWR, 0); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { a.Close() })
	if b, err = os.OpenFile(path, os.O_RDWR, 0); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { b.Close() })
	return path, a, b
}

func TestSharedLocksCoexistAndExclusiveConflicts(t *testing.T) {
	_, a, b := scratch(t)
	if err := Lock(a, 0, 100, Shared, true); err != nil {
		t.Fatalf("first shared lock: %v", err)
	}
	if err := Lock(b, 0, 100, Shared, true); err != nil {
		t.Fatalf("a second shared lock on the same range must be granted: %v", err)
	}
	if err := Lock(b, 50, 10, Exclusive, true); !errors.Is(err, ErrNotGranted) {
		t.Fatalf("an exclusive lock over shared locks = %v, want ErrNotGranted", err)
	}

	// A handle may convert its own range once nothing else holds it.
	if err := Lock(b, 0, 100, Unlock, true); err != nil {
		t.Fatalf("unlock: %v", err)
	}
	if err := Lock(a, 50, 10, Exclusive, true); err != nil {
		t.Fatalf("a handle must be able to convert its own lock: %v", err)
	}
	// The converted part is exclusive to everyone else; the parts a did not
	// convert stay shared, so b may still hold those.
	if err := Lock(b, 50, 10, Shared, true); !errors.Is(err, ErrNotGranted) {
		t.Fatalf("a shared lock over an exclusive one = %v, want ErrNotGranted", err)
	}
	if err := Lock(b, 0, 40, Shared, true); err != nil {
		t.Fatalf("the unconverted part of a's range must still be shared: %v", err)
	}
	if err := Lock(b, 0, 40, Exclusive, true); !errors.Is(err, ErrNotGranted) {
		t.Fatalf("a shared lock still blocks an exclusive one: %v", err)
	}
	// Downgrading a's exclusive range back to shared lets b in.
	if err := Lock(a, 50, 10, Shared, true); err != nil {
		t.Fatalf("downgrade: %v", err)
	}
	if err := Lock(b, 50, 10, Shared, true); err != nil {
		t.Fatalf("after the downgrade b must be able to share: %v", err)
	}
}

func TestUnlockingSplitsARange(t *testing.T) {
	_, a, b := scratch(t)
	if err := Lock(a, 0, 100, Exclusive, true); err != nil {
		t.Fatal(err)
	}
	// Punch a hole in the middle: the two ends must still be held.
	if err := Lock(a, 40, 20, Unlock, true); err != nil {
		t.Fatalf("partial unlock: %v", err)
	}
	if err := Lock(b, 40, 20, Exclusive, true); err != nil {
		t.Fatalf("the unlocked middle must be free: %v", err)
	}
	// The two ends are still a's, so b cannot take them.
	for _, r := range [][2]uint64{{0, 39}, {60, 40}} {
		if err := Lock(b, r[0], r[1], Exclusive, true); !errors.Is(err, ErrNotGranted) {
			t.Fatalf("range %d+%d = %v, want it still locked", r[0], r[1], err)
		}
	}
	if err := Lock(a, 0, 0, Unlock, true); err != nil {
		t.Fatalf("whole-file unlock: %v", err)
	}
	if err := Lock(b, 0, 0, Exclusive, true); err != nil {
		t.Fatalf("after a whole-file unlock the range must be free: %v", err)
	}
}

func TestZeroLengthMeansToEndOfFile(t *testing.T) {
	_, a, b := scratch(t)
	if err := Lock(a, 4000, 0, Exclusive, true); err != nil {
		t.Fatal(err)
	}
	// Anything from 4000 up to the end of the file conflicts.
	if err := Lock(b, 1<<40, 1, Exclusive, true); !errors.Is(err, ErrNotGranted) {
		t.Fatalf("a lock to the end of the file must cover it: %v", err)
	}
	// Anything below does not.
	if err := Lock(b, 1, 1, Exclusive, true); err != nil {
		t.Fatalf("a range below the locked suffix must be free: %v", err)
	}
}

// TestTopOfTheAddressSpace checks the one place the wire's 64-bit offsets cannot
// be handed to the kernel unchanged: a range starting beyond the largest signed
// offset. The registry keeps it exactly (it is the protocol's authority) and the
// kernel is simply not asked.
func TestTopOfTheAddressSpace(t *testing.T) {
	_, a, b := scratch(t)
	if err := Lock(a, ^uint64(0), ^uint64(0), Exclusive, true); err != nil {
		t.Fatalf("lock at the top of the address space: %v", err)
	}
	if err := Lock(b, ^uint64(0), 1, Exclusive, true); !errors.Is(err, ErrNotGranted) {
		t.Fatalf("the last byte of the address space = %v, want ErrNotGranted", err)
	}
	if err := Lock(a, ^uint64(0), 1, Unlock, true); err != nil {
		t.Fatalf("unlock at the top of the address space: %v", err)
	}
	if err := Lock(b, ^uint64(0), 1, Exclusive, true); err != nil {
		t.Fatalf("after the unlock the last byte must be free: %v", err)
	}
	if got := Count(); got != 1 {
		t.Fatalf("registry holds %d ranges, want 1", got)
	}
}

func TestExclusiveRequiresAWriteHandle(t *testing.T) {
	path, _, _ := scratch(t)
	ro, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer ro.Close()
	if err := Lock(ro, 0, 10, Shared, false); err != nil {
		t.Fatalf("a shared lock through a read-only handle: %v", err)
	}
	if err := Lock(ro, 0, 10, Exclusive, false); !errors.Is(err, ErrNoWriteAccess) {
		t.Fatalf("an exclusive lock through a read-only handle = %v, want ErrNoWriteAccess", err)
	}
	// A write handle keeps it as an error, but a different one. The rule is
	// enforced from the caller's own record so that a platform whose kernel would
	// allow it (Windows) answers the same way.
	if err := Lock(ro, 0, 10, Shared, true); err != nil {
		t.Fatalf("the same range shared through a write handle: %v", err)
	}
}

func TestReleaseDropsEveryLockOfAHandle(t *testing.T) {
	_, a, b := scratch(t)
	if err := Lock(a, 0, 10, Exclusive, true); err != nil {
		t.Fatal(err)
	}
	if err := Lock(a, 100, 10, Exclusive, true); err != nil {
		t.Fatal(err)
	}
	if Count() != 2 {
		t.Fatalf("registry holds %d ranges, want 2", Count())
	}
	if err := Lock(b, 0, 10, Exclusive, true); !errors.Is(err, ErrNotGranted) {
		t.Fatal("the range must be held")
	}
	Release(a)
	if got := Count(); got != 0 {
		t.Fatalf("after Release the registry holds %d ranges", got)
	}
	if err := Lock(b, 0, 10, Exclusive, true); err != nil {
		t.Fatalf("the range must be free once the holder is gone: %v", err)
	}
}

// TestReleaseIsIdempotentAndHandlesAnUnknownHandle checks that a teardown path
// can call Release without tracking whether it ever took a lock.
func TestReleaseIsIdempotentAndHandlesAnUnknownHandle(t *testing.T) {
	_, a, _ := scratch(t)
	Release(a)
	Release(a)
	Release(nil)
}

func TestRangesAreBoundedPerHandle(t *testing.T) {
	_, a, _ := scratch(t)
	// Non-adjacent ranges, so coalescing cannot shrink the table.
	for i := range MaxRangesPerHandle {
		off := uint64(i) * 2
		if err := Lock(a, off, 1, Exclusive, true); err != nil {
			t.Fatalf("range %d of %d: %v", i, MaxRangesPerHandle, err)
		}
	}
	if got := Count(); got != MaxRangesPerHandle {
		t.Fatalf("registry holds %d ranges, want %d", got, MaxRangesPerHandle)
	}
	if err := Lock(a, uint64(MaxRangesPerHandle)*2, 1, Exclusive, true); !errors.Is(err, ErrTooMany) {
		t.Fatalf("one range past the bound = %v, want ErrTooMany", err)
	}
	// Unlocking frees room again, so a client that releases as it goes is never
	// refused.
	if err := Lock(a, 0, 1, Unlock, true); err != nil {
		t.Fatal(err)
	}
	if err := Lock(a, uint64(MaxRangesPerHandle)*2, 1, Exclusive, true); err != nil {
		t.Fatalf("after an unlock the bound must have room: %v", err)
	}
}

// TestAdjacentRangesCoalesce keeps the table small for a client that locks a file
// one byte at a time, which is what makes the bound above generous rather than
// tight.
func TestAdjacentRangesCoalesce(t *testing.T) {
	_, a, _ := scratch(t)
	for i := range 64 {
		if err := Lock(a, uint64(i), 1, Exclusive, true); err != nil {
			t.Fatal(err)
		}
	}
	if got := Count(); got != 1 {
		t.Fatalf("64 adjacent byte locks became %d ranges, want 1", got)
	}
}

func TestLockOnAClosedDescriptorFails(t *testing.T) {
	path, _, _ := scratch(t)
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	f.Close()
	if err := Lock(f, 0, 1, Shared, true); err == nil {
		t.Fatal("locking a closed descriptor must fail")
	}
}

// TestNormalizeRange pins the arithmetic that turns a wire pair into a range,
// including the saturations at the top of the address space.
func TestNormalizeRange(t *testing.T) {
	cases := []struct {
		off, length uint64
		want        extent
	}{
		{0, 1, extent{start: 0, end: 0}},
		{10, 5, extent{start: 10, end: 14}},
		{0, 0, extent{start: 0, end: toEnd}},
		{100, 0, extent{start: 100, end: toEnd}},
		{math.MaxInt64, 1, extent{start: math.MaxInt64, end: math.MaxInt64}},
		{^uint64(0), 1, extent{start: toEnd, end: toEnd}},
		{^uint64(0), ^uint64(0), extent{start: toEnd, end: toEnd}},
		{toEnd - 1, 10, extent{start: toEnd - 1, end: toEnd}},
	}
	for _, c := range cases {
		if got := normalizeRange(c.off, c.length); got != c.want {
			t.Errorf("normalizeRange(%d, %d) = %+v, want %+v", c.off, c.length, got, c.want)
		}
	}
}

// TestKernelRange pins the conversion to what the kernel's signed offsets and
// zero-means-to-the-end length can express.
func TestKernelRange(t *testing.T) {
	cases := []struct {
		in     extent
		start  int64
		length int64
		ok     bool
	}{
		{extent{start: 0, end: 0}, 0, 1, true},
		{extent{start: 10, end: 14}, 10, 5, true},
		{extent{start: 100, end: toEnd}, 100, 0, true},
		{extent{start: math.MaxInt64, end: math.MaxInt64}, math.MaxInt64, 1, true},
		// Beyond the signed range: not expressible, and reported rather than
		// silently reinterpreted.
		{extent{start: toEnd, end: toEnd}, 0, 0, false},
		{extent{start: uint64(math.MaxInt64) + 1, end: toEnd}, 0, 0, false},
	}
	for _, c := range cases {
		start, length, ok := kernelRange(c.in)
		if ok != c.ok {
			t.Errorf("kernelRange(%+v) expressible = %v, want %v", c.in, ok, c.ok)
			continue
		}
		if ok && (start != c.start || length != c.length) {
			t.Errorf("kernelRange(%+v) = %d+%d, want %d+%d", c.in, start, length, c.start, c.length)
		}
	}
}

func TestSubtractAndCoalesce(t *testing.T) {
	base := []extent{{start: 0, end: 100, exclusive: true}}
	split := subtract(base, extent{start: 40, end: 60})
	if len(split) != 2 || split[0] != (extent{start: 0, end: 39, exclusive: true}) ||
		split[1] != (extent{start: 61, end: 100, exclusive: true}) {
		t.Fatalf("subtract(0..100, 40..60) = %+v", split)
	}
	if got := subtract(base, extent{start: 200, end: 300}); len(got) != 1 {
		t.Fatalf("subtracting a disjoint range changed the set: %+v", got)
	}
	if got := subtract(base, extent{start: 0, end: toEnd}); len(got) != 0 {
		t.Fatalf("subtracting everything left %+v", got)
	}
	// Subtracting a range that reaches the top of the address space must not
	// overflow the split.
	if got := subtract([]extent{{start: 5, end: toEnd}}, extent{start: 9, end: toEnd}); len(got) != 1 ||
		got[0] != (extent{start: 5, end: 8}) {
		t.Fatalf("truncating at the top = %+v", got)
	}

	// Coalescing merges touching same-mode ranges and nothing else.
	merged := coalesce([]extent{
		{start: 11, end: 20, exclusive: true},
		{start: 0, end: 10, exclusive: true},
		{start: 30, end: 40, exclusive: false},
		{start: 21, end: 25, exclusive: true},
	})
	want := []extent{
		{start: 0, end: 25, exclusive: true},
		{start: 30, end: 40, exclusive: false},
	}
	if len(merged) != len(want) {
		t.Fatalf("coalesce = %+v", merged)
	}
	for i := range want {
		if merged[i] != want[i] {
			t.Fatalf("coalesce[%d] = %+v, want %+v", i, merged[i], want[i])
		}
	}
}

// TestConcurrentLocking exists for the race detector: the registry is shared by
// every connection and every worker.
func TestConcurrentLocking(t *testing.T) {
	_, a, b := scratch(t)
	done := make(chan struct{})
	for w := 0; w < 4; w++ {
		go func(w int) {
			defer func() { done <- struct{}{} }()
			f := a
			if w%2 == 1 {
				f = b
			}
			for i := range 200 {
				off := uint64(i % 16)
				kind := Shared
				if i%3 == 0 {
					kind = Exclusive
				}
				_ = Lock(f, off, 4, kind, true)
				if i%5 == 0 {
					_ = Lock(f, off, 4, Unlock, true)
				}
			}
		}(w)
	}
	for range 4 {
		<-done
	}
	ReleaseAll()
	if Count() != 0 {
		t.Fatalf("registry holds %d ranges after a reset", Count())
	}
}

// TestBackendsMatchThePlatform pins the mechanism each platform is documented to
// provide, so the README table cannot drift from the code.
func TestBackendsMatchThePlatform(t *testing.T) {
	switch runtime.GOOS {
	case "linux":
		if Backend() != "OFD" {
			t.Fatalf("Linux Backend() = %q, want the open-file-description locks", Backend())
		}
	case "windows":
		if Backend() != "LockFileEx" {
			t.Fatalf("Windows Backend() = %q, want LockFileEx", Backend())
		}
	case "darwin", "freebsd", "openbsd", "netbsd", "dragonfly":
		if Backend() != "in-process" {
			t.Fatalf("%s Backend() = %q, want the in-process registry", runtime.GOOS, Backend())
		}
	}
}

// TestReLockAndUpgradeOnTheSameHandle covers the operations that decided the shape
// of the kernel layer. A client may re-lock a range it already holds, and may
// change the mode of a range it holds; POSIX locks do both in place, Windows
// refuses both, and the answer has to be the same for the client either way.
func TestReLockAndUpgradeOnTheSameHandle(t *testing.T) {
	_, a, b := scratch(t)
	if err := Lock(a, 0, 8, Exclusive, true); err != nil {
		t.Fatal(err)
	}
	defer Release(a)

	// The same range, twice, from the handle that holds it.
	if err := Lock(a, 0, 8, Exclusive, true); err != nil {
		t.Fatalf("a handle must be able to re-lock its own range: %v", err)
	}
	if err := Lock(a, 0, 8, Shared, true); err != nil {
		t.Fatalf("a handle must be able to downgrade its own range: %v", err)
	}
	// It is shared now, so another handle may share it but not take it alone.
	if err := Lock(b, 0, 8, Shared, true); err != nil {
		t.Fatalf("a downgraded range must be shareable: %v", err)
	}
	if err := Lock(b, 0, 8, Exclusive, true); !errors.Is(err, ErrNotGranted) {
		t.Fatalf("exclusive over a shared pair = %v, want ErrNotGranted", err)
	}
	// Upgrading it back to exclusive fails while the other handle shares it...
	if err := Lock(a, 0, 8, Exclusive, true); !errors.Is(err, ErrNotGranted) {
		t.Fatalf("upgrading over another handle's shared lock = %v, want ErrNotGranted", err)
	}
	// ...and succeeds once that handle is gone, on the same handle that holds the
	// shared lock — which is the in-place conversion Windows does not have.
	if err := Lock(b, 0, 8, Unlock, true); err != nil {
		t.Fatal(err)
	}
	if err := Lock(a, 0, 8, Exclusive, true); err != nil {
		t.Fatalf("upgrade after the other handle released: %v", err)
	}
	if err := Lock(b, 0, 8, Shared, true); !errors.Is(err, ErrNotGranted) {
		t.Fatalf("the upgraded range = %v, want ErrNotGranted", err)
	}
}
