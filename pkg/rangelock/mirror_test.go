package rangelock

import (
	"reflect"
	"testing"
)

// The mirror plan is the Windows lock path's whole algorithm, and it is pure
// arithmetic over ranges — so it is tested here, on every platform, rather than
// only on the one that needs it. Each case is a sequence a real client produces.
//
// The properties being checked, in Windows' terms: the ranges marked for release
// are exactly the objects the handle took (so an exact-match unlock can release
// them), and the ranges marked for acquisition are taken only after nothing of the
// handle's own is in the way (so the same-handle refusal cannot fire).

// rng builds an inclusive range from a start and a length, the way a client's
// LOCK request arrives.
func rng(start, length uint64, exclusive bool) extent {
	e := normalizeRange(start, length)
	e.exclusive = exclusive
	return e
}

func TestPlanMirrorFreshLock(t *testing.T) {
	want := rng(0, 100, true)
	region, release, acquire := planMirror(nil, []extent{want}, want)
	if len(release) != 0 {
		t.Fatalf("nothing was held, so nothing should be released: %+v", release)
	}
	if !reflect.DeepEqual(acquire, []extent{want}) {
		t.Fatalf("acquire = %+v, want the requested range", acquire)
	}
	if region != want {
		t.Fatalf("region = %+v, want the requested range", region)
	}
}

// TestPlanMirrorMergeIsTheCaseThatForcedThis covers a client locking a gap between
// two ranges it holds. The registry coalesces the three into one, so the kernel's
// two objects are both in the way — even though neither overlaps the request.
func TestPlanMirrorMergeIsTheCaseThatForcedThis(t *testing.T) {
	held := []extent{rng(0, 40, true), rng(60, 40, true)}
	want := rng(40, 20, true)
	next := coalesce(append(append([]extent{}, held...), want))

	region, release, acquire := planMirror(held, next, want)
	if !reflect.DeepEqual(release, held) {
		t.Fatalf("release = %+v, want both held ranges", release)
	}
	if len(acquire) != 1 || acquire[0] != rng(0, 100, true) {
		t.Fatalf("acquire = %+v, want the merged range", acquire)
	}
	// The region has to reach both neighbours, because the merged range covers
	// them: releasing only what the request overlapped would leave the handle's own
	// lock in the way of the acquisition.
	if region != rng(0, 100, true) {
		t.Fatalf("region = %+v, want the whole merged span", region)
	}
}

// TestPlanMirrorSplit covers a partial unlock, which Windows cannot express at all:
// the range has to be released whole and the parts the client keeps taken again.
func TestPlanMirrorSplit(t *testing.T) {
	held := []extent{rng(0, 100, true)}
	want := rng(40, 20, false) // an unlock is not exclusive
	next := subtract(append([]extent{}, held...), want)

	_, release, acquire := planMirror(held, next, want)
	if !reflect.DeepEqual(release, held) {
		t.Fatalf("release = %+v, want the whole held range", release)
	}
	want2 := []extent{rng(0, 40, true), rng(60, 40, true)}
	if !reflect.DeepEqual(acquire, want2) {
		t.Fatalf("acquire = %+v, want the two remaining ends", acquire)
	}
}

// TestPlanMirrorConversion covers a client changing the mode of a range it holds,
// which on Windows would be refused as a lock of a range the handle already holds.
func TestPlanMirrorConversion(t *testing.T) {
	held := []extent{rng(0, 100, false)}
	want := rng(50, 10, true)
	next := coalesce(append(subtract(append([]extent{}, held...), want), want))

	_, release, acquire := planMirror(held, next, want)
	if !reflect.DeepEqual(release, held) {
		t.Fatalf("release = %+v, want the shared range", release)
	}
	want2 := []extent{rng(0, 50, false), rng(50, 10, true), rng(60, 40, false)}
	if !reflect.DeepEqual(acquire, want2) {
		t.Fatalf("acquire = %+v, want the three resulting ranges", acquire)
	}
}

// TestPlanMirrorLeavesTheRestAlone checks that a change confined to one range does
// not disturb a handle's other locks: they are neither released nor re-taken.
func TestPlanMirrorLeavesTheRestAlone(t *testing.T) {
	far := rng(1<<40, 10, true)
	held := []extent{rng(0, 10, true), far}
	want := rng(20, 10, true)
	next := coalesce(append(append([]extent{}, held...), want))

	region, release, acquire := planMirror(held, next, want)
	if len(release) != 0 {
		t.Fatalf("release = %+v, want nothing: no held range is in the way", release)
	}
	if len(acquire) != 1 || acquire[0] != want {
		t.Fatalf("acquire = %+v, want only the new range", acquire)
	}
	if region.overlaps(far) {
		t.Fatalf("region %+v reaches a lock that has nothing to do with the change", region)
	}
}

// TestPlanMirrorFullRelease covers the last reference to a range going away: the
// kernel object is released and nothing is taken.
func TestPlanMirrorFullRelease(t *testing.T) {
	held := []extent{rng(0, 100, true)}
	want := rng(0, 0, false) // whole-file unlock
	_, release, acquire := planMirror(held, nil, want)
	if !reflect.DeepEqual(release, held) {
		t.Fatalf("release = %+v, want the held range", release)
	}
	if len(acquire) != 0 {
		t.Fatalf("acquire = %+v, want nothing", acquire)
	}
}

// TestPlanMirrorRepeatedIdenticalLock covers a client locking what it already
// holds: the kernel object is rebuilt rather than re-taken, which is what keeps
// Windows from refusing it.
func TestPlanMirrorRepeatedIdenticalLock(t *testing.T) {
	held := []extent{rng(0, 100, true)}
	want := rng(0, 100, true)
	_, release, acquire := planMirror(held, held, want)
	if !reflect.DeepEqual(release, held) {
		t.Fatalf("release = %+v, want the held range", release)
	}
	if !reflect.DeepEqual(acquire, held) {
		t.Fatalf("acquire = %+v, want the same range back", acquire)
	}
}

// TestPlanMirrorAcquireNeverOverlapsTheHandleOwn is the invariant the whole design
// rests on: whatever the change, nothing is taken until the handle's own locks in
// the region have been released — on Windows an overlapping acquisition is refused.
func TestPlanMirrorAcquireNeverOverlapsTheHandleOwn(t *testing.T) {
	held := []extent{rng(0, 50, false), rng(50, 50, true), rng(200, 20, false)}
	changes := []struct {
		want   extent
		unlock bool
	}{
		{rng(0, 100, false), false},
		{rng(10, 10, true), false},
		{rng(120, 10, false), false},
		{rng(0, 0, true), true},
		{rng(200, 20, true), false},
		{rng(49, 2, true), false},
		{rng(100, 0, true), true},
	}
	for _, c := range changes {
		var next []extent
		if c.unlock {
			next = subtract(append([]extent{}, held...), c.want)
		} else {
			next = coalesce(append(subtract(append([]extent{}, held...), c.want), c.want))
		}
		region, release, acquire := planMirror(held, next, c.want)
		// Two invariants, and they are what Windows requires:
		//
		//   - every held range that overlaps an acquisition is in the release set,
		//     so nothing of the handle's own is in the way when it is taken (the
		//     release is always executed first); and
		//   - nothing is acquired outside the region, so no unrelated lock is
		//     disturbed.
		for _, m := range held {
			for _, a := range acquire {
				if m.overlaps(a) && !containsRange(release, m) {
					t.Fatalf("change %+v: held %+v overlaps the acquisition %+v but is not released",
						c.want, m, a)
				}
			}
		}
		for _, a := range acquire {
			if !region.contains(a) {
				t.Fatalf("change %+v: acquisition %+v is outside region %+v", c.want, a, region)
			}
		}
	}
}

// containsRange reports whether the set holds a range equal to r.
func containsRange(set []extent, r extent) bool {
	for _, e := range set {
		if e == r {
			return true
		}
	}
	return false
}

// TestPlanMirrorRegionCoversEverythingTouched checks the fixpoint: whatever the
// registry's before and after pictures, every range in either that overlaps the
// region must be in the plan.
func TestPlanMirrorRegionCoversEverythingTouched(t *testing.T) {
	held := []extent{rng(0, 30, true), rng(30, 30, false), rng(100, 10, true)}
	next := []extent{rng(0, 60, true), rng(100, 10, true)}
	// A change that merges the first two and leaves the third alone.
	want := rng(30, 30, true)
	region, _, acquire := planMirror(held, next, want)
	if len(acquire) != 1 || acquire[0] != rng(0, 60, true) {
		t.Fatalf("acquire = %+v, want the merged range", acquire)
	}
	if !region.contains(rng(0, 60, true)) {
		t.Fatalf("region %+v does not cover the merged range", region)
	}
	if region.overlaps(rng(100, 10, true)) {
		t.Fatalf("region %+v reaches the untouched range", region)
	}
}
