package rangelock

// Planning the kernel's half of a lock change.
//
// On Linux the kernel's lock table is updated incrementally: F_OFD_SETLK takes or
// releases exactly the range it is given, and it splits, merges and converts
// ranges the way POSIX says. Windows is not like that at all. Its byte-range locks
// are *exact-match objects* owned by a handle:
//
//   - a range must be unlocked with exactly the range it was locked with (two
//     adjacent locks cannot be released by one call spanning both, and a locked
//     range cannot be unlocked in part);
//   - a handle cannot lock a range it already holds, and a shared lock cannot be
//     upgraded in place — the request is refused even for the same handle;
//   - a range whose offset plus length runs past the largest signed offset is
//     refused outright (ERROR_INVALID_LOCK_RANGE).
//
// So on Windows the kernel's table cannot be nudged; it has to be *rebuilt* around
// each change: release exactly the objects that are in the way, then take exactly
// the objects the registry wants there. planMirror computes those two sets, and
// because it is pure arithmetic over ranges it is tested on every platform rather
// than only on the one that needs it.

// planMirror reports the region a change affects, which of a handle's mirrored
// kernel ranges must be released, and which of the registry's ranges must be taken,
// to move the kernel's table from mirror to next after the change described by
// want.
//
// mirror is what the kernel holds for this handle (exact objects, as they were
// locked); next is the registry's view of what the handle should hold; want is the
// range this operation touched.
//
// The answer is a *region*: every mirrored range that overlaps the change, every
// range the registry wants inside that region, and — because a lock can coalesce
// with a neighbour — every mirrored range that overlaps those, until nothing new
// is added. Releasing outside the region would be pointless, and taking anything
// before releasing everything in it would collide with the handle's own lock.
func planMirror(mirror, next []extent, want extent) (region extent, release, acquire []extent) {
	region = want
	for {
		grew := false
		for _, e := range next {
			if e.overlaps(region) && !region.contains(e) {
				region = union(region, e)
				grew = true
			}
		}
		for _, m := range mirror {
			if m.overlaps(region) && !region.contains(m) {
				region = union(region, m)
				grew = true
			}
		}
		if !grew {
			break
		}
	}
	for _, m := range mirror {
		if m.overlaps(region) {
			release = append(release, m)
		}
	}
	for _, e := range next {
		if e.overlaps(region) {
			acquire = append(acquire, e)
		}
	}
	return region, release, acquire
}

// union returns the smallest range covering both, keeping the mode of the first.
// The region built by planMirror only carries a position; its mode is never used,
// because every range in it is either released or taken from the registry's own
// description.
func union(a, b extent) extent {
	if b.start < a.start {
		a.start = b.start
	}
	if b.extends(a) {
		a.end = b.end
	}
	return a
}
