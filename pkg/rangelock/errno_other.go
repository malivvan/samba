//go:build !unix

package rangelock

// isConflict reports whether a kernel lock failed because another holder has the
// range. On the platforms whose kernel backend is not POSIX (Windows, which maps
// its own ERROR_LOCK_VIOLATION where the lock is taken) and on those that have no
// kernel backend at all, there is nothing to translate.
func isConflict(error) bool { return false }
