//go:build unix

package rangelock

import (
	"errors"
	"syscall"
)

// isConflict reports whether a kernel lock failed because another holder has the
// range.
//
// POSIX says F_SETLK answers EACCES or EAGAIN for a range held elsewhere, and
// which of the two a platform picks is not specified, so both count.
func isConflict(err error) bool {
	return errors.Is(err, syscall.EAGAIN) || errors.Is(err, syscall.EACCES)
}
