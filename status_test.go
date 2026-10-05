package samba

import (
	"errors"
	"os"
	"syscall"
	"testing"
)

func TestStatusFromErrnoTable(t *testing.T) {
	cases := []struct {
		errno syscall.Errno
		want  uint32
	}{
		{syscall.ENOENT, StatusObjectNameNotFound},
		{syscall.ENOTDIR, StatusObjectPathNotFound},
		{syscall.EACCES, StatusAccessDenied},
		{syscall.EPERM, StatusAccessDenied},
		{syscall.EROFS, StatusAccessDenied},
		{syscall.EBADF, StatusAccessDenied},
		{syscall.EEXIST, StatusObjectNameCollision},
		{syscall.EISDIR, StatusFileIsADirectory},
		{syscall.ENOTEMPTY, StatusDirectoryNotEmpty},
		{syscall.ENOSPC, StatusDiskFull},
		{syscall.EDQUOT, StatusDiskFull},
		{syscall.ENFILE, StatusInsufficientResources},
		{syscall.EMFILE, StatusInsufficientResources},
		{syscall.ENOMEM, StatusInsufficientResources},
		{syscall.EINVAL, StatusInvalidParameter},
		{syscall.EBUSY, StatusSharingViolation},
		{syscall.EIO, StatusIoDeviceError},
		{syscall.EAGAIN, StatusUnsuccessful},
		{syscall.EPERM + 1000, StatusUnsuccessful},
	}
	for _, c := range cases {
		if got := StatusFromErrno(c.errno); got != c.want {
			t.Errorf("StatusFromErrno(%v) = %#x, want %#x", c.errno, got, c.want)
		}
	}
	if got := StatusFromErrno(0); got != StatusUnsuccessful {
		t.Errorf("StatusFromErrno(0) = %#x, want UNSUCCESSFUL", got)
	}
}

func TestErrnoOf(t *testing.T) {
	if got := errnoOf(nil); got != 0 {
		t.Errorf("errnoOf(nil) = %v", got)
	}
	if got := errnoOf(syscall.EACCES); got != syscall.EACCES {
		t.Errorf("errnoOf(EACCES) = %v", got)
	}
	// A wrapped errno is unwrapped.
	if got := errnoOf(&osPathError{err: syscall.ENOSPC}); got != syscall.ENOSPC {
		t.Errorf("errnoOf(wrapped) = %v", got)
	}
	// Filesystem sentinel errors map to the obvious errno.
	if got := errnoOf(os.ErrNotExist); got != syscall.ENOENT {
		t.Errorf("errnoOf(ErrNotExist) = %v", got)
	}
	if got := errnoOf(os.ErrPermission); got != syscall.EACCES {
		t.Errorf("errnoOf(ErrPermission) = %v", got)
	}
	if got := errnoOf(os.ErrExist); got != syscall.EEXIST {
		t.Errorf("errnoOf(ErrExist) = %v", got)
	}
	// Anything unrecognized is an I/O error.
	if got := errnoOf(errors.New("mystery")); got != syscall.EIO {
		t.Errorf("errnoOf(unknown) = %v, want EIO", got)
	}
}

// osPathError is a minimal wrapper carrying an errno, like *os.PathError.
type osPathError struct{ err error }

func (e *osPathError) Error() string { return e.err.Error() }
func (e *osPathError) Unwrap() error { return e.err }
