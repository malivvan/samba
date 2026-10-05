//go:build unix

package fsutil

import "golang.org/x/sys/unix"

// DirOpenFlags is what callers OR into their open flags to get a directory
// descriptor. Every Unix target has O_DIRECTORY, which makes the kernel fail
// the open if the path is not a directory — that check is what stops a CREATE
// from being redirected to a file.
const DirOpenFlags = unix.O_DIRECTORY
