//go:build !unix

package fsutil

// DirOpenFlags is zero where the platform has no directory-only open flag.
// Windows and the rest refuse a read of a directory descriptor by other means,
// so nothing is lost: the flag is an optimisation and a fail-fast check, not
// the mechanism that keeps directory opens and file opens apart.
const DirOpenFlags = 0
