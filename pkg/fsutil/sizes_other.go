//go:build !linux && !windows && !darwin && !freebsd && !openbsd && !netbsd && !dragonfly

package fsutil

import "os"

// Platforms outside the supported set expose no filesystem-size call this layer
// can reach without cgo. Reporting an error is the honest outcome: the client
// gets STATUS_NOT_SUPPORTED for FileFsSizeInformation instead of a fabricated
// free-space figure it might act on.
func Sizes(*os.File, string) (total, avail, free uint64, sectorsPerUnit, bytesPerSector uint32, err error) {
	return 0, 0, 0, 0, 0, ErrUnsupported
}
