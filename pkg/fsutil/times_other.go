//go:build !linux && !windows && !darwin && !freebsd && !openbsd && !netbsd && !dragonfly

package fsutil

import "os"

// Platforms outside the supported set have no timestamp call this layer can use
// without cgo, so updating timestamps fails cleanly with ErrUnsupported rather
// than silently reporting success: a client must never believe a SET_INFO took
// effect when it did not. Everything else in this package still works there.
func SetTimes(*os.File, Times) error { return ErrUnsupported }
