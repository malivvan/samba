//go:build !unix && !windows

package fsutil

import "os"

// Platforms outside the supported set have no accessible file metadata through
// this layer. The error is returned rather than an empty Info, so a caller
// cannot mistake "no attributes" for "an empty file".
func StatPath(string) (Info, error)   { return Info{}, ErrUnsupported }
func LstatPath(string) (Info, error)  { return Info{}, ErrUnsupported }
func StatFile(*os.File) (Info, error) { return Info{}, ErrUnsupported }
func FileID(*os.File) (uint64, uint64, error) {
	return 0, 0, ErrUnsupported
}
