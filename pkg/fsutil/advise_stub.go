//go:build !linux && !freebsd && !netbsd

package fsutil

import "os"

// No readahead hint this layer can issue without cgo.
//
//   - macOS has F_RDADVISE, but it takes a pointer to a Radvisory structure and
//     x/sys/unix only exposes the integer-argument fcntl wrapper, which would
//     pass a null pointer. The kernel's own readahead applies regardless.
//   - OpenBSD, DragonFly, Windows and the rest expose nothing equivalent.
//
// This is a pure performance hint: skipping it changes no result the client can
// observe, only how much of a cold file's read latency is hidden.
func AdviseSequential(*os.File) {}
