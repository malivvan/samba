//go:build !linux && !windows && !darwin && !freebsd && !openbsd && !netbsd && !dragonfly

package watch

import "time"

// Platforms outside the supported set have no change-notification facility this
// package can reach, so the polling watcher is the implementation rather than a
// fallback. It is deliberately the same code the supported platforms use when
// they are asked for it explicitly, so the behaviour is exercised wherever the
// test suite runs.
const backend = "poll"

// nativeSupported reports that this platform has *no* facility of its own, which
// is what tells an operator (and the README table) that changes are noticed by
// polling rather than by the kernel.
func nativeSupported() bool { return false }

// New returns the polling watcher.
func New() Watcher { return newPolling(time.Duration(0)) }
