//go:build !unix && !windows

package rangelock

import "os"

// backend is what the operator-facing capability report prints, and what the
// README support table documents.
const backend = "in-process"

// Platforms outside the supported set have no lock API this package can reach,
// so the registry is the only table. Locking between SMB clients still works,
// which is the part the protocol specifies; locking against other processes on
// the host does not.
func kernelLock(*os.File, int64, int64, Kind) error { return nil }

// kernelUpdate applies one logical change to the kernel's lock table. This
// platform has none.
func kernelUpdate(*os.File, []extent, []extent, extent, Kind) error { return nil }

// kernelRelease releases the kernel's records for a handle that is going away.
func kernelRelease(*os.File, []extent) {}

// resetKernel forgets every kernel record.
func resetKernel() {}

// Degraded reports how many times this process gave up on mirroring a handle's
// locks into the kernel. Always zero: there is no kernel table to keep in step.
func Degraded() int64 { return 0 }
