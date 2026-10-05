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
