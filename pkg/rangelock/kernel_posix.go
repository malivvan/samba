//go:build unix && !linux

package rangelock

import "os"

// backend is what the operator-facing capability report prints, and what the
// README support table documents.
const backend = "in-process"

// These platforms have classic POSIX record locks (F_SETLK) and nothing better:
// their locks belong to the *process*, not to the open file description, so
//
//   - two handles of one file would never conflict at the kernel, and
//   - closing any descriptor of a file releases every lock the process holds on
//     it, including one a sibling handle is relying on.
//
// Taking such a lock would therefore add no protection between SMB clients (the
// registry already does that correctly) while occasionally *dropping*
// protection that was thought to be held. Unreliable protection that silently
// disappears is worse than none, so this platform takes no kernel lock and the
// registry alone is authoritative — the same trade-off Samba describes for
// "kernel oplocks".
//
// The consequence is stated where operators will see it (README support table,
// SECURITY.md): on these platforms a lock is enforced between SMB clients but
// not against a local process writing to the same file, so a share must not be
// used both locally and over SMB.
func kernelLock(*os.File, int64, int64, Kind) error { return nil }
