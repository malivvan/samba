package samba

import "syscall"

// NTSTATUS codes used on the wire, plus errno mapping.
const (
	StatusSuccess               uint32 = 0x0000_0000
	StatusPending               uint32 = 0x0000_0103
	StatusNotifyCleanup         uint32 = 0x0000_010B
	StatusNotifyEnumDir         uint32 = 0x0000_010C
	StatusBufferOverflow        uint32 = 0x8000_0005
	StatusNoMoreFiles           uint32 = 0x8000_0006
	StatusUnsuccessful          uint32 = 0xC000_0001
	StatusNotImplemented        uint32 = 0xC000_0002
	StatusInvalidParameter      uint32 = 0xC000_000D
	StatusNoSuchFile            uint32 = 0xC000_000F
	StatusInvalidDeviceRequest  uint32 = 0xC000_0010
	StatusEndOfFile             uint32 = 0xC000_0011
	StatusMoreProcessingRequire uint32 = 0xC000_0016
	StatusAccessDenied          uint32 = 0xC000_0022
	StatusBufferTooSmall        uint32 = 0xC000_0023
	StatusObjectNameInvalid     uint32 = 0xC000_0033
	StatusObjectNameNotFound    uint32 = 0xC000_0034
	StatusObjectNameCollision   uint32 = 0xC000_0035
	StatusObjectPathNotFound    uint32 = 0xC000_003A
	StatusSharingViolation      uint32 = 0xC000_0043
	StatusFileLockConflict      uint32 = 0xC000_0054
	StatusLockNotGranted        uint32 = 0xC000_0055
	StatusDeletePending         uint32 = 0xC000_0056
	StatusLogonFailure          uint32 = 0xC000_006D
	StatusDiskFull              uint32 = 0xC000_007F
	StatusInsufficientResources uint32 = 0xC000_009A
	StatusFileIsADirectory      uint32 = 0xC000_00BA
	StatusNotSupported          uint32 = 0xC000_00BB
	StatusNetworkNameDeleted    uint32 = 0xC000_00C9
	StatusBadNetworkName        uint32 = 0xC000_00CC
	StatusDirectoryNotEmpty     uint32 = 0xC000_0101
	StatusNotADirectory         uint32 = 0xC000_0103
	StatusCancelled             uint32 = 0xC000_0120
	StatusFileClosed            uint32 = 0xC000_0128
	// StatusTimeDifferenceAtDC signals Kerberos clock skew between
	// client/server/KDC beyond policy (MS-ERREF).
	StatusTimeDifferenceAtDC uint32 = 0xC000_0133
	StatusIoDeviceError      uint32 = 0xC000_0185
	StatusUserSessionDeleted uint32 = 0xC000_0203
)

// StatusFromErrno maps a Unix errno to the closest NTSTATUS.
func StatusFromErrno(e syscall.Errno) uint32 {
	switch e {
	case syscall.ENOENT:
		return StatusObjectNameNotFound
	case syscall.ENOTDIR:
		return StatusObjectPathNotFound
	case syscall.EACCES, syscall.EPERM, syscall.EROFS, syscall.EBADF:
		return StatusAccessDenied
	case syscall.EEXIST:
		return StatusObjectNameCollision
	case syscall.EISDIR:
		return StatusFileIsADirectory
	case syscall.ENOTEMPTY:
		return StatusDirectoryNotEmpty
	case syscall.ENOSPC, syscall.EDQUOT:
		return StatusDiskFull
	case syscall.ENFILE, syscall.EMFILE, syscall.ENOMEM:
		return StatusInsufficientResources
	case syscall.EINVAL:
		return StatusInvalidParameter
	case syscall.EBUSY:
		return StatusSharingViolation
	case syscall.EIO:
		return StatusIoDeviceError
	default:
		return StatusUnsuccessful
	}
}

// statusFromErr maps any error carrying an errno to an NTSTATUS, defaulting to
// STATUS_IO_DEVICE_ERROR when the wrapped errno is unavailable. A nil error is
// success.
func statusFromErr(err error) uint32 {
	if err == nil {
		return StatusSuccess
	}
	return StatusFromErrno(errnoOf(err))
}
