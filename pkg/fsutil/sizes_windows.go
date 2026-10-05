package fsutil

import (
	"encoding/binary"
	"os"
	"path/filepath"

	"golang.org/x/sys/windows"
)

// FileFsSizeInformation has no named constant in x/sys/windows; this is its
// documented value in the FILE_INFO_BY_HANDLE_CLASS enumeration.
const fileFsSizeInformation = 3

// fileFsSizeInformationSize is the wire size of FILE_FS_SIZE_INFORMATION:
// two LARGE_INTEGERs and two ULONGs.
const fileFsSizeInformationSize = 24

// Volume geometry is only exposed for a *volume* or *directory* handle, never
// for a file handle, so Sizes uses the path the caller already has: it opens
// the volume root and asks for FILE_FS_SIZE_INFORMATION, which is the same
// structure the SMB reply is built from. If that fails it falls back to
// GetDiskFreeSpaceEx, which reports the byte counts but not the allocation unit
// — hence the documented 4 KiB assumption below.
const windowsAssumedAllocationSize = 4096

func volumeRoot(path string) string {
	if path == "" {
		return "."
	}
	vol := filepath.VolumeName(path)
	if vol == "" {
		return path
	}
	return vol + string(filepath.Separator)
}

func Sizes(f *os.File, path string) (total, avail, free uint64, sectorsPerUnit, bytesPerSector uint32, err error) {
	if t, a, s, b, ok := volumeUnits(path); ok {
		// Windows reports only the space available to the caller, not a
		// separate total-free count, so the two are the same figure here.
		return t, a, a, s, b, nil
	}
	root, cerr := windows.UTF16PtrFromString(volumeRoot(path))
	if cerr != nil {
		return 0, 0, 0, 0, 0, cerr
	}
	var availToCaller, totalBytes, totalFree uint64
	if err = windows.GetDiskFreeSpaceEx(root, &availToCaller, &totalBytes, &totalFree); err != nil {
		return 0, 0, 0, 0, 0, err
	}
	spu, bps := blockUnits(windowsAssumedAllocationSize)
	return totalBytes / windowsAssumedAllocationSize,
		availToCaller / windowsAssumedAllocationSize,
		totalFree / windowsAssumedAllocationSize,
		spu, bps, nil
}

// volumeUnits reads FILE_FS_SIZE_INFORMATION for the volume holding path.
func volumeUnits(path string) (total, avail uint64, sectorsPerUnit, bytesPerSector uint32, ok bool) {
	p, err := windows.UTF16PtrFromString(volumeRoot(path))
	if err != nil {
		return 0, 0, 0, 0, false
	}
	h, err := windows.CreateFile(
		p,
		windows.FILE_READ_ATTRIBUTES,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
		nil,
		windows.OPEN_EXISTING,
		windows.FILE_FLAG_BACKUP_SEMANTICS,
		0,
	)
	if err != nil {
		return 0, 0, 0, 0, false
	}
	defer windows.CloseHandle(h)
	// The buffer is a plain byte slice and is decoded with encoding/binary, so
	// no unsafe pointer arithmetic is involved.
	buf := make([]byte, fileFsSizeInformationSize)
	if err := windows.GetFileInformationByHandleEx(h, fileFsSizeInformation, &buf[0], uint32(len(buf))); err != nil {
		return 0, 0, 0, 0, false
	}
	total = binary.LittleEndian.Uint64(buf[0:8])
	avail = binary.LittleEndian.Uint64(buf[8:16])
	spu := binary.LittleEndian.Uint32(buf[16:20])
	bps := binary.LittleEndian.Uint32(buf[20:24])
	if spu == 0 || bps == 0 {
		return 0, 0, 0, 0, false
	}
	if spu > MaxSectorsPerUnit {
		spu = MaxSectorsPerUnit
	}
	return total, avail, spu, bps, true
}
