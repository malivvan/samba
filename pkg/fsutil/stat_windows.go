package fsutil

import (
	"os"
	"time"

	"golang.org/x/sys/windows"
)

// Windows has no stat(2) equivalent that exposes a file identity, so the
// portable metadata comes from two places:
//
//   - os.Stat / os.Lstat, for size, mode, type and timestamps.
//   - GetFileInformationByHandle, for the volume serial number (the device) and
//     the file index (the inode), which leases and byte-range locks key on.
//
// The second one needs a handle, so the identity is only filled in where the
// caller already has one (StatFile) or where opening the file is acceptable
// (StatPath, used for directory enumeration). A file that cannot be opened is
// still described, just without an identity — lease code treats a zero
// identity as "cannot key on this" and opens without a lease.

// windowsStatToInfo converts the Win32 file information into the portable form.
func windowsStatToInfo(bhfi *windows.ByHandleFileInformation, base Info) Info {
	base.Dev = uint64(bhfi.VolumeSerialNumber)
	base.Ino = uint64(bhfi.FileIndexHigh)<<32 | uint64(bhfi.FileIndexLow)
	base.Nlink = uint32(bhfi.NumberOfLinks)
	if base.Nlink == 0 {
		base.Nlink = 1
	}
	base.Atime = time.Unix(0, bhfi.LastAccessTime.Nanoseconds())
	base.Mtime = time.Unix(0, bhfi.LastWriteTime.Nanoseconds())
	// Windows has no separate status-change time; the modification time is the
	// closest thing, which is also how the Unix side reports a filesystem that
	// has no ctime.
	base.Ctime = base.Mtime
	if base.Blocks == 0 && base.Size > 0 {
		base.Blocks = (base.Size + 511) / 512
	}
	return base
}

// infoFromFileInfo describes a file from what the standard library already
// knows, used when no handle is available.
func infoFromFileInfo(fi os.FileInfo) Info {
	mtime := fi.ModTime()
	info := Info{
		Size:  fi.Size(),
		Mode:  fi.Mode(),
		IsDir: fi.IsDir(),
		Nlink: 1,
		Atime: mtime,
		Mtime: mtime,
		Ctime: mtime,
	}
	if info.Size > 0 {
		info.Blocks = (info.Size + 511) / 512
	}
	return info
}

// openForAttributes opens path to read its identity, asking for as little
// access as the task needs: attributes only, no data.
func openForAttributes(path string) (windows.Handle, error) {
	p, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return windows.InvalidHandle, err
	}
	return windows.CreateFile(
		p,
		windows.FILE_READ_ATTRIBUTES,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
		nil,
		windows.OPEN_EXISTING,
		// Directories (and reparse points we must not follow) need this flag.
		windows.FILE_FLAG_BACKUP_SEMANTICS|windows.FILE_FLAG_OPEN_REPARSE_POINT,
		0,
	)
}

// StatPath reports the metadata of path, following symlinks.
func StatPath(path string) (Info, error) {
	fi, err := os.Stat(path)
	if err != nil {
		return Info{}, err
	}
	info := infoFromFileInfo(fi)
	if h, err := openForAttributes(path); err == nil {
		var bhfi windows.ByHandleFileInformation
		if windows.GetFileInformationByHandle(h, &bhfi) == nil {
			info = windowsStatToInfo(&bhfi, info)
			info.IsDir = fi.IsDir()
			info.Mode = fi.Mode()
		}
		windows.CloseHandle(h)
	}
	return info, nil
}

// LstatPath reports the metadata of path without following a final symlink or
// reparse point.
func LstatPath(path string) (Info, error) {
	fi, err := os.Lstat(path)
	if err != nil {
		return Info{}, err
	}
	info := infoFromFileInfo(fi)
	if h, err := openForAttributes(path); err == nil {
		var bhfi windows.ByHandleFileInformation
		if windows.GetFileInformationByHandle(h, &bhfi) == nil {
			info = windowsStatToInfo(&bhfi, info)
			info.IsDir = fi.IsDir()
			info.Mode = fi.Mode()
		}
		windows.CloseHandle(h)
	}
	return info, nil
}

// StatFile reports the metadata of an open handle, including the file identity
// used for leases and byte-range locks.
func StatFile(f *os.File) (Info, error) {
	fi, err := f.Stat()
	if err != nil {
		return Info{}, err
	}
	info := infoFromFileInfo(fi)
	var bhfi windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(windows.Handle(f.Fd()), &bhfi); err == nil {
		info = windowsStatToInfo(&bhfi, info)
	}
	// The standard library's view of size and type stays authoritative; the
	// Win32 structure is only consulted for what it alone exposes.
	info.Size = fi.Size()
	info.Mode = fi.Mode()
	info.IsDir = fi.IsDir()
	return info, nil
}

// FileID reports the (volume serial, file index) pair that identifies f.
func FileID(f *os.File) (dev, ino uint64, err error) {
	var bhfi windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(windows.Handle(f.Fd()), &bhfi); err != nil {
		return 0, 0, err
	}
	return uint64(bhfi.VolumeSerialNumber), uint64(bhfi.FileIndexHigh)<<32 | uint64(bhfi.FileIndexLow), nil
}
