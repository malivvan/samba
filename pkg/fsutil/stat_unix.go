//go:build unix

package fsutil

import (
	"os"

	"golang.org/x/sys/unix"
)

// Unix file metadata comes from the kernel's own stat structure rather than
// from os.FileInfo, for one reason: x/sys/unix names the fields identically on
// every Unix target (Atim/Mtim/Ctim, Dev, Ino, Nlink, Blocks), while the
// standard library's syscall.Stat_t does not (darwin and the BSDs use
// Mtimespec and friends, and the counter widths differ). One uniform file is
// worth more here than saving a type assertion.
//
// The mode is the exception: x/sys/unix keeps the raw kernel bits, so the
// os.FileMode conversion below is written out instead of borrowed from os.

// StatPath reports the metadata of path, following symlinks.
func StatPath(path string) (Info, error) {
	var st unix.Stat_t
	if err := unix.Stat(path, &st); err != nil {
		return Info{}, err
	}
	return infoFromStat(&st), nil
}

// LstatPath reports the metadata of path without following a final symlink, so
// the entry itself is described.
func LstatPath(path string) (Info, error) {
	var st unix.Stat_t
	if err := unix.Lstat(path, &st); err != nil {
		return Info{}, err
	}
	return infoFromStat(&st), nil
}

// StatFile reports the metadata of an open handle. It is the only way to see a
// file that has been unlinked since it was opened.
func StatFile(f *os.File) (Info, error) {
	var st unix.Stat_t
	if err := unix.Fstat(int(f.Fd()), &st); err != nil {
		return Info{}, err
	}
	return infoFromStat(&st), nil
}

// FileID reports the (device, inode) pair that identifies f. It is what leases
// and byte-range locks key on, so it must not change while the handle is open.
func FileID(f *os.File) (dev, ino uint64, err error) {
	var st unix.Stat_t
	if err := unix.Fstat(int(f.Fd()), &st); err != nil {
		return 0, 0, err
	}
	return uint64(st.Dev), uint64(st.Ino), nil
}

// infoFromStat converts a kernel stat structure into the portable form. The
// explicit conversions are what make this one file compile for every target:
// the underlying field types differ between platforms (Dev is int32 on darwin
// and uint64 on Linux, Nlink is uint16 on darwin and uint64 on FreeBSD, and
// Timespec is 32-bit on 32-bit platforms).
func infoFromStat(st *unix.Stat_t) Info {
	mode := uint32(st.Mode)
	info := Info{
		Size:   int64(st.Size),
		Mode:   modeFromRaw(mode),
		IsDir:  mode&uint32(unix.S_IFMT) == uint32(unix.S_IFDIR),
		Dev:    uint64(st.Dev),
		Ino:    uint64(st.Ino),
		Nlink:  uint32(st.Nlink),
		Blocks: int64(st.Blocks),
		Atime:  clampTimespec(int64(st.Atim.Sec), int64(st.Atim.Nsec)),
		Mtime:  clampTimespec(int64(st.Mtim.Sec), int64(st.Mtim.Nsec)),
		Ctime:  clampTimespec(int64(st.Ctim.Sec), int64(st.Ctim.Nsec)),
	}
	return info
}

// modeFromRaw maps the kernel's mode bits onto os.FileMode. It is the inverse
// of the conversion the standard library performs in os.FileInfo.Mode.
func modeFromRaw(mode uint32) os.FileMode {
	m := os.FileMode(mode & 0o777)
	switch mode & uint32(unix.S_IFMT) {
	case uint32(unix.S_IFDIR):
		m |= os.ModeDir
	case uint32(unix.S_IFLNK):
		m |= os.ModeSymlink
	case uint32(unix.S_IFIFO):
		m |= os.ModeNamedPipe
	case uint32(unix.S_IFSOCK):
		m |= os.ModeSocket
	case uint32(unix.S_IFBLK):
		m |= os.ModeDevice
	case uint32(unix.S_IFCHR):
		m |= os.ModeDevice | os.ModeCharDevice
	}
	if mode&uint32(unix.S_ISUID) != 0 {
		m |= os.ModeSetuid
	}
	if mode&uint32(unix.S_ISGID) != 0 {
		m |= os.ModeSetgid
	}
	if mode&uint32(unix.S_ISVTX) != 0 {
		m |= os.ModeSticky
	}
	return m
}
