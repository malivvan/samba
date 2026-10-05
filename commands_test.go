package samba

import (
	"os"
	"path/filepath"
	"testing"
)

// Protocol coverage for every command the server implements, driven through
// ProcessFrame on a real established session. These are the tests a file server
// needs: each command's success path, its parameter validation, and the errors
// a client can actually provoke.

// fixture is an established session with one share, plus frame builders.
type fixture struct {
	t     *testing.T
	srv   *Srv
	pc    *ProtoConn
	sess  uint64
	tree  uint32
	dir   string
	msgID uint64
}

func newFixture(t *testing.T, opts ...func(*Config)) *fixture {
	t.Helper()
	dir := t.TempDir()
	for _, name := range []string{"a.txt", "b.log"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("hello "+name), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Mkdir(filepath.Join(dir, "sub"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "sub", "inner.txt"), []byte("inner"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "readonly.txt"), []byte("ro"), 0o444); err != nil {
		t.Fatal(err)
	}
	cfg := &Config{}
	*cfg = newConfig()
	cfg.Shares = []ShareCfg{{Name: "t", Path: dir}}
	for _, opt := range opts {
		opt(cfg)
	}
	srv := testSrvFromConfig(t, cfg)
	pc := NewProtoConn(srv, 0, 0, 1)
	sess, tree := establish(t, srv, pc)
	return &fixture{t: t, srv: srv, pc: pc, sess: sess, tree: tree, dir: dir}
}

// testSrvFromConfig builds a shared context from a full configuration.
func testSrvFromConfig(t *testing.T, cfg *Config) *Srv {
	t.Helper()
	users, err := cfg.UserDB()
	if err != nil {
		t.Fatal(err)
	}
	return &Srv{
		cfg:        *cfg,
		guid:       [16]byte{9},
		maxRead:    MaxReadTarget,
		users:      users,
		allowGuest: cfg.GuestAllowed(),
		sessions:   NewRegistry(),
		mailboxes:  []*Mailbox{NewMailbox()},
		leases:     NewLeaseTable(),
	}
}

func (f *fixture) nextID() uint64 {
	f.msgID++
	return f.msgID
}

func (f *fixture) rt(frame []byte) resp {
	f.t.Helper()
	return roundtrip(f.t, f.srv, f.pc, frame)
}

// open opens a file and returns its FileId.
func (f *fixture) open(name string, disp, opts, desired uint32) uint64 {
	f.t.Helper()
	st, fid := createFile(f.t, f.srv, f.pc, f.sess, f.tree, name, disp, opts, desired)
	if st != StatusSuccess {
		f.t.Fatalf("open %q: status %#x", name, st)
	}
	return fid
}

func (f *fixture) closeFID(fid uint64) uint32 {
	f.t.Helper()
	w := reqHdr(CmdClose, f.nextID(), f.tree, f.sess)
	w.U16(24)
	w.U16(1)
	w.U32(0)
	w.U64(fid)
	w.U64(fid)
	return f.rt(w.Bytes()).status
}

func (f *fixture) writeAt(fid, off uint64, data []byte) uint32 {
	f.t.Helper()
	w := reqHdr(CmdWrite, f.nextID(), f.tree, f.sess)
	w.U16(49)
	w.U16(112)
	w.U32(uint32(len(data)))
	w.U64(off)
	w.U64(fid)
	w.U64(fid)
	w.U32(0)
	w.U32(0)
	w.U16(0)
	w.U16(0)
	w.U32(0)
	w.Bytes8(data)
	return f.rt(w.Bytes()).status
}

func (f *fixture) readAt(fid, off uint64, length uint32) resp {
	f.t.Helper()
	r := reqHdr(CmdRead, f.nextID(), f.tree, f.sess)
	r.U16(49)
	r.U8(0)
	r.U8(0)
	r.U32(length)
	r.U64(off)
	r.U64(fid)
	r.U64(fid)
	r.U32(0)
	r.U32(0)
	r.U32(0)
	r.U16(0)
	r.U16(0)
	r.U8(0)
	return f.rt(r.Bytes())
}

// infoFrame builds a QUERY_INFO or SET_INFO request.
func (f *fixture) infoFrame(cmd uint16, fid uint64, infoType, class uint8, data []byte, outLen uint32) []byte {
	w := reqHdr(cmd, f.nextID(), f.tree, f.sess)
	if cmd == CmdQueryInfo {
		w.U16(41)
		w.U8(infoType)
		w.U8(class)
		w.U32(outLen)
		w.U16(0) // input buffer offset
		w.U16(0)
		w.U32(0) // input buffer length
		w.U32(0) // additional information
		w.U32(0) // flags
		w.U64(fid)
		w.U64(fid)
		return w.Bytes()
	}
	w.U16(33)
	w.U8(infoType)
	w.U8(class)
	w.U32(uint32(len(data)))
	w.U16(96) // buffer offset (64 header + 32 body)
	w.U16(0)
	w.U32(0)
	w.U64(fid)
	w.U64(fid)
	w.Bytes8(data)
	return w.Bytes()
}

func (f *fixture) queryInfo(fid uint64, infoType, class uint8, outLen uint32) resp {
	f.t.Helper()
	return f.rt(f.infoFrame(CmdQueryInfo, fid, infoType, class, nil, outLen))
}

func (f *fixture) setInfo(fid uint64, class uint8, data []byte) uint32 {
	f.t.Helper()
	return f.rt(f.infoFrame(CmdSetInfo, fid, infoFile, class, data, 0)).status
}

func (f *fixture) flush(fid uint64) uint32 {
	f.t.Helper()
	w := reqHdr(CmdFlush, f.nextID(), f.tree, f.sess)
	w.U16(24)
	w.U16(0)
	w.U32(0)
	w.U64(fid)
	w.U64(fid)
	return f.rt(w.Bytes()).status
}

// queryDir lists a directory handle.
func (f *fixture) queryDir(fid uint64, class, flags uint8, pattern string, outLen uint32) resp {
	f.t.Helper()
	pat := UTF16LE(pattern)
	w := reqHdr(CmdQueryDirectory, f.nextID(), f.tree, f.sess)
	w.U16(33)
	w.U8(class)
	w.U8(flags)
	w.U32(0)
	w.U64(fid)
	w.U64(fid)
	w.U16(96)
	w.U16(uint16(len(pat)))
	w.U32(outLen)
	w.Bytes8(pat)
	return f.rt(w.Bytes())
}

type lockElem struct {
	off, length uint64
	flags       uint32
}

func (f *fixture) lock(fid uint64, elems ...lockElem) uint32 {
	f.t.Helper()
	w := reqHdr(CmdLock, f.nextID(), f.tree, f.sess)
	w.U16(48)
	w.U16(uint16(len(elems)))
	w.U32(0)
	w.U64(fid)
	w.U64(fid)
	for _, e := range elems {
		w.U64(e.off)
		w.U64(e.length)
		w.U32(e.flags)
		w.U32(0)
	}
	return f.rt(w.Bytes()).status
}

func TestCommandFlush(t *testing.T) {
	f := newFixture(t)
	fid := f.open("a.txt", fileOpen, 0x40, 0x1000_0000)
	if st := f.flush(fid); st != StatusSuccess {
		t.Fatalf("flush status %#x", st)
	}
	// A bad structure size is rejected.
	w := reqHdr(CmdFlush, f.nextID(), f.tree, f.sess)
	w.U16(9)
	if st := f.rt(w.Bytes()).status; st != StatusInvalidParameter {
		t.Fatalf("bad structure size status %#x", st)
	}
	// An unknown handle is refused.
	if st := f.flush(0xDEAD); st != StatusFileClosed {
		t.Fatalf("unknown handle status %#x", st)
	}
}

func TestCommandLogoff(t *testing.T) {
	f := newFixture(t)
	w := reqHdr(CmdLogoff, f.nextID(), 0, f.sess)
	w.U16(4)
	w.U16(0)
	if r := f.rt(w.Bytes()); r.status != StatusSuccess {
		t.Fatalf("logoff status %#x", r.status)
	}
	// The channel is gone, so a follow-up request reports the session as dead.
	if st, _ := createFile(t, f.srv, f.pc, f.sess, f.tree, "a.txt", fileOpen, 0x40, 0x8000_0000); st != StatusUserSessionDeleted {
		t.Fatalf("after logoff status %#x, want USER_SESSION_DELETED", st)
	}
	// A second logoff on the same (now unknown) session is refused.
	if r := f.rt(w.Bytes()); r.status != StatusUserSessionDeleted {
		t.Fatalf("second logoff status %#x", r.status)
	}
}

func TestCommandTreeDisconnect(t *testing.T) {
	f := newFixture(t)
	w := reqHdr(CmdTreeDisconnect, f.nextID(), f.tree, f.sess)
	w.U16(4)
	w.U16(0)
	if r := f.rt(w.Bytes()); r.status != StatusSuccess {
		t.Fatalf("tree disconnect status %#x", r.status)
	}
	if st, _ := createFile(t, f.srv, f.pc, f.sess, f.tree, "a.txt", fileOpen, 0x40, 0x8000_0000); st != StatusNetworkNameDeleted {
		t.Fatalf("after disconnect status %#x, want NETWORK_NAME_DELETED", st)
	}
	// A tree that was never connected is rejected too.
	w = reqHdr(CmdTreeDisconnect, f.nextID(), 0x2BAD, f.sess)
	w.U16(4)
	w.U16(0)
	if r := f.rt(w.Bytes()); r.status != StatusNetworkNameDeleted {
		t.Fatalf("unknown tree status %#x", r.status)
	}
}

func TestCommandIpcShare(t *testing.T) {
	f := newFixture(t)
	path := UTF16LE(`\\srv\IPC$`)
	w := reqHdr(CmdTreeConnect, f.nextID(), 0, f.sess)
	w.U16(9)
	w.U16(0)
	w.U16(72)
	w.U16(uint16(len(path)))
	w.Bytes8(path)
	r := f.rt(w.Bytes())
	if r.status != StatusSuccess {
		t.Fatalf("IPC$ connect status %#x", r.status)
	}
	if shareType := r.body[2]; shareType != 2 {
		t.Fatalf("IPC$ share type = %d, want 2 (pipe)", shareType)
	}
	// The stub tree allows IOCTL only.
	ioctl := reqHdr(CmdIoctl, f.nextID(), r.treeID, f.sess)
	ioctl.U16(57)
	ioctl.U16(0)
	ioctl.U32(fsctlValidateNegotiateInfo)
	ioctl.Zeros(16)
	ioctl.U32(0)
	ioctl.U32(0)
	ioctl.U32(112)
	ioctl.U32(0)
	ioctl.U32(112)
	ioctl.U32(0)
	ioctl.U32(0)
	ioctl.U32(0)
	if got := f.rt(ioctl.Bytes()).status; got != StatusSuccess {
		t.Fatalf("IPC$ ioctl status %#x", got)
	}
	// Anything else on the pipe tree is refused.
	create := reqHdr(CmdCreate, f.nextID(), r.treeID, f.sess)
	create.U16(57)
	create.U8(0)
	create.U8(0)
	create.U32(2)
	create.U64(0)
	create.U64(0)
	create.U32(0x8000_0000)
	create.U32(0)
	create.U32(7)
	create.U32(fileOpen)
	create.U32(0)
	create.U16(120)
	create.U16(0)
	create.U32(0)
	create.U32(0)
	if got := f.rt(create.Bytes()).status; got != StatusAccessDenied {
		t.Fatalf("IPC$ create status %#x, want ACCESS_DENIED", got)
	}
	// And an unknown share name is a bad network name.
	bad := UTF16LE(`\\srv\nosuchshare`)
	w = reqHdr(CmdTreeConnect, f.nextID(), 0, f.sess)
	w.U16(9)
	w.U16(0)
	w.U16(72)
	w.U16(uint16(len(bad)))
	w.Bytes8(bad)
	if got := f.rt(w.Bytes()).status; got != StatusBadNetworkName {
		t.Fatalf("unknown share status %#x, want BAD_NETWORK_NAME", got)
	}
}

func TestCommandCreateVariants(t *testing.T) {
	f := newFixture(t)
	const read = uint32(0x8000_0000)
	const write = uint32(genericWrite)
	const all = uint32(0x1000_0000)

	t.Run("create new", func(t *testing.T) {
		st, _ := createFile(t, f.srv, f.pc, f.sess, f.tree, "new.txt", fileCreate, 0x40, all)
		if st != StatusSuccess {
			t.Fatalf("status %#x", st)
		}
		// Again: the file exists now.
		if st, _ := createFile(t, f.srv, f.pc, f.sess, f.tree, "new.txt", fileCreate, 0x40, all); st != StatusObjectNameCollision {
			t.Fatalf("status %#x, want OBJECT_NAME_COLLISION", st)
		}
	})
	t.Run("open missing", func(t *testing.T) {
		if st, _ := createFile(t, f.srv, f.pc, f.sess, f.tree, "missing.txt", fileOpen, 0x40, read); st != StatusObjectNameNotFound {
			t.Fatalf("status %#x, want OBJECT_NAME_NOT_FOUND", st)
		}
		if st, _ := createFile(t, f.srv, f.pc, f.sess, f.tree, "missing.txt", fileOverwrite, 0x40, read); st != StatusObjectNameNotFound {
			t.Fatalf("overwrite status %#x, want OBJECT_NAME_NOT_FOUND", st)
		}
	})
	t.Run("open if creates", func(t *testing.T) {
		st, fid := createFile(t, f.srv, f.pc, f.sess, f.tree, "openif.txt", fileOpenIf, 0x40, all)
		if st != StatusSuccess {
			t.Fatalf("status %#x", st)
		}
		if f.closeFID(fid) != StatusSuccess {
			t.Fatal("close failed")
		}
		if _, err := os.Stat(filepath.Join(f.dir, "openif.txt")); err != nil {
			t.Fatalf("open-if must create: %v", err)
		}
	})
	t.Run("directory requested on a file", func(t *testing.T) {
		if st, _ := createFile(t, f.srv, f.pc, f.sess, f.tree, "a.txt", fileOpen, fileDirectoryFile, read); st != StatusNotADirectory {
			t.Fatalf("status %#x, want NOT_A_DIRECTORY", st)
		}
	})
	t.Run("file requested on a directory", func(t *testing.T) {
		if st, _ := createFile(t, f.srv, f.pc, f.sess, f.tree, "sub", fileOpen, fileNonDirectoryFile, read); st != StatusFileIsADirectory {
			t.Fatalf("status %#x, want FILE_IS_A_DIRECTORY", st)
		}
	})
	t.Run("mkdir", func(t *testing.T) {
		st, fid := createFile(t, f.srv, f.pc, f.sess, f.tree, "madethis", fileCreate, fileDirectoryFile, read)
		if st != StatusSuccess {
			t.Fatalf("status %#x", st)
		}
		fi, err := os.Stat(filepath.Join(f.dir, "madethis"))
		if err != nil || !fi.IsDir() {
			t.Fatalf("mkdir did not create a directory: %v", err)
		}
		if f.closeFID(fid) != StatusSuccess {
			t.Fatal("close failed")
		}
	})
	t.Run("delete on close", func(t *testing.T) {
		st, fid := createFile(t, f.srv, f.pc, f.sess, f.tree, "doomed.txt", fileOverwriteIf, 0x40|fileDeleteOnClose, all)
		if st != StatusSuccess {
			t.Fatalf("status %#x", st)
		}
		if f.closeFID(fid) != StatusSuccess {
			t.Fatal("close failed")
		}
		if _, err := os.Stat(filepath.Join(f.dir, "doomed.txt")); !os.IsNotExist(err) {
			t.Fatalf("delete-on-close must remove the file: %v", err)
		}
	})
	t.Run("traversal", func(t *testing.T) {
		if st, _ := createFile(t, f.srv, f.pc, f.sess, f.tree, `..\escape`, fileOpenIf, 0x40, all); st != StatusObjectNameInvalid {
			t.Fatalf("status %#x, want OBJECT_NAME_INVALID", st)
		}
	})
	t.Run("read-only file without write access", func(t *testing.T) {
		// A file with no write permission opens read-only even for a writable
		// request only if the process cannot write it; the mode here is 0444 and
		// the test process owns it, so this exercises the MAXIMUM_ALLOWED
		// fallback instead.
		st, fid := createFile(t, f.srv, f.pc, f.sess, f.tree, "readonly.txt", fileOpen, 0x40, maximumAllowed)
		if st != StatusSuccess {
			t.Fatalf("status %#x", st)
		}
		if got := f.writeAt(fid, 0, []byte("nope")); got == StatusSuccess {
			t.Log("write to a read-only-mode file succeeded (running as owner)")
		}
		f.closeFID(fid)
	})
}

func TestCommandCreateOnReadOnlyShare(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "f.txt"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg := &Config{}
	*cfg = newConfig()
	cfg.Shares = []ShareCfg{{Name: "t", Path: dir, ReadOnly: true}}
	srv := testSrvFromConfig(t, cfg)
	pc := NewProtoConn(srv, 0, 0, 1)
	sess, tree := establish(t, srv, pc)

	// Opening for read is fine.
	if st, _ := createFile(t, srv, pc, sess, tree, "f.txt", fileOpen, 0x40, 0x8000_0000); st != StatusSuccess {
		t.Fatalf("read open status %#x", st)
	}
	// Creating, writing or deleting on a read-only share is refused.
	if st, _ := createFile(t, srv, pc, sess, tree, "new.txt", fileOverwriteIf, 0x40, 0x1000_0000); st != StatusAccessDenied {
		t.Fatalf("create status %#x, want ACCESS_DENIED", st)
	}
	if st, _ := createFile(t, srv, pc, sess, tree, "f.txt", fileOpen, 0x40|fileDeleteOnClose, 0x8000_0000); st != StatusAccessDenied {
		t.Fatalf("delete-on-close status %#x, want ACCESS_DENIED", st)
	}
	if st, _ := createFile(t, srv, pc, sess, tree, "f.txt", fileOpen, 0x40, genericWrite); st != StatusAccessDenied {
		t.Fatalf("write open status %#x, want ACCESS_DENIED", st)
	}
}

func TestCommandReadVariants(t *testing.T) {
	f := newFixture(t)
	fid := f.open("a.txt", fileOpen, 0x40, 0x8000_0000)
	defer f.closeFID(fid)

	// A normal read returns the file's bytes.
	r := f.readAt(fid, 0, 5)
	if r.status != StatusSuccess {
		t.Fatalf("read status %#x", r.status)
	}
	if got := string(r.body[16 : 16+5]); got != "hello" {
		t.Fatalf("read %q", got)
	}
	// Reading at EOF is an EOF, not an empty success.
	if r := f.readAt(fid, 1<<20, 16); r.status != StatusEndOfFile {
		t.Fatalf("read past EOF status %#x, want END_OF_FILE", r.status)
	}
	// A minimum count that cannot be met is also an EOF.
	w := reqHdr(CmdRead, f.nextID(), f.tree, f.sess)
	w.U16(49)
	w.U8(0)
	w.U8(0)
	w.U32(4096)
	w.U64(0)
	w.U64(fid)
	w.U64(fid)
	w.U32(4096) // MinimumCount larger than the file
	w.U32(0)
	w.U32(0)
	w.U16(0)
	w.U16(0)
	w.U8(0)
	if r := f.rt(w.Bytes()); r.status != StatusEndOfFile {
		t.Fatalf("short read status %#x, want END_OF_FILE", r.status)
	}
	// A directory cannot be read.
	dfid := f.open("sub", fileOpen, fileDirectoryFile, 0x8000_0000)
	defer f.closeFID(dfid)
	if r := f.readAt(dfid, 0, 16); r.status != StatusInvalidDeviceRequest {
		t.Fatalf("read of a directory status %#x, want INVALID_DEVICE_REQUEST", r.status)
	}
	// A malformed request is rejected.
	w = reqHdr(CmdRead, f.nextID(), f.tree, f.sess)
	w.U16(9)
	if r := f.rt(w.Bytes()); r.status != StatusInvalidParameter {
		t.Fatalf("bad structure size status %#x", r.status)
	}
}

func TestCommandWriteVariants(t *testing.T) {
	f := newFixture(t)
	fid := f.open("w.txt", fileOverwriteIf, 0x40, genericWrite)
	if st := f.writeAt(fid, 0, []byte("data")); st != StatusSuccess {
		t.Fatalf("write status %#x", st)
	}
	got, err := os.ReadFile(filepath.Join(f.dir, "w.txt"))
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "data" {
		t.Fatalf("file contains %q", got)
	}
	// A read-only handle refuses writes.
	ro := f.open("a.txt", fileOpen, 0x40, 0x8000_0000)
	if st := f.writeAt(ro, 0, []byte("nope")); st != StatusAccessDenied {
		t.Fatalf("write on a read handle status %#x, want ACCESS_DENIED", st)
	}
	// A bad structure size and an unknown handle are rejected.
	w := reqHdr(CmdWrite, f.nextID(), f.tree, f.sess)
	w.U16(9)
	if st := f.rt(w.Bytes()).status; st != StatusInvalidParameter {
		t.Fatalf("bad structure size status %#x", st)
	}
	if st := f.writeAt(0xDEAD, 0, []byte("x")); st != StatusFileClosed {
		t.Fatalf("unknown handle status %#x", st)
	}
	if st := f.writeAt(fid, 0, nil); st != StatusSuccess {
		t.Fatalf("zero-length write status %#x", st)
	}
}

func TestCommandQueryInfoClasses(t *testing.T) {
	f := newFixture(t)
	fid := f.open("a.txt", fileOpen, 0x40, 0x8000_0000)
	defer f.closeFID(fid)
	dfid := f.open("sub", fileOpen, fileDirectoryFile, 0x8000_0000)
	defer f.closeFID(dfid)

	fileClasses := []struct {
		class uint8
		size  int
	}{
		{4, 40},  // FileBasicInformation
		{5, 24},  // FileStandardInformation
		{6, 8},   // FileInternalInformation
		{7, 4},   // FileEaInformation
		{8, 4},   // FileAccessInformation
		{14, 8},  // FilePositionInformation
		{16, 4},  // FileModeInformation
		{17, 4},  // FileAlignmentInformation
		{34, 56}, // FileNetworkOpenInformation
		{35, 8},  // FileAttributeTagInformation
	}
	for _, c := range fileClasses {
		r := f.queryInfo(fid, infoFile, c.class, 4096)
		if r.status != StatusSuccess {
			t.Fatalf("class %d status %#x", c.class, r.status)
		}
		if got := int(le32(r.body[4:8])); got != c.size {
			t.Fatalf("class %d returned %d bytes, want %d", c.class, got, c.size)
		}
	}
	// FileNameInformation and FileAllInformation carry the name.
	for _, class := range []uint8{9, 18} {
		r := f.queryInfo(fid, infoFile, class, 4096)
		if r.status != StatusSuccess {
			t.Fatalf("class %d status %#x", class, r.status)
		}
		if !containsBytes(r.body, UTF16LE(`\a.txt`)) {
			t.Fatalf("class %d must carry the file name", class)
		}
	}
	// FileStreamInformation names the default stream for a file...
	r := f.queryInfo(fid, infoFile, 22, 4096)
	if r.status != StatusSuccess || !containsBytes(r.body, UTF16LE("::$DATA")) {
		t.Fatalf("class 22 status %#x", r.status)
	}
	// ...and is empty for a directory.
	if r := f.queryInfo(dfid, infoFile, 22, 4096); r.status != StatusSuccess || le32(r.body[4:8]) != 0 {
		t.Fatalf("directory class 22 returned %d bytes", le32(r.body[4:8]))
	}
	// An unknown class is not supported.
	if r := f.queryInfo(fid, infoFile, 99, 4096); r.status != StatusNotSupported {
		t.Fatalf("unknown class status %#x, want NOT_SUPPORTED", r.status)
	}
	// Filesystem information classes.
	for _, class := range []uint8{1, 3, 4, 5, 7} {
		if r := f.queryInfo(fid, infoFilesystem, class, 4096); r.status != StatusSuccess {
			t.Fatalf("filesystem class %d status %#x", class, r.status)
		}
	}
	if r := f.queryInfo(fid, infoFilesystem, 99, 4096); r.status != StatusNotSupported {
		t.Fatalf("unknown filesystem class status %#x", r.status)
	}
	// The security descriptor is synthesized for clients that demand one.
	r = f.queryInfo(fid, infoSecurity, 0, 4096)
	if r.status != StatusSuccess || int(le32(r.body[4:8])) != 80 {
		t.Fatalf("security query status %#x, size %d", r.status, le32(r.body[4:8]))
	}
	// An unknown information type is refused.
	if r := f.queryInfo(fid, 9, 4, 4096); r.status != StatusNotSupported {
		t.Fatalf("unknown info type status %#x", r.status)
	}
	// A short output buffer overflows rather than failing.
	r = f.queryInfo(fid, infoFile, 18, 8)
	if r.status != StatusBufferOverflow {
		t.Fatalf("short buffer status %#x, want BUFFER_OVERFLOW", r.status)
	}
	if got := int(le32(r.body[4:8])); got != 8 {
		t.Fatalf("truncated to %d bytes, want 8", got)
	}
	// A bad handle and a bad structure size are rejected.
	if r := f.queryInfo(0xDEAD, infoFile, 4, 4096); r.status != StatusFileClosed {
		t.Fatalf("unknown handle status %#x", r.status)
	}
	w := reqHdr(CmdQueryInfo, f.nextID(), f.tree, f.sess)
	w.U16(9)
	if r := f.rt(w.Bytes()); r.status != StatusInvalidParameter {
		t.Fatalf("bad structure size status %#x", r.status)
	}
}

func TestCommandSetInfoClasses(t *testing.T) {
	f := newFixture(t)

	t.Run("basic information", func(t *testing.T) {
		fid := f.open("a.txt", fileOpen, 0x40, 0x1000_0000)
		defer f.closeFID(fid)
		// Change time = all ones means "leave unchanged"; atime/mtime are set.
		data := NewWriter(0)
		data.U64(^uint64(0)) // creation time: omit
		data.U64(0)          // access time: omit
		data.U64(0)          // write time: omit
		data.U64(^uint64(0)) // change time: omit
		data.U32(AttrArchive)
		data.U32(0)
		if st := f.setInfo(fid, 4, data.Bytes()); st != StatusSuccess {
			t.Fatalf("status %#x", st)
		}
		// A short buffer is rejected.
		if st := f.setInfo(fid, 4, []byte{0, 1, 2}); st != StatusInvalidParameter {
			t.Fatalf("short buffer status %#x", st)
		}
	})

	t.Run("mtime is applied", func(t *testing.T) {
		fid := f.open("a.txt", fileOpen, 0x40, 0x1000_0000)
		defer f.closeFID(fid)
		want := filetimeNow() - 86400*10_000_000 // ten days ago
		data := NewWriter(0)
		data.U64(0)
		data.U64(0)
		data.U64(want)
		data.U64(0)
		data.U32(0)
		data.U32(0)
		if st := f.setInfo(fid, 4, data.Bytes()); st != StatusSuccess {
			t.Fatalf("status %#x", st)
		}
		fi, err := os.Stat(filepath.Join(f.dir, "a.txt"))
		if err != nil {
			t.Fatal(err)
		}
		got := timeToFiletime(fi.ModTime())
		if absDiff(got, want) > 2*10_000_000 { // within two seconds
			t.Fatalf("mtime = %d, want ~%d", got, want)
		}
	})

	t.Run("rename", func(t *testing.T) {
		fid := f.open("b.log", fileOpen, 0x40, 0x1000_0000)
		name := UTF16LE(`renamed.log`)
		data := NewWriter(0)
		data.U8(1) // replace if exists
		data.Zeros(7)
		data.U64(0)
		data.U32(uint32(len(name)))
		data.Bytes8(name)
		if st := f.setInfo(fid, 10, data.Bytes()); st != StatusSuccess {
			t.Fatalf("status %#x", st)
		}
		if _, err := os.Stat(filepath.Join(f.dir, "renamed.log")); err != nil {
			t.Fatalf("rename did not move the file: %v", err)
		}
		// The handle follows the rename.
		r := f.queryInfo(fid, infoFile, 9, 4096)
		if !containsBytes(r.body, UTF16LE(`\renamed.log`)) {
			t.Fatal("the handle must follow the rename")
		}
		// Renaming without replace onto an existing name collides.
		name = UTF16LE(`a.txt`)
		data = NewWriter(0)
		data.U8(0)
		data.Zeros(7)
		data.U64(0)
		data.U32(uint32(len(name)))
		data.Bytes8(name)
		if st := f.setInfo(fid, 10, data.Bytes()); st != StatusObjectNameCollision {
			t.Fatalf("status %#x, want OBJECT_NAME_COLLISION", st)
		}
		// With replace it succeeds.
		data = NewWriter(0)
		data.U8(1)
		data.Zeros(7)
		data.U64(0)
		data.U32(uint32(len(name)))
		data.Bytes8(name)
		if st := f.setInfo(fid, 10, data.Bytes()); st != StatusSuccess {
			t.Fatalf("replace status %#x", st)
		}
		// Traversal is refused.
		name = UTF16LE(`..\escape`)
		data = NewWriter(0)
		data.U8(1)
		data.Zeros(7)
		data.U64(0)
		data.U32(uint32(len(name)))
		data.Bytes8(name)
		if st := f.setInfo(fid, 10, data.Bytes()); st != StatusObjectNameInvalid {
			t.Fatalf("traversal status %#x, want OBJECT_NAME_INVALID", st)
		}
		f.closeFID(fid)
	})

	t.Run("truncate", func(t *testing.T) {
		fid := f.open("trunc.txt", fileOverwriteIf, 0x40, genericWrite)
		if st := f.writeAt(fid, 0, []byte("0123456789")); st != StatusSuccess {
			t.Fatalf("write status %#x", st)
		}
		data := NewWriter(0)
		data.U64(4)
		if st := f.setInfo(fid, 20, data.Bytes()); st != StatusSuccess {
			t.Fatalf("truncate status %#x", st)
		}
		got, err := os.ReadFile(filepath.Join(f.dir, "trunc.txt"))
		if err != nil {
			t.Fatal(err)
		}
		if string(got) != "0123" {
			t.Fatalf("file contains %q after truncate", got)
		}
		// A short buffer is rejected.
		if st := f.setInfo(fid, 20, []byte{0, 1}); st != StatusInvalidParameter {
			t.Fatalf("short truncate status %#x", st)
		}
		f.closeFID(fid)
	})

	t.Run("disposition", func(t *testing.T) {
		st, fid := createFile(t, f.srv, f.pc, f.sess, f.tree, "dod.txt", fileOverwriteIf, 0x40, 0x1000_0000)
		if st != StatusSuccess {
			t.Fatalf("create status %#x", st)
		}
		if st := f.setInfo(fid, 13, []byte{1}); st != StatusSuccess {
			t.Fatalf("status %#x", st)
		}
		if f.closeFID(fid) != StatusSuccess {
			t.Fatal("close failed")
		}
		if _, err := os.Stat(filepath.Join(f.dir, "dod.txt")); !os.IsNotExist(err) {
			t.Fatalf("delete-on-close must remove the file: %v", err)
		}
		// A non-empty directory cannot be marked for deletion.
		dfid := f.open("sub", fileOpen, fileDirectoryFile, 0x1000_0000)
		if st := f.setInfo(dfid, 13, []byte{1}); st != StatusDirectoryNotEmpty {
			t.Fatalf("non-empty dir status %#x, want DIRECTORY_NOT_EMPTY", st)
		}
		f.closeFID(dfid)
		// An empty buffer is invalid.
		fid2 := f.open("a.txt", fileOpen, 0x40, 0x1000_0000)
		if st := f.setInfo(fid2, 13, nil); st != StatusInvalidParameter {
			t.Fatalf("empty disposition status %#x", st)
		}
		f.closeFID(fid2)
	})

	t.Run("allocation is a no-op", func(t *testing.T) {
		fid := f.open("a.txt", fileOpen, 0x40, 0x1000_0000)
		defer f.closeFID(fid)
		data := NewWriter(0)
		data.U64(4096)
		if st := f.setInfo(fid, 19, data.Bytes()); st != StatusSuccess {
			t.Fatalf("status %#x", st)
		}
	})

	t.Run("unsupported classes", func(t *testing.T) {
		fid := f.open("a.txt", fileOpen, 0x40, 0x1000_0000)
		defer f.closeFID(fid)
		if st := f.setInfo(fid, 21, []byte{0}); st != StatusNotSupported {
			t.Fatalf("class 21 status %#x, want NOT_SUPPORTED", st)
		}
		// A filesystem information type is not supported either.
		w := f.infoFrame(CmdSetInfo, fid, infoFilesystem, 1, nil, 0)
		if r := f.rt(w); r.status != StatusNotSupported {
			t.Fatalf("filesystem set info status %#x", r.status)
		}
		// A bad structure size and an unknown handle are rejected.
		bad := reqHdr(CmdSetInfo, f.nextID(), f.tree, f.sess)
		bad.U16(9)
		if r := f.rt(bad.Bytes()); r.status != StatusInvalidParameter {
			t.Fatalf("bad structure size status %#x", r.status)
		}
		w = f.infoFrame(CmdSetInfo, 0xDEAD, infoFile, 19, make([]byte, 8), 0)
		if r := f.rt(w); r.status != StatusFileClosed {
			t.Fatalf("unknown handle status %#x", r.status)
		}
	})
}

func TestCommandSetInfoOnReadOnlyShare(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "f.txt"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg := &Config{}
	*cfg = newConfig()
	cfg.Shares = []ShareCfg{{Name: "t", Path: dir, ReadOnly: true}}
	srv := testSrvFromConfig(t, cfg)
	pc := NewProtoConn(srv, 0, 0, 1)
	sess, tree := establish(t, srv, pc)
	f := &fixture{t: t, srv: srv, pc: pc, sess: sess, tree: tree, dir: dir}
	st, fid := createFile(t, srv, pc, sess, tree, "f.txt", fileOpen, 0x40, 0x8000_0000)
	if st != StatusSuccess {
		t.Fatalf("open status %#x", st)
	}
	data := NewWriter(0)
	data.U64(0)
	if got := f.setInfo(fid, 20, data.Bytes()); got != StatusAccessDenied {
		t.Fatalf("set info on a read-only share status %#x, want ACCESS_DENIED", got)
	}
}

func TestCommandLock(t *testing.T) {
	f := newFixture(t)
	const (
		lockShared    = 0x1
		lockExclusive = 0x2
		lockUnlock    = 0x4
	)
	first := f.open("a.txt", fileOpen, 0x40, 0x1000_0000)
	second := f.open("a.txt", fileOpen, 0x40, 0x1000_0000)
	defer f.closeFID(first)
	defer f.closeFID(second)

	// A shared lock is granted to both handles.
	if st := f.lock(first, lockElem{0, 100, lockShared}); st != StatusSuccess {
		t.Fatalf("shared lock status %#x", st)
	}
	if st := f.lock(second, lockElem{0, 100, lockShared}); st != StatusSuccess {
		t.Fatalf("second shared lock status %#x", st)
	}
	// An exclusive lock over the same range conflicts...
	if st := f.lock(first, lockElem{0, 100, lockExclusive}); st != StatusLockNotGranted {
		t.Fatalf("conflicting exclusive lock status %#x, want LOCK_NOT_GRANTED", st)
	}
	// ...but a range nobody holds is fine.
	if st := f.lock(first, lockElem{200, 100, lockExclusive}); st != StatusSuccess {
		t.Fatalf("disjoint exclusive lock status %#x", st)
	}
	// Unlocking releases it.
	if st := f.lock(first, lockElem{200, 100, lockUnlock}); st != StatusSuccess {
		t.Fatalf("unlock status %#x", st)
	}
	if st := f.lock(second, lockElem{200, 100, lockExclusive}); st != StatusSuccess {
		t.Fatalf("lock after unlock status %#x", st)
	}

	// A batch is all-or-nothing: a conflict unwinds the locks it already took.
	third := f.open("a.txt", fileOpen, 0x40, 0x1000_0000)
	defer f.closeFID(third)
	st := f.lock(third, lockElem{1000, 10, lockExclusive}, lockElem{200, 100, lockExclusive})
	if st != StatusLockNotGranted {
		t.Fatalf("batch status %#x, want LOCK_NOT_GRANTED", st)
	}
	// The first element of the batch must have been unwound, so another handle
	// can take it.
	if st := f.lock(first, lockElem{1000, 10, lockExclusive}); st != StatusSuccess {
		t.Fatalf("unwound lock status %#x", st)
	}

	// A lock with no kind at all is a parameter error.
	if st := f.lock(first, lockElem{0, 10, 0}); st != StatusInvalidParameter {
		t.Fatalf("kindless lock status %#x, want INVALID_PARAMETER", st)
	}
	// An empty batch and an oversized one are rejected.
	if st := f.lock(first); st != StatusInvalidParameter {
		t.Fatalf("empty batch status %#x", st)
	}
	elems := make([]lockElem, 65)
	for i := range elems {
		elems[i] = lockElem{uint64(i) * 4096, 1, lockShared}
	}
	if st := f.lock(first, elems...); st != StatusInvalidParameter {
		t.Fatalf("oversized batch status %#x", st)
	}
	// A directory cannot be locked, and an unknown handle is refused.
	dfid := f.open("sub", fileOpen, fileDirectoryFile, 0x1000_0000)
	defer f.closeFID(dfid)
	if st := f.lock(dfid, lockElem{0, 10, lockShared}); st != StatusInvalidParameter {
		t.Fatalf("directory lock status %#x", st)
	}
	if st := f.lock(0xDEAD, lockElem{0, 10, lockShared}); st != StatusFileClosed {
		t.Fatalf("unknown handle status %#x", st)
	}
	// A truncated body is rejected.
	w := reqHdr(CmdLock, f.nextID(), f.tree, f.sess)
	w.U16(48)
	w.U16(1)
	w.U32(0)
	w.U64(first)
	w.U64(first)
	w.U64(0)
	if st := f.rt(w.Bytes()).status; st != StatusInvalidParameter {
		t.Fatalf("truncated lock status %#x", st)
	}
}

func TestCommandQueryDirectoryClasses(t *testing.T) {
	f := newFixture(t)
	dfid := f.open("", fileOpen, 0x1, 0x8000_0000)
	defer f.closeFID(dfid)

	classes := []uint8{
		fileDirectoryInformation,
		fileFullDirectoryInformation,
		fileBothDirectoryInformation,
		fileNameInformation,
		fileIDBothDirectoryInformation,
		fileIDFullDirectoryInformation,
	}
	for _, class := range classes {
		r := f.queryDir(dfid, class, qdRestartScans, "*", 65536)
		if r.status != StatusSuccess {
			t.Fatalf("class %d status %#x", class, r.status)
		}
		for _, name := range []string{"a.txt", "b.log", "sub"} {
			if !containsBytes(r.body, UTF16LE(name)) {
				t.Fatalf("class %d listing is missing %s", class, name)
			}
		}
	}
	// An unknown class is a parameter error.
	if r := f.queryDir(dfid, 99, qdRestartScans, "*", 65536); r.status != StatusInvalidParameter {
		t.Fatalf("unknown class status %#x, want INVALID_PARAMETER", r.status)
	}
	// A pattern that matches nothing reports no such file.
	if r := f.queryDir(dfid, fileIDBothDirectoryInformation, qdRestartScans, "nomatch*", 65536); r.status != StatusNoSuchFile {
		t.Fatalf("unmatched pattern status %#x, want NO_SUCH_FILE", r.status)
	}
	// A single-entry request returns one entry and a continuation ends.
	r := f.queryDir(dfid, fileIDBothDirectoryInformation, qdRestartScans|qdReturnSingle, "*", 65536)
	if r.status != StatusSuccess {
		t.Fatalf("single status %#x", r.status)
	}
	if next := le32(r.body[8+4 : 8+8]); next != 0 {
		t.Fatalf("a single-entry response must terminate the list (next = %d)", next)
	}
	// A buffer too small for even one entry overflows.
	if r := f.queryDir(dfid, fileIDBothDirectoryInformation, qdRestartScans, "*", 1); r.status != StatusBufferTooSmall {
		t.Fatalf("tiny buffer status %#x, want BUFFER_TOO_SMALL", r.status)
	}
	// Walking past the end reports no more files.
	f.queryDir(dfid, fileIDBothDirectoryInformation, qdRestartScans, "*", 65536)
	if r := f.queryDir(dfid, fileIDBothDirectoryInformation, 0, "*", 65536); r.status != StatusNoMoreFiles {
		t.Fatalf("exhausted listing status %#x, want NO_MORE_FILES", r.status)
	}
	// Reopening restarts it.
	if r := f.queryDir(dfid, fileIDBothDirectoryInformation, qdReopen, "*", 65536); r.status != StatusSuccess {
		t.Fatalf("reopen status %#x", r.status)
	}
	// A file handle cannot be enumerated.
	fid := f.open("a.txt", fileOpen, 0x40, 0x8000_0000)
	defer f.closeFID(fid)
	if r := f.queryDir(fid, fileIDBothDirectoryInformation, qdRestartScans, "*", 65536); r.status != StatusInvalidParameter {
		t.Fatalf("file handle status %#x", r.status)
	}
	// An unknown handle is refused.
	if r := f.queryDir(0xDEAD, fileIDBothDirectoryInformation, 0, "*", 65536); r.status != StatusFileClosed {
		t.Fatalf("unknown handle status %#x", r.status)
	}
}

func TestCommandIoctlUnknown(t *testing.T) {
	f := newFixture(t)
	w := reqHdr(CmdIoctl, f.nextID(), f.tree, f.sess)
	w.U16(57)
	w.U16(0)
	w.U32(0x0014_0999)
	w.Zeros(16)
	w.U32(0)
	w.U32(0)
	w.U32(112)
	w.U32(0)
	w.U32(112)
	w.U32(0)
	w.U32(0)
	w.U32(0)
	if r := f.rt(w.Bytes()); r.status != StatusNotSupported {
		t.Fatalf("unknown ioctl status %#x, want NOT_SUPPORTED", r.status)
	}
	// A bad structure size is a parameter error.
	bad := reqHdr(CmdIoctl, f.nextID(), f.tree, f.sess)
	bad.U16(9)
	if r := f.rt(bad.Bytes()); r.status != StatusInvalidParameter {
		t.Fatalf("bad structure size status %#x", r.status)
	}
}

// TestCommandCompoundChain drives several related requests in one frame: the
// later ones inherit the session and tree and refer to the first one's file.
func TestCommandCompoundChain(t *testing.T) {
	f := newFixture(t)

	name := UTF16LE("chained.txt")
	create := reqHdr(CmdCreate, 1, f.tree, f.sess)
	create.U16(57)
	create.U8(0)
	create.U8(0)
	create.U32(2)
	create.U64(0)
	create.U64(0)
	create.U32(0x1000_0000)
	create.U32(0)
	create.U32(7)
	create.U32(fileOverwriteIf)
	create.U32(0)
	create.U16(120)
	create.U16(uint16(len(name)))
	create.U32(0)
	create.U32(0)
	create.Bytes8(name)

	// The WRITE and CLOSE are "related": they inherit from the chain and use the
	// all-ones FileId, meaning "the handle the previous request used".
	write := reqHdr(CmdWrite, 2, f.tree, f.sess)
	put32(write.Bytes()[16:20], FlagRelated)
	write.U16(49)
	write.U16(112)
	write.U32(4)
	write.U64(0)
	write.U64(^uint64(0))
	write.U64(^uint64(0))
	write.U32(0)
	write.U32(0)
	write.U16(0)
	write.U16(0)
	write.U32(0)
	write.Bytes8([]byte("abc!"))

	cl := reqHdr(CmdClose, 3, f.tree, f.sess)
	put32(cl.Bytes()[16:20], FlagRelated)
	cl.U16(24)
	cl.U16(0)
	cl.U32(0)
	cl.U64(^uint64(0))
	cl.U64(^uint64(0))

	frame := compoundFrame(create.Bytes(), write.Bytes(), cl.Bytes())
	tx := NewWriter(0)
	if act, _ := ProcessFrame(f.srv, f.pc, frame, tx); act != actionRespond {
		t.Fatal("the chain must be answered")
	}
	statuses := walkCompoundStatuses(t, tx.Bytes())
	if len(statuses) != 3 {
		t.Fatalf("chain produced %d responses, want 3", len(statuses))
	}
	for i, st := range statuses {
		if st != StatusSuccess {
			t.Fatalf("chain response %d status %#x", i, st)
		}
	}
	// The write went through the handle the create opened.
	got, err := os.ReadFile(filepath.Join(f.dir, "chained.txt"))
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "abc!" {
		t.Fatalf("chained write produced %q", got)
	}
	// And the close released it, so the file is not held open.
	if st, _ := createFile(t, f.srv, f.pc, f.sess, f.tree, "chained.txt", fileOverwriteIf, 0x40, 0x1000_0000); st != StatusSuccess {
		t.Fatalf("reopen after the chain status %#x", st)
	}
}

// absDiff returns the absolute difference of two uint64 file times.
func absDiff(a, b uint64) uint64 {
	if a > b {
		return a - b
	}
	return b - a
}

// compoundFrame chains messages into one frame, 8-aligning each and patching
// NextCommand.
func compoundFrame(msgs ...[]byte) []byte {
	var out []byte
	for i, m := range msgs {
		if i == len(msgs)-1 {
			out = append(out, m...)
			break
		}
		next := len(m)
		if rem := next % 8; rem != 0 {
			next += 8 - rem
		}
		put32(m[20:24], uint32(next))
		out = append(out, m...)
		out = append(out, make([]byte, next-len(m))...)
	}
	return out
}

// walkCompoundStatuses returns the status of each response in a (possibly
// compound) framed response, walking NextCommand.
func walkCompoundStatuses(t *testing.T, framed []byte) []uint32 {
	t.Helper()
	b := framed[4:] // strip the NBT prefix
	var out []uint32
	for off := 0; off+64 <= len(b); {
		out = append(out, le32(b[off+8:off+12]))
		next := int(le32(b[off+20 : off+24]))
		if next == 0 {
			break
		}
		off += next
	}
	return out
}
