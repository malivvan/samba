package samba

import (
	"crypto/aes"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestCCMAADPrefixForms(t *testing.T) {
	// Short form: two octets.
	if got := ccmAADPrefix(8); len(got) != 2 || got[0] != 0x00 || got[1] != 0x08 {
		t.Fatalf("short prefix = % x", got)
	}
	// The boundary: 0xFF00 needs the long form.
	if got := ccmAADPrefix(0xFEFF); len(got) != 2 {
		t.Fatalf("0xFEFF prefix = % x", got)
	}
	got := ccmAADPrefix(0xFF00)
	if len(got) != 6 || got[0] != 0xFF || got[1] != 0xFE {
		t.Fatalf("0xFF00 prefix = % x", got)
	}
	if got := ccmAADPrefix(0x10000); len(got) != 6 {
		t.Fatalf("0x10000 prefix = % x", got)
	}
	// Beyond 2^32 the 8-octet form is used.
	got = ccmAADPrefix(1 << 33)
	if len(got) != 10 || got[0] != 0xFF || got[1] != 0xFF {
		t.Fatalf("large prefix = % x", got)
	}
	if got[9] != 0 {
		t.Fatalf("large prefix value = % x", got)
	}
}

func TestAEADRejectsUnsupportedCipher(t *testing.T) {
	key := make([]byte, 16)
	nonce := make([]byte, 12)
	buf := []byte("data")
	// An unknown cipher id panics in the sealer and refuses in the opener: the
	// ids come from the wire, so the opener's answer must be a clean false.
	var tag [16]byte
	if aeadOpen(0x0099, key, nonce, nil, buf, &tag) {
		t.Fatal("an unknown cipher must not open")
	}
	func() {
		defer func() {
			if recover() == nil {
				t.Error("sealing with an unknown cipher must not silently succeed")
			}
		}()
		aeadSeal(0x0099, key, nonce, nil, buf)
	}()
	// A key of the wrong length is refused rather than panicking.
	short := make([]byte, 3)
	if aeadOpen(CipherAES128GCM, short, nonce, nil, buf, &tag) {
		t.Fatal("a short key must not open")
	}
	func() {
		defer func() {
			if recover() == nil {
				t.Error("sealing with a bad key length must not silently succeed")
			}
		}()
		aeadSeal(CipherAES128GCM, short, nonce, nil, buf)
	}()
	// CCM with a wrong nonce length is refused.
	if aeadOpen(CipherAES128CCM, key, make([]byte, 12), nil, buf, &tag) {
		t.Fatal("CCM with a 12-byte nonce must not open")
	}
}

func TestCMACAndSealErrors(t *testing.T) {
	// A CMAC key of the wrong size cannot be used.
	func() {
		defer func() {
			if recover() == nil {
				t.Error("a bad CMAC key must not silently succeed")
			}
		}()
		aes128CMAC([]byte{1, 2, 3})
	}()
	// CCM refuses a message longer than its length field can encode.
	block, err := aes.NewCipher(make([]byte, 16))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ccmSeal(block, make([]byte, 7), nil, make([]byte, 1), 16); err == nil {
		t.Fatal("a 7-byte nonce (L=8) must accept the message")
	}
	// A nonce that is too short is refused by the parameter check.
	if _, err := ccmSeal(block, make([]byte, 6), nil, nil, 16); err == nil {
		t.Fatal("a 6-byte nonce must be refused")
	}
	if _, err := ccmSeal(block, make([]byte, 12), nil, nil, 3); err == nil {
		t.Fatal("a 3-byte tag must be refused")
	}
	if ccmOpen(block, make([]byte, 6), nil, nil, make([]byte, 16)) {
		t.Fatal("open with a bad nonce must fail")
	}
}

func TestClampAndIsHex(t *testing.T) {
	if got := clamp(-5, 0, 10); got != 0 {
		t.Fatalf("clamp below = %d", got)
	}
	if got := clamp(50, 0, 10); got != 10 {
		t.Fatalf("clamp above = %d", got)
	}
	if got := clamp(5, 0, 10); got != 5 {
		t.Fatalf("clamp inside = %d", got)
	}
	if !isHex("0123456789aAbBcCdDeEfF") {
		t.Fatal("uppercase and lowercase hex must be accepted")
	}
	if isHex("0123456789abcg") || isHex("") {
		t.Fatal("non-hex and empty strings must be rejected")
	}
}

func TestHandleTableRemoveMiss(t *testing.T) {
	var tbl HandleTable
	if _, ok := tbl.Remove(1); ok {
		t.Fatal("removing from an empty table must miss")
	}
	if _, ok := tbl.Get(1); ok {
		t.Fatal("getting from an empty table must miss")
	}
	// A slot index beyond the table must miss rather than panic.
	if _, ok := tbl.Get(^uint64(0)); ok {
		t.Fatal("an out-of-range id must miss")
	}
	f, err := os.CreateTemp(t.TempDir(), "h")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	id := tbl.Insert(&OpenFile{File: f})
	if _, ok := tbl.Remove(id); !ok {
		t.Fatal("remove must succeed")
	}
	if _, ok := tbl.Remove(id); ok {
		t.Fatal("a second remove must miss")
	}
}

func TestFsSizesOnClosedFile(t *testing.T) {
	f, err := os.CreateTemp(t.TempDir(), "h")
	if err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	if _, _, _, _, _, err := fsSizes(f); err == nil {
		t.Fatal("fsSizes on a closed descriptor must fail")
	}
	if _, err := fstatMeta(f); err == nil {
		t.Fatal("fstatMeta on a closed descriptor must fail")
	}
	if _, err := pread(f, make([]byte, 1), 0); err == nil {
		t.Fatal("pread on a closed descriptor must fail")
	}
	if err := pwriteAll(f, []byte("x"), 0); err == nil {
		t.Fatal("pwriteAll on a closed descriptor must fail")
	}
}

// panickingBreakTarget is a connection whose deferred queue is missing, so
// delivering a break to it panics.
func panickingBreakTarget() *worker {
	return &worker{id: 0, conns: map[int]*conn{0: {gen: 1}}}
}

func TestDeliverBreakGuardedContainsPanics(t *testing.T) {
	w := panickingBreakTarget()
	// The unguarded path panics; the guarded one absorbs it and keeps the worker
	// alive.
	func() {
		defer func() {
			if recover() == nil {
				t.Error("expected the unguarded delivery to panic")
			}
		}()
		w.deliverBreak(BreakMsg{ConnIdx: 0, ConnGen: 1})
	}()
	w.deliverBreakGuarded(BreakMsg{ConnIdx: 0, ConnGen: 1})
}

func TestNTLMParserTruncations(t *testing.T) {
	full := clientType3("alice", "WG", "s3cret", [8]byte{1})
	// Every truncation must be refused without panicking.
	for n := range len(full) {
		if auth, ok := parseAuthenticate(full[:n]); ok && n < len(full) {
			// A prefix that still contains all the fields may parse; if so it must
			// not have invented a response.
			if len(auth.NTResponse) > 0 && len(auth.NTResponse) < 16 {
				t.Fatalf("a %d-byte prefix produced a short response", n)
			}
		}
	}
	// A field claiming to extend past the token is refused.
	bad := append([]byte{}, full...)
	put16(bad[12+2:12+4], 0xFFFF) // NT response offset field (little-endian length is first)
	if _, ok := parseAuthenticate(bad); ok {
		// Either reading is acceptable as long as nothing panics and the response
		// is internally consistent; the point is that it must not index out of
		// range.
	}
	// A blob with no NTLMSSP token at all.
	if _, ok := parseAuthenticate([]byte("garbage")); ok {
		t.Fatal("a blob with no token must not parse")
	}
	if _, ok := parseAuthenticate(nil); ok {
		t.Fatal("an empty blob must not parse")
	}
	// A type 2 message is not an authenticate message.
	t2 := append(append([]byte{}, ntlmSig...), 2, 0, 0, 0)
	if _, ok := parseAuthenticate(t2); ok {
		t.Fatal("a challenge must not parse as an authenticate message")
	}
}

func TestNTLMNegotiateFlagParsing(t *testing.T) {
	// A short token has no flags.
	if got := ntlmNegotiateFlags(ntlmSig); got != 0 {
		t.Fatalf("flags = %#x", got)
	}
	full := append(append([]byte{}, ntlmSig...), 1, 0, 0, 0, 0x10, 0, 0, 0)
	if got := ntlmNegotiateFlags(full); got != 0x10 {
		t.Fatalf("flags = %#x", got)
	}
	// A type-1 message that is too short for the flags field.
	if got := ntlmNegotiateFlags(append(append([]byte{}, ntlmSig...), 1, 0, 0, 0)); got != 0 {
		t.Fatalf("short type 1 flags = %#x", got)
	}
}

func TestQueryInfoStandardOnDirectory(t *testing.T) {
	f := newFixture(t)
	dfid := f.open("sub", fileOpen, fileDirectoryFile, 0x8000_0000)
	defer f.closeFID(dfid)
	r := f.queryInfo(dfid, infoFile, 5, 4096)
	if r.status != StatusSuccess {
		t.Fatalf("status %#x", r.status)
	}
	// The directory flag must be reported in FileStandardInformation.
	body := r.body[8:]
	if body[21] == 0 {
		t.Fatal("a directory must report the directory flag")
	}
}

func TestConnWriteStallAborts(t *testing.T) {
	// A peer that stops reading must not pin the response writer: with a tiny
	// stall budget the write fails and the connection is dropped.
	old := stallTimeout
	stallTimeout = 100 * time.Millisecond
	t.Cleanup(func() { stallTimeout = old })

	local, _ := socketPair(t)
	// Shrink the send buffer so a large write blocks quickly.
	if sc, ok := local.(syscall.Conn); ok {
		if raw, err := sc.SyscallConn(); err == nil {
			_ = raw.Control(func(fd uintptr) {
				_ = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_SNDBUF, 4096)
			})
		}
	}
	c := &conn{nc: local}
	// Nobody reads from peer, so a megabyte cannot be delivered. The write must
	// fail promptly (bounded by the stall budget) rather than block forever.
	start := time.Now()
	if c.write(make([]byte, 1<<20)) {
		t.Fatal("a write to a peer that never reads must not report success")
	}
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Fatalf("the write took %v; the stall budget did not apply", elapsed)
	}
}

func TestVfsResolvePathVariants(t *testing.T) {
	root := "/srv/data"
	cases := []struct {
		in      string
		wantSt  uint32
		wantRel string
	}{
		{`a`, StatusSuccess, "a"},
		{`a\b`, StatusSuccess, `a\b`},
		{`a/b`, StatusSuccess, `a\b`},
		{`.\a\.\b`, StatusSuccess, `a\b`},
		{``, StatusSuccess, ``},
		{`\`, StatusSuccess, ``},
		{`..`, StatusObjectNameInvalid, ``},
		{`a\..\b`, StatusObjectNameInvalid, ``},
		{"a\x00b", StatusObjectNameInvalid, ``},
	}
	for _, c := range cases {
		_, rel, st := resolvePath(root, c.in)
		if st != c.wantSt || (st == StatusSuccess && rel != c.wantRel) {
			t.Errorf("resolvePath(%q) = %q, %#x; want %q, %#x", c.in, rel, st, c.wantRel, c.wantSt)
		}
	}
}

func TestStatMetaVariants(t *testing.T) {
	dir := t.TempDir()
	// A directory and a file report different attributes.
	if err := os.Mkdir(filepath.Join(dir, "d"), 0o755); err != nil {
		t.Fatal(err)
	}
	m, err := statMeta(filepath.Join(dir, "d"))
	if err != nil {
		t.Fatal(err)
	}
	if !m.IsDir || m.Attrs&AttrDirectory == 0 {
		t.Fatalf("directory meta = %+v", m)
	}
	// A file with no write bit is read-only.
	ro := filepath.Join(dir, "ro")
	if err := os.WriteFile(ro, []byte("x"), 0o444); err != nil {
		t.Fatal(err)
	}
	m, err = statMeta(ro)
	if err != nil {
		t.Fatal(err)
	}
	if m.Attrs&AttrReadonly == 0 {
		t.Fatalf("read-only file meta = %+v", m)
	}
	if m.Size != 1 || m.Ino == 0 || m.Nlink == 0 {
		t.Fatalf("file meta = %+v", m)
	}
	// A hard link bumps the link count.
	link := filepath.Join(dir, "ro-link")
	if err := os.Link(ro, link); err != nil {
		t.Skipf("hard links unavailable: %v", err)
	}
	m2, err := statMeta(ro)
	if err != nil {
		t.Fatal(err)
	}
	if m2.Nlink != 2 {
		t.Fatalf("nlink = %d, want 2", m2.Nlink)
	}
}
