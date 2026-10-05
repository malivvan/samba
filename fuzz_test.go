package samba

import (
	"os"
	"path/filepath"
	"testing"
)

// Native Go fuzzing targets.
//
// Ported from the original cargo-fuzz targets. They cover the two parsers that
// run on attacker-controlled bytes before any authentication: the SMB2 wire
// entry point (header codec, compound dispatch, and every command's
// body/offset/length decoding) and the NTLMSSP parser.
//
// Run a target continuously with:
//
//	go test -run '^$' -fuzz FuzzProcessFrame -fuzztime 60s .
//	go test -run '^$' -fuzz FuzzNTLM         -fuzztime 60s .

// fuzzShare is a read-only share created once per process, so a fuzz iteration
// does no filesystem setup; fresh protocol state per input keeps iterations
// independent.
var fuzzShare = func() string {
	dir := filepath.Join(os.TempDir(), "samba-fuzz-share")
	_ = os.MkdirAll(dir, 0o755)
	return dir
}()

func newFuzzSrv() *Srv {
	cfg := &Config{}
	*cfg = newConfig()
	cfg.Listen = "127.0.0.1:445"
	cfg.Workers = 1
	cfg.ServerName = "FUZZ"
	cfg.LogLevel = LevelWarn
	cfg.Multichannel = true
	cfg.Oplocks = false
	allowGuest := true
	cfg.AllowGuest = &allowGuest
	cfg.Shares = []ShareCfg{{Name: "f", Path: fuzzShare, ReadOnly: true}}
	cfg.Users = []UserCfg{{Name: "u", Password: "p"}}
	users, _ := cfg.UserDB()
	return &Srv{
		cfg:        *cfg,
		maxRead:    MaxReadTarget,
		users:      users,
		allowGuest: cfg.GuestAllowed(),
		sessions:   NewRegistry(),
		mailboxes:  []*Mailbox{NewMailbox()},
		leases:     NewLeaseTable(),
	}
}

// FuzzProcessFrame drives the SMB2 wire entry point: a NetBIOS-framed message
// through ParseHdr, compound dispatch, and every command's body/offset/length
// parsing.
func FuzzProcessFrame(f *testing.F) {
	// Seeds: a negotiate request, an echo, an NTLMSSP session setup, an SMB1
	// negotiate, and a transform-wrapped frame.
	neg := reqHdr(CmdNegotiate, 0, 0, 0)
	neg.U16(36)
	neg.U16(3)
	neg.U16(1)
	neg.U16(0)
	neg.U32(0)
	neg.Zeros(16 + 8)
	neg.U16(0x0210)
	neg.U16(0x0300)
	neg.U16(0x0302)
	f.Add(neg.Bytes())

	echo := reqHdr(CmdEcho, 1, 0, 0)
	echo.U16(4)
	echo.U16(0)
	f.Add(echo.Bytes())

	blob := append([]byte{}, ntlmSig...)
	blob = append(blob, 1, 0, 0, 0)
	ss := reqHdr(CmdSessionSetup, 1, 0, 0)
	ss.U16(25)
	ss.U8(0)
	ss.U8(1)
	ss.U32(0)
	ss.U32(0)
	ss.U16(88)
	ss.U16(uint16(len(blob)))
	ss.U64(0)
	ss.Bytes8(blob)
	f.Add(ss.Bytes())

	f.Add(append([]byte{0xFF, 'S', 'M', 'B'}, make([]byte, 32)...))
	f.Add(append(append([]byte{}, transformProto...), make([]byte, 64)...))
	f.Add([]byte{})

	f.Fuzz(func(t *testing.T, data []byte) {
		srv := newFuzzSrv()
		pc := NewProtoConn(srv, 0, 0, 1)
		tx := NewWriter(0)
		act, plan := ProcessFrame(srv, pc, data, tx)
		if act == actionZcRead {
			// A plan must describe a bounded, non-empty read.
			if plan == nil {
				t.Fatal("zc plan action without a plan")
			}
			if plan.Length == 0 || plan.Length > MaxReadTarget {
				t.Fatalf("zc plan length %d out of range", plan.Length)
			}
			if tx.Len() != 0 {
				t.Fatalf("a zero-copy plan must leave tx empty, got %d bytes", tx.Len())
			}
		}
		// Every complete frame in the output must be well formed: the NBT
		// length must match the bytes that follow.
		b := tx.Bytes()
		for off := 0; off+4 <= len(b); {
			nbt := int(b[off+1])<<16 | int(b[off+2])<<8 | int(b[off+3])
			if off+4+nbt > len(b) {
				t.Fatalf("truncated response frame at %d (want %d, have %d)", off, nbt, len(b)-off-4)
			}
			if nbt < 64 {
				t.Fatalf("response frame at %d is %d bytes", off, nbt)
			}
			off += 4 + nbt
		}
	})
}

// FuzzNTLM covers the NTLMSSP parser: token location and the AUTHENTICATE field
// (offset/length) decoding, which run on attacker-controlled bytes during
// SESSION_SETUP.
func FuzzNTLM(f *testing.F) {
	f.Add(append(append([]byte{}, ntlmSig...), 1, 0, 0, 0))
	f.Add(append(append([]byte{}, ntlmSig...), 3, 0, 0, 0))
	f.Add(append([]byte{0x60, 0x82, 0x01, 0x00}, append([]byte{}, ntlmSig...)...))
	f.Add([]byte("garbage"))
	f.Add([]byte{})

	f.Fuzz(func(t *testing.T, data []byte) {
		_ = findToken(data)
		_ = classifyToken(data)
		if auth, ok := parseAuthenticate(data); ok {
			_ = auth.IsAnonymous()
			// A parsed token must report a user and response through the
			// public shape without panicking.
			_ = auth.User
			_ = auth.Domain
			if len(auth.NTResponse) > 0 {
				var key [16]byte
				var chal [8]byte
				_, _ = verifyNTLMv2(&key, auth, &chal)
			}
		}
	})
}

// FuzzClassifyBlob covers the SPNEGO/GSS token classifier, which parses
// attacker-controlled DER before any mechanism is chosen.
func FuzzClassifyBlob(f *testing.F) {
	f.Add(negInitHint([]Mech{mechKrb5, mechNtlmssp}))
	f.Add(spnegoHint())
	f.Add(spnegoWrapChallenge([]byte("NTLMSSP\x00fake")))
	f.Add(negResp(acceptCompleted, mechKrb5, []byte("ap-rep")))
	f.Add([]byte{0x60, 0x82, 0x01, 0x00})
	f.Add([]byte{0xA1, 0x05, 0x30, 0x03, 0xA2, 0x01, 0x00})
	f.Add([]byte{})

	f.Fuzz(func(t *testing.T, data []byte) {
		inc := classifyBlob(data)
		switch inc.Mech {
		case mechKrb5, mechNtlmssp, mechUnknown:
		default:
			t.Fatalf("classifier produced an out-of-range mechanism %d", inc.Mech)
		}
		if inc.Mech == mechUnknown {
			return
		}
		// A recognized mechanism must hand the acceptor a token that is a slice
		// of the input (never synthesized bytes).
		if len(inc.Token) > 0 && len(data) > 0 {
			found := false
			for i := 0; i+len(inc.Token) <= len(data); i++ {
				if &data[i] == &inc.Token[0] {
					found = true
					break
				}
			}
			if !found {
				t.Fatal("the classified token must alias the input blob")
			}
		}
		_, _ = unwrapGSSAPREQ(inc.Token)
	})
}

// FuzzParseLeaseCtx covers the SMB2_CREATE_CONTEXT walker that looks for an
// RqLs lease request inside a client-supplied context chain.
func FuzzParseLeaseCtx(f *testing.F) {
	w := NewWriter(0)
	leaseKey := [16]byte{1}
	w.Bytes8(leaseKey[:])
	w.U32(LeaseReadCaching)
	w.U32(0)
	w.U64(0)
	f.Add(rqlsCtx(w.Bytes()))
	f.Add(rqlsCtx(make([]byte, 52)))
	f.Add([]byte{})
	f.Add(make([]byte, 16))

	f.Fuzz(func(t *testing.T, data []byte) {
		l, ok := parseLeaseCtx(data)
		if ok && l == nil {
			t.Fatal("a successful parse must return a lease request")
		}
	})
}
