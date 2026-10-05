package samba

import (
	"bytes"
	"testing"
)

func TestClassifyRawAndWrapped(t *testing.T) {
	t1 := append([]byte{}, ntlmSig...)
	t1 = append(t1, 1, 0, 0, 0)
	if got := classifyToken(t1); got != TokenNegotiate {
		t.Fatalf("raw type 1 = %v", got)
	}
	t3 := []byte{0xA1, 0x82, 0x01, 0x00}
	t3 = append(t3, ntlmSig...)
	t3 = append(t3, 3, 0, 0, 0)
	if got := classifyToken(t3); got != TokenAuthenticate {
		t.Fatalf("wrapped type 3 = %v", got)
	}
	if got := classifyToken([]byte("garbage")); got != TokenOther {
		t.Fatalf("garbage = %v", got)
	}
}

func TestChallengeShape(t *testing.T) {
	c := ntlmChallenge("SRV", [8]byte{7, 7, 7, 7, 7, 7, 7, 7}, 0)
	if !bytes.Equal(c[:8], ntlmSig) {
		t.Fatalf("signature = % x", c[:8])
	}
	if got := le32(c[8:12]); got != 2 {
		t.Fatalf("message type = %d", got)
	}
	if !bytes.Equal(c[24:32], []byte{7, 7, 7, 7, 7, 7, 7, 7}) {
		t.Fatalf("challenge = % x", c[24:32])
	}
	off := int(le32(c[16:20]))
	if !bytes.Equal(c[off:off+6], UTF16LE("SRV")) {
		t.Fatalf("target name at %d = % x", off, c[off:off+6])
	}
}

// buildType3 builds a synthetic AUTHENTICATE_MESSAGE the way a real client
// would.
func buildType3(user, domain, password string, chal *[8]byte) []byte {
	nt := ntHash(password)
	id := UTF16LE(toUpperASCII(user))
	id = append(id, UTF16LE(domain)...)
	v2 := hmacMD5(nt[:], id)
	// temp blob: resp type(2) reserved(6) time(8) client challenge(8) res(4) EOL(4)
	temp := []byte{1, 1, 0, 0, 0, 0, 0, 0}
	temp = append(temp, make([]byte, 8)...)
	temp = append(temp, bytes.Repeat([]byte{0xAA}, 8)...)
	temp = append(temp, make([]byte, 8)...)
	buf := append([]byte{}, chal[:]...)
	buf = append(buf, temp...)
	proof := hmacMD5(v2[:], buf)
	ntResp := append([]byte{}, proof[:]...)
	ntResp = append(ntResp, temp...)

	user16 := UTF16LE(user)
	dom16 := UTF16LE(domain)
	w := NewWriter(0)
	w.Bytes8(ntlmSig)
	w.U32(3)
	const base = 64 // header size up to the flags field
	off := base
	lengths := []int{0, len(ntResp), len(dom16), len(user16), 0, 0}
	for _, l := range lengths {
		w.U16(uint16(l))
		w.U16(uint16(l))
		w.U32(uint32(off))
		off += l
	}
	w.U32(0) // flags: no KEY_EXCH
	w.Bytes8(ntResp)
	w.Bytes8(dom16)
	w.Bytes8(user16)
	return w.Bytes()
}

func toUpperASCII(s string) string {
	out := []byte(s)
	for i, c := range out {
		if c >= 'a' && c <= 'z' {
			out[i] = c - 'a' + 'A'
		}
	}
	return string(out)
}

func TestNTLMv2Roundtrip(t *testing.T) {
	chal := [8]byte{9, 9, 9, 9, 9, 9, 9, 9}
	blob := buildType3("glenn", "WORKGROUP", "secretpw", &chal)
	auth, ok := parseAuthenticate(blob)
	if !ok {
		t.Fatal("parse failed")
	}
	if auth.User != "glenn" || auth.Domain != "WORKGROUP" {
		t.Fatalf("parsed user/domain = %q/%q", auth.User, auth.Domain)
	}
	if auth.IsAnonymous() {
		t.Fatal("a user token is not anonymous")
	}
	nt := ntHash("secretpw")
	if _, ok := verifyNTLMv2(&nt, auth, &chal); !ok {
		t.Fatal("correct password must verify")
	}
	// A wrong password must fail.
	bad := ntHash("wrongpw")
	if _, ok := verifyNTLMv2(&bad, auth, &chal); ok {
		t.Fatal("wrong password must fail")
	}
	// A tampered challenge must fail.
	other := [8]byte{}
	if _, ok := verifyNTLMv2(&nt, auth, &other); ok {
		t.Fatal("tampered challenge must fail")
	}
}

func TestNTLMv2KeyExchange(t *testing.T) {
	chal := [8]byte{1, 2, 3, 4, 5, 6, 7, 8}
	nt := ntHash("pw")
	id := append(UTF16LE("U"), UTF16LE("D")...)
	v2 := hmacMD5(nt[:], id)
	temp := []byte{1, 1, 0, 0, 0, 0, 0, 0}
	temp = append(temp, make([]byte, 8)...)
	temp = append(temp, bytes.Repeat([]byte{0x42}, 8)...)
	temp = append(temp, make([]byte, 8)...)
	buf := append([]byte{}, chal[:]...)
	buf = append(buf, temp...)
	proof := hmacMD5(v2[:], buf)
	ntResp := append([]byte{}, proof[:]...)
	ntResp = append(ntResp, temp...)
	sessionBase := hmacMD5(v2[:], proof[:])
	// The client wraps the session key with RC4.
	clientKey := [16]byte{0xC, 0xC, 0xC, 0xC, 0xC, 0xC, 0xC, 0xC, 0xC, 0xC, 0xC, 0xC, 0xC, 0xC, 0xC, 0xC}
	encKey := rc4XOR(sessionBase[:], clientKey[:])

	user16 := UTF16LE("u")
	dom16 := UTF16LE("D")
	w := NewWriter(0)
	w.Bytes8(ntlmSig)
	w.U32(3)
	off := 64
	fields := []struct {
		data []byte
	}{{nil}, {ntResp}, {dom16}, {user16}, {nil}, {encKey}}
	for _, f := range fields {
		w.U16(uint16(len(f.data)))
		w.U16(uint16(len(f.data)))
		w.U32(uint32(off))
		off += len(f.data)
	}
	const flagKeyExch = 0x4000_0000
	w.U32(flagKeyExch)
	for _, f := range fields {
		w.Bytes8(f.data)
	}

	auth, ok := parseAuthenticate(w.Bytes())
	if !ok {
		t.Fatal("parse failed")
	}
	got, ok := verifyNTLMv2(&nt, auth, &chal)
	if !ok {
		t.Fatal("must verify")
	}
	if got != clientKey {
		t.Fatalf("key exchange recovered %x, want %x", got, clientKey)
	}
}

func TestSPNEGODERShapes(t *testing.T) {
	hint := spnegoHint()
	if hint[0] != 0x60 {
		t.Fatalf("hint tag = %#x", hint[0])
	}
	chal := spnegoWrapChallenge([]byte("NTLMSSP\x00fake"))
	if chal[0] != 0xA1 {
		t.Fatalf("challenge tag = %#x", chal[0])
	}
	if findToken(chal) == nil {
		t.Fatal("wrapped challenge must still contain the token")
	}
	done := spnegoAcceptCompleted()
	if done[0] != 0xA1 {
		t.Fatalf("accept-completed tag = %#x", done[0])
	}
	if !isSPNEGO(done) {
		t.Fatal("accept-completed must classify as SPNEGO")
	}
	// The NTLM hint must be exactly the generic NegTokenInit2 for NTLMSSP.
	if !bytes.Equal(hint, negInitHint([]Mech{mechNtlmssp})) {
		t.Fatal("NTLM hint must match the generic mechanism hint")
	}
	if !bytes.Equal(chal, negResp(acceptIncomplete, mechNtlmssp, []byte("NTLMSSP\x00fake"))) {
		t.Fatal("wrapped challenge must match the generic NegTokenResp")
	}
	if !bytes.Equal(done, negResp(acceptCompleted, mechUnknown, nil)) {
		t.Fatal("accept-completed must match the generic NegTokenResp")
	}
}

func TestChallengeEchoesSealOnlyWhenRequested(t *testing.T) {
	chal := [8]byte{1, 2, 3, 4, 5, 6, 7, 8}
	// A plain client gets the baseline flags, without NEGOTIATE_SEAL.
	base := ntlmChallenge("SRV", chal, 0)
	if flags := le32(base[20:24]); flags&ntlmFlagSeal != 0 {
		t.Fatalf("SEAL must not be offered unasked: %#x", flags)
	}
	if flags := le32(base[20:24]); flags&0x0000_0010 == 0 {
		t.Fatalf("SIGN must always be offered (cifs needs it): %#x", flags)
	}
	// A client that asks for sealing gets it echoed, which is what makes
	// Samba's client willing to turn on SMB3 encryption.
	asked := ntlmChallenge("SRV", chal, ntlmFlagSeal|0x0000_0001)
	flags := le32(asked[20:24])
	if flags&ntlmFlagSeal == 0 {
		t.Fatalf("SEAL must be echoed when requested: %#x", flags)
	}
	if flags&ntlmFlagKeyExch == 0 || flags&0x0000_0200 == 0 {
		t.Fatalf("the baseline flags must survive: %#x", flags)
	}
}

func TestNTLMNegotiateFlags(t *testing.T) {
	// A synthesized type-1 message carrying SEAL.
	w := NewWriter(0)
	w.Bytes8(ntlmSig)
	w.U32(1)
	w.U32(ntlmFlagSeal | 0x0000_0001)
	if got := ntlmNegotiateFlags(w.Bytes()); got&ntlmFlagSeal == 0 {
		t.Fatalf("flags = %#x, want SEAL set", got)
	}
	if got := ntlmNegotiateFlags([]byte("garbage")); got != 0 {
		t.Fatalf("a non-NTLMSSP blob must report 0 flags, got %#x", got)
	}
	// A type-3 message has no NegotiateFlags at that offset and must report 0.
	w = NewWriter(0)
	w.Bytes8(ntlmSig)
	w.U32(3)
	w.U32(ntlmFlagSeal)
	if got := ntlmNegotiateFlags(w.Bytes()); got != 0 {
		t.Fatalf("a type-3 message must report 0 flags, got %#x", got)
	}
}
