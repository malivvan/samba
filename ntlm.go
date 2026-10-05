package samba

import "strings"

// NTLMSSP: challenge generation, NTLMv2 verification, session key derivation.
//
// MIC verification is not implemented (the server omits the MsvAvTimestamp AV
// pair, so well-behaved clients do not send one).

// ntlmSig is the NTLMSSP message signature, kept always available so SPNEGO
// classification can recognize — and a build without NTLM could reject —
// NTLMSSP tokens.
var ntlmSig = []byte("NTLMSSP\x00")

const (
	ntlmFlagAnonymous uint32 = 0x0000_0800
	// ntlmFlagSeal is NTLMSSP_NEGOTIATE_SEAL. It is only echoed back when the
	// client asks for it: Samba's client requires the echo before it will
	// enable SMB3 encryption (client protection = encrypt), while cifs.ko and
	// Windows enable encryption from the SMB-layer negotiation alone.
	ntlmFlagSeal    uint32 = 0x0000_0020
	ntlmFlagKeyExch uint32 = 0x4000_0000
)

// TokenKind classifies an NTLMSSP message.
type TokenKind int

const (
	// TokenNegotiate is a NEGOTIATE_MESSAGE (type 1).
	TokenNegotiate TokenKind = iota
	// TokenAuthenticate is an AUTHENTICATE_MESSAGE (type 3).
	TokenAuthenticate
	// TokenOther is anything else (including no token at all).
	TokenOther
)

// findToken locates an NTLMSSP token inside a raw or SPNEGO-wrapped blob.
func findToken(blob []byte) []byte {
	p := indexOf(blob, ntlmSig)
	if p < 0 {
		return nil
	}
	return blob[p:]
}

// indexOf returns the first index of sep in b, or -1.
func indexOf(b, sep []byte) int {
	if len(sep) == 0 {
		return 0
	}
	for i := 0; i+len(sep) <= len(b); i++ {
		match := true
		for j := range sep {
			if b[i+j] != sep[j] {
				match = false
				break
			}
		}
		if match {
			return i
		}
	}
	return -1
}

// classifyToken reports which NTLMSSP message kind a blob carries.
func classifyToken(blob []byte) TokenKind {
	tok := findToken(blob)
	if len(tok) < 12 {
		return TokenOther
	}
	switch le32(tok[8:12]) {
	case 1:
		return TokenNegotiate
	case 3:
		return TokenAuthenticate
	default:
		return TokenOther
	}
}

const ntlmFlags uint32 = 0x0000_0001 | // UNICODE
	0x0000_0010 | // SIGN (cifs requires this for sec=ntlmsspi)
	0x0000_0200 | // NTLM
	0x0000_8000 | // ALWAYS_SIGN
	0x0002_0000 | // TARGET_TYPE_SERVER
	0x0008_0000 | // EXTENDED_SESSIONSECURITY
	0x0080_0000 | // TARGET_INFO
	0x0200_0000 | // VERSION
	0x2000_0000 | // 128-bit
	0x4000_0000 | // KEY_EXCH
	0x8000_0000 // 56-bit

// ntlmNegotiateFlags reads the NegotiateFlags field of a NEGOTIATE_MESSAGE
// (type 1), or reports 0 when the blob does not carry one.
func ntlmNegotiateFlags(blob []byte) uint32 {
	tok := findToken(blob)
	// Signature(8) + MessageType(4) + NegotiateFlags(4).
	const flagsOff = 12
	if len(tok) < flagsOff+4 || le32(tok[8:12]) != 1 {
		return 0
	}
	return le32(tok[flagsOff : flagsOff+4])
}

// ntlmChallenge builds a CHALLENGE_MESSAGE (type 2). clientFlags is the
// NegotiateFlags the client sent, so the server can echo the capabilities it
// honours (currently NEGOTIATE_SEAL).
func ntlmChallenge(serverName string, chal [8]byte, clientFlags uint32) []byte {
	target := UTF16LE(serverName)
	info := NewWriter(64)
	// AV pairs: NetBIOS domain (2), NetBIOS computer (1), EOL (0).
	for _, id := range []uint16{2, 1} {
		info.U16(id)
		info.U16(uint16(len(target)))
		info.Bytes8(target)
	}
	info.U16(0)
	info.U16(0)

	const hdr = 56
	w := NewWriter(hdr + len(target) + info.Len())
	w.Bytes8(ntlmSig)
	w.U32(2) // MessageType
	w.U16(uint16(len(target)))
	w.U16(uint16(len(target)))
	w.U32(hdr)
	flags := ntlmFlags
	if clientFlags&ntlmFlagSeal != 0 {
		flags |= ntlmFlagSeal
	}
	w.U32(flags)
	w.Bytes8(chal[:])
	w.U64(0) // Reserved
	w.U16(uint16(info.Len()))
	w.U16(uint16(info.Len()))
	w.U32(uint32(hdr + len(target)))
	// Version: 6.1 build 7601, NTLMSSP revision 15.
	w.Bytes8([]byte{0x06, 0x01, 0xB1, 0x1D, 0x00, 0x00, 0x00, 0x0F})
	w.Bytes8(target)
	w.Bytes8(info.Bytes())
	return w.Bytes()
}

// Authenticate is a parsed AUTHENTICATE_MESSAGE (type 3).
type Authenticate struct {
	User          string
	Domain        string
	NTResponse    []byte
	EncSessionKey []byte
	Flags         uint32
}

// IsAnonymous reports whether the client asked for an anonymous session.
func (a *Authenticate) IsAnonymous() bool {
	return a.Flags&ntlmFlagAnonymous != 0 || (a.User == "" && len(a.NTResponse) < 16)
}

// ntlmField reads one length/max/offset security buffer out of tok.
func ntlmField(tok []byte, r *Reader) ([]byte, bool) {
	length, ok := r.U16()
	if !ok {
		return nil, false
	}
	if _, ok := r.U16(); !ok { // max length
		return nil, false
	}
	off, ok := r.U32()
	if !ok {
		return nil, false
	}
	if length == 0 {
		return []byte{}, true
	}
	return sliceAt(tok, int(off), int(length))
}

// sliceAt returns tok[off:off+n] or reports failure.
func sliceAt(b []byte, off, n int) ([]byte, bool) {
	if off < 0 || n < 0 || off > len(b)-n {
		return nil, false
	}
	return b[off : off+n], true
}

// parseAuthenticate parses an AUTHENTICATE_MESSAGE (type 3) from a raw or
// SPNEGO-wrapped blob.
func parseAuthenticate(blob []byte) (*Authenticate, bool) {
	tok := findToken(blob)
	if tok == nil {
		return nil, false
	}
	r := NewReader(tok)
	if !r.Skip(8) {
		return nil, false
	}
	if t, ok := r.U32(); !ok || t != 3 {
		return nil, false
	}
	if _, ok := ntlmField(tok, r); !ok { // LM response
		return nil, false
	}
	ntResponse, ok := ntlmField(tok, r)
	if !ok {
		return nil, false
	}
	domain, ok := ntlmField(tok, r)
	if !ok {
		return nil, false
	}
	user, ok := ntlmField(tok, r)
	if !ok {
		return nil, false
	}
	if _, ok := ntlmField(tok, r); !ok { // workstation
		return nil, false
	}
	encKey, ok := ntlmField(tok, r)
	if !ok {
		return nil, false
	}
	flags, ok := r.U32()
	if !ok {
		return nil, false
	}
	return &Authenticate{
		User:          FromUTF16LE(user),
		Domain:        FromUTF16LE(domain),
		NTResponse:    ntResponse,
		EncSessionKey: encKey,
		Flags:         flags,
	}, true
}

// verifyNTLMv2 verifies an NTLMv2 response and returns the 16-byte
// ExportedSessionKey on success (used as the SMB session key).
func verifyNTLMv2(ntHash *[16]byte, auth *Authenticate, serverChallenge *[8]byte) ([16]byte, bool) {
	if len(auth.NTResponse) < 16+28 {
		return [16]byte{}, false
	}
	// NTLMv2 hash = HMAC-MD5(NT hash, UPPER(user) + domain) in UTF-16LE, with
	// the domain exactly as the client sent it.
	id := UTF16LE(strings.ToUpper(auth.User))
	id = append(id, UTF16LE(auth.Domain)...)
	v2Hash := hmacMD5(ntHash[:], id)

	proof := auth.NTResponse[:16]
	temp := auth.NTResponse[16:]
	buf := make([]byte, 0, 8+len(temp))
	buf = append(buf, serverChallenge[:]...)
	buf = append(buf, temp...)
	expect := hmacMD5(v2Hash[:], buf)
	if !cmacEqual(expect[:], proof) {
		return [16]byte{}, false
	}

	sessionBase := hmacMD5(v2Hash[:], proof)
	if auth.Flags&ntlmFlagKeyExch != 0 && len(auth.EncSessionKey) == 16 {
		key := rc4XOR(sessionBase[:], auth.EncSessionKey)
		if len(key) != 16 {
			return [16]byte{}, false
		}
		var out [16]byte
		copy(out[:], key)
		return out, true
	}
	return sessionBase, true
}

// isSPNEGO reports whether a security blob is SPNEGO-wrapped.
func isSPNEGO(blob []byte) bool {
	if len(blob) == 0 {
		return false
	}
	return blob[0] == 0x60 || blob[0] == 0xA1
}

// spnegoHint is the NegTokenInit2 hint advertising NTLMSSP, placed in the
// NEGOTIATE response security buffer so Windows clients pick NTLMSSP.
func spnegoHint() []byte { return negInitHint([]Mech{mechNtlmssp}) }

// spnegoWrapChallenge wraps our CHALLENGE in a NegTokenResp with
// negState = accept-incomplete.
func spnegoWrapChallenge(token []byte) []byte {
	return negResp(acceptIncomplete, mechNtlmssp, token)
}

// spnegoAcceptCompleted is a NegTokenResp with negState = accept-completed.
func spnegoAcceptCompleted() []byte { return negResp(acceptCompleted, mechUnknown, nil) }
