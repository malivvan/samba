package samba

// SPNEGO (RFC 4178) DER glue and mechanism classification.
//
// This file owns the SPNEGO wire encoding — the minimal DER writer/reader, the
// mechanism OIDs, the NegTokenInit2 hint placed in the NEGOTIATE response, and
// classification of an inbound SESSION_SETUP security blob into the mechanism
// plus the token to hand the acceptor. It is pure ASN.1 with no external
// dependency, so it is fully unit-testable on any host. The NTLM-specific
// message bodies live in ntlm.go, and the session that a successful
// authentication produces is established in auth.go.
//
// NTLMSSP is the only mechanism this server accepts. The Kerberos OIDs are
// still recognized — so that a Kerberos token can be refused instead of being
// mistaken for an anonymous one, which would be a downgrade — but nothing here
// advertises or negotiates Kerberos. See the authentication note in AGENTS.md.

// Mechanism OIDs.
var (
	// oidSPNEGO is 1.3.6.1.5.5.2.
	oidSPNEGO = []byte{0x2B, 0x06, 0x01, 0x05, 0x05, 0x02}
	// oidNTLMSSP is 1.3.6.1.4.1.311.2.2.10.
	oidNTLMSSP = []byte{0x2B, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x02, 0x0A}
	// oidKrb5 is 1.2.840.113554.1.2.2. Not advertised: recognized only so a
	// Kerberos token is refused rather than served as an anonymous session.
	oidKrb5 = []byte{0x2A, 0x86, 0x48, 0x86, 0xF7, 0x12, 0x01, 0x02, 0x02}
	// oidMSKrb5 is the legacy MS Kerberos alias Windows still sends:
	// 1.2.840.48018.1.2.2.
	oidMSKrb5 = []byte{0x2A, 0x86, 0x48, 0x82, 0xF7, 0x12, 0x01, 0x02, 0x02}
)

// Mech is a security mechanism seen on the wire.
type Mech int

const (
	// mechKrb5 is Kerberos 5 (either the canonical or the MS OID). It is
	// recognized only so that sessionSetup can refuse it: this server does not
	// implement Kerberos.
	mechKrb5 Mech = iota
	// mechNtlmssp is NTLMSSP, the only mechanism this server accepts.
	mechNtlmssp
	// mechUnknown is an unrecognized or unsupported mechanism.
	mechUnknown
)

func mechFromOID(oid []byte) Mech {
	switch {
	case bytesEqual(oid, oidKrb5), bytesEqual(oid, oidMSKrb5):
		return mechKrb5
	case bytesEqual(oid, oidNTLMSSP):
		return mechNtlmssp
	default:
		return mechUnknown
	}
}

func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// der writes a DER TLV with a definite length. The short and 1/2-byte long
// forms are enough for SPNEGO tokens, which never exceed 64 KiB.
func der(tag byte, content []byte) []byte {
	out := make([]byte, 0, len(content)+4)
	out = append(out, tag)
	n := len(content)
	switch {
	case n < 128:
		out = append(out, byte(n))
	case n < 256:
		out = append(out, 0x81, byte(n))
	default:
		out = append(out, 0x82, byte(n>>8), byte(n))
	}
	return append(out, content...)
}

// derOID encodes an OBJECT IDENTIFIER from its body bytes.
func derOID(body []byte) []byte { return der(0x06, body) }

// tlv is one DER element: its tag, the slice holding its content, and the total
// number of bytes consumed (header + value) so a parser can walk siblings.
type tlv struct {
	tag byte
	val []byte
	len int
}

// parseTLV parses one TLV at the front of buf. Only the definite short and
// 1/2-byte long forms are accepted.
func parseTLV(buf []byte) (tlv, bool) {
	if len(buf) < 2 {
		return tlv{}, false
	}
	tag := buf[0]
	b1 := int(buf[1])
	var hdr, n int
	switch {
	case b1 < 0x80:
		hdr, n = 2, b1
	case b1 == 0x81:
		if len(buf) < 3 {
			return tlv{}, false
		}
		hdr, n = 3, int(buf[2])
	case b1 == 0x82:
		if len(buf) < 4 {
			return tlv{}, false
		}
		hdr, n = 4, int(buf[2])<<8|int(buf[3])
	default:
		return tlv{}, false // indefinite / >2-byte length is not used by SPNEGO
	}
	if hdr > len(buf)-n {
		return tlv{}, false
	}
	return tlv{tag: tag, val: buf[hdr : hdr+n], len: hdr + n}, true
}

// childrenTLV walks the children of a constructed element.
func childrenTLV(buf []byte) []tlv {
	var out []tlv
	for len(buf) > 0 {
		t, ok := parseTLV(buf)
		if !ok {
			break
		}
		out = append(out, t)
		buf = buf[t.len:]
	}
	return out
}

// negInitHint builds the NegTokenInit2 advertised in the NEGOTIATE response
// security buffer, mechanisms in the given order; an empty list yields an empty
// buffer. Kerberos is skipped rather than advertised, however the list is built:
// this server does not accept it (see the file comment).
func negInitHint(mechs []Mech) []byte {
	if len(mechs) == 0 {
		return nil
	}
	var oids []byte
	for _, m := range mechs {
		var oid []byte
		switch m {
		case mechNtlmssp:
			oid = oidNTLMSSP
		default:
			continue
		}
		oids = append(oids, derOID(oid)...)
	}
	mechList := der(0xA0, der(0x30, oids))
	// The bogus hint string Windows expects (RFC 4178 §4.2.1 negHints).
	hintStr := der(0x1B, []byte("not_defined_in_RFC4178@please_ignore"))
	hints := der(0xA3, der(0x30, der(0xA0, hintStr)))
	init := append(mechList, hints...)
	token := der(0xA0, der(0x30, init))
	body := derOID(oidSPNEGO)
	body = append(body, token...)
	return der(0x60, body)
}

// Incoming describes what an inbound SESSION_SETUP security blob carries.
type Incoming struct {
	// Mech is the selected mechanism.
	Mech Mech
	// SPNEGO is true when the blob was SPNEGO-wrapped (vs a raw mech token);
	// the response must be SPNEGO-wrapped to match.
	SPNEGO bool
	// Token is the mechanism token to feed the acceptor: for NTLMSSP the
	// NTLMSSP\0… message. For a bare SPNEGO NegTokenInit with no mechToken this
	// is empty.
	Token []byte
}

// classifyBlob classifies a SESSION_SETUP security blob: SPNEGO NegTokenInit
// (0x60 with the SPNEGO OID), SPNEGO NegTokenResp (0xA1), a raw GSS token (0x60
// with a mechanism OID — a Kerberos AP-REQ is recognized so it can be refused),
// or a raw NTLMSSP message.
func classifyBlob(blob []byte) Incoming {
	if len(blob) == 0 {
		if startsWith(blob, ntlmSig) {
			return Incoming{Mech: mechNtlmssp, Token: blob}
		}
		return Incoming{Mech: mechUnknown, Token: blob}
	}
	switch blob[0] {
	// application-0: either SPNEGO NegTokenInit or a raw GSS mech token.
	case 0x60:
		if t, ok := parseTLV(blob); ok {
			kids := childrenTLV(t.val)
			if len(kids) > 0 && kids[0].tag == 0x06 {
				oid := kids[0].val
				switch {
				case bytesEqual(oid, oidSPNEGO):
					// SPNEGO NegTokenInit: descend into the [0] NegTokenInit.
					if len(kids) > 1 {
						return parseNegInit(kids[1].val)
					}
				default:
					// Raw GSS mech token (Kerberos AP-REQ): the whole blob is
					// the GSS token the acceptor wants.
					return Incoming{Mech: mechFromOID(oid), Token: blob}
				}
			}
		}
		return Incoming{Mech: mechUnknown, Token: blob}
	// SPNEGO NegTokenResp continuation from the client.
	case 0xA1:
		return parseNegResp(blob)
	default:
		if startsWith(blob, ntlmSig) {
			return Incoming{Mech: mechNtlmssp, Token: blob}
		}
		return Incoming{Mech: mechUnknown, Token: blob}
	}
}

func startsWith(b, prefix []byte) bool {
	return len(b) >= len(prefix) && bytesEqual(b[:len(prefix)], prefix)
}

// parseNegInit parses a SPNEGO NegTokenInit body: [0] mechTypes, optional [2]
// mechToken. It selects the first mechanism we understand and returns its token.
func parseNegInit(body []byte) Incoming {
	seq, ok := parseTLV(body)
	if !ok || seq.tag != 0x30 {
		return Incoming{Mech: mechUnknown, SPNEGO: true}
	}
	inc := Incoming{Mech: mechUnknown, SPNEGO: true}
	for _, field := range childrenTLV(seq.val) {
		switch field.tag {
		case 0xA0:
			// mechTypes: SEQUENCE OF OID — pick the first we support.
			list, ok := parseTLV(field.val)
			if !ok || list.tag != 0x30 {
				continue
			}
			for _, oid := range childrenTLV(list.val) {
				if oid.tag != 0x06 {
					continue
				}
				if m := mechFromOID(oid.val); m != mechUnknown {
					inc.Mech = m
					break
				}
			}
		case 0xA2:
			// mechToken: OCTET STRING.
			if os, ok := parseTLV(field.val); ok && os.tag == 0x04 {
				inc.Token = os.val
			}
		}
	}
	return inc
}

// parseNegResp parses a SPNEGO NegTokenResp: it extracts [1] supportedMech (if
// present) and [2] responseToken. The mechanism is inferred from the response
// token when supportedMech is absent (common on later legs).
func parseNegResp(blob []byte) Incoming {
	outer, ok := parseTLV(blob)
	if !ok || outer.tag != 0xA1 {
		return Incoming{Mech: mechUnknown, SPNEGO: true}
	}
	seq, ok := parseTLV(outer.val)
	if !ok || seq.tag != 0x30 {
		return Incoming{Mech: mechUnknown, SPNEGO: true}
	}
	inc := Incoming{Mech: mechUnknown, SPNEGO: true}
	for _, field := range childrenTLV(seq.val) {
		switch field.tag {
		case 0xA1:
			if oid, ok := parseTLV(field.val); ok && oid.tag == 0x06 {
				inc.Mech = mechFromOID(oid.val)
			}
		case 0xA2:
			if os, ok := parseTLV(field.val); ok && os.tag == 0x04 {
				inc.Token = os.val
			}
		}
	}
	// Fall back to sniffing the response token if supportedMech was omitted.
	if inc.Mech == mechUnknown {
		switch {
		case startsWith(inc.Token, ntlmSig):
			inc.Mech = mechNtlmssp
		case len(inc.Token) > 0 && inc.Token[0] == 0x60:
			inc.Mech = mechKrb5
		}
	}
	return inc
}

// SPNEGO negState values (RFC 4178 §4.2.2).
const (
	acceptCompleted  byte = 0x00
	acceptIncomplete byte = 0x01
)

// negResp wraps a mechanism's output token in a NegTokenResp with the given
// negState and supportedMech. token may be empty (e.g. the final
// accept-completed leg with no AP-REP).
func negResp(state byte, mech Mech, token []byte) []byte {
	var oid []byte
	switch mech {
	case mechNtlmssp:
		oid = oidNTLMSSP
	case mechKrb5:
		// Kept so a test can build a SPNEGO-wrapped Kerberos token to prove the
		// server refuses it. The server never answers with a Kerberos OID.
		oid = oidKrb5
	}
	inner := der(0xA0, []byte{0x0A, 0x01, state}) // negState ENUMERATED
	if len(oid) > 0 {
		inner = append(inner, der(0xA1, derOID(oid))...) // supportedMech
	}
	if len(token) > 0 {
		inner = append(inner, der(0xA2, der(0x04, token))...) // responseToken
	}
	return der(0xA1, der(0x30, inner))
}
