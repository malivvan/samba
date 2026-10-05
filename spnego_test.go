package samba

import (
	"bytes"
	"testing"
)

// TestHintAdvertisesNtlmOnly checks what NEGOTIATE tells a client this server
// can do. Kerberos must never appear, even if a caller asks for it: advertising
// a mechanism the server refuses would just produce a failed logon.
func TestHintAdvertisesNtlmOnly(t *testing.T) {
	h := negInitHint([]Mech{mechKrb5, mechNtlmssp})
	if len(h) == 0 || h[0] != 0x60 {
		t.Fatalf("hint must be an application-0 token, got % x", h)
	}
	if !bytes.Contains(h, oidNTLMSSP) {
		t.Fatal("the NTLMSSP OID must be advertised")
	}
	if !bytes.Contains(h, oidSPNEGO) {
		t.Fatal("the SPNEGO OID must be present")
	}
	if bytes.Contains(h, oidKrb5) || bytes.Contains(h, oidMSKrb5) {
		t.Fatalf("Kerberos must not be advertised: % x", h)
	}
}

func TestEmptyMechListIsEmptyHint(t *testing.T) {
	if got := negInitHint(nil); len(got) != 0 {
		t.Fatalf("empty mech list must yield an empty hint, got % x", got)
	}
}

func TestClassifySPNEGOWrappedKerberosAPReq(t *testing.T) {
	// A (fake) GSS AP-REQ: application-0 + KRB5 OID + token id + body.
	gssBody := derOID(oidKrb5)
	gssBody = append(gssBody, 0x01, 0x00) // AP-REQ token id
	gssBody = append(gssBody, []byte("ap-req-bytes")...)
	apReq := der(0x60, gssBody)

	// Wrap it in a SPNEGO NegTokenInit with mechTypes=[krb5] and mechToken.
	mechList := der(0xA0, der(0x30, derOID(oidKrb5)))
	mechTok := der(0xA2, der(0x04, apReq))
	init := append(mechList, mechTok...)
	neg := der(0xA0, der(0x30, init))
	body := derOID(oidSPNEGO)
	body = append(body, neg...)
	blob := der(0x60, body)

	inc := classifyBlob(blob)
	if inc.Mech != mechKrb5 {
		t.Fatalf("mech = %v", inc.Mech)
	}
	if !inc.SPNEGO {
		t.Fatal("must classify as SPNEGO-wrapped")
	}
	if !bytes.Equal(inc.Token, apReq) {
		t.Fatal("the token must be the GSS AP-REQ")
	}
}

func TestClassifyRawKerberosToken(t *testing.T) {
	gssBody := derOID(oidMSKrb5)
	gssBody = append(gssBody, 0x01, 0x00)
	gssBody = append(gssBody, 'x')
	blob := der(0x60, gssBody)
	inc := classifyBlob(blob)
	if inc.Mech != mechKrb5 {
		t.Fatalf("mech = %v", inc.Mech)
	}
	if inc.SPNEGO {
		t.Fatal("a raw GSS token is not SPNEGO-wrapped")
	}
	if !bytes.Equal(inc.Token, blob) {
		t.Fatal("the whole blob is the GSS token")
	}
}

func TestClassifyRawNTLMSSP(t *testing.T) {
	blob := append([]byte{}, ntlmSig...)
	blob = append(blob, 3, 0, 0, 0)
	inc := classifyBlob(blob)
	if inc.Mech != mechNtlmssp || inc.SPNEGO {
		t.Fatalf("mech = %v, spnego = %t", inc.Mech, inc.SPNEGO)
	}
}

func TestClassifyEmptyBlobIsUnknown(t *testing.T) {
	inc := classifyBlob(nil)
	if inc.Mech != mechUnknown {
		t.Fatalf("empty blob must be unknown, got %v", inc.Mech)
	}
}

func TestNegRespRoundtripShape(t *testing.T) {
	r := negResp(acceptIncomplete, mechKrb5, []byte("ap-rep"))
	// Re-classify our own NegTokenResp to confirm it parses back.
	inc := classifyBlob(r)
	if inc.Mech != mechKrb5 {
		t.Fatalf("mech = %v", inc.Mech)
	}
	if !inc.SPNEGO {
		t.Fatal("must be SPNEGO")
	}
	if !bytes.Equal(inc.Token, []byte("ap-rep")) {
		t.Fatalf("token = % x", inc.Token)
	}
}

func TestMalformedBlobsDoNotPanic(t *testing.T) {
	blobs := [][]byte{
		nil,
		{0x60},
		{0x60, 0x82},
		{0xA1, 0x05, 0x30},
		{0x60, 0x7F},
		{0x60, 0x03, 0x06, 0x01, 0x02},
		{0xA1, 0x04, 0x30, 0x02, 0xA2, 0x00},
		bytes.Repeat([]byte{0xFF}, 64),
	}
	for _, b := range blobs {
		_ = classifyBlob(b)
		_, _ = parseTLV(b)
	}
}

func TestDERLengthForms(t *testing.T) {
	// Short form.
	if got := der(0x04, bytes.Repeat([]byte{0}, 100)); got[1] != 100 {
		t.Fatalf("short form length = %d", got[1])
	}
	// 1-byte long form.
	if got := der(0x04, bytes.Repeat([]byte{0}, 200)); got[1] != 0x81 || got[2] != 200 {
		t.Fatalf("long form header = % x", got[:3])
	}
	// 2-byte long form.
	body := bytes.Repeat([]byte{0}, 300)
	got := der(0x04, body)
	if got[1] != 0x82 || got[2] != 1 || got[3] != 44 {
		t.Fatalf("2-byte long form header = % x", got[:4])
	}
	// And it parses back.
	parsed, ok := parseTLV(got)
	if !ok || len(parsed.val) != 300 || parsed.len != len(got) {
		t.Fatalf("roundtrip of a 300-byte TLV failed")
	}
}
