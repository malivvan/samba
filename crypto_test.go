package samba

import (
	"bytes"
	"crypto/aes"
	"encoding/hex"
	"testing"
)

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("bad hex %q: %v", s, err)
	}
	return b
}

func TestNTHashClassic(t *testing.T) {
	// The canonical NT hash of "password".
	got := ntHash("password")
	if !bytes.Equal(got[:], mustHex(t, "8846f7eaee8fb117ad06bdd830b7586c")) {
		t.Fatalf("nt_hash(password) = %x", got)
	}
}

func TestMD4RFC1320(t *testing.T) {
	// RFC 1320 test vectors.
	cases := []struct {
		in, want string
	}{
		{"", "31d6cfe0d16ae931b73c59d7e0c089c0"},
		{"a", "bde52cb31de33e46245e05fbdbd6fb24"},
		{"abc", "a448017aaf21d8525fc10ae87aa6729d"},
		{"message digest", "d9130a8164549fe818874806e1c7014b"},
		{"abcdefghijklmnopqrstuvwxyz", "d79e1c308aa5bbcdeea8ed63df412da9"},
		{"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789", "043f8582f241db351ce627e153e7f0e4"},
		{"12345678901234567890123456789012345678901234567890123456789012345678901234567890", "e33b4ddc9c38f2199c3e7b164fcc0536"},
	}
	for _, c := range cases {
		got := md4Sum([]byte(c.in))
		if !bytes.Equal(got[:], mustHex(t, c.want)) {
			t.Errorf("md4(%q) = %x, want %s", c.in, got, c.want)
		}
	}
}

func TestHMACMD5Reference(t *testing.T) {
	// Verified against Python:
	//   hmac.new(b"Jefe", b"what do ya wanna do for nothing?", hashlib.md5)
	mac := hmacMD5([]byte("Jefe"), []byte("what do ya wanna do for nothing?"))
	if !bytes.Equal(mac[:], mustHex(t, "78eb0e153d16ebb2a9a5c3be5965c8ab")) {
		t.Fatalf("hmac_md5 = %x", mac)
	}
}

func TestHMACSHA256RFC4231(t *testing.T) {
	// RFC 4231 test case 1, truncated to the 16-byte SMB signature.
	key := bytes.Repeat([]byte{0x0b}, 16)
	sig := smb2Signature(SignHmacSha256, (*[16]byte)(key), []byte("Hi There"))
	expect := hmacSHA256(key, []byte("Hi There"))
	if !bytes.Equal(sig[:], expect[:16]) {
		t.Fatalf("smb2_signature = %x, want %x", sig, expect[:16])
	}
}

func TestCMACRFC4493(t *testing.T) {
	key := mustHex(t, "2b7e151628aed2a6abf7158809cf4f3c")
	var k [16]byte
	copy(k[:], key)

	sig := smb2Signature(SignAesCmac, &k)
	if !bytes.Equal(sig[:], mustHex(t, "bb1d6929e95937287fa37d129b756746")) {
		t.Fatalf("cmac(empty) = %x", sig)
	}

	msg := mustHex(t, "6bc1bee22e409f96e93d7e117393172a")
	// Feed in two parts to exercise chunked updates.
	sig = smb2Signature(SignAesCmac, &k, msg[:7], msg[7:])
	if !bytes.Equal(sig[:], mustHex(t, "070a16b46b4d4144f79bdd9dd04a287c")) {
		t.Fatalf("cmac(msg) = %x", sig)
	}

	// The remaining RFC 4493 vectors.
	cases := []struct {
		in, want string
	}{
		{"6bc1bee22e409f96e93d7e117393172a", "070a16b46b4d4144f79bdd9dd04a287c"},
		{"6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e51" +
			"30c81c46a35ce411", "dfa66747de9ae63030ca32611497c827"},
		{"6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e51" +
			"30c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710",
			"51f0bebf7e3b9d92fc49741779363cfe"},
	}
	for _, c := range cases {
		got := aes128CMAC(key, mustHex(t, c.in))
		if !bytes.Equal(got[:], mustHex(t, c.want)) {
			t.Errorf("cmac(%s) = %x, want %s", c.in, got, c.want)
		}
	}
}

func TestRC4Known(t *testing.T) {
	got := rc4XOR([]byte("Key"), []byte("Plaintext"))
	if !bytes.Equal(got, mustHex(t, "bbf316e8d940af0ad3")) {
		t.Fatalf("rc4 = %x", got)
	}
}

func TestCCMRFC3610Vectors(t *testing.T) {
	// RFC 3610 packet vectors 1-3, cross-checked against the reference
	// implementation of CCM in the RFC: 8-byte tag, 13-byte nonce, 8-byte AAD.
	cases := []struct {
		key   string
		nonce string
		aad   string
		plain string
		ct    string
		tag   string
	}{
		{
			key:   "c0c1c2c3c4c5c6c7c8c9cacbcccdcecf",
			nonce: "00000003020100a0a1a2a3a4a5",
			aad:   "0001020304050607",
			plain: "08090a0b0c0d0e0f101112131415161718191a1b1c1d1e",
			ct:    "588c979a61c663d2f066d0c2c0f989806d5f6b61dac384",
			tag:   "17e8d12cfdf926e0",
		},
		{
			key:   "c0c1c2c3c4c5c6c7c8c9cacbcccdcecf",
			nonce: "00000004030201a0a1a2a3a4a5",
			aad:   "0001020304050607",
			plain: "08090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
			ct:    "72c91a36e135f8cf291ca894085c87e3cc15c439c9e43a3b",
			tag:   "a091d56e10400916",
		},
		{
			key:   "c0c1c2c3c4c5c6c7c8c9cacbcccdcecf",
			nonce: "00000005040302a0a1a2a3a4a5",
			aad:   "0001020304050607",
			plain: "08090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20",
			ct:    "51b1e5f44a197d1da46b0f8e2d282ae871e838bb64da859657",
			tag:   "4adaa76fbd9fb0c5",
		},
	}
	for i, c := range cases {
		key := mustHex(t, c.key)
		nonce := mustHex(t, c.nonce)
		aad := mustHex(t, c.aad)
		plain := mustHex(t, c.plain)
		wantCT := mustHex(t, c.ct)
		wantTag := mustHex(t, c.tag)

		block, err := aes.NewCipher(key)
		if err != nil {
			t.Fatal(err)
		}
		buf := append([]byte{}, plain...)
		tag, err := ccmSeal(block, nonce, aad, buf, len(wantTag))
		if err != nil {
			t.Fatalf("vector %d: %v", i+1, err)
		}
		if !bytes.Equal(buf, wantCT) {
			t.Fatalf("vector %d ciphertext = %x, want %x", i+1, buf, wantCT)
		}
		if !bytes.Equal(tag[:len(wantTag)], wantTag) {
			t.Fatalf("vector %d tag = %x, want %x", i+1, tag[:len(wantTag)], wantTag)
		}
		dec := append([]byte{}, buf...)
		if !ccmOpen(block, nonce, aad, dec, wantTag) {
			t.Fatalf("vector %d open failed", i+1)
		}
		if !bytes.Equal(dec, plain) {
			t.Fatalf("vector %d recovered %x, want %x", i+1, dec, plain)
		}
		// Tampered tag, wrong AAD and wrong key must all fail.
		badTag := append([]byte{}, wantTag...)
		badTag[0] ^= 1
		if ccmOpen(block, nonce, aad, append([]byte{}, buf...), badTag) {
			t.Fatalf("vector %d tampered tag accepted", i+1)
		}
		if ccmOpen(block, nonce, []byte("other!!!"), append([]byte{}, buf...), wantTag) {
			t.Fatalf("vector %d wrong AAD accepted", i+1)
		}
		other, err := aes.NewCipher(make([]byte, 16))
		if err != nil {
			t.Fatal(err)
		}
		if ccmOpen(other, nonce, aad, append([]byte{}, buf...), wantTag) {
			t.Fatalf("vector %d wrong key accepted", i+1)
		}
	}
}

func TestSMB3CCMParameters(t *testing.T) {
	// The SMB wrapper pins an 11-byte nonce (L = 4) and a 16-byte tag.
	block, err := aes.NewCipher(make([]byte, 16))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ccmSeal(block, make([]byte, 12), nil, make([]byte, 4), smbCCMTagLen); err != nil {
		t.Fatalf("a 12-byte nonce is legal CCM: %v", err)
	}
	if _, err := ccmSeal(block, make([]byte, 6), nil, make([]byte, 4), smbCCMTagLen); err == nil {
		t.Fatal("a 6-byte nonce must be rejected")
	}
	if _, err := ccmSeal(block, make([]byte, 11), nil, make([]byte, 4), 3); err == nil {
		t.Fatal("a 3-byte tag must be rejected")
	}
}

func TestAEADRoundtripAndTamper(t *testing.T) {
	aad := []byte("smb2-transform-header-aad")
	plain := []byte("the quick brown fox jumps over the lazy SMB share")
	for _, cipherID := range []uint16{CipherAES128GCM, CipherAES256GCM, CipherAES128CCM, CipherAES256CCM} {
		key := bytes.Repeat([]byte{0x11}, cipherKeyLen(cipherID))
		nonce := bytes.Repeat([]byte{0x22}, cipherNonceLen(cipherID))
		buf := append([]byte{}, plain...)
		tag := aeadSeal(cipherID, key, nonce, aad, buf)
		if bytes.Equal(buf, plain) {
			t.Fatalf("ciphertext must differ (%#x)", cipherID)
		}
		dec := append([]byte{}, buf...)
		if !aeadOpen(cipherID, key, nonce, aad, dec, &tag) {
			t.Fatalf("open %#x", cipherID)
		}
		if !bytes.Equal(dec, plain) {
			t.Fatalf("recover %#x", cipherID)
		}
		bad := tag
		bad[0] ^= 1
		if aeadOpen(cipherID, key, nonce, aad, append([]byte{}, buf...), &bad) {
			t.Fatalf("tampered tag accepted (%#x)", cipherID)
		}
		if aeadOpen(cipherID, key, nonce, []byte("other"), append([]byte{}, buf...), &tag) {
			t.Fatalf("wrong AAD accepted (%#x)", cipherID)
		}
		wrongKey := make([]byte, cipherKeyLen(cipherID))
		if aeadOpen(cipherID, wrongKey, nonce, aad, append([]byte{}, buf...), &tag) {
			t.Fatalf("wrong key accepted (%#x)", cipherID)
		}
	}
}

func TestAESGCMKnownAnswer(t *testing.T) {
	// NIST GCM test case 3 (empty AAD, 128-bit key), the same construction the
	// SMB transform header uses.
	key := mustHex(t, "feffe9928665731c6d6a8f9467308308")
	nonce := mustHex(t, "cafebabefacedbaddecaf888")
	plain := mustHex(t, "d9313225f88406e5a55909c5aff5269a"+
		"86a7a9531534f7da2e4c303d8a318a72"+
		"1c3c0c95956809532fcf0e2449a6b525"+
		"b16aedf5aa0de657ba637b391aafd255")
	wantCT := mustHex(t, "42831ec2217774244b7221b784d0d49c"+
		"e3aa212f2c02a4e035c17e2329aca12e"+
		"21d514b25466931c7d8f6a5aac84aa05"+
		"1ba30b396a0aac973d58e091473f5985")
	wantTag := mustHex(t, "4d5c2af327cd64a62cf35abd2ba6fab4")

	buf := append([]byte{}, plain...)
	tag := aeadSeal(CipherAES128GCM, key, nonce, nil, buf)
	if !bytes.Equal(buf, wantCT) {
		t.Fatalf("gcm ciphertext = %x", buf)
	}
	if !bytes.Equal(tag[:], wantTag) {
		t.Fatalf("gcm tag = %x", tag)
	}
	dec := append([]byte{}, buf...)
	if !aeadOpen(CipherAES128GCM, key, nonce, nil, dec, &tag) {
		t.Fatal("gcm open failed")
	}
	if !bytes.Equal(dec, plain) {
		t.Fatalf("gcm recover = %x", dec)
	}
}

func TestEncKeysDeterministicAndDistinct(t *testing.T) {
	sk := [16]byte{7}
	pa := [64]byte{}
	for i := range pa {
		pa[i] = 9
	}
	c2s, s2c := smb311EncryptionKeys(CipherAES128GCM, &sk, &pa)
	if c2s == s2c {
		t.Fatal("c2s and s2c must differ")
	}
	c2s2, _ := smb311EncryptionKeys(CipherAES128GCM, &sk, &pa)
	if c2s != c2s2 {
		t.Fatal("derivation must be deterministic")
	}
	c256, _ := smb311EncryptionKeys(CipherAES256GCM, &sk, &pa)
	if c256 == [32]byte{} {
		t.Fatal("256-bit key must fill 32 bytes")
	}
	if c256 == c2s {
		t.Fatal("128 and 256 derivations must differ")
	}
	// Only the first 16 bytes are used for AES-128.
	var zeroTail [16]byte
	if !bytes.Equal(c2s[16:], zeroTail[:]) {
		t.Fatal("AES-128 key must leave the tail zeroed")
	}
}

// TestSMB3EncryptionKeysMatchSpec pins the SMB 3.0/3.0.2 key derivation against
// vectors computed independently from MS-SMB2 3.1.4.2 (and matching what the
// Linux client and ksmbd derive). The labels and contexts carry their
// terminating NUL, and the "ServerIn " context carries a trailing space, which
// no round-trip test against our own code can catch: a transposed byte here
// produces keys that are self-consistent and silently never interoperate.
func TestSMB3EncryptionKeysMatchSpec(t *testing.T) {
	var sk [16]byte
	for i := range sk {
		sk[i] = byte(i)
	}
	c2s, s2c := smb3EncryptionKeys(&sk)
	const (
		wantC2S = "8e21f3cae16d07d84c03d74467f57878" // KDF(sk, "SMB2AESCCM\0", "ServerIn \0")
		wantS2C = "95d8b55c852cd25349994b3842fa4105" // KDF(sk, "SMB2AESCCM\0", "ServerOut\0")
	)
	if got := hex.EncodeToString(c2s[:16]); got != wantC2S {
		t.Errorf("client→server key = %s, want %s", got, wantC2S)
	}
	if got := hex.EncodeToString(s2c[:16]); got != wantS2C {
		t.Errorf("server→client key = %s, want %s", got, wantS2C)
	}
	if c2s == s2c {
		t.Fatal("the two directions must differ: a swapped pair encrypts with the peer's key")
	}
	// AES-128: the 32-byte buffers are only half filled.
	var zeroTail [16]byte
	if !bytes.Equal(c2s[16:], zeroTail[:]) {
		t.Error("the AES-128 key must leave the tail zeroed")
	}
}

func TestKDF128Structure(t *testing.T) {
	// Pin the exact SP800-108 message layout against a manual HMAC.
	key := [16]byte{7}
	label := []byte("SMB2AESCMAC\x00")
	ctx := []byte("SmbSign\x00")
	msg := []byte{0, 0, 0, 1}
	msg = append(msg, label...)
	msg = append(msg, 0)
	msg = append(msg, ctx...)
	msg = append(msg, 0, 0, 0, 128)
	expect := hmacSHA256(key[:], msg)
	got := kdf128(&key, label, ctx)
	if !bytes.Equal(got[:], expect[:16]) {
		t.Fatalf("kdf128 = %x, want %x", got, expect[:16])
	}
}

func TestCipherParams(t *testing.T) {
	cases := []struct {
		cipher    uint16
		keyLen    int
		nonceLen  int
		supported bool
	}{
		{CipherAES128GCM, 16, 12, true},
		{CipherAES256GCM, 32, 12, true},
		{CipherAES128CCM, 16, 11, true},
		{CipherAES256CCM, 32, 11, true},
		{0x0099, 16, 12, false},
	}
	for _, c := range cases {
		if got := cipherKeyLen(c.cipher); got != c.keyLen {
			t.Errorf("cipherKeyLen(%#x) = %d, want %d", c.cipher, got, c.keyLen)
		}
		if got := cipherNonceLen(c.cipher); got != c.nonceLen {
			t.Errorf("cipherNonceLen(%#x) = %d, want %d", c.cipher, got, c.nonceLen)
		}
		if got := cipherSupported(c.cipher); got != c.supported {
			t.Errorf("cipherSupported(%#x) = %t, want %t", c.cipher, got, c.supported)
		}
	}
}
