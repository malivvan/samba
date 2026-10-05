package samba

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/md5"
	"crypto/rc4"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/binary"
)

// Crypto constructions for NTLMv2 and SMB2/3 signing and sealing.
//
// Everything here is pure Go (no CGO), so the package stays statically
// linkable and memory safe. Go's standard library supplies AES, HMAC, SHA-2,
// MD5 and RC4; the SMB-specific compositions — the SP800-108 counter-mode KDF,
// AES-CMAC, AES-CCM and the two wire signature algorithms — live in this file
// and its neighbours (cmac.go, ccm.go, md4.go).

// NT hash: MD4 of the UTF-16LE password.
func ntHash(password string) [16]byte {
	return md4Sum(UTF16LE(password))
}

// hmacMD5 is HMAC-MD5, used by NTLMv2 (NTLMv2 hash, proof, session base key).
func hmacMD5(key, data []byte) [16]byte {
	m := hmac.New(md5.New, key)
	m.Write(data)
	var out [16]byte
	copy(out[:], m.Sum(nil))
	return out
}

// RC4 keystream XOR, used only for the NTLMSSP EncryptedRandomSessionKey
// unwrap. RC4 is broken as a cipher but is mandated by the NTLM key exchange.
func rc4XOR(key, data []byte) []byte {
	// crypto/rc4's Cipher is stateless for a single call; an error can only
	// come from a key longer than 256 bytes, which NTLM never produces.
	c, err := rc4.NewCipher(key)
	if err != nil {
		return nil
	}
	out := make([]byte, len(data))
	c.XORKeyStream(out, data)
	return out
}

func sha512Parts(parts ...[]byte) [64]byte {
	h := sha512.New()
	for _, p := range parts {
		h.Write(p)
	}
	var out [64]byte
	copy(out[:], h.Sum(nil))
	return out
}

func hmacSHA256(key []byte, parts ...[]byte) [32]byte {
	m := hmac.New(sha256.New, key)
	for _, p := range parts {
		m.Write(p)
	}
	var out [32]byte
	copy(out[:], m.Sum(nil))
	return out
}

// kdf128 is the SP800-108 KDF in counter mode with HMAC-SHA256 producing a
// 128-bit output — the SMB3 key derivation (MS-SMB2 3.1.4.2). label and context
// are used exactly as given; the spec's labels include their trailing NUL.
func kdf128(key *[16]byte, label, context []byte) [16]byte {
	var counter [4]byte
	binary.BigEndian.PutUint32(counter[:], 1)
	var bits [4]byte
	binary.BigEndian.PutUint32(bits[:], 128)
	mac := hmacSHA256(key[:], counter[:], label, []byte{0}, context, bits[:])
	var out [16]byte
	copy(out[:], mac[:16])
	return out
}

// kdf is the SP800-108 counter-mode KDF (HMAC-SHA256) producing outBits/8 bytes.
func kdf(key, label, context []byte, outBits uint32) []byte {
	outBytes := int(outBits / 8)
	out := make([]byte, 0, outBytes+32)
	var bits [4]byte
	binary.BigEndian.PutUint32(bits[:], outBits)
	for counter := uint32(1); len(out) < outBytes; counter++ {
		var c [4]byte
		binary.BigEndian.PutUint32(c[:], counter)
		block := hmacSHA256(key, c[:], label, []byte{0}, context, bits[:])
		out = append(out, block[:]...)
	}
	return out[:outBytes]
}

// SignAlg selects which signature goes on the wire for a given dialect.
type SignAlg int

const (
	// SignHmacSha256 is SMB 2.0.2 / 2.1: HMAC-SHA256(session key).
	SignHmacSha256 SignAlg = iota
	// SignAesCmac is SMB 3.x: AES-128-CMAC(derived signing key).
	SignAesCmac
)

// smb2Signature computes the 16-byte SMB2 signature over a message supplied in
// parts, so callers can substitute a zeroed signature field without copying.
func smb2Signature(alg SignAlg, key *[16]byte, parts ...[]byte) [16]byte {
	if alg == SignHmacSha256 {
		mac := hmacSHA256(key[:], parts...)
		var out [16]byte
		copy(out[:], mac[:16])
		return out
	}
	return aes128CMAC(key[:], parts...)
}

// ----------------------------------------------------------- SMB3 encryption

// SMB3 cipher ids (MS-SMB2 SMB2_ENCRYPTION_CAPABILITIES), in preference order.
const (
	CipherAES128CCM uint16 = 0x0001
	CipherAES128GCM uint16 = 0x0002
	CipherAES256CCM uint16 = 0x0003
	CipherAES256GCM uint16 = 0x0004
)

// cipherKeyLen returns the AES key length for a cipher (16 = 128-bit, 32 = 256-bit).
func cipherKeyLen(cipher uint16) int {
	switch cipher {
	case CipherAES256GCM, CipherAES256CCM:
		return 32
	default:
		return 16
	}
}

// cipherNonceLen returns the AEAD nonce length: GCM uses 12 bytes, CCM uses 11
// (MS-SMB2 3.1.1).
func cipherNonceLen(cipher uint16) int {
	switch cipher {
	case CipherAES128CCM, CipherAES256CCM:
		return 11
	default:
		return 12
	}
}

// cipherSupported reports whether the cipher id is one this server offers.
func cipherSupported(cipher uint16) bool {
	switch cipher {
	case CipherAES128CCM, CipherAES128GCM, CipherAES256CCM, CipherAES256GCM:
		return true
	default:
		return false
	}
}

// smb311EncryptionKeys derives the SMB 3.1.1 encryption keys for cipher from
// the session key and preauth hash: (client→server decrypt key, server→client
// encrypt key). Keys are returned in 32-byte buffers; only the first
// cipherKeyLen bytes are used (16 for AES-128, 32 for AES-256).
func smb311EncryptionKeys(cipher uint16, sessionKey *[16]byte, preauth *[64]byte) (c2s, s2c [32]byte) {
	bits := uint32(cipherKeyLen(cipher) * 8)
	c := kdf(sessionKey[:], []byte("SMBC2SCipherKey\x00"), preauth[:], bits)
	s := kdf(sessionKey[:], []byte("SMBS2CCipherKey\x00"), preauth[:], bits)
	copy(c2s[:], c)
	copy(s2c[:], s)
	return c2s, s2c
}

// aeadSeal encrypts buf in place for cipher and returns the 16-byte tag.
// key/nonce must be the cipher's correct length; aad is the authenticated
// TRANSFORM_HEADER bytes.
func aeadSeal(cipherID uint16, key, nonce, aad []byte, buf []byte) [16]byte {
	switch cipherID {
	case CipherAES128GCM, CipherAES256GCM:
		block, err := aes.NewCipher(key)
		if err != nil {
			panic("samba: bad GCM key: " + err.Error())
		}
		g, err := cipher.NewGCM(block)
		if err != nil {
			panic("samba: " + err.Error())
		}
		var tag [16]byte
		// crypto/cipher's GCM cannot encrypt in place, so seal into a scratch
		// buffer (ciphertext then tag) and copy the ciphertext back over buf —
		// the same observable behaviour as the detached in-place API.
		out := g.Seal(nil, nonce, buf, aad)
		copy(buf, out[:len(buf)])
		copy(tag[:], out[len(buf):])
		return tag
	case CipherAES128CCM, CipherAES256CCM:
		block, err := aes.NewCipher(key)
		if err != nil {
			panic("samba: bad CCM key: " + err.Error())
		}
		tag, err := ccmSeal(block, nonce, aad, buf, smbCCMTagLen)
		if err != nil {
			panic("samba: " + err.Error())
		}
		return tag
	default:
		panic("samba: unknown cipher")
	}
}

// aeadOpen verifies the tag and decrypts buf in place. It reports false on
// authentication failure.
func aeadOpen(cipherID uint16, key, nonce, aad, buf []byte, tag *[16]byte) bool {
	switch cipherID {
	case CipherAES128GCM, CipherAES256GCM:
		block, err := aes.NewCipher(key)
		if err != nil {
			return false
		}
		g, err := cipher.NewGCM(block)
		if err != nil {
			return false
		}
		sealed := make([]byte, len(buf), len(buf)+16)
		copy(sealed, buf)
		sealed = append(sealed, tag[:]...)
		plain, err := g.Open(nil, nonce, sealed, aad)
		if err != nil || len(plain) != len(buf) {
			return false
		}
		copy(buf, plain)
		return true
	case CipherAES128CCM, CipherAES256CCM:
		block, err := aes.NewCipher(key)
		if err != nil {
			return false
		}
		return ccmOpen(block, nonce, aad, buf, tag[:])
	default:
		return false
	}
}
