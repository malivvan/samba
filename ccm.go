package samba

import (
	"crypto/cipher"
	"errors"
)

// AES-CCM (RFC 3610).
//
// Go's standard library ships GCM but not CCM, and SMB 3.1.1 lets a client
// negotiate AES-128-CCM / AES-256-CCM, so the mode is implemented here. The
// generic form below takes the nonce and tag lengths as parameters (the RFC's
// own test vectors use an 8-byte tag and a 13-byte nonce, and validating
// against them is the only honest way to trust a hand-written AEAD); the SMB
// entry points pin the protocol's parameters — 16-byte tag, 11-byte nonce,
// which fixes CCM's length field L at 4.

const ccmBlockSize = 16

// ccmParams derives the CCM length field L from the nonce length.
func ccmParams(nonceLen, tagLen int) (l int, err error) {
	if nonceLen < 7 || nonceLen > 13 {
		return 0, errors.New("ccm: nonce length must be 7..13")
	}
	if tagLen < 4 || tagLen > 16 || tagLen%2 != 0 {
		return 0, errors.New("ccm: tag length must be an even value in 4..16")
	}
	return 15 - nonceLen, nil
}

// ccmB0 builds the first authentication block: flags, nonce and message length.
func ccmB0(nonce []byte, msgLen int, hasAAD bool, tagLen, l int) [16]byte {
	var b0 [16]byte
	if hasAAD {
		b0[0] |= 1 << 6
	}
	b0[0] |= byte((tagLen-2)/2) << 3
	b0[0] |= byte(l - 1)
	copy(b0[1:], nonce)
	putBigEndian(b0[16-l:], uint64(msgLen))
	return b0
}

func ccmCounter(nonce []byte, counter uint32, l int) [16]byte {
	var a [16]byte
	a[0] = byte(l - 1)
	copy(a[1:], nonce)
	putBigEndian(a[16-l:], uint64(counter))
	return a
}

// putBigEndian writes v into dst as a big-endian integer.
func putBigEndian(dst []byte, v uint64) {
	for i := len(dst) - 1; i >= 0; i-- {
		dst[i] = byte(v)
		v >>= 8
	}
}

// ccmMAC accumulates the CBC-MAC input blocks.
type ccmMAC struct {
	block cipher.Block
	y     [16]byte
	buf   [16]byte
	in    [16]byte // scratch for the XOR step (a field so it does not escape)
	n     int
}

func (m *ccmMAC) update(data []byte) {
	for len(data) > 0 {
		k := copy(m.buf[m.n:], data)
		m.n += k
		data = data[k:]
		if m.n == ccmBlockSize {
			m.flush()
		}
	}
}

// flush XORs the buffered block (zero-padded to 16 bytes) into the MAC state.
func (m *ccmMAC) flush() {
	for i := range 16 {
		m.in[i] = m.y[i] ^ m.buf[i]
	}
	m.block.Encrypt(m.y[:], m.in[:])
	m.n = 0
	m.buf = [16]byte{}
}

// ccmAADPrefix encodes the associated-data length in CCM's variable form.
func ccmAADPrefix(n int) []byte {
	switch {
	case n < 0xFF00:
		return []byte{byte(n >> 8), byte(n)}
	case uint64(n) <= 0xFFFF_FFFF:
		return []byte{0xFF, 0xFE, byte(n >> 24), byte(n >> 16), byte(n >> 8), byte(n)}
	default:
		out := make([]byte, 10)
		out[0], out[1] = 0xFF, 0xFF
		putBigEndian(out[2:], uint64(n))
		return out
	}
}

func ccmComputeTag(block cipher.Block, nonce, aad, msg []byte, tagLen, l int) [16]byte {
	m := &ccmMAC{block: block}
	b0 := ccmB0(nonce, len(msg), len(aad) > 0, tagLen, l)
	block.Encrypt(m.y[:], b0[:])
	if len(aad) > 0 {
		m.update(ccmAADPrefix(len(aad)))
		m.update(aad)
		// The associated data is zero-padded to a whole number of blocks
		// before the payload begins (RFC 3610 §2.2), so the payload never
		// shares a block with it.
		if m.n > 0 {
			m.flush()
		}
	}
	m.update(msg)
	// The payload is zero-padded to a whole number of blocks; data that already
	// ended on a block boundary contributes no extra block.
	if m.n > 0 {
		m.flush()
	}
	s0 := ccmCounter(nonce, 0, l)
	var enc [16]byte
	block.Encrypt(enc[:], s0[:])
	var tag [16]byte
	for i := range 16 {
		tag[i] = m.y[i] ^ enc[i]
	}
	return tag
}

// ccmCrypt applies the CCM counter-mode keystream to buf in place.
func ccmCrypt(block cipher.Block, nonce, buf []byte, l int) {
	var stream [16]byte
	for i := 0; i < len(buf); i += ccmBlockSize {
		a := ccmCounter(nonce, uint32(i/ccmBlockSize+1), l)
		block.Encrypt(stream[:], a[:])
		end := min(i+ccmBlockSize, len(buf))
		for j := i; j < end; j++ {
			buf[j] ^= stream[j-i]
		}
	}
}

// ccmSeal encrypts buf in place and returns the tag. Only tagLen bytes of the
// returned value are significant.
func ccmSeal(block cipher.Block, nonce, aad, buf []byte, tagLen int) ([16]byte, error) {
	l, err := ccmParams(len(nonce), tagLen)
	if err != nil {
		return [16]byte{}, err
	}
	// The message length is encoded in L octets; a longer message would be
	// encoded with the high bits silently dropped, which would authenticate the
	// wrong length. SMB3 payloads never approach this, but the primitive should
	// not pretend to seal what it cannot length-encode.
	if uint64(len(buf)) >= uint64(1)<<(8*uint(l)) {
		return [16]byte{}, errors.New("ccm: message too long for the nonce length")
	}
	tag := ccmComputeTag(block, nonce, aad, buf, tagLen, l)
	ccmCrypt(block, nonce, buf, l)
	return tag, nil
}

// ccmOpen decrypts buf in place after verifying the tag.
func ccmOpen(block cipher.Block, nonce, aad, buf, tag []byte) bool {
	l, err := ccmParams(len(nonce), len(tag))
	if err != nil {
		return false
	}
	plain := make([]byte, len(buf))
	copy(plain, buf)
	ccmCrypt(block, nonce, plain, l)
	want := ccmComputeTag(block, nonce, aad, plain, len(tag), l)
	if !cmacEqual(want[:len(tag)], tag) {
		return false
	}
	copy(buf, plain)
	return true
}

// ---------------------------------------------------------------- SMB3 wiring

// smbCCMNonceLen and smbCCMTagLen are the parameters MS-SMB2 fixes for SMB3
// encryption.
const (
	smbCCMNonceLen = 11
	smbCCMTagLen   = 16
)
