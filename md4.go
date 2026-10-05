package samba

import "encoding/binary"

// MD4 (RFC 1320).
//
// Go's standard library deliberately omits MD4, but NTLM's NT hash is defined
// as MD4 over the UTF-16LE password, so the primitive has to exist. It is used
// only by the NTLM authentication path (see ntHash); nothing else calls it.
//
// Implemented from the RFC directly rather than pulled from a dependency so
// the whole crypto surface of this package is auditable in one place.

func md4Block(state *[4]uint32, block []byte) {
	var x [16]uint32
	for i := range 16 {
		x[i] = binary.LittleEndian.Uint32(block[i*4:])
	}

	a, b, c, d := state[0], state[1], state[2], state[3]

	// Round 1: F(x,y,z) = (x & y) | (~x & z)
	rl1 := func(a, b, c, d uint32, k int, s uint) uint32 {
		a += (b&c | ^b&d) + x[k]
		return a<<s | a>>(32-s)
	}
	a = rl1(a, b, c, d, 0, 3)
	d = rl1(d, a, b, c, 1, 7)
	c = rl1(c, d, a, b, 2, 11)
	b = rl1(b, c, d, a, 3, 19)
	a = rl1(a, b, c, d, 4, 3)
	d = rl1(d, a, b, c, 5, 7)
	c = rl1(c, d, a, b, 6, 11)
	b = rl1(b, c, d, a, 7, 19)
	a = rl1(a, b, c, d, 8, 3)
	d = rl1(d, a, b, c, 9, 7)
	c = rl1(c, d, a, b, 10, 11)
	b = rl1(b, c, d, a, 11, 19)
	a = rl1(a, b, c, d, 12, 3)
	d = rl1(d, a, b, c, 13, 7)
	c = rl1(c, d, a, b, 14, 11)
	b = rl1(b, c, d, a, 15, 19)

	// Round 2: G(x,y,z) = (x & y) | (x & z) | (y & z), constant 0x5A827999
	rl2 := func(a, b, c, d uint32, k int, s uint) uint32 {
		a += (b&c | b&d | c&d) + x[k] + 0x5A827999
		return a<<s | a>>(32-s)
	}
	a = rl2(a, b, c, d, 0, 3)
	d = rl2(d, a, b, c, 4, 5)
	c = rl2(c, d, a, b, 8, 9)
	b = rl2(b, c, d, a, 12, 13)
	a = rl2(a, b, c, d, 1, 3)
	d = rl2(d, a, b, c, 5, 5)
	c = rl2(c, d, a, b, 9, 9)
	b = rl2(b, c, d, a, 13, 13)
	a = rl2(a, b, c, d, 2, 3)
	d = rl2(d, a, b, c, 6, 5)
	c = rl2(c, d, a, b, 10, 9)
	b = rl2(b, c, d, a, 14, 13)
	a = rl2(a, b, c, d, 3, 3)
	d = rl2(d, a, b, c, 7, 5)
	c = rl2(c, d, a, b, 11, 9)
	b = rl2(b, c, d, a, 15, 13)

	// Round 3: H(x,y,z) = x ^ y ^ z, constant 0x6ED9EBA1
	rl3 := func(a, b, c, d uint32, k int, s uint) uint32 {
		a += (b ^ c ^ d) + x[k] + 0x6ED9EBA1
		return a<<s | a>>(32-s)
	}
	a = rl3(a, b, c, d, 0, 3)
	d = rl3(d, a, b, c, 8, 9)
	c = rl3(c, d, a, b, 4, 11)
	b = rl3(b, c, d, a, 12, 15)
	a = rl3(a, b, c, d, 2, 3)
	d = rl3(d, a, b, c, 10, 9)
	c = rl3(c, d, a, b, 6, 11)
	b = rl3(b, c, d, a, 14, 15)
	a = rl3(a, b, c, d, 1, 3)
	d = rl3(d, a, b, c, 9, 9)
	c = rl3(c, d, a, b, 5, 11)
	b = rl3(b, c, d, a, 13, 15)
	a = rl3(a, b, c, d, 3, 3)
	d = rl3(d, a, b, c, 11, 9)
	c = rl3(c, d, a, b, 7, 11)
	b = rl3(b, c, d, a, 15, 15)

	state[0] += a
	state[1] += b
	state[2] += c
	state[3] += d
}

// md4Sum returns the 16-byte MD4 digest of p.
func md4Sum(p []byte) [16]byte {
	state := [4]uint32{0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476}

	full := len(p) &^ 63
	for off := 0; off < full; off += 64 {
		md4Block(&state, p[off:off+64])
	}

	// Padding: 0x80, zeros, then the 64-bit little-endian bit length.
	tail := make([]byte, 0, 128)
	tail = append(tail, p[full:]...)
	tail = append(tail, 0x80)
	for len(tail)%64 != 56 {
		tail = append(tail, 0)
	}
	var bits [8]byte
	binary.LittleEndian.PutUint64(bits[:], uint64(len(p))*8)
	tail = append(tail, bits[:]...)
	for off := 0; off < len(tail); off += 64 {
		md4Block(&state, tail[off:off+64])
	}

	var out [16]byte
	for i, s := range state {
		binary.LittleEndian.PutUint32(out[i*4:], s)
	}
	return out
}
