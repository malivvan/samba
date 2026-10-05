package samba

import (
	"crypto/aes"
	"crypto/subtle"
)

// AES-CMAC (RFC 4493).
//
// Go's standard library has no CMAC, but SMB 3.x signs every message with
// AES-128-CMAC. Implemented from the RFC: the subkey derivation, the padding
// rule (a full final block gets K1, otherwise 0x80 padding then K2) and the
// final CBC-MAC are all spelled out below.

const cmacRb = 0x87 // the Rb constant for a 128-bit block cipher

// cmacShift doubles a 128-bit big-endian value in place into dst, folding in
// the Rb constant when the most significant bit is set (RFC 4493 §2.3).
func cmacShift(dst, src []byte) {
	var carry byte
	for i := 15; i >= 0; i-- {
		b := src[i]
		dst[i] = b<<1 | carry
		carry = b >> 7
	}
	// carry now holds the most significant bit of the value; when set, the
	// doubling overflowed and Rb is folded into the least significant byte.
	if carry != 0 {
		dst[15] ^= cmacRb
	}
}

// cmac is an incremental AES-CMAC over a message of unknown length: it buffers
// one block so the final block can be treated differently from the rest.
type cmac struct {
	block func(dst, src []byte)
	k1    [16]byte
	k2    [16]byte
	y     [16]byte // running CBC-MAC state
	buf   [16]byte // the not-yet-committed block
	in    [16]byte // scratch for the XOR step (a field so it does not escape)
	n     int      // bytes buffered in buf
}

func newCMAC(key []byte) (*cmac, error) {
	b, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	c := &cmac{block: b.Encrypt}
	var l [16]byte
	b.Encrypt(l[:], l[:])
	cmacShift(c.k1[:], l[:])
	cmacShift(c.k2[:], c.k1[:])
	return c, nil
}

// macBlock folds one complete block into the CBC-MAC state: Y = E(Y ⊕ B).
func (c *cmac) macBlock(block []byte) {
	for i := range 16 {
		c.in[i] = c.y[i] ^ block[i]
	}
	c.block(c.y[:], c.in[:])
}

// Write consumes the next chunk of the message.
func (c *cmac) Write(p []byte) {
	for len(p) > 0 {
		if c.n == 16 {
			c.macBlock(c.buf[:]) // a full block that is not the last one
			c.n = 0
		}
		k := copy(c.buf[c.n:], p)
		c.n += k
		p = p[k:]
	}
}

// Sum returns the final MAC. It must be called once, after all Writes.
func (c *cmac) Sum() [16]byte {
	var last [16]byte
	if c.n == 16 {
		for i := range 16 {
			last[i] = c.buf[i] ^ c.k1[i]
		}
	} else {
		copy(last[:], c.buf[:c.n])
		last[c.n] = 0x80
		for i := range 16 {
			last[i] ^= c.k2[i]
		}
	}
	c.macBlock(last[:])
	return c.y
}

// aes128CMAC computes AES-128-CMAC over the concatenation of parts.
func aes128CMAC(key []byte, parts ...[]byte) [16]byte {
	c, err := newCMAC(key)
	if err != nil {
		panic("samba: bad CMAC key: " + err.Error())
	}
	for _, p := range parts {
		c.Write(p)
	}
	return c.Sum()
}

// cmacEqual is a constant-time 16-byte comparison.
func cmacEqual(a, b []byte) bool { return subtle.ConstantTimeCompare(a, b) == 1 }
