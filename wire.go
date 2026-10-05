package samba

import (
	"encoding/binary"
	"unicode/utf16"
)

// Little-endian wire primitives shared by all protocol code.
//
// Reader is a bounds-checked cursor over a byte slice. Every accessor reports
// failure instead of panicking, mirroring the Option-returning decoder the
// protocol was originally written against; callers turn a failure into the
// appropriate protocol error (usually STATUS_INVALID_PARAMETER).
type Reader struct {
	b   []byte
	pos int
}

// NewReader returns a cursor positioned at the front of b.
func NewReader(b []byte) *Reader { return &Reader{b: b} }

// Take consumes and returns the next n bytes, or reports failure when fewer
// than n bytes remain or n overflows.
func (r *Reader) Take(n int) ([]byte, bool) {
	if n < 0 || r.pos > len(r.b)-n {
		return nil, false
	}
	s := r.b[r.pos : r.pos+n]
	r.pos += n
	return s, true
}

// Skip consumes n bytes without returning them.
func (r *Reader) Skip(n int) bool {
	_, ok := r.Take(n)
	return ok
}

func (r *Reader) U8() (uint8, bool) {
	s, ok := r.Take(1)
	if !ok {
		return 0, false
	}
	return s[0], true
}

func (r *Reader) U16() (uint16, bool) {
	s, ok := r.Take(2)
	if !ok {
		return 0, false
	}
	return binary.LittleEndian.Uint16(s), true
}

func (r *Reader) U32() (uint32, bool) {
	s, ok := r.Take(4)
	if !ok {
		return 0, false
	}
	return binary.LittleEndian.Uint32(s), true
}

func (r *Reader) U64() (uint64, bool) {
	s, ok := r.Take(8)
	if !ok {
		return 0, false
	}
	return binary.LittleEndian.Uint64(s), true
}

// Writer is an append-only little-endian encoder. It is the Go analogue of the
// protocol's byte-buffer builder, including the two operations the SMB2 codec
// relies on: patching a previously written 32-bit field, and padding to an
// 8-byte boundary measured from a base offset.
type Writer struct {
	b []byte
}

// NewWriter returns an empty encoder with room for cap bytes.
func NewWriter(cap int) *Writer { return &Writer{b: make([]byte, 0, cap)} }

// Bytes returns the encoded payload. The returned slice aliases the writer.
func (w *Writer) Bytes() []byte { return w.b }

// Len reports the number of encoded bytes.
func (w *Writer) Len() int { return len(w.b) }

func (w *Writer) U8(v uint8) { w.b = append(w.b, v) }

func (w *Writer) U16(v uint16) { w.b = binary.LittleEndian.AppendUint16(w.b, v) }

func (w *Writer) U32(v uint32) { w.b = binary.LittleEndian.AppendUint32(w.b, v) }

func (w *Writer) U64(v uint64) { w.b = binary.LittleEndian.AppendUint64(w.b, v) }

func (w *Writer) Write(p []byte) (int, error) {
	w.b = append(w.b, p...)
	return len(p), nil
}

func (w *Writer) Bytes8(p []byte) { w.b = append(w.b, p...) }

// Zeros appends n zero bytes.
func (w *Writer) Zeros(n int) {
	w.b = append(w.b, make([]byte, n)...)
}

// Truncate drops everything past n bytes.
func (w *Writer) Truncate(n int) { w.b = w.b[:n] }

// Patch32 overwrites the 4 bytes at off.
func (w *Writer) Patch32(off int, v uint32) { binary.LittleEndian.PutUint32(w.b[off:off+4], v) }

// Patch16 overwrites the 2 bytes at off.
func (w *Writer) Patch16(off int, v uint16) { binary.LittleEndian.PutUint16(w.b[off:off+2], v) }

// Pad8 appends zero bytes so that (len - base) is a multiple of 8.
func (w *Writer) Pad8(base int) {
	if rem := (len(w.b) - base) % 8; rem != 0 {
		w.Zeros(8 - rem)
	}
}

// UTF16LE encodes s as UTF-16 little-endian (no BOM, no terminator).
func UTF16LE(s string) []byte {
	out := make([]byte, 0, len(s)*2)
	for _, u := range []rune(s) {
		if u > 0xFFFF {
			// Encode as a surrogate pair, exactly like Rust's encode_utf16.
			u -= 0x10000
			hi := 0xD800 + (u >> 10)
			lo := 0xDC00 + (u & 0x3FF)
			out = binary.LittleEndian.AppendUint16(out, uint16(hi))
			out = binary.LittleEndian.AppendUint16(out, uint16(lo))
			continue
		}
		out = binary.LittleEndian.AppendUint16(out, uint16(u))
	}
	return out
}

// FromUTF16LE decodes little-endian UTF-16, replacing malformed units with the
// Unicode replacement character (Rust's from_utf16_lossy).
func FromUTF16LE(b []byte) string {
	n := len(b) / 2
	if n == 0 {
		return ""
	}
	units := make([]uint16, n)
	for i := range n {
		units[i] = binary.LittleEndian.Uint16(b[i*2:])
	}
	return string(utf16.Decode(units))
}

// le16/le32/le64 decode little-endian fields from a byte slice that the caller
// has already bounds-checked.
func le16(b []byte) uint16 { return binary.LittleEndian.Uint16(b) }
func le32(b []byte) uint32 { return binary.LittleEndian.Uint32(b) }
func le64(b []byte) uint64 { return binary.LittleEndian.Uint64(b) }

// put16/put32/put64 write little-endian fields into a pre-sized slice.
func put16(b []byte, v uint16) { binary.LittleEndian.PutUint16(b, v) }
func put32(b []byte, v uint32) { binary.LittleEndian.PutUint32(b, v) }
func put64(b []byte, v uint64) { binary.LittleEndian.PutUint64(b, v) }
