package samba

import (
	"bytes"
	"testing"
)

func TestReaderWriterRoundtrip(t *testing.T) {
	w := NewWriter(0)
	w.U8(0xAB)
	w.U16(0x1234)
	w.U32(0xDEADBEEF)
	w.U64(0x0102030405060708)
	r := NewReader(w.Bytes())
	if v, ok := r.U8(); !ok || v != 0xAB {
		t.Fatalf("u8 = %#x, %v", v, ok)
	}
	if v, ok := r.U16(); !ok || v != 0x1234 {
		t.Fatalf("u16 = %#x, %v", v, ok)
	}
	if v, ok := r.U32(); !ok || v != 0xDEADBEEF {
		t.Fatalf("u32 = %#x, %v", v, ok)
	}
	if v, ok := r.U64(); !ok || v != 0x0102030405060708 {
		t.Fatalf("u64 = %#x, %v", v, ok)
	}
	if _, ok := r.U8(); ok {
		t.Fatal("read past the end must fail")
	}
}

func TestUTF16Roundtrip(t *testing.T) {
	s := `héllo\wörld`
	if got := FromUTF16LE(UTF16LE(s)); got != s {
		t.Fatalf("roundtrip = %q, want %q", got, s)
	}
}

func TestUTF16SurrogatePair(t *testing.T) {
	// U+1F600 is outside the BMP and must encode as a surrogate pair, exactly
	// like Rust's encode_utf16.
	s := "a😀b"
	enc := UTF16LE(s)
	if len(enc) != 8 {
		t.Fatalf("encoded length = %d, want 8", len(enc))
	}
	if got := FromUTF16LE(enc); got != s {
		t.Fatalf("roundtrip = %q, want %q", got, s)
	}
}

func TestPad8(t *testing.T) {
	w := NewWriter(0)
	w.Zeros(4)
	w.Bytes8([]byte("abc"))
	w.Pad8(4)
	if (w.Len()-4)%8 != 0 {
		t.Fatalf("pad8 produced %d bytes after the base", w.Len()-4)
	}
}

func TestPatchAndTruncate(t *testing.T) {
	w := NewWriter(0)
	w.Zeros(8)
	w.Patch32(2, 0xDEADBEEF)
	w.Patch16(0, 0x1234)
	if !bytes.Equal(w.Bytes(), []byte{0x34, 0x12, 0xEF, 0xBE, 0xAD, 0xDE, 0, 0}) {
		t.Fatalf("patch produced % x", w.Bytes())
	}
	w.Truncate(4)
	if w.Len() != 4 {
		t.Fatalf("truncate left %d bytes", w.Len())
	}
}
