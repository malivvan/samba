package samba

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

// Benchmarks.
//
// Two layers are measured:
//
//   - micro-benchmarks of the protocol codec, signing and the AEAD/KDF
//     primitives, which are the per-message costs on the SMB2 hot path, and
//   - socket-level benchmarks that drive a real client against a running
//     server, reporting bytes/op so `go test -bench` prints throughput
//     directly. These are the same paths the headline numbers in
//     docs/BENCHMARKS.md measure end to end against Samba with bench/bench.sh.
//
// The full-size runs (1 GiB sequential read, 512 MiB fsync write, multichannel
// aggregate) are the shell suite; these benchmarks are sized to run in CI.

// ---------------------------------------------------------------- codec / crypto

func BenchmarkProcessFrameEcho(b *testing.B) {
	srv := newFuzzSrv()
	pc := NewProtoConn(srv, 0, 0, 1)
	echo := reqHdr(CmdEcho, 1, 0, 0)
	echo.U16(4)
	echo.U16(0)
	frame := echo.Bytes()
	tx := NewWriter(0)
	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		tx.Truncate(0)
		ProcessFrame(srv, pc, frame, tx)
	}
}

func BenchmarkProcessFrameNegotiate(b *testing.B) {
	srv := newFuzzSrv()
	pc := NewProtoConn(srv, 0, 0, 1)
	neg := reqHdr(CmdNegotiate, 1, 0, 0)
	neg.U16(36)
	neg.U16(3)
	neg.U16(1)
	neg.U16(0)
	neg.U32(0)
	neg.Zeros(16 + 8)
	neg.U16(0x0210)
	neg.U16(0x0300)
	neg.U16(0x0302)
	frame := neg.Bytes()
	tx := NewWriter(0)
	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		tx.Truncate(0)
		ProcessFrame(srv, pc, frame, tx)
	}
}

func BenchmarkSignHMACSHA256(b *testing.B) {
	sc := SignCtx{Alg: SignHmacSha256, Key: [16]byte{1}}
	msg := make([]byte, 1<<20)
	b.SetBytes(int64(len(msg)))
	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		_ = smb2Signature(sc.Alg, &sc.Key, msg)
	}
}

func BenchmarkSignAESCMAC(b *testing.B) {
	sc := SignCtx{Alg: SignAesCmac, Key: [16]byte{1}}
	msg := make([]byte, 1<<20)
	b.SetBytes(int64(len(msg)))
	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		_ = smb2Signature(sc.Alg, &sc.Key, msg)
	}
}

func BenchmarkVerifySignature(b *testing.B) {
	sc := SignCtx{Alg: SignAesCmac, Key: [16]byte{1}}
	msg := make([]byte, 4096)
	sig := smb2Signature(sc.Alg, &sc.Key, msg[:48], make([]byte, 16), msg[64:])
	copy(msg[48:64], sig[:])
	b.SetBytes(int64(len(msg)))
	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		if !verifySignature(msg, &sc) {
			b.Fatal("signature must verify")
		}
	}
}

func benchAEAD(b *testing.B, cipherID uint16, size int) {
	key := bytes.Repeat([]byte{0x11}, cipherKeyLen(cipherID))
	nonce := bytes.Repeat([]byte{0x22}, cipherNonceLen(cipherID))
	aad := bytes.Repeat([]byte{0x33}, 32)
	src := make([]byte, size)
	name := fmt.Sprintf("cipher=%#x/size=%d", cipherID, size)
	b.Run(name, func(b *testing.B) {
		b.SetBytes(int64(size))
		b.ReportAllocs()
		b.ResetTimer()
		for range b.N {
			buf := make([]byte, size)
			copy(buf, src)
			tag := aeadSeal(cipherID, key, nonce, aad, buf)
			if !aeadOpen(cipherID, key, nonce, aad, buf, &tag) {
				b.Fatal("open must succeed")
			}
		}
	})
}

func BenchmarkAEADSealOpenGCM128(b *testing.B) { benchAEAD(b, CipherAES128GCM, 64*1024) }
func BenchmarkAEADSealOpenGCM256(b *testing.B) { benchAEAD(b, CipherAES256GCM, 64*1024) }
func BenchmarkAEADSealOpenCCM128(b *testing.B) { benchAEAD(b, CipherAES128CCM, 64*1024) }
func BenchmarkAEADSealOpenCCM256(b *testing.B) { benchAEAD(b, CipherAES256CCM, 64*1024) }

func BenchmarkNTHash(b *testing.B) {
	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		_ = ntHash("correct horse battery staple")
	}
}

func BenchmarkHMACMD5(b *testing.B) {
	key := [16]byte{1}
	msg := make([]byte, 64)
	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		_ = hmacMD5(key[:], msg)
	}
}

func BenchmarkKDF128(b *testing.B) {
	key := [16]byte{1}
	preauth := [64]byte{}
	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		_ = kdf128(&key, []byte("SMBSigningKey\x00"), preauth[:])
	}
}

func BenchmarkBuildReadRespPrefix(b *testing.B) {
	plan := &ZcReadPlan{Length: MaxReadTarget, Credits: 512, TreeID: 1, SessionID: 2}
	tx := NewWriter(0)
	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		BuildReadRespPrefix(plan, MaxReadTarget, tx)
	}
}

func BenchmarkDirSnapshot(b *testing.B) {
	dir := b.TempDir()
	for i := range 256 {
		if err := os.WriteFile(filepath.Join(dir, fmt.Sprintf("f%04d.txt", i)), []byte("x"), 0o644); err != nil {
			b.Fatal(err)
		}
	}
	f, err := os.Open(dir)
	if err != nil {
		b.Fatal(err)
	}
	defer f.Close()
	of := &OpenFile{File: f, Path: dir, IsDir: true}
	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		if _, err := dirSnapshot(of, "*"); err != nil {
			b.Fatal(err)
		}
	}
}

// --------------------------------------------------------------- socket level

// benchShareFile writes a scratch file of the given size into dir.
func benchShareFile(b *testing.B, dir string, size int) {
	b.Helper()
	if _, err := os.Stat(filepath.Join(dir, "bench.bin")); err == nil {
		return
	}
	buf := make([]byte, 1<<20)
	for i := range buf {
		buf[i] = byte(i * 13)
	}
	f, err := os.Create(filepath.Join(dir, "bench.bin"))
	if err != nil {
		b.Fatal(err)
	}
	defer f.Close()
	for written := 0; written < size; written += len(buf) {
		if _, err := f.Write(buf); err != nil {
			b.Fatal(err)
		}
	}
}

// benchSrvAndClient boots a server with a scratch share and one prepared
// connection.
func benchSrvAndClient(b *testing.B, opts ...func(*Config)) (*testClient, string) {
	b.Helper()
	dir := b.TempDir()
	benchShareFile(b, dir, 128<<20)
	var tune func(*Config)
	if len(opts) > 0 {
		tune = opts[0]
	}
	srv := startTestServer(b, dir, tune)
	c := dialTestClient(b, srv.Addr().String())
	c.establish(0x0302)
	return c, dir
}

// BenchmarkServerReadZeroCopy measures the zero-copy read path: the response
// header is written and the file's cached pages are spliced straight to the
// socket.
func BenchmarkServerReadZeroCopy(b *testing.B) {
	c, _ := benchSrvAndClient(b)
	const chunk = 1 << 20
	st, fid := c.create("bench.bin", fileOpen, 0x40, 0x8000_0000, nil)
	if st != StatusSuccess {
		b.Fatalf("create status %#x", st)
	}
	defer c.close(fid)

	b.SetBytes(chunk)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		st, got := c.read(fid, 0, chunk)
		if st != StatusSuccess {
			b.Fatalf("read status %#x", st)
		}
		if len(got) != chunk {
			b.Fatalf("read returned %d bytes", len(got))
		}
	}
}

// BenchmarkServerReadBuffered measures the buffered read path (small reads,
// which is also what signed and encrypted channels take).
func BenchmarkServerReadBuffered(b *testing.B) {
	c, _ := benchSrvAndClient(b)
	const chunk = 4096
	st, fid := c.create("bench.bin", fileOpen, 0x40, 0x8000_0000, nil)
	if st != StatusSuccess {
		b.Fatalf("create status %#x", st)
	}
	defer c.close(fid)

	b.SetBytes(chunk)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if st, _ := c.read(fid, 0, chunk); st != StatusSuccess {
			b.Fatalf("read status %#x", st)
		}
	}
}

// BenchmarkServerWrite measures the write round trip (one 1 MiB WRITE per
// iteration).
func BenchmarkServerWrite(b *testing.B) {
	c, dir := benchSrvAndClient(b)
	const chunk = 1 << 20
	st, fid := c.create("w.bin", fileOverwriteIf, 0x40, genericWrite, nil)
	if st != StatusSuccess {
		b.Fatalf("create status %#x", st)
	}
	defer c.close(fid)
	payload := make([]byte, chunk)

	b.SetBytes(chunk)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if st := c.write(fid, 0, payload); st != StatusSuccess {
			b.Fatalf("write status %#x", st)
		}
	}
	b.StopTimer()
	_ = os.Remove(filepath.Join(dir, "w.bin"))
}

// BenchmarkServerMetaOps measures the small-file metadata path (create, write,
// close, unlink) that the README's metadata benchmark covers end to end.
func BenchmarkServerMetaOps(b *testing.B) {
	c, _ := benchSrvAndClient(b)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		name := fmt.Sprintf("meta-%d.txt", i%512)
		st, fid := c.create(name, fileOverwriteIf, 0x40, 0x1000_0000, nil)
		if st != StatusSuccess {
			b.Fatalf("create status %#x", st)
		}
		if st := c.write(fid, 0, []byte("x\n")); st != StatusSuccess {
			b.Fatalf("write status %#x", st)
		}
		if st := c.close(fid); st != StatusSuccess {
			b.Fatalf("close status %#x", st)
		}
	}
}

// BenchmarkServerPipelinedEcho measures batched request handling: a burst of
// ECHO requests travels in one write and every response must come back.
func BenchmarkServerPipelinedEcho(b *testing.B) {
	c, _ := benchSrvAndClient(b)
	const burst = 32
	frame := reqHdr(CmdEcho, 1, 0, c.sess)
	frame.U16(4)
	frame.U16(0)
	body := frame.Bytes()
	var batch []byte
	var nbt [4]byte
	nbt[1] = byte(len(body) >> 16)
	nbt[2] = byte(len(body) >> 8)
	nbt[3] = byte(len(body))
	for range burst {
		batch = append(batch, nbt[:]...)
		batch = append(batch, body...)
	}

	b.SetBytes(int64(len(batch)))
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := c.conn.Write(batch); err != nil {
			b.Fatal(err)
		}
		for range burst {
			if _, err := c.readFrame(); err != nil {
				b.Fatal(err)
			}
		}
	}
}

// ------------------------------------------------------- headline transfers

// The benchmarks below have the same shape as the end-to-end suite's headline
// measurements — a 1 GiB sequential read and a 512 MiB sequential write — but
// drive them through the protocol over a socket instead of through a cifs
// mount, so they run anywhere (including CI). Because the benchmark client keeps
// one request in flight, they are a floor: a real client pipelines, which is
// what the batching in processBatch exists to exploit. Run them with a fixed
// iteration count:
//
//	go test -run '^$' -bench 'Headline' -benchtime 3x .

const headlineChunk = 1 << 20

// writeScratchFile creates path with size bytes of deterministic content.
func writeScratchFile(b *testing.B, path string, size int) {
	b.Helper()
	f, err := os.Create(path)
	if err != nil {
		b.Fatal(err)
	}
	defer f.Close()
	buf := make([]byte, headlineChunk)
	for i := range buf {
		buf[i] = byte(i * 31)
	}
	for written := 0; written < size; written += len(buf) {
		if _, err := f.Write(buf); err != nil {
			b.Fatal(err)
		}
	}
}

// headlineClient boots a server over dir and returns a connected, established
// client.
func headlineClient(b *testing.B, dir string) *testClient {
	b.Helper()
	srv := startTestServer(b, dir, nil)
	c := dialTestClient(b, srv.Addr().String())
	c.establish(0x0302)
	return c
}

// BenchmarkServerHeadlineRead1GiB reads a 1 GiB file sequentially in 1 MiB
// requests, which is the shape of the end-to-end suite's sequential read.
func BenchmarkServerHeadlineRead1GiB(b *testing.B) {
	const fileSize = 1 << 30
	dir := b.TempDir()
	writeScratchFile(b, filepath.Join(dir, "headline.bin"), fileSize)
	c := headlineClient(b, dir)

	st, fid := c.create("headline.bin", fileOpen, 0x40, 0x8000_0000, nil)
	if st != StatusSuccess {
		b.Fatalf("create status %#x", st)
	}
	defer c.close(fid)

	b.SetBytes(fileSize)
	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		for off := 0; off < fileSize; off += headlineChunk {
			st, got := c.read(fid, uint64(off), headlineChunk)
			if st != StatusSuccess || len(got) != headlineChunk {
				b.Fatalf("read at %d: status %#x, %d bytes", off, st, len(got))
			}
		}
	}
}

// BenchmarkServerHeadlineWrite512MiB writes a 512 MiB file in 1 MiB requests,
// which is the shape of the end-to-end suite's sequential write.
func BenchmarkServerHeadlineWrite512MiB(b *testing.B) {
	const fileSize = 512 << 20
	dir := b.TempDir()
	c := headlineClient(b, dir)

	st, fid := c.create("headline-write.bin", fileOverwriteIf, 0x40, genericWrite, nil)
	if st != StatusSuccess {
		b.Fatalf("create status %#x", st)
	}
	defer c.close(fid)
	payload := make([]byte, headlineChunk)

	b.SetBytes(fileSize)
	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		for off := 0; off < fileSize; off += headlineChunk {
			if st := c.write(fid, uint64(off), payload); st != StatusSuccess {
				b.Fatalf("write at %d: status %#x", off, st)
			}
		}
	}
}
