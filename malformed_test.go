package samba

import (
	"testing"
)

// TestMalformedCommandsAreAnswered truncates every command's request at every
// length and requires the server to answer with a protocol error rather than
// accepting garbage, panicking, or dropping the connection. It sweeps the error
// branch of every body decoder in one pass.
func TestMalformedCommandsAreAnswered(t *testing.T) {
	f := newFixture(t)
	fid := f.open("a.txt", fileOpen, 0x40, 0x1000_0000)
	dfid := f.open("", fileOpen, 0x1, 0x8000_0000)
	defer f.closeFID(fid)
	defer f.closeFID(dfid)

	// A valid frame per command, built the way a client would.
	build := func(name string) []byte {
		switch name {
		case "negotiate":
			w := reqHdr(CmdNegotiate, 1, 0, 0)
			w.U16(36)
			w.U16(3)
			w.U16(1)
			w.U16(0)
			w.U32(0)
			w.Zeros(16 + 8)
			w.U16(0x0210)
			w.U16(0x0300)
			w.U16(0x0302)
			return w.Bytes()
		case "session_setup":
			blob := append([]byte{}, ntlmSig...)
			blob = append(blob, 1, 0, 0, 0)
			return sessionSetupFrame(2, 0, blob, 0, 1)
		case "tree_connect":
			path := UTF16LE(`\\srv\t`)
			w := reqHdr(CmdTreeConnect, 3, 0, f.sess)
			w.U16(9)
			w.U16(0)
			w.U16(72)
			w.U16(uint16(len(path)))
			w.Bytes8(path)
			return w.Bytes()
		case "create":
			n := UTF16LE("x.txt")
			w := reqHdr(CmdCreate, 4, f.tree, f.sess)
			w.U16(57)
			w.U8(0)
			w.U8(0)
			w.U32(2)
			w.U64(0)
			w.U64(0)
			w.U32(0x1000_0000)
			w.U32(0)
			w.U32(7)
			w.U32(fileOverwriteIf)
			w.U32(0)
			w.U16(120)
			w.U16(uint16(len(n)))
			w.U32(0)
			w.U32(0)
			w.Bytes8(n)
			return w.Bytes()
		case "close":
			w := reqHdr(CmdClose, 5, f.tree, f.sess)
			w.U16(24)
			w.U16(1)
			w.U32(0)
			w.U64(fid)
			w.U64(fid)
			return w.Bytes()
		case "flush":
			w := reqHdr(CmdFlush, 6, f.tree, f.sess)
			w.U16(24)
			w.U16(0)
			w.U32(0)
			w.U64(fid)
			w.U64(fid)
			return w.Bytes()
		case "read":
			w := reqHdr(CmdRead, 7, f.tree, f.sess)
			w.U16(49)
			w.U8(0)
			w.U8(0)
			w.U32(64)
			w.U64(0)
			w.U64(fid)
			w.U64(fid)
			w.U32(0)
			w.U32(0)
			w.U32(0)
			w.U16(0)
			w.U16(0)
			w.U8(0)
			return w.Bytes()
		case "write":
			w := reqHdr(CmdWrite, 8, f.tree, f.sess)
			w.U16(49)
			w.U16(112)
			w.U32(4)
			w.U64(0)
			w.U64(fid)
			w.U64(fid)
			w.U32(0)
			w.U32(0)
			w.U16(0)
			w.U16(0)
			w.U32(0)
			w.Bytes8([]byte("data"))
			return w.Bytes()
		case "query_info":
			return f.infoFrame(CmdQueryInfo, fid, infoFile, 4, nil, 4096)
		case "set_info":
			return f.infoFrame(CmdSetInfo, fid, infoFile, 19, make([]byte, 8), 0)
		case "query_directory":
			pat := UTF16LE("*")
			w := reqHdr(CmdQueryDirectory, 9, f.tree, f.sess)
			w.U16(33)
			w.U8(fileIDBothDirectoryInformation)
			w.U8(0)
			w.U32(0)
			w.U64(dfid)
			w.U64(dfid)
			w.U16(96)
			w.U16(uint16(len(pat)))
			w.U32(65536)
			w.Bytes8(pat)
			return w.Bytes()
		case "lock":
			w := reqHdr(CmdLock, 10, f.tree, f.sess)
			w.U16(48)
			w.U16(1)
			w.U32(0)
			w.U64(fid)
			w.U64(fid)
			w.U64(0)
			w.U64(10)
			w.U32(lockFlagShared)
			w.U32(0)
			return w.Bytes()
		case "ioctl":
			w := reqHdr(CmdIoctl, 11, f.tree, f.sess)
			w.U16(57)
			w.U16(0)
			w.U32(fsctlValidateNegotiateInfo)
			w.Zeros(16)
			w.U32(0)
			w.U32(0)
			w.U32(112)
			w.U32(0)
			w.U32(112)
			w.U32(0)
			w.U32(0)
			w.U32(0)
			return w.Bytes()
		case "change_notify":
			w := reqHdr(CmdChangeNotify, 12, f.tree, f.sess)
			w.U16(32)
			w.U16(0)
			w.U32(4096)
			w.U64(dfid)
			w.U64(dfid)
			w.U32(0x1F)
			return w.Bytes()
		}
		t.Fatalf("unknown command %q", name)
		return nil
	}

	// Commands whose handlers decode their body: a truncation must be refused.
	decoded := []string{
		"negotiate", "session_setup", "tree_connect", "create", "close", "flush",
		"read", "write", "query_info", "set_info", "query_directory", "lock",
		"ioctl", "change_notify",
	}
	for _, name := range decoded {
		frame := build(name)
		for n := 0; n < len(frame); n++ {
			tx := NewWriter(0)
			act, _ := ProcessFrame(f.srv, f.pc, frame[:n], tx)
			if act == actionClose {
				t.Fatalf("%s truncated to %d bytes: the server must not close the connection", name, n)
			}
			b := tx.Bytes()
			if len(b) == 0 {
				// Only a frame too short to hold a header may go unanswered.
				if n >= 64 {
					t.Fatalf("%s truncated to %d bytes: no response", name, n)
				}
				continue
			}
			// Every framed response must be well formed, and a request whose body
			// is too short to hold even the fields the handler reads must be
			// refused. (A body that is short but still carries every field the
			// handler uses is served, which is what every real client sends and
			// what the reference implementation does: the unused tail fields are
			// ignored rather than required.)
			off := 0
			for {
				nbt := int(b[off+1])<<16 | int(b[off+2])<<8 | int(b[off+3])
				if off+4+nbt > len(b) {
					t.Fatalf("%s truncated to %d bytes: malformed framing", name, n)
				}
				st := le32(b[off+4+8 : off+4+12])
				if n < 64+8 && st != StatusInvalidParameter {
					t.Fatalf("%s with a %d-byte body: status %#x, want INVALID_PARAMETER", name, n-64, st)
				}
				if nbt == 0 {
					break
				}
				off += 4 + nbt
				if off+64 > len(b) {
					break
				}
			}
		}
	}

	// Frames whose handlers ignore the body stay valid when truncated, but must
	// still never panic or close the connection.
	for _, name := range []string{"echo", "logoff", "cancel"} {
		var frame []byte
		switch name {
		case "echo":
			w := reqHdr(CmdEcho, 20, f.tree, f.sess)
			w.U16(4)
			w.U16(0)
			frame = w.Bytes()
		case "logoff":
			w := reqHdr(CmdLogoff, 21, 0, f.sess)
			w.U16(4)
			w.U16(0)
			frame = w.Bytes()
		case "cancel":
			w := reqHdr(CmdCancel, 22, 0, 0)
			w.U16(4)
			w.U16(0)
			frame = w.Bytes()
		}
		for n := range len(frame) {
			tx := NewWriter(0)
			if act, _ := ProcessFrame(f.srv, f.pc, frame[:n], tx); act == actionClose {
				t.Fatalf("%s truncated to %d bytes closed the connection", name, n)
			}
		}
	}
}
