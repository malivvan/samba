package reuseport

import (
	"context"
	"net"
	"syscall"
	"testing"

	"golang.org/x/sys/windows"
)

// TestListenerCannotBeHijacked proves the property this package exists for on
// Windows: a socket that asks for SO_REUSEADDR — the option that makes a Windows
// bind forcibly succeed against an address already in use — must still not be
// able to take one this package holds.
//
// This is the security half of the Windows story, and it is the reason
// control_windows.go sets SO_EXCLUSIVEADDRUSE rather than doing nothing: without
// it, the second bind below would succeed and the server's port would be
// answering for whoever got there second. It also verifies the constant, which
// winsock2.h defines as the complement of SO_REUSEADDR rather than as a literal:
// a wrong value would fail the first Listen instead of passing this test.
func TestListenerCannotBeHijacked(t *testing.T) {
	if Available() {
		t.Skip("this platform shares the address rather than protecting it exclusively")
	}
	addr := freePort(t)
	ln, err := Listen("tcp", addr)
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	defer ln.Close()

	// The attacker: a plain socket that asks for the option that lets a Windows
	// bind forcibly take an address in use.
	attacker := net.ListenConfig{Control: func(_, _ string, c syscall.RawConn) error {
		var serr error
		if err := c.Control(func(fd uintptr) {
			serr = windows.SetsockoptInt(windows.Handle(fd), windows.SOL_SOCKET, windows.SO_REUSEADDR, 1)
		}); err != nil {
			return err
		}
		return serr
	}}
	second, err := attacker.Listen(context.Background(), "tcp", addr)
	if err == nil {
		second.Close()
		t.Fatal("a second socket took an address the server holds: the listener is not exclusive")
	}
	// The server is still the one on that address.
	if ln.Addr().String() != addr {
		t.Fatalf("the listener moved to %s", ln.Addr())
	}
}
