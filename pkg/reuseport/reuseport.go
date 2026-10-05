// Package reuseport creates the listening sockets samba's workers share.
//
// # What it is for
//
// samba runs one worker per CPU, each accepting connections independently. On
// the platforms that have it, that is done with SO_REUSEPORT: every worker
// binds the same address with its own socket, and the kernel spreads incoming
// connections across them, so one worker never has to hand a connection to
// another.
//
// # Why it is not just "set the socket option"
//
// SO_REUSEADDR and SO_REUSEPORT do not mean the same thing everywhere, and on
// one platform the difference is a security one. On Windows, SO_REUSEADDR lets
// *another* socket forcibly bind an address that is already in use and take over
// its connections — the exact opposite of what a reuse option should do for a
// server that counts on being reachable. Windows also has no SO_REUSEPORT at
// all, and Go's own net package sets nothing for a Windows listener (its
// `setDefaultListenerSockopts` is a documented no-op precisely because of that
// semantics). So this package sets the option that *protects* the listener there
// instead: SO_EXCLUSIVEADDRUSE, which is Windows' answer to port hijacking and
// what Microsoft tells servers to use. Available() is still false, because
// exclusive use is the opposite of sharing one address between sockets, so the
// workers fall back to a single shared listener.
//
// The rule this follows is the project's: a platform gets the facility where the
// facility is sound, and an honest, documented fallback where it is not — never
// a socket option that weakens the listener to look portable.
package reuseport

import (
	"context"
	"net"
)

// Available reports whether the platform can spread accepts across independent
// listeners bound to one address. It is false on Windows, where the option that
// exists has unsafe semantics and the load-spreading one does not exist.
func Available() bool { return available() }

// Listen binds a listener with the reuse options this platform should have.
//
// On the platforms that support it, every call binds the same address
// independently; on the others, a second call for an address already bound fails
// with EADDRINUSE, which is why Listeners exists.
func Listen(network, address string) (net.Listener, error) {
	lc := net.ListenConfig{Control: control}
	return lc.Listen(context.Background(), network, address)
}

// Listeners returns the listeners the workers should share.
//
// Where the platform supports it, that is n independent sockets on the same
// address and the kernel balances accepts between them. Where it does not, it is
// a single socket returned on its own, and the caller must let every worker
// accept from that one listener instead. The length of the result is the number
// of sockets the caller has to close.
func Listeners(n int, network, address string) ([]net.Listener, error) {
	if n < 1 {
		n = 1
	}
	if !available() {
		ln, err := Listen(network, address)
		if err != nil {
			return nil, err
		}
		return []net.Listener{ln}, nil
	}
	out := make([]net.Listener, 0, n)
	for range n {
		ln, err := Listen(network, address)
		if err != nil {
			closeAll(out)
			return nil, err
		}
		out = append(out, ln)
	}
	return out, nil
}

func closeAll(lns []net.Listener) {
	for _, ln := range lns {
		_ = ln.Close()
	}
}
