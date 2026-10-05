package main

import (
	"testing"
	"time"
)

// timeoutAfter returns a channel that fires after n seconds, for tests that must
// not hang forever.
func timeoutAfter(t *testing.T, n int) <-chan time.Time {
	t.Helper()
	return time.After(time.Duration(n) * time.Second)
}
