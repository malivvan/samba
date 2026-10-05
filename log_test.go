package samba

import (
	"testing"
	"time"
)

// sleepMillis waits a little between rate-limit checks.
func sleepMillis(ms int) { time.Sleep(time.Duration(ms) * time.Millisecond) }

func TestLogLevels(t *testing.T) {
	old := uint8(LevelInfo)
	t.Cleanup(func() { SetLogLevel(old) })

	SetLogLevel(LevelWarn)
	if LogEnabled(LevelInfo) || LogEnabled(LevelDebug) {
		t.Fatal("warn level must disable info and debug")
	}
	if !LogEnabled(LevelWarn) {
		t.Fatal("warn level must enable warn")
	}
	SetLogLevel(LevelDebug)
	if !LogEnabled(LevelInfo) || !LogEnabled(LevelDebug) {
		t.Fatal("debug level must enable everything")
	}

	// Emitting at every level must not panic or block, whatever the level.
	SetLogLevel(LevelDebug)
	LogWarn("test warning %d", 1)
	LogInfo("test info %d", 2)
	LogDebug("test debug %d", 3)
	SetLogLevel(LevelWarn)
	LogInfo("suppressed info")
	LogDebug("suppressed debug")
	// A zero value is the floor and still works.
	SetLogLevel(0)
	LogWarn("floor")
}

func TestWarnSuppressionSummary(t *testing.T) {
	// Drain the bucket, generate suppressed messages, then allow one through —
	// it must carry the summary of what was swallowed.
	for range 10000 {
		if !warnAllowed() {
			break
		}
	}
	for range 5 {
		LogWarn("this one is suppressed")
	}
	if n := warnSuppressed.Load(); n < 5 {
		t.Fatalf("suppressed counter = %d, want at least 5", n)
	}
	// Wait for the bucket to refill, then the next warn reports the summary and
	// resets the counter.
	deadline := warnRefillWait()
	for {
		LogWarn("visible again")
		if warnSuppressed.Load() == 0 {
			break
		}
		if !deadline() {
			t.Fatal("the warn bucket never refilled")
		}
	}
}

// warnRefillWait returns a predicate that reports whether the deadline has not
// yet passed, sleeping a little between checks.
func warnRefillWait() func() bool {
	remaining := 200
	return func() bool {
		if remaining <= 0 {
			return false
		}
		remaining--
		sleepMillis(10)
		return true
	}
}
