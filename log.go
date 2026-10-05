package samba

import (
	"fmt"
	"os"
	"sync"
	"sync/atomic"
	"time"
)

// Minimal leveled stderr logger.
//
// Levels: 0 = warn, 1 = info (default), 2 = debug. A single process-wide level
// is set once at startup from the config; the logger is safe for concurrent
// use because the level is held in an atomic.
const (
	LevelWarn  uint8 = 0
	LevelInfo  uint8 = 1
	LevelDebug uint8 = 2
)

var logLevel atomic.Uint32

func init() { logLevel.Store(uint32(LevelInfo)) }

// SetLogLevel sets the process-wide log level.
func SetLogLevel(l uint8) { logLevel.Store(uint32(l)) }

// LogEnabled reports whether messages at level l would be emitted.
func LogEnabled(l uint8) bool { return uint8(logLevel.Load()) >= l }

func logLine(prefix, format string, args ...any) {
	fmt.Fprintf(os.Stderr, "[%s] %s\n", prefix, fmt.Sprintf(format, args...))
}

// Warn messages are rate limited.
//
// A peer can make the server emit a warn line per request (a rejected request,
// a failed logon, an unencrypted frame on a sealed session), so without a bound
// a single client can fill the log filesystem or burn CPU in the logging path —
// a denial of service against the host rather than the server. The limiter
// allows a burst and then a steady trickle, and reports how many messages it
// swallowed so nothing is lost silently.
const (
	warnBurstPerSecond = 50
	warnBurst          = 200
)

var (
	// warnTokens is scaled by 1000 so the refill can stay integral.
	warnTokens     atomic.Int64
	warnSuppressed atomic.Int64
	warnLimiterMu  sync.Mutex
	warnLastRefill = time.Now()
)

func init() { warnTokens.Store(warnBurst * 1000) }

// warnAllowed reports whether a warn line may be emitted now, refilling the
// bucket according to the time elapsed.
func warnAllowed() bool {
	warnLimiterMu.Lock()
	defer warnLimiterMu.Unlock()
	now := time.Now()
	if elapsed := now.Sub(warnLastRefill); elapsed > 0 {
		if refill := int64(elapsed.Seconds() * warnBurstPerSecond * 1000); refill > 0 {
			warnLastRefill = now
			if v := warnTokens.Add(refill); v > warnBurst*1000 {
				warnTokens.Store(warnBurst * 1000)
			}
		}
	}
	for {
		cur := warnTokens.Load()
		if cur < 1000 {
			return false
		}
		if warnTokens.CompareAndSwap(cur, cur-1000) {
			return true
		}
	}
}

// LogWarn emits at level 0 (the floor), subject to the warn rate limit.
func LogWarn(format string, args ...any) {
	if !warnAllowed() {
		warnSuppressed.Add(1)
		return
	}
	if n := warnSuppressed.Swap(0); n > 0 {
		logLine("warn", "%d further warning(s) suppressed by the log rate limit", n)
	}
	logLine("warn", format, args...)
}

// LogInfo emits at level >= 1.
func LogInfo(format string, args ...any) {
	if LogEnabled(LevelInfo) {
		logLine("info", format, args...)
	}
}

// LogDebug emits at level >= 2.
func LogDebug(format string, args ...any) {
	if LogEnabled(LevelDebug) {
		logLine("debug", format, args...)
	}
}
