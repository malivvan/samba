package samba

import (
	"fmt"
	"os"
	"sync/atomic"
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

// LogWarn always emits (level 0 is the floor).
func LogWarn(format string, args ...any) { logLine("warn", format, args...) }

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
