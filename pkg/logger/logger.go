// Package logger provides a structured zerolog-based logger for LEMAS.
// All components should obtain a logger via logger.With() or logger.ForJob().
package logger

import (
	"io"
	"os"
	"time"

	"github.com/rs/zerolog"
)

var root zerolog.Logger

func init() {
	// Human-friendly console output; swap to zerolog.New(os.Stdout) for JSON pipelines.
	output := zerolog.ConsoleWriter{
		Out:        os.Stderr,
		TimeFormat: time.RFC3339,
	}
	root = zerolog.New(output).With().Timestamp().Logger()
	zerolog.SetGlobalLevel(zerolog.InfoLevel)
}

// SetLevel changes the global minimum log level.
func SetLevel(lvl zerolog.Level) {
	zerolog.SetGlobalLevel(lvl)
}

// SetOutput replaces the root writer (e.g. for JSON output to a file).
func SetOutput(w io.Writer) {
	root = zerolog.New(w).With().Timestamp().Logger()
}

// Root returns the global root logger.
func Root() zerolog.Logger { return root }

// With returns a child logger with the given key/value fields pre-attached.
func With(key, value string) zerolog.Logger {
	return root.With().Str(key, value).Logger()
}

// ForJob returns a child logger pre-tagged with a job_id field.
func ForJob(jobID string) zerolog.Logger {
	return root.With().Str("job_id", jobID).Logger()
}

// ForComponent returns a child logger pre-tagged with a component field.
func ForComponent(name string) zerolog.Logger {
	return root.With().Str("component", name).Logger()
}
