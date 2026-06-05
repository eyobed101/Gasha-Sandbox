package isolation

import (
	"context"
	"io"
)

// Process represents a sample running inside our isolated context.
type Process interface {
	// PID returns the OS process ID.
	PID() int

	// Kill terminates the entire process tree recursively.
	Kill() error

	// Wait blocks until the process exits, returning the exit code or error.
	Wait() (int, error)

	// Stdout returns a reader for the process's standard output, if captured.
	Stdout() io.Reader

	// Stderr returns a reader for the process's standard error, if captured.
	Stderr() io.Reader
}

// Limits defines the resource restrictions applied to the isolation layer.
type Limits struct {
	CPULimitPercent int   // Restrict CPU consumption (e.g. 25%)
	MemoryLimitMB   int64 // Restrict maximum memory in MB
	MaxProcesses    int   // Limit child processes count (prevent fork bombs)
}

// Provider defines the interface for creating sandboxed execution environments.
type Provider interface {
	// CreateProcess launches a binary within the isolation envelope.
	CreateProcess(ctx context.Context, path string, args []string, dir string, limits Limits) (Process, error)
}
