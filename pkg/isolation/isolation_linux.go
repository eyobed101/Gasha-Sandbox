//go:build !windows

package isolation

import (
	"context"
	"fmt"
	"io"
	"os/exec"
	"syscall"
)

// LinuxProcess implements isolation.Process
type LinuxProcess struct {
	cmd    *exec.Cmd
	stdout io.Reader
	stderr io.Reader
}

func (p *LinuxProcess) PID() int {
	if p.cmd.Process != nil {
		return p.cmd.Process.Pid
	}
	return 0
}

func (p *LinuxProcess) Kill() error {
	// Kill the entire process group recursively
	pid := p.PID()
	if pid > 0 {
		// Negative PID sends signal to the whole process group
		return syscall.Kill(-pid, syscall.SIGKILL)
	}
	return nil
}

func (p *LinuxProcess) Wait() (int, error) {
	err := p.cmd.Wait()
	if err != nil {
		if exitError, ok := err.(*exec.ExitError); ok {
			return exitError.ExitCode(), nil
		}
		return -1, err
	}
	return 0, nil
}

func (p *LinuxProcess) Stdout() io.Reader {
	return p.stdout
}

func (p *LinuxProcess) Stderr() io.Reader {
	return p.stderr
}

// LinuxIsolationProvider implements isolation.Provider
type LinuxIsolationProvider struct{}

func NewProvider() *LinuxIsolationProvider {
	return &LinuxIsolationProvider{}
}

func (l *LinuxIsolationProvider) CreateProcess(ctx context.Context, path string, args []string, dir string, limits Limits) (Process, error) {
	cmd := exec.CommandContext(ctx, path, args...)
	cmd.Dir = dir

	stdoutPipe, err := cmd.StdoutPipe()
	if err != nil {
		return nil, fmt.Errorf("failed to create stdout pipe: %v", err)
	}
	stderrPipe, err := cmd.StderrPipe()
	if err != nil {
		return nil, fmt.Errorf("failed to create stderr pipe: %v", err)
	}

	// First try with full namespaces (requires root/CAP_SYS_ADMIN)
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Setpgid: true, // Put in new process group for group-kill
		Cloneflags: syscall.CLONE_NEWPID |
			syscall.CLONE_NEWNS |
			syscall.CLONE_NEWUTS |
			syscall.CLONE_NEWIPC |
			syscall.CLONE_NEWNET, // loopback only
	}

	// Try starting. If it fails due to permissions (unprivileged namespace creation disabled), fallback
	if err := cmd.Start(); err != nil {
		// Fallback to basic PGID-only isolation (no namespaces)
		cmd = exec.CommandContext(ctx, path, args...)
		cmd.Dir = dir
		stdoutPipe, _ = cmd.StdoutPipe()
		stderrPipe, _ = cmd.StderrPipe()
		
		cmd.SysProcAttr = &syscall.SysProcAttr{
			Setpgid: true, // Put in new process group
		}
		
		if errFallback := cmd.Start(); errFallback != nil {
			return nil, fmt.Errorf("failed to start process: %v (fallback failed: %v)", err, errFallback)
		}
	}

	return &LinuxProcess{
		cmd:    cmd,
		stdout: stdoutPipe,
		stderr: stderrPipe,
	}, nil
}
