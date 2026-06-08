package main

import "C"
import (
	"context"
	"sync"

	"github.com/lemas-sandbox/lemas/pkg/config"
	"github.com/lemas-sandbox/lemas/pkg/orchestrator"
)

var (
	orch      *orchestrator.Orchestrator
	orchMutex sync.Mutex
	ctx       context.Context
	cancel    context.CancelFunc
)

// LemasInit initializes the LEMAS orchestrator from explicit path arguments.
// This entry point is used by EDR embedders that manage their own config.
// Returns 1 on success, 0 on failure.
//
//export LemasInit
func LemasInit(dbPath *C.char, reportsDir *C.char, rulesDir *C.char) C.int {
	orchMutex.Lock()
	defer orchMutex.Unlock()

	if orch != nil {
		return 1
	}

	// Build a config from defaults and override the three core paths.
	cfg := config.DefaultConfig()
	cfg.Analysis.StoragePath = C.GoString(dbPath)
	cfg.Analysis.ReportsDir  = C.GoString(reportsDir)
	cfg.Analysis.RulesDir    = C.GoString(rulesDir)

	o, err := orchestrator.NewOrchestrator(cfg)
	if err != nil {
		return 0
	}

	orch = o
	ctx, cancel = context.WithCancel(context.Background())
	orch.Start(ctx)

	return 1
}

// LemasSubmit submits a filepath to the orchestrator queue for sandboxed execution.
// Returns a dynamically allocated C-string containing the Job UUID, or NULL.
// The caller is responsible for freeing the returned string using free().
//
//export LemasSubmit
func LemasSubmit(filePath *C.char) *C.char {
	orchMutex.Lock()
	defer orchMutex.Unlock()

	if orch == nil {
		return nil
	}

	goPath := C.GoString(filePath)
	jobID, err := orch.SubmitJob(goPath)
	if err != nil {
		return nil
	}

	return C.CString(jobID)
}

// LemasClose terminates the orchestrator instance and background queue workers.
//
//export LemasClose
func LemasClose() {
	orchMutex.Lock()
	defer orchMutex.Unlock()

	if cancel != nil {
		cancel()
	}
	if orch != nil {
		orch.Close()
		orch = nil
	}
}

// LemasShutdown helper
func main() {
	// Must remain empty for C-shared builds
}
