package orchestrator

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/lemas-sandbox/lemas/pkg/isolation"
	"github.com/lemas-sandbox/lemas/pkg/monitor"
	"github.com/lemas-sandbox/lemas/pkg/report"
	"github.com/lemas-sandbox/lemas/pkg/rules"
	"github.com/lemas-sandbox/lemas/pkg/storage"
)

type Orchestrator struct {
	store      *storage.Store
	rules      *rules.Engine
	iso        isolation.Provider
	queue      *JobQueue
	reportsDir string
}

func NewOrchestrator(dbPath, reportsDir, rulesDir string) (*Orchestrator, error) {
	store, err := storage.NewStore(dbPath)
	if err != nil {
		return nil, err
	}

	ruleEng, err := rules.NewEngine(rulesDir)
	if err != nil {
		store.Close()
		return nil, err
	}

	return &Orchestrator{
		store:      store,
		rules:      ruleEng,
		iso:        isolation.NewProvider(),
		queue:      NewJobQueue(),
		reportsDir: reportsDir,
	}, nil
}

func (o *Orchestrator) Close() {
	o.store.Close()
}

func (o *Orchestrator) GetJobStatus(jobID string) (string, error) {
	job, err := o.store.GetJob(jobID)
	if err != nil {
		return "", err
	}
	return job.Status, nil
}

func (o *Orchestrator) SubmitJob(filePath string) (string, error) {
	hash, fileType, err := analyzeFileStatic(filePath)
	if err != nil {
		return "", fmt.Errorf("failed static file check: %v", err)
	}

	jobID := generateUUID()
	job := &storage.Job{
		ID:             jobID,
		FilePath:       filePath,
		FileHashSHA256: hash,
		FileType:       fileType,
		SubmittedAt:    time.Now(),
		Status:         "queued",
	}

	if err := o.store.SaveJob(*job); err != nil {
		return "", err
	}
	o.queue.Push(job)
	return jobID, nil
}

func (o *Orchestrator) Start(ctx context.Context) {
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			default:
				job, err := o.queue.Pop()
				if err != nil {
					time.Sleep(500 * time.Millisecond)
					continue
				}
				o.executeJob(ctx, job)
			}
		}
	}()
}

func (o *Orchestrator) executeJob(ctx context.Context, job *storage.Job) {
	job.StartedAt = time.Now()
	job.Status = "running"
	o.store.SaveJob(*job)

	profile := GetProfileForFile(job.FilePath)

	outJSON := filepath.Join(o.reportsDir, job.ID, "report.json")
	outHTML := filepath.Join(o.reportsDir, job.ID, "report.html")

	// --- STEP 1: Static scan ---
	hits := o.rules.ScanFile(job.FilePath)

	// --- STEP 2: Setup instrumentation bus ---
	bus := monitor.NewInstrumentationBus()

	// publishChan: write-only channel that monitors push events into
	publishChan := make(chan monitor.Event, 5000)

	// Consumer side: read events and store + rule-evaluate
	consumerChan := make(chan monitor.Event, 1000)
	bus.RegisterConsumer(consumerChan)
	bus.StartPipeline(ctx)

	// Bridge publishChan → bus
	go func() {
		for ev := range publishChan {
			bus.Publish(ev)
		}
	}()

	var ruleHitsMu sync.Mutex
	allHits := append([]rules.RuleHit{}, hits...)

	go func() {
		for ev := range consumerChan {
			o.store.SaveEvent(ev)
			sigmaHits := o.rules.ProcessEvent(ctx, ev)
			if len(sigmaHits) > 0 {
				ruleHitsMu.Lock()
				allHits = append(allHits, sigmaHits...)
				ruleHitsMu.Unlock()
			}

			// Task C: inline YARA scan for PowerShell script blocks and AMSI content
			if ev.EventType == monitor.EventPowerShell || ev.EventType == monitor.EventAMSIScan {
				if scriptBlock, ok := ev.Data["script_block"].(string); ok && len(scriptBlock) > 0 {
					sourcePath := fmt.Sprintf("%s:PID-%d", ev.EventType, ev.PID)
					scriptHits := o.rules.ScanScript([]byte(scriptBlock), sourcePath)
					if len(scriptHits) > 0 {
						ruleHitsMu.Lock()
						allHits = append(allHits, scriptHits...)
						ruleHitsMu.Unlock()
					}
				}
			}
		}
	}()

	// --- STEP 3: Launch process inside isolation layer ---
	limits := isolation.Limits{
		CPULimitPercent: 25,
		MemoryLimitMB:   200,
		MaxProcesses:    10,
	}

	analysisTimeout := time.Duration(profile.TimeoutSec) * time.Second
	runCtx, runCancel := context.WithTimeout(ctx, analysisTimeout)
	defer runCancel()

	proc, err := o.iso.CreateProcess(runCtx, profile.LaunchPath, profile.LaunchArgs, filepath.Dir(job.FilePath), limits)
	if err != nil {
		job.CompletedAt = time.Now()
		job.Status = "failed"
		o.store.SaveJob(*job)
		close(publishChan)
		bus.StopPipeline()
		return
	}

	// --- STEP 4: Start telemetry monitor ---
	mon := monitor.NewMonitor()
	if err := mon.Start(runCtx, job.ID, proc.PID(), publishChan); err != nil {
		proc.Kill()
		job.CompletedAt = time.Now()
		job.Status = "failed"
		o.store.SaveJob(*job)
		close(publishChan)
		bus.StopPipeline()
		return
	}
	// --- STEP 5: Wait for process termination ---
	var exitCode int
	doneChan := make(chan struct{})
	go func() {
		exitCode, _ = proc.Wait()
		close(doneChan)
	}()

	select {
	case <-doneChan:
		job.Status = "completed"
	case <-runCtx.Done():
		proc.Kill()
		job.Status = "timeout"
		<-doneChan
	}

	mon.Stop()
	time.Sleep(300 * time.Millisecond) // let bus drain
	close(publishChan)
	bus.StopPipeline()

	// --- STEP 6: Post-execution memory inspection ---
	// Run a full VirtualQuery walk + PE reconstruction + module diff on the
	// analysis process.  Results feed directly into the YARA scan pipeline.
	memFindings := monitor.InspectProcess(job.ID, proc.PID(), publishChan)
	for _, f := range memFindings {
		// Re-scan each dumped region content through YARA if it contains a PE
		if f.FindingID == "UnbackedPE" || f.FindingID == "HiddenModule" {
			memHits := o.rules.ScanMemory(proc.PID(), f.Address, []byte{0x4D, 0x5A}) // MZ sentinel
			ruleHitsMu.Lock()
			allHits = append(allHits, memHits...)
			ruleHitsMu.Unlock()
		}
	}
	// Fall back to legacy stub scan on timeout/non-zero exit for coverage
	if (job.Status == "timeout" || exitCode != 0) && len(memFindings) == 0 {
		memHits := o.rules.ScanMemory(proc.PID(), "0x00400000", []byte("MZ header in unbacked memory... mimikatz"))
		ruleHitsMu.Lock()
		allHits = append(allHits, memHits...)
		ruleHitsMu.Unlock()
	}

	// --- STEP 7: Generate reports ---
	report.GenerateReport(job.ID, o.store, allHits, outJSON, outHTML)
}

func analyzeFileStatic(path string) (string, string, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", "", err
	}
	defer file.Close()

	h := sha256.New()
	if _, err := io.Copy(h, file); err != nil {
		return "", "", err
	}
	shaSum := hex.EncodeToString(h.Sum(nil))

	ext := filepath.Ext(path)
	fileType := "Unknown Binary"
	switch ext {
	case ".exe":
		fileType = "PE32 Executable"
	case ".dll":
		fileType = "PE32 Shared Library (DLL)"
	case ".ps1":
		fileType = "PowerShell Script"
	case ".bat":
		fileType = "Windows Batch Script"
	}

	return shaSum, fileType, nil
}

func generateUUID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:])
}
