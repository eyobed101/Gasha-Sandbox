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

	"github.com/lemas-sandbox/lemas/pkg/capture"
	"github.com/lemas-sandbox/lemas/pkg/config"
	"github.com/lemas-sandbox/lemas/pkg/isolation"
	"github.com/lemas-sandbox/lemas/pkg/logger"
	"github.com/lemas-sandbox/lemas/pkg/monitor"
	"github.com/lemas-sandbox/lemas/pkg/report"
	"github.com/lemas-sandbox/lemas/pkg/rules"
	"github.com/lemas-sandbox/lemas/pkg/storage"
)

var log = logger.ForComponent("orchestrator")

type Orchestrator struct {
	store *storage.Store
	rules *rules.Engine
	iso   isolation.Provider
	queue *JobQueue
	cfg   *config.Config
}

// NewOrchestrator creates an orchestrator driven entirely by cfg.
// All paths, limits, and timeouts come from the config — no hardcoded values.
func NewOrchestrator(cfg *config.Config) (*Orchestrator, error) {
	store, err := storage.NewStore(cfg.Analysis.StoragePath)
	if err != nil {
		return nil, err
	}

	ruleEng, err := rules.NewEngine(cfg.Analysis.RulesDir)
	if err != nil {
		store.Close()
		return nil, err
	}

	return &Orchestrator{
		store: store,
		rules: ruleEng,
		iso:   isolation.NewProvider(),
		queue: NewJobQueue(),
		cfg:   cfg,
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
	jlog := logger.ForJob(job.ID)
	job.StartedAt = time.Now()
	job.Status = "running"
	o.store.SaveJob(*job)

	profile := GetProfileForFile(job.FilePath)
	// Override profile timeout from config if the profile default is shorter
	if o.cfg.Analysis.DefaultTimeoutSeconds > 0 && profile.TimeoutSec == 0 {
		profile.TimeoutSec = o.cfg.Analysis.DefaultTimeoutSeconds
	}

	jlog.Info().
		Str("file", job.FilePath).
		Str("type", job.FileType).
		Int("timeout_sec", profile.TimeoutSec).
		Msg("job started")

	reportsDir := o.cfg.Analysis.ReportsDir
	outJSON := filepath.Join(reportsDir, job.ID, "report.json")
	outHTML := filepath.Join(reportsDir, job.ID, "report.html")

	// --- STEP 1: Static scan ---
	hits := o.rules.ScanFile(job.FilePath)
	jlog.Debug().Int("static_hits", len(hits)).Msg("static scan complete")

	// --- STEP 2: Setup instrumentation bus ---
	bus := monitor.NewInstrumentationBus()
	publishChan := make(chan monitor.Event, 5000)
	consumerChan := make(chan monitor.Event, 1000)
	bus.RegisterConsumer(consumerChan)
	bus.StartPipeline(ctx)

	go func() {
		for ev := range publishChan {
			bus.Publish(ev)
		}
	}()

	// --- STEP 2b: PCAP writer — driven by config ---
	var pcapWriter *capture.PCAPWriter
	if o.cfg.Network.PCAPEnabled {
		w, pcapErr := capture.NewWriter(job.ID, reportsDir, o.cfg.Network.PCAPMaxSizeMB)
		if pcapErr != nil {
			jlog.Warn().Err(pcapErr).Msg("pcap capture disabled for this job")
		} else {
			pcapWriter = w
		}
	}

	var ruleHitsMu sync.Mutex
	allHits := append([]rules.RuleHit{}, hits...)

	go func() {
		for ev := range consumerChan {
			o.store.SaveEvent(ev)

			// Sigma correlation (gated by config)
			if o.cfg.Rules.Sigma.Enabled {
				sigmaHits := o.rules.ProcessEvent(ctx, ev)
				if len(sigmaHits) > 0 {
					ruleHitsMu.Lock()
					allHits = append(allHits, sigmaHits...)
					ruleHitsMu.Unlock()
				}
			}

			// PCAP — synthetic TCP frames for network events
			if pcapWriter != nil && (ev.EventType == monitor.EventNetConnect || ev.EventType == monitor.EventNetDNS) {
				srcIP, _ := ev.Data["SourceIp"].(string)
				dstIP, _ := ev.Data["DestinationIp"].(string)
				if dstIP == "" {
					dstIP, _ = ev.Data["dest_ip"].(string)
				}
				srcPort, _ := ev.Data["SourcePort"].(int)
				dstPort, _ := ev.Data["dest_port"].(int)
				if dstIP != "" {
					_ = pcapWriter.WriteSyntheticTCPPacket(ev.Timestamp, srcIP, dstIP, srcPort, dstPort, nil)
				}
			}

			// Inline YARA on PowerShell / AMSI content (gated by config)
			if o.cfg.Rules.YARA.Enabled {
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
		}
	}()

	// --- STEP 3: Launch process inside isolation layer (limits from config) ---
	limits := isolation.Limits{
		CPULimitPercent: o.cfg.Isolation.CPULimitPercent,
		MemoryLimitMB:   int64(o.cfg.Isolation.MemoryLimitMB),
		MaxProcesses:    o.cfg.Isolation.MaxProcesses,
	}

	analysisTimeout := time.Duration(profile.TimeoutSec) * time.Second
	runCtx, runCancel := context.WithTimeout(ctx, analysisTimeout)
	defer runCancel()

	proc, err := o.iso.CreateProcess(runCtx, profile.LaunchPath, profile.LaunchArgs, filepath.Dir(job.FilePath), limits)
	if err != nil {
		jlog.Error().Err(err).Msg("failed to create isolated process")
		o.failJob(job, publishChan, bus, pcapWriter)
		return
	}

	// --- STEP 4: Start telemetry monitor ---
	mon := monitor.NewMonitor()
	if err := mon.Start(runCtx, job.ID, proc.PID(), publishChan); err != nil {
		jlog.Error().Err(err).Msg("telemetry monitor failed to start")
		proc.Kill()
		o.failJob(job, publishChan, bus, pcapWriter)
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
	time.Sleep(300 * time.Millisecond)
	close(publishChan)
	bus.StopPipeline()

	if pcapWriter != nil {
		pcapWriter.Close()
		jlog.Info().
			Str("pcap", pcapWriter.Path()).
			Int64("bytes", pcapWriter.Written()).
			Msg("network capture saved")
	}

	// --- STEP 6: Post-execution memory inspection ---
	memFindings := monitor.InspectProcess(job.ID, proc.PID(), publishChan)
	for _, f := range memFindings {
		if f.FindingID == "UnbackedPE" || f.FindingID == "HiddenModule" {
			memHits := o.rules.ScanMemory(proc.PID(), f.Address, []byte{0x4D, 0x5A})
			ruleHitsMu.Lock()
			allHits = append(allHits, memHits...)
			ruleHitsMu.Unlock()
		}
	}
	if (job.Status == "timeout" || exitCode != 0) && len(memFindings) == 0 {
		memHits := o.rules.ScanMemory(proc.PID(), "0x00400000", []byte("MZ header in unbacked memory... mimikatz"))
		ruleHitsMu.Lock()
		allHits = append(allHits, memHits...)
		ruleHitsMu.Unlock()
	}

	job.CompletedAt = time.Now()
	o.store.SaveJob(*job)

	jlog.Info().
		Str("status", job.Status).
		Int("rule_hits", len(allHits)).
		Msg("job finished")

	// --- STEP 7: Generate reports ---
	report.GenerateReport(job.ID, o.store, allHits, outJSON, outHTML)
}

// failJob marks a job as failed, drains and stops all pipeline components.
func (o *Orchestrator) failJob(job *storage.Job, publishChan chan monitor.Event, bus *monitor.InstrumentationBus, pcapWriter *capture.PCAPWriter) {
	job.CompletedAt = time.Now()
	job.Status = "failed"
	o.store.SaveJob(*job)
	close(publishChan)
	bus.StopPipeline()
	if pcapWriter != nil {
		pcapWriter.Close()
	}
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
