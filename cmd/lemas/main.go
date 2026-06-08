package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/lemas-sandbox/lemas/pkg/config"
	"github.com/lemas-sandbox/lemas/pkg/integration"
	"github.com/lemas-sandbox/lemas/pkg/logger"
	"github.com/lemas-sandbox/lemas/pkg/orchestrator"
	"github.com/rs/zerolog"
)

var log = logger.ForComponent("main")

func main() {
	// ── CLI flags ─────────────────────────────────────────────────────────────
	// Flags that are set override their corresponding config.yaml value.
	// Flags that are not set keep the value from the config file (or defaults).
	configPath := flag.String("config", "config.yaml", "Path to config.yaml")
	daemonMode := flag.Bool("daemon", false, "Start as REST API server")
	listenAddr := flag.String("addr", "", "Override api.listen_addr from config")
	filePath   := flag.String("file", "", "File to analyze (standalone mode)")
	dbPath     := flag.String("db", "", "Override analysis.storage_path from config")
	reportsDir := flag.String("reports", "", "Override analysis.reports_dir from config")
	rulesDir   := flag.String("rules", "", "Override analysis.rules_dir from config")
	verbose    := flag.Bool("verbose", false, "Enable debug-level logging")
	flag.Parse()

	if *verbose {
		logger.SetLevel(zerolog.DebugLevel)
	}

	// ── Load config ───────────────────────────────────────────────────────────
	cfg, err := config.Load(*configPath)
	if err != nil {
		log.Fatal().Err(err).Str("path", *configPath).Msg("failed to load config")
	}

	// Apply CLI overrides (only when the flag was explicitly provided)
	flag.Visit(func(f *flag.Flag) {
		switch f.Name {
		case "db":
			cfg.Analysis.StoragePath = *dbPath
		case "reports":
			cfg.Analysis.ReportsDir = *reportsDir
		case "rules":
			cfg.Analysis.RulesDir = *rulesDir
		case "addr":
			cfg.API.ListenAddr = *listenAddr
		}
	})

	log.Info().
		Str("config", *configPath).
		Str("db", cfg.Analysis.StoragePath).
		Str("reports_dir", cfg.Analysis.ReportsDir).
		Str("rules_dir", cfg.Analysis.RulesDir).
		Int("default_timeout_sec", cfg.Analysis.DefaultTimeoutSeconds).
		Int("cpu_limit_pct", cfg.Isolation.CPULimitPercent).
		Int("memory_limit_mb", cfg.Isolation.MemoryLimitMB).
		Bool("pcap_enabled", cfg.Network.PCAPEnabled).
		Bool("yara_enabled", cfg.Rules.YARA.Enabled).
		Bool("sigma_enabled", cfg.Rules.Sigma.Enabled).
		Msg("configuration loaded")

	// Ensure required directories exist
	os.MkdirAll(cfg.Analysis.RulesDir, 0755)
	os.MkdirAll(cfg.Analysis.ReportsDir, 0755)
	os.MkdirAll(cfg.Analysis.MemoryDumpsDir, 0755)

	// ── Orchestrator ──────────────────────────────────────────────────────────
	orch, err := orchestrator.NewOrchestrator(cfg)
	if err != nil {
		log.Fatal().Err(err).Msg("failed to initialize LEMAS core engine")
	}
	defer orch.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	orch.Start(ctx)

	// ── Mode selection ────────────────────────────────────────────────────────
	if *daemonMode {
		addr := cfg.API.ListenAddr
		if addr == "" {
			addr = ":8080"
		}
		server := integration.NewAPIServer(orch, cfg)
		go func() {
			if err := server.Start(addr); err != nil {
				log.Fatal().Err(err).Msg("REST API server failed")
			}
		}()

		sigChan := make(chan os.Signal, 1)
		signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
		<-sigChan
		log.Info().Msg("shutting down LEMAS daemon")
		return
	}

	// ── Standalone analysis mode ──────────────────────────────────────────────
	if *filePath == "" {
		fmt.Println("LEMAS — Lightweight Endpoint Malware Analysis Sandbox")
		fmt.Println()
		fmt.Println("Usage:")
		flag.PrintDefaults()
		fmt.Println()
		fmt.Println("Examples:")
		fmt.Println("  lemas -file malware.exe")
		fmt.Println("  lemas -file malware.exe -config /etc/lemas/config.yaml")
		fmt.Println("  lemas -daemon -config /etc/lemas/config.yaml")
		os.Exit(1)
	}

	absPath, err := filepath.Abs(*filePath)
	if err != nil {
		log.Fatal().Err(err).Msg("failed to resolve file path")
	}

	log.Info().Str("path", absPath).Msg("submitting target file")
	jobID, err := orch.SubmitJob(absPath)
	if err != nil {
		log.Fatal().Err(err).Msg("submission failed")
	}
	log.Info().Str("job_id", jobID).Msg("job queued — running analysis")

	reportJSONPath := filepath.Join(cfg.Analysis.ReportsDir, jobID, "report.json")
	// Poll timeout = max_timeout_seconds + a small buffer for report writing
	pollTimeout := time.Duration(cfg.Analysis.MaxTimeoutSeconds+30) * time.Second

	ticker  := time.NewTicker(1 * time.Second)
	timeout := time.After(pollTimeout)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			status, err := orch.GetJobStatus(jobID)
			if err != nil {
				log.Warn().Err(err).Msg("could not check job status")
				continue
			}
			switch status {
			case "failed":
				log.Fatal().Msg("analysis failed — ensure the process is running with admin/root privileges")
			case "completed", "timeout":
				if _, err := os.Stat(reportJSONPath); err == nil {
					log.Info().Str("status", status).Msg("analysis complete")
					printSummary(reportJSONPath, cfg.Analysis.ReportsDir, jobID)
					return
				} else if status == "timeout" {
					log.Fatal().Msg("analysis timed out with no report generated")
				}
			}
		case <-timeout:
			log.Fatal().Msg("polling timed out waiting for report")
		}
	}
}

func printSummary(jsonReportPath, reportsDir, jobID string) {
	data, err := os.ReadFile(jsonReportPath)
	if err != nil {
		log.Fatal().Err(err).Msg("failed to read report")
	}

	var rep struct {
		Summary struct {
			ThreatLevel       string   `json:"threat_level"`
			ThreatScore       int      `json:"threat_score"`
			BehavioralSummary string   `json:"behavioral_summary"`
			KeyBehaviors      []string `json:"key_behaviors"`
		} `json:"summary"`
	}
	if err := json.Unmarshal(data, &rep); err != nil {
		log.Fatal().Err(err).Msg("failed to parse report JSON")
	}

	fmt.Println("\n=========================================")
	fmt.Println("          ANALYSIS SUMMARY               ")
	fmt.Println("=========================================")
	fmt.Printf("THREAT LEVEL  : %s\n", rep.Summary.ThreatLevel)
	fmt.Printf("THREAT SCORE  : %d / 100\n", rep.Summary.ThreatScore)
	fmt.Printf("SUMMARY       : %s\n", rep.Summary.BehavioralSummary)
	fmt.Println("KEY BEHAVIORS :")
	for _, b := range rep.Summary.KeyBehaviors {
		fmt.Printf("  - %s\n", b)
	}
	fmt.Println("=========================================")
	fmt.Printf("JSON report → %s\n", jsonReportPath)
	fmt.Printf("HTML report → %s\n", filepath.Join(reportsDir, jobID, "report.html"))
}
