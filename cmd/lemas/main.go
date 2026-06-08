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

	"github.com/lemas-sandbox/lemas/pkg/integration"
	"github.com/lemas-sandbox/lemas/pkg/logger"
	"github.com/lemas-sandbox/lemas/pkg/orchestrator"
	"github.com/rs/zerolog"
)

var log = logger.ForComponent("main")

func main() {
	// ── CLI flags ─────────────────────────────────────────────────────────────
	daemonMode := flag.Bool("daemon", false, "Start LEMAS as a background REST API server")
	listenAddr := flag.String("addr", ":8080", "Address for REST API server to listen on")
	filePath   := flag.String("file", "", "Path to the file to analyze (standalone mode)")
	dbPath     := flag.String("db", "./lemas.db", "Path to SQLite database")
	reportsDir := flag.String("reports", "./reports", "Directory to write analysis reports")
	rulesDir   := flag.String("rules", "./rules", "Directory containing YARA/Sigma rules")
	verbose    := flag.Bool("verbose", false, "Enable debug-level logging")
	flag.Parse()

	if *verbose {
		logger.SetLevel(zerolog.DebugLevel)
	}

	// API key from env (preferred) or auto-disabled in dev
	apiKey := os.Getenv("LEMAS_API_KEY")

	os.MkdirAll(*rulesDir, 0755)
	os.MkdirAll(*reportsDir, 0755)

	// ── Orchestrator ──────────────────────────────────────────────────────────
	orch, err := orchestrator.NewOrchestrator(*dbPath, *reportsDir, *rulesDir)
	if err != nil {
		log.Fatal().Err(err).Msg("failed to initialize LEMAS core engine")
	}
	defer orch.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	orch.Start(ctx)

	// ── Mode selection ────────────────────────────────────────────────────────
	if *daemonMode {
		server := integration.NewAPIServer(orch, *reportsDir, apiKey)
		go func() {
			if err := server.Start(*listenAddr); err != nil {
				log.Fatal().Err(err).Msg("REST API server failed")
			}
		}()

		sigChan := make(chan os.Signal, 1)
		signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
		<-sigChan
		log.Info().Msg("shutting down LEMAS daemon")
	} else {
		// ── Standalone analysis mode ──────────────────────────────────────────
		if *filePath == "" {
			fmt.Println("LEMAS — Lightweight Endpoint Malware Analysis Sandbox")
			fmt.Println("Usage:")
			flag.PrintDefaults()
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

		reportJSONPath := filepath.Join(*reportsDir, jobID, "report.json")
		ticker  := time.NewTicker(1 * time.Second)
		timeout := time.After(130 * time.Second)
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
						printSummary(reportJSONPath)
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
}

func printSummary(jsonReportPath string) {
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
	fmt.Printf("HTML report → %s\n", filepath.Join(filepath.Dir(jsonReportPath), "report.html"))
}
