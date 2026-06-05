package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/lemas-sandbox/lemas/pkg/integration"
	"github.com/lemas-sandbox/lemas/pkg/orchestrator"
)

func main() {
	// 1. Setup CLI flags
	daemonMode := flag.Bool("daemon", false, "Start LEMAS as a background REST API server")
	listenAddr := flag.String("addr", ":8080", "Address for REST API server to listen on")
	filePath := flag.String("file", "", "Path to the file to analyze (standalone mode)")
	dbPath := flag.String("db", "./lemas.db", "Path to SQLite database")
	reportsDir := flag.String("reports", "./reports", "Directory to write analysis reports")
	rulesDir := flag.String("rules", "./rules", "Directory containing YARA/Sigma rules")

	flag.Parse()

	// Ensure rule directory exists
	os.MkdirAll(*rulesDir, 0755)
	os.MkdirAll(*reportsDir, 0755)

	// 2. Initialize orchestrator
	orch, err := orchestrator.NewOrchestrator(*dbPath, *reportsDir, *rulesDir)
	if err != nil {
		log.Fatalf("Failed to initialize LEMAS core engine: %v", err)
	}
	defer orch.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Start orchestrator background loop
	orch.Start(ctx)

	// 3. Select mode
	if *daemonMode {
		log.Printf("Starting LEMAS Daemon on %s...", *listenAddr)
		server := integration.NewAPIServer(orch, *reportsDir)
		
		go func() {
			if err := server.Start(*listenAddr); err != nil {
				log.Fatalf("REST API server failed: %v", err)
			}
		}()

		// Graceful shutdown
		sigChan := make(chan os.Signal, 1)
		signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
		<-sigChan
		log.Println("Shutting down LEMAS Daemon...")
	} else {
		// Standalone Mode
		if *filePath == "" {
			fmt.Println("LEMAS - Lightweight Endpoint Malware Analysis Sandbox")
			fmt.Println("Usage:")
			flag.PrintDefaults()
			os.Exit(1)
		}

		absPath, err := filepath.Abs(*filePath)
		if err != nil {
			log.Fatalf("Failed to resolve absolute file path: %v", err)
		}

		log.Printf("[+] Submitting target file: %s", absPath)
		jobID, err := orch.SubmitJob(absPath)
		if err != nil {
			log.Fatalf("Submission failed: %v", err)
		}

		log.Printf("[+] Analysis job queued. ID: %s", jobID)
		log.Printf("[*] Executing analysis... (max timeout: 120s)")

		// Poll status until completed
		reportJSONPath := filepath.Join(*reportsDir, jobID, "report.json")
		ticker := time.NewTicker(1 * time.Second)
		defer ticker.Stop()

		timeout := time.After(130 * time.Second)
		for {
			select {
			case <-ticker.C:
				if _, err := os.Stat(reportJSONPath); err == nil {
					// Report is generated
					log.Printf("[+] Analysis complete!")
					printSummary(reportJSONPath)
					return
				}
			case <-timeout:
				log.Fatalf("[-] Analysis timed out waiting for reports.")
			}
		}
	}
}

func printSummary(jsonReportPath string) {
	data, err := os.ReadFile(jsonReportPath)
	if err != nil {
		log.Fatalf("Failed to read report: %v", err)
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
		log.Fatalf("Failed to parse report: %v", err)
	}

	fmt.Println("\n=========================================")
	fmt.Println("           ANALYSIS RUN SUMMARY          ")
	fmt.Println("=========================================")
	fmt.Printf("THREAT CLASSIFICATION : %s\n", rep.Summary.ThreatLevel)
	fmt.Printf("THREAT SCORE (0-100)  : %d\n", rep.Summary.ThreatScore)
	fmt.Printf("BEHAVIOR SUMMARY      : %s\n", rep.Summary.BehavioralSummary)
	fmt.Println("KEY DETECTED BEHAVIORS:")
	for _, b := range rep.Summary.KeyBehaviors {
		fmt.Printf(" - %s\n", b)
	}
	fmt.Println("=========================================")
	fmt.Printf("Full HTML Report saved at: %s\n", filepath.Join(filepath.Dir(jsonReportPath), "report.html"))
}
