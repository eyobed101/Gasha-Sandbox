package integration

import (
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/lemas-sandbox/lemas/pkg/orchestrator"
)

type APIServer struct {
	orch       *orchestrator.Orchestrator
	reportsDir string
}

func NewAPIServer(orch *orchestrator.Orchestrator, reportsDir string) *APIServer {
	return &APIServer{
		orch:       orch,
		reportsDir: reportsDir,
	}
}

func (s *APIServer) Start(addr string) error {
	mux := http.NewServeMux()
	mux.HandleFunc("/submit", s.handleSubmit)
	mux.HandleFunc("/status/", s.handleStatus)
	mux.HandleFunc("/report/", s.handleReport)

	return http.ListenAndServe(addr, mux)
}

func (s *APIServer) handleSubmit(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// 1. Check if submission is via multi-part file upload
	var tempPath string
	file, header, err := r.FormFile("file")
	if err == nil {
		defer file.Close()
		
		// Write upload to a temp directory
		os.MkdirAll("./temp_uploads", 0755)
		tempPath = filepath.Join("./temp_uploads", header.Filename)
		
		tempFile, err := os.Create(tempPath)
		if err != nil {
			http.Error(w, "Failed to prepare file buffer: "+err.Error(), http.StatusInternalServerError)
			return
		}
		defer tempFile.Close()
		
		if _, err := io.Copy(tempFile, file); err != nil {
			http.Error(w, "Failed to write uploaded file: "+err.Error(), http.StatusInternalServerError)
			return
		}
	} else {
		// Try parsing local file path from JSON or query param
		localPath := r.URL.Query().Get("path")
		if localPath == "" {
			http.Error(w, "No file uploaded and no local path parameter supplied", http.StatusBadRequest)
			return
		}
		tempPath = localPath
	}

	// 2. Submit to orchestrator
	jobID, err := s.orch.SubmitJob(tempPath)
	if err != nil {
		http.Error(w, "Analysis submission failed: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// 3. Return JSON response
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"job_id": jobID,
		"status": "queued",
		"message": "File successfully queued for dynamic sandbox analysis",
	})
}

func (s *APIServer) handleStatus(w http.ResponseWriter, r *http.Request) {
	// Extract job ID from /status/{id}
	parts := strings.Split(r.URL.Path, "/")
	if len(parts) < 3 || parts[2] == "" {
		http.Error(w, "Missing Job ID", http.StatusBadRequest)
		return
	}
	jobID := parts[2]

	// In a real EDR system we'd load job status from database
	// For status API, we can parse job status details directly from SQLite via the orchestrator.
	// Since orchestrator doesn't expose the store publicly, let's look up files.
	// Alternatively, we can check if report files exist.
	jsonReportPath := filepath.Join(s.reportsDir, jobID, "report.json")
	
	status := "running"
	if _, err := os.Stat(jsonReportPath); err == nil {
		status = "completed"
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"job_id": jobID,
		"status": status,
	})
}

func (s *APIServer) handleReport(w http.ResponseWriter, r *http.Request) {
	// Expected URL pattern: /report/{id}/[json|html]
	parts := strings.Split(r.URL.Path, "/")
	if len(parts) < 4 || parts[2] == "" {
		http.Error(w, "Malformed report request path", http.StatusBadRequest)
		return
	}
	jobID := parts[2]
	format := parts[3]

	var reportPath string
	if format == "json" {
		reportPath = filepath.Join(s.reportsDir, jobID, "report.json")
		w.Header().Set("Content-Type", "application/json")
	} else if format == "html" {
		reportPath = filepath.Join(s.reportsDir, jobID, "report.html")
		w.Header().Set("Content-Type", "text/html")
	} else {
		http.Error(w, "Unsupported report format", http.StatusBadRequest)
		return
	}

	data, err := os.ReadFile(reportPath)
	if err != nil {
		http.Error(w, "Report not found or still generating", http.StatusNotFound)
		return
	}

	w.Write(data)
}
