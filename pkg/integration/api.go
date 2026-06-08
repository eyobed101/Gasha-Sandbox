package integration

import (
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/go-chi/httprate"
	"github.com/lemas-sandbox/lemas/pkg/logger"
	"github.com/lemas-sandbox/lemas/pkg/middleware"
	"github.com/lemas-sandbox/lemas/pkg/orchestrator"
)

var log = logger.ForComponent("api")

// APIServer exposes the LEMAS analysis pipeline over HTTP.
type APIServer struct {
	orch       *orchestrator.Orchestrator
	reportsDir string
	apiKey     string // empty = auth disabled
}

// NewAPIServer creates the server. apiKey is read from config/env by the caller.
func NewAPIServer(orch *orchestrator.Orchestrator, reportsDir, apiKey string) *APIServer {
	return &APIServer{
		orch:       orch,
		reportsDir: reportsDir,
		apiKey:     apiKey,
	}
}

// Start registers routes and begins serving. Blocks until the listener errors.
func (s *APIServer) Start(addr string) error {
	mux := http.NewServeMux()
	mux.HandleFunc("/submit", s.handleSubmit)
	mux.HandleFunc("/status/", s.handleStatus)
	mux.HandleFunc("/report/", s.handleReport)
	mux.HandleFunc("/health", s.handleHealth)

	// Middleware stack (outermost = first executed):
	//   1. Request logger
	//   2. Rate limiter  — 30 requests / minute per IP
	//   3. API key auth
	//   4. Content-type guard
	var handler http.Handler = mux
	handler = middleware.ContentTypeJSON(handler)
	handler = middleware.APIKeyAuth(s.apiKey)(handler)
	handler = httprate.LimitByIP(30, time.Minute)(handler)
	handler = middleware.RequestLogger(handler)

	log.Info().Str("addr", addr).Msg("LEMAS REST API listening")
	return http.ListenAndServe(addr, handler)
}

// handleHealth is an unauthenticated liveness probe endpoint.
func (s *APIServer) handleHealth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
}

func (s *APIServer) handleSubmit(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		jsonError(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var tempPath string
	var cleanupTemp bool

	file, header, err := r.FormFile("file")
	if err == nil {
		defer file.Close()

		// Sanitise the filename to prevent path traversal.
		safeName := filepath.Base(header.Filename)
		if safeName == "." || safeName == "/" {
			jsonError(w, "invalid filename", http.StatusBadRequest)
			return
		}

		if err := os.MkdirAll("./temp_uploads", 0755); err != nil {
			jsonError(w, "server error", http.StatusInternalServerError)
			return
		}
		tempPath = filepath.Join("./temp_uploads", safeName)
		cleanupTemp = true

		tmp, err := os.Create(tempPath)
		if err != nil {
			jsonError(w, "failed to buffer upload: "+err.Error(), http.StatusInternalServerError)
			return
		}
		defer tmp.Close()

		if _, err := io.Copy(tmp, file); err != nil {
			jsonError(w, "failed to write upload: "+err.Error(), http.StatusInternalServerError)
			return
		}
	} else {
		localPath := r.URL.Query().Get("path")
		if localPath == "" {
			jsonError(w, "no file uploaded and no ?path= supplied", http.StatusBadRequest)
			return
		}
		tempPath = localPath
	}

	jobID, err := s.orch.SubmitJob(tempPath)
	if err != nil {
		if cleanupTemp {
			os.Remove(tempPath)
		}
		log.Error().Err(err).Str("path", tempPath).Msg("job submission failed")
		jsonError(w, "submission failed: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// Temp file cleanup: schedule removal after a short delay so the orchestrator
	// has time to open the file before we delete it.
	if cleanupTemp {
		go func() {
			time.Sleep(5 * time.Second)
			os.Remove(tempPath)
		}()
	}

	log.Info().Str("job_id", jobID).Str("file", tempPath).Msg("job queued")
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"job_id":  jobID,
		"status":  "queued",
		"message": "file queued for analysis",
	})
}

func (s *APIServer) handleStatus(w http.ResponseWriter, r *http.Request) {
	jobID := extractPathSegment(r.URL.Path, 2)
	if jobID == "" {
		jsonError(w, "missing job_id", http.StatusBadRequest)
		return
	}

	status, err := s.orch.GetJobStatus(jobID)
	if err != nil {
		jsonError(w, "job not found", http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"job_id": jobID,
		"status": status,
	})
}

func (s *APIServer) handleReport(w http.ResponseWriter, r *http.Request) {
	// /report/{id}/{json|html}
	jobID := extractPathSegment(r.URL.Path, 2)
	format := extractPathSegment(r.URL.Path, 3)
	if jobID == "" || format == "" {
		jsonError(w, "malformed report path: use /report/{job_id}/{json|html}", http.StatusBadRequest)
		return
	}

	var (
		reportPath  string
		contentType string
	)
	switch format {
	case "json":
		reportPath = filepath.Join(s.reportsDir, jobID, "report.json")
		contentType = "application/json"
	case "html":
		reportPath = filepath.Join(s.reportsDir, jobID, "report.html")
		contentType = "text/html; charset=utf-8"
	default:
		jsonError(w, "unsupported format: use json or html", http.StatusBadRequest)
		return
	}

	data, err := os.ReadFile(reportPath)
	if err != nil {
		jsonError(w, "report not found or still generating", http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", contentType)
	w.Write(data)
}

// ─── helpers ──────────────────────────────────────────────────────────────────

func jsonError(w http.ResponseWriter, msg string, code int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(map[string]string{"error": msg})
}

// extractPathSegment splits a URL path by "/" and returns the element at index i.
// Index 0 is always "", index 1 is the first path component, etc.
func extractPathSegment(path string, index int) string {
	parts := strings.Split(path, "/")
	if index >= len(parts) {
		return ""
	}
	return parts[index]
}
