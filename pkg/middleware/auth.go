// Package middleware provides HTTP middleware for the LEMAS REST API.
package middleware

import (
	"net/http"
	"strings"

	"github.com/lemas-sandbox/lemas/pkg/logger"
)

var log = logger.ForComponent("api-middleware")

// APIKeyAuth returns a middleware that enforces a static API key check.
// The key is read from the X-API-Key header or the ?api_key= query parameter.
// Pass an empty apiKey to disable auth (development mode).
func APIKeyAuth(apiKey string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		if apiKey == "" {
			// Auth disabled — log a warning and pass through.
			log.Warn().Msg("API key auth is DISABLED — set LEMAS_API_KEY to enable")
			return next
		}
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			key := r.Header.Get("X-API-Key")
			if key == "" {
				key = r.URL.Query().Get("api_key")
			}
			if !secureCompare(key, apiKey) {
				log.Warn().
					Str("remote", r.RemoteAddr).
					Str("path", r.URL.Path).
					Msg("unauthorized API request")
				http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// secureCompare does a constant-time string comparison to prevent timing attacks.
func secureCompare(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	var diff byte
	for i := 0; i < len(a); i++ {
		diff |= a[i] ^ b[i]
	}
	return diff == 0
}

// ContentTypeJSON forces Content-Type: application/json on POST requests.
func ContentTypeJSON(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			ct := r.Header.Get("Content-Type")
			// Allow multipart/form-data (file upload) and application/json
			if ct != "" &&
				!strings.HasPrefix(ct, "application/json") &&
				!strings.HasPrefix(ct, "multipart/form-data") {
				http.Error(w, `{"error":"unsupported content-type"}`, http.StatusUnsupportedMediaType)
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

// RequestLogger logs each incoming request at INFO level.
func RequestLogger(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log.Info().
			Str("method", r.Method).
			Str("path", r.URL.Path).
			Str("remote", r.RemoteAddr).
			Msg("api request")
		next.ServeHTTP(w, r)
	})
}
