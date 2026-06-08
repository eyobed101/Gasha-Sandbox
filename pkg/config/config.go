// Package config loads and validates the LEMAS configuration file (config.yaml).
// All subsystems receive a *Config instead of reading individual flags or
// hardcoded literals. CLI flags override file values when explicitly supplied.
package config

import (
	"fmt"
	"os"
	"time"

	"gopkg.in/yaml.v3"
)

// Config is the top-level configuration object.
type Config struct {
	Analysis  AnalysisConfig  `yaml:"analysis"`
	Isolation IsolationConfig `yaml:"isolation"`
	Network   NetworkConfig   `yaml:"network"`
	Rules     RulesConfig     `yaml:"rules"`
	API       APIConfig       `yaml:"api"`
}

// AnalysisConfig controls job lifecycle and storage paths.
type AnalysisConfig struct {
	DefaultTimeoutSeconds int    `yaml:"default_timeout_seconds"`
	MaxTimeoutSeconds     int    `yaml:"max_timeout_seconds"`
	StoragePath           string `yaml:"storage_path"`
	ReportsDir            string `yaml:"reports_dir"`
	MemoryDumpsDir        string `yaml:"memory_dumps_dir"`
	RulesDir              string `yaml:"rules_dir"`
}

// IsolationConfig controls the sandbox resource envelope.
type IsolationConfig struct {
	Provider        string `yaml:"provider"`         // job_object | namespace | none
	CPULimitPercent int    `yaml:"cpu_limit_percent"`
	MemoryLimitMB   int    `yaml:"memory_limit_mb"`
	MaxProcesses    int    `yaml:"max_processes"`
}

// NetworkConfig controls packet capture and containment.
type NetworkConfig struct {
	Containment    string `yaml:"containment"`      // deny_all | loopback_only | monitored_egress
	DNSServer      string `yaml:"dns_server"`
	PCAPEnabled    bool   `yaml:"pcap_enabled"`
	PCAPMaxSizeMB  int    `yaml:"pcap_max_size_mb"`
}

// RulesConfig toggles detection engines.
type RulesConfig struct {
	YARA  YARARulesConfig  `yaml:"yara"`
	Sigma SigmaRulesConfig `yaml:"sigma"`
}

type YARARulesConfig struct {
	Enabled  bool `yaml:"enabled"`
	FastScan bool `yaml:"fast_scan"`
}

type SigmaRulesConfig struct {
	Enabled        bool `yaml:"enabled"`
	BatchWindowMS  int  `yaml:"batch_window_ms"`
}

// APIConfig controls the REST daemon.
type APIConfig struct {
	ListenAddr     string `yaml:"listen_addr"`
	APIKey         string `yaml:"api_key"`         // overridden by LEMAS_API_KEY env
	RateLimitPerMin int   `yaml:"rate_limit_per_min"`
}

// DefaultConfig returns a Config populated with the same values that were
// previously hardcoded across the codebase. This ensures the system works
// out-of-the-box with no config file present.
func DefaultConfig() *Config {
	return &Config{
		Analysis: AnalysisConfig{
			DefaultTimeoutSeconds: 120,
			MaxTimeoutSeconds:     300,
			StoragePath:           "./lemas.db",
			ReportsDir:            "./reports",
			MemoryDumpsDir:        "./reports/dumps",
			RulesDir:              "./rules",
		},
		Isolation: IsolationConfig{
			Provider:        "job_object",
			CPULimitPercent: 25,
			MemoryLimitMB:   200,
			MaxProcesses:    10,
		},
		Network: NetworkConfig{
			Containment:   "loopback_only",
			DNSServer:     "8.8.8.8",
			PCAPEnabled:   true,
			PCAPMaxSizeMB: 100,
		},
		Rules: RulesConfig{
			YARA:  YARARulesConfig{Enabled: true, FastScan: true},
			Sigma: SigmaRulesConfig{Enabled: true, BatchWindowMS: 100},
		},
		API: APIConfig{
			ListenAddr:      ":8080",
			RateLimitPerMin: 30,
		},
	}
}

// Load reads a YAML config file and merges it over the defaults.
// Missing fields in the file keep their default values.
// If path is empty or the file does not exist, defaults are returned silently.
func Load(path string) (*Config, error) {
	cfg := DefaultConfig()

	if path == "" {
		return cfg, nil
	}

	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return cfg, nil // no file → defaults
		}
		return nil, fmt.Errorf("config: read %q: %w", path, err)
	}

	if err := yaml.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("config: parse %q: %w", path, err)
	}

	// Environment variable overrides (highest priority)
	if v := os.Getenv("LEMAS_API_KEY"); v != "" {
		cfg.API.APIKey = v
	}
	if v := os.Getenv("LEMAS_LISTEN_ADDR"); v != "" {
		cfg.API.ListenAddr = v
	}
	if v := os.Getenv("LEMAS_DB_PATH"); v != "" {
		cfg.Analysis.StoragePath = v
	}
	if v := os.Getenv("LEMAS_REPORTS_DIR"); v != "" {
		cfg.Analysis.ReportsDir = v
	}
	if v := os.Getenv("LEMAS_RULES_DIR"); v != "" {
		cfg.Analysis.RulesDir = v
	}

	if err := validate(cfg); err != nil {
		return nil, fmt.Errorf("config: validation: %w", err)
	}

	return cfg, nil
}

// validate returns an error if any required field has an invalid value.
func validate(c *Config) error {
	if c.Analysis.DefaultTimeoutSeconds <= 0 {
		return fmt.Errorf("analysis.default_timeout_seconds must be > 0")
	}
	if c.Analysis.MaxTimeoutSeconds < c.Analysis.DefaultTimeoutSeconds {
		return fmt.Errorf("analysis.max_timeout_seconds must be >= default_timeout_seconds")
	}
	if c.Analysis.StoragePath == "" {
		return fmt.Errorf("analysis.storage_path must not be empty")
	}
	if c.Analysis.ReportsDir == "" {
		return fmt.Errorf("analysis.reports_dir must not be empty")
	}
	if c.Analysis.RulesDir == "" {
		return fmt.Errorf("analysis.rules_dir must not be empty")
	}
	if c.Isolation.CPULimitPercent < 0 || c.Isolation.CPULimitPercent > 100 {
		return fmt.Errorf("isolation.cpu_limit_percent must be 0–100")
	}
	if c.Isolation.MemoryLimitMB < 0 {
		return fmt.Errorf("isolation.memory_limit_mb must be >= 0")
	}
	if c.Isolation.MaxProcesses < 0 {
		return fmt.Errorf("isolation.max_processes must be >= 0")
	}
	if c.Network.PCAPMaxSizeMB < 0 {
		return fmt.Errorf("network.pcap_max_size_mb must be >= 0")
	}
	if c.API.RateLimitPerMin <= 0 {
		c.API.RateLimitPerMin = 30 // silently fix
	}
	return nil
}

// DefaultTimeout returns the default analysis timeout as a time.Duration.
func (c *Config) DefaultTimeout() time.Duration {
	return time.Duration(c.Analysis.DefaultTimeoutSeconds) * time.Second
}

// MaxTimeout returns the maximum analysis timeout as a time.Duration.
func (c *Config) MaxTimeout() time.Duration {
	return time.Duration(c.Analysis.MaxTimeoutSeconds) * time.Second
}
