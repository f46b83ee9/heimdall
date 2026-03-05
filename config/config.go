// Package config provides exhaustive configuration for Heimdall
// using Viper with strict validation at startup.
package config

import (
	"fmt"
	"strings"
	"time"

	"github.com/spf13/viper"
)

// Config is the top-level configuration for Heimdall.
type Config struct {
	Server    ServerConfig    `mapstructure:"server" json:"server" yaml:"server"`
	Mimir     MimirConfig     `mapstructure:"mimir" json:"mimir" yaml:"mimir"`
	JWT       JWTConfig       `mapstructure:"jwt" json:"jwt" yaml:"jwt"`
	OPA       OPAConfig       `mapstructure:"opa" json:"opa" yaml:"opa"`
	Database  DatabaseConfig  `mapstructure:"database" json:"database" yaml:"database"`
	FanOut    FanOutConfig    `mapstructure:"fanout" json:"fanout" yaml:"fanout"`
	Telemetry TelemetryConfig `mapstructure:"telemetry" json:"telemetry" yaml:"telemetry"`
}

// ServerConfig holds HTTP server settings.
type ServerConfig struct {
	Main   ListenerConfig `mapstructure:"main" json:"main" yaml:"main"`
	Bundle ListenerConfig `mapstructure:"bundle" json:"bundle" yaml:"bundle"`
}

// ListenerConfig holds settings for a single HTTP(S) listener.
type ListenerConfig struct {
	Addr         string          `mapstructure:"addr" json:"addr" yaml:"addr"`
	ReadTimeout  time.Duration   `mapstructure:"read_timeout" json:"read_timeout" yaml:"read_timeout"`
	WriteTimeout time.Duration   `mapstructure:"write_timeout" json:"write_timeout" yaml:"write_timeout"`
	IdleTimeout  time.Duration   `mapstructure:"idle_timeout" json:"idle_timeout" yaml:"idle_timeout"`
	TLS          ServerTLSConfig `mapstructure:"tls" json:"tls" yaml:"tls"`
}

// ServerTLSConfig holds optional TLS settings for a listener.
type ServerTLSConfig struct {
	CertFile     string `mapstructure:"cert_file" json:"cert_file" yaml:"cert_file"`
	KeyFile      string `mapstructure:"key_file" json:"key_file" yaml:"key_file"`
	ClientCAFile string `mapstructure:"client_ca_file" json:"client_ca_file" yaml:"client_ca_file"`
}

// Enabled returns true when both CertFile and KeyFile are configured.
func (t *ServerTLSConfig) Enabled() bool {
	return t.CertFile != "" && t.KeyFile != ""
}

// MimirConfig holds upstream Mimir settings.
type MimirConfig struct {
	URL             string        `mapstructure:"url" json:"url" yaml:"url"`
	ReadURL         string        `mapstructure:"read_url" json:"read_url" yaml:"read_url"`
	WriteURL        string        `mapstructure:"write_url" json:"write_url" yaml:"write_url"`
	RulerURL        string        `mapstructure:"ruler_url" json:"ruler_url" yaml:"ruler_url"`
	AlertmanagerURL string        `mapstructure:"alertmanager_url" json:"alertmanager_url" yaml:"alertmanager_url"`
	Timeout         time.Duration `mapstructure:"timeout" json:"timeout" yaml:"timeout"`
	Auth            AuthConfig    `mapstructure:"auth" json:"auth" yaml:"auth"`
}

// JWTConfig holds JWT validation settings.
type JWTConfig struct {
	JWKSURL     string `mapstructure:"jwks_url" json:"jwks_url" yaml:"jwks_url"`
	Issuer      string `mapstructure:"issuer" json:"issuer" yaml:"issuer"`
	Audience    string `mapstructure:"audience" json:"audience" yaml:"audience"`
	GroupsClaim string `mapstructure:"groups_claim" json:"groups_claim" yaml:"groups_claim"`
}

// OPAConfig holds Open Policy Agent settings.
type OPAConfig struct {
	URL        string        `mapstructure:"url" json:"url" yaml:"url"`
	PolicyPath string        `mapstructure:"policy_path" json:"policy_path" yaml:"policy_path"`
	Timeout    time.Duration `mapstructure:"timeout" json:"timeout" yaml:"timeout"`
	Auth       AuthConfig    `mapstructure:"auth" json:"auth" yaml:"auth"`
}

// DatabaseConfig holds database connection settings.
type DatabaseConfig struct {
	Driver          string        `mapstructure:"driver" json:"driver" yaml:"driver"`
	DSN             string        `mapstructure:"dsn" json:"dsn" yaml:"dsn"`
	RefreshInterval time.Duration `mapstructure:"refresh_interval" json:"refresh_interval" yaml:"refresh_interval"`
}

// FanOutConfig holds fan-out concurrency settings.
type FanOutConfig struct {
	MaxConcurrency int           `mapstructure:"max_concurrency" json:"max_concurrency" yaml:"max_concurrency"`
	Timeout        time.Duration `mapstructure:"timeout" json:"timeout" yaml:"timeout"`
}

// TelemetryConfig holds OpenTelemetry settings.
type TelemetryConfig struct {
	Enabled      bool   `mapstructure:"enabled" json:"enabled" yaml:"enabled"`
	OTLPEndpoint string `mapstructure:"otlp_endpoint" json:"otlp_endpoint" yaml:"otlp_endpoint"`
	ServiceName  string `mapstructure:"service_name" json:"service_name" yaml:"service_name"`
}

// Load reads configuration from the given path and validates all required fields.
// It fails fast if any required value is missing.
func Load(path string) (*Config, error) {
	v := viper.New()
	v.SetConfigFile(path)

	// Environment variable binding with HEIMDALL_ prefix
	v.SetEnvPrefix("HEIMDALL")
	v.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))
	v.AutomaticEnv()

	// Defaults (non-security-related only)
	v.SetDefault("server.main.addr", ":9091")
	v.SetDefault("server.main.read_timeout", 30*time.Second)
	v.SetDefault("server.main.write_timeout", 30*time.Second)
	v.SetDefault("server.main.idle_timeout", 120*time.Second)
	v.SetDefault("server.bundle.addr", ":9092")
	v.SetDefault("mimir.timeout", 30*time.Second)
	v.SetDefault("jwt.groups_claim", "groups")
	v.SetDefault("opa.policy_path", "v1/data/proxy/authz")
	v.SetDefault("opa.timeout", 5*time.Second)
	v.SetDefault("database.driver", "sqlite")
	v.SetDefault("database.dsn", "heimdall.db")
	v.SetDefault("database.refresh_interval", 5*time.Second)
	v.SetDefault("fanout.max_concurrency", 10)
	v.SetDefault("fanout.timeout", 30*time.Second)
	v.SetDefault("telemetry.enabled", false)
	v.SetDefault("telemetry.service_name", "heimdall")

	if err := v.ReadInConfig(); err != nil {
		return nil, fmt.Errorf("reading config file: %w", err)
	}

	var cfg Config
	if err := v.Unmarshal(&cfg); err != nil {
		return nil, fmt.Errorf("unmarshaling config: %w", err)
	}

	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("config validation failed: %w", err)
	}

	return &cfg, nil
}

// Validate checks basic configuration required for all commands (database, etc.).
// Use ValidateServe for the full server validation including JWT and OPA.
func (c *Config) Validate() error {
	var errs []string

	// Server
	if c.Server.Main.Addr == "" {
		errs = append(errs, "server.main.addr is required")
	}

	// Mimir upstream (required)
	if c.Mimir.URL == "" {
		errs = append(errs, "mimir.url is required")
	}

	// Database
	if c.Database.DSN == "" {
		errs = append(errs, "database.dsn is required")
	}

	// Fan-out
	if c.FanOut.MaxConcurrency <= 0 {
		errs = append(errs, "fanout.max_concurrency must be > 0")
	}

	if len(errs) > 0 {
		return fmt.Errorf("missing required configuration:\n  - %s", strings.Join(errs, "\n  - "))
	}

	return nil
}

// ValidateServe checks all configuration required for running the HTTP server,
// including security-sensitive JWT and OPA settings.
func (c *Config) ValidateServe() error {
	if err := c.Validate(); err != nil {
		return err
	}

	var errs []string

	// JWT (all security-sensitive, no defaults)
	if c.JWT.JWKSURL == "" {
		errs = append(errs, "jwt.jwks_url is required")
	}
	if c.JWT.Issuer == "" {
		errs = append(errs, "jwt.issuer is required")
	}
	if c.JWT.Audience == "" {
		errs = append(errs, "jwt.audience is required")
	}

	// OPA (required for serve)
	if c.OPA.URL == "" {
		errs = append(errs, "opa.url is required")
	}

	// Auth validation
	if err := c.Mimir.Auth.Validate(); err != nil {
		errs = append(errs, fmt.Sprintf("mimir.auth: %v", err))
	}
	if err := c.OPA.Auth.Validate(); err != nil {
		errs = append(errs, fmt.Sprintf("opa.auth: %v", err))
	}

	// Server TLS validation
	if (c.Server.Main.TLS.CertFile != "") != (c.Server.Main.TLS.KeyFile != "") {
		errs = append(errs, "server.main.tls: both cert_file and key_file must be set together")
	}
	if c.Server.Main.TLS.ClientCAFile != "" && !c.Server.Main.TLS.Enabled() {
		errs = append(errs, "server.main.tls: client_ca_file requires cert_file and key_file to be set")
	}

	// Bundle TLS validation
	if (c.Server.Bundle.TLS.CertFile != "") != (c.Server.Bundle.TLS.KeyFile != "") {
		errs = append(errs, "server.bundle.tls: both cert_file and key_file must be set together")
	}
	if c.Server.Bundle.TLS.ClientCAFile != "" && !c.Server.Bundle.TLS.Enabled() {
		errs = append(errs, "server.bundle.tls: client_ca_file requires cert_file and key_file to be set")
	}

	if len(errs) > 0 {
		return fmt.Errorf("missing required configuration:\n  - %s", strings.Join(errs, "\n  - "))
	}

	return nil
}
