package config

import (
	"os"
	"strings"
	"testing"
	"time"
)

func TestValidate_AllFieldsSet(t *testing.T) {
	cfg := &Config{
		Server: ServerConfig{
			Main: ListenerConfig{
				Addr:         ":9091",
				ReadTimeout:  30 * time.Second,
				WriteTimeout: 30 * time.Second,
				IdleTimeout:  120 * time.Second,
			},
			Bundle: ListenerConfig{Addr: ":9092"},
		},
		Mimir: MimirConfig{
			URL:     "http://mimir:8080",
			Timeout: 30 * time.Second,
		},
		JWT: JWTConfig{
			JWKSURL:     "http://jwks.example.com/.well-known/jwks.json",
			Issuer:      "test-issuer",
			Audience:    "test-audience",
			GroupsClaim: "groups",
		},
		OPA: OPAConfig{
			URL:        "http://opa:8181",
			PolicyPath: "v1/data/proxy/authz",
			Timeout:    5 * time.Second,
		},
		Database: DatabaseConfig{
			Driver:          "sqlite",
			DSN:             "test.db",
			RefreshInterval: 5 * time.Second,
		},
		FanOut: FanOutConfig{
			MaxConcurrency: 10,
			Timeout:        30 * time.Second,
		},
	}

	if err := cfg.Validate(); err != nil {
		t.Errorf("Validate() unexpected error: %v", err)
	}
	if err := cfg.ValidateServe(); err != nil {
		t.Errorf("ValidateServe() unexpected error: %v", err)
	}
}

func TestValidate_CLIOnlyWithoutJWTOPA(t *testing.T) {
	// CLI commands (tenant, policy, migrate) only need basic config.
	// Validate() should pass without JWT/OPA fields.
	cfg := &Config{
		Server:   ServerConfig{Main: ListenerConfig{Addr: ":9091"}},
		Mimir:    MimirConfig{URL: "http://mimir:8080"},
		Database: DatabaseConfig{DSN: "test.db"},
		FanOut:   FanOutConfig{MaxConcurrency: 10},
	}
	if err := cfg.Validate(); err != nil {
		t.Errorf("Validate() should pass for CLI-only config: %v", err)
	}
	if err := cfg.ValidateServe(); err == nil {
		t.Error("ValidateServe() should fail without JWT/OPA fields")
	}
}

func TestValidate_MissingMimirURL(t *testing.T) {
	cfg := validConfig()
	cfg.Mimir.URL = ""
	err := cfg.Validate()
	if err == nil {
		t.Fatal("expected error for missing mimir.url")
	}
}

func TestValidateServe_MissingJWTFields(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(c *Config)
	}{
		{"missing jwks_url", func(c *Config) { c.JWT.JWKSURL = "" }},
		{"missing issuer", func(c *Config) { c.JWT.Issuer = "" }},
		{"missing audience", func(c *Config) { c.JWT.Audience = "" }},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := validConfig()
			tt.mutate(cfg)
			if err := cfg.ValidateServe(); err == nil {
				t.Fatal("expected validation error")
			}
		})
	}
}

func TestValidateServe_MissingOPAURL(t *testing.T) {
	cfg := validConfig()
	cfg.OPA.URL = ""
	if err := cfg.ValidateServe(); err == nil {
		t.Fatal("expected error for missing opa.url")
	}
}

func TestValidate_MissingDSN(t *testing.T) {
	cfg := validConfig()
	cfg.Database.DSN = ""
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected error for missing database.dsn")
	}
}

func TestValidate_InvalidConcurrency(t *testing.T) {
	cfg := validConfig()
	cfg.FanOut.MaxConcurrency = 0
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected error for zero max_concurrency")
	}
}

func TestValidate_MissingListenAddr(t *testing.T) {
	cfg := validConfig()
	cfg.Server.Main.Addr = ""
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected error for missing server.main.addr")
	}
}

func TestValidate_MultipleErrors(t *testing.T) {
	cfg := &Config{} // everything missing
	err := cfg.Validate()
	if err == nil {
		t.Fatal("expected error for empty config")
	}
	// Should mention multiple missing fields
	t.Logf("validation error: %v", err)
}

func TestLoad_ValidFile(t *testing.T) {
	yaml := `
server:
  main:
    addr: ":9091"
  bundle:
    addr: ":9092"
mimir:
  url: "http://mimir:8080"
jwt:
  jwks_url: "http://jwks.example.com/.well-known/jwks.json"
  issuer: "test"
  audience: "test"
opa:
  url: "http://opa:8181"
database:
  dsn: "test.db"
fanout:
  max_concurrency: 5
`
	tmpFile, err := os.CreateTemp("", "config-*.yaml")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tmpFile.Name())
	tmpFile.WriteString(yaml)
	tmpFile.Close()

	cfg, err := Load(tmpFile.Name())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if cfg.Server.Main.Addr != ":9091" {
		t.Errorf("expected :9091, got %s", cfg.Server.Main.Addr)
	}
	if cfg.Mimir.URL != "http://mimir:8080" {
		t.Errorf("expected mimir URL, got %s", cfg.Mimir.URL)
	}
	if cfg.FanOut.MaxConcurrency != 5 {
		t.Errorf("expected 5, got %d", cfg.FanOut.MaxConcurrency)
	}
}

func TestLoad_MissingFile(t *testing.T) {
	_, err := Load("/nonexistent/config.yaml")
	if err == nil {
		t.Fatal("expected error for missing file")
	}
}

func TestLoad_InvalidYAMLFailsValidation(t *testing.T) {
	yaml := `
server:
  main:
    addr: ":9091"
`
	tmpFile, err := os.CreateTemp("", "bad-config-*.yaml")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tmpFile.Name())
	tmpFile.WriteString(yaml)
	tmpFile.Close()

	_, err = Load(tmpFile.Name())
	if err == nil {
		t.Fatal("expected validation error for incomplete config")
	}
}

// validConfig returns a fully populated Config for mutations.
func validConfig() *Config {
	return &Config{
		Server:   ServerConfig{Main: ListenerConfig{Addr: ":9091"}, Bundle: ListenerConfig{Addr: ":9092"}},
		Mimir:    MimirConfig{URL: "http://mimir:8080"},
		JWT:      JWTConfig{JWKSURL: "http://jwks.example.com/.well-known/jwks.json", Issuer: "test", Audience: "test"},
		OPA:      OPAConfig{URL: "http://opa:8181"},
		Database: DatabaseConfig{DSN: "test.db"},
		FanOut:   FanOutConfig{MaxConcurrency: 10},
	}
}

func TestValidateServe_TLS_BothCertAndKey_Passes(t *testing.T) {
	cfg := validConfig()
	cfg.Server.Main.TLS = ServerTLSConfig{
		CertFile: "/etc/tls/server.crt",
		KeyFile:  "/etc/tls/server.key",
	}
	if err := cfg.ValidateServe(); err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
}

func TestValidateServe_TLS_CertOnly_Fails(t *testing.T) {
	cfg := validConfig()
	cfg.Server.Main.TLS = ServerTLSConfig{
		CertFile: "/etc/tls/server.crt",
	}
	err := cfg.ValidateServe()
	if err == nil {
		t.Fatal("expected error when only cert_file is set")
	}
	if !strings.Contains(err.Error(), "both cert_file and key_file must be set together") {
		t.Errorf("unexpected error message: %v", err)
	}
}

func TestValidateServe_TLS_ClientCAWithoutTLS_Fails(t *testing.T) {
	cfg := validConfig()
	cfg.Server.Main.TLS = ServerTLSConfig{
		ClientCAFile: "/etc/tls/ca.crt",
	}
	err := cfg.ValidateServe()
	if err == nil {
		t.Fatal("expected error when client_ca_file is set without TLS")
	}
	if !strings.Contains(err.Error(), "client_ca_file requires cert_file and key_file") {
		t.Errorf("unexpected error message: %v", err)
	}
}
