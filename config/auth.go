package config

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"net/http"
	"os"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/clientcredentials"
)

// AuthType defines the supported authentication methods for upstream services.
type AuthType string

const (
	AuthTypeNone   AuthType = ""
	AuthTypeBasic  AuthType = "basic"
	AuthTypeBearer AuthType = "bearer"
	AuthTypeOAuth2 AuthType = "oauth2"
	AuthTypeAPIKey AuthType = "api_key"
	AuthTypeMTLS   AuthType = "mtls"
)

// AuthConfig holds authentication configuration for an upstream service.
// Only one auth method should be configured at a time.
type AuthConfig struct {
	Type AuthType `mapstructure:"type" json:"type" yaml:"type"`

	// Basic auth
	Username string `mapstructure:"username" json:"username" yaml:"username"`
	Password string `mapstructure:"password" json:"password" yaml:"password"`

	// Bearer token
	Token string `mapstructure:"token" json:"token" yaml:"token"`

	// OAuth2 client credentials
	ClientID     string   `mapstructure:"client_id" json:"client_id" yaml:"client_id"`
	ClientSecret string   `mapstructure:"client_secret" json:"client_secret" yaml:"client_secret"`
	TokenURL     string   `mapstructure:"token_url" json:"token_url" yaml:"token_url"`
	Scopes       []string `mapstructure:"scopes" json:"scopes" yaml:"scopes"`

	// API key — sent as a plain header value
	APIKey       string `mapstructure:"api_key" json:"api_key" yaml:"api_key"`
	APIKeyHeader string `mapstructure:"api_key_header" json:"api_key_header" yaml:"api_key_header"` // defaults to "X-API-Key"

	// mTLS — client certificate and key files
	CertFile string `mapstructure:"cert_file" json:"cert_file" yaml:"cert_file"`
	KeyFile  string `mapstructure:"key_file" json:"key_file" yaml:"key_file"`
	CAFile   string `mapstructure:"ca_file" json:"ca_file" yaml:"ca_file"` // optional CA for server verification
}

// Validate checks that the auth configuration is internally consistent.
func (a *AuthConfig) Validate() error {
	switch a.Type {
	case AuthTypeNone:
		return nil
	case AuthTypeBasic:
		if a.Username == "" || a.Password == "" {
			return fmt.Errorf("basic auth requires username and password")
		}
	case AuthTypeBearer:
		if a.Token == "" {
			return fmt.Errorf("bearer auth requires token")
		}
	case AuthTypeOAuth2:
		if a.ClientID == "" || a.ClientSecret == "" || a.TokenURL == "" {
			return fmt.Errorf("oauth2 auth requires client_id, client_secret, and token_url")
		}
	case AuthTypeAPIKey:
		if a.APIKey == "" {
			return fmt.Errorf("api_key auth requires api_key")
		}
	case AuthTypeMTLS:
		if a.CertFile == "" || a.KeyFile == "" {
			return fmt.Errorf("mtls auth requires cert_file and key_file")
		}
	default:
		return fmt.Errorf("unsupported auth type: %q (valid: basic, bearer, oauth2, api_key, mtls)", a.Type)
	}
	return nil
}

// NewAuthTransport creates an http.RoundTripper that injects authentication
// into every outgoing request. Returns nil for AuthTypeNone (callers
// should use http.DefaultTransport in that case).
func NewAuthTransport(cfg AuthConfig) (http.RoundTripper, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}

	base := http.DefaultTransport

	switch cfg.Type {
	case AuthTypeNone:
		return nil, nil

	case AuthTypeBasic:
		creds := base64.StdEncoding.EncodeToString([]byte(cfg.Username + ":" + cfg.Password))
		return &headerTransport{
			base:        base,
			headerName:  "Authorization",
			headerValue: "Basic " + creds,
		}, nil

	case AuthTypeBearer:
		return &headerTransport{
			base:        base,
			headerName:  "Authorization",
			headerValue: "Bearer " + cfg.Token,
		}, nil

	case AuthTypeOAuth2:
		oauthCfg := &clientcredentials.Config{
			ClientID:     cfg.ClientID,
			ClientSecret: cfg.ClientSecret,
			TokenURL:     cfg.TokenURL,
			Scopes:       cfg.Scopes,
		}
		// oauth2.Transport handles token caching and refresh automatically.
		return &oauth2.Transport{
			Source: oauthCfg.TokenSource(oauth2.NoContext),
			Base:   base,
		}, nil

	case AuthTypeAPIKey:
		headerName := cfg.APIKeyHeader
		if headerName == "" {
			headerName = "X-API-Key"
		}
		return &headerTransport{
			base:        base,
			headerName:  headerName,
			headerValue: cfg.APIKey,
		}, nil

	case AuthTypeMTLS:
		return newMTLSTransport(cfg)

	default:
		return nil, fmt.Errorf("unsupported auth type: %q", cfg.Type)
	}
}

// newMTLSTransport creates an http.RoundTripper with client certificate authentication.
func newMTLSTransport(cfg AuthConfig) (http.RoundTripper, error) {
	cert, err := tls.LoadX509KeyPair(cfg.CertFile, cfg.KeyFile)
	if err != nil {
		return nil, fmt.Errorf("loading client certificate: %w", err)
	}

	tlsCfg := &tls.Config{
		Certificates: []tls.Certificate{cert},
	}

	// Optional: load CA cert for server verification
	if cfg.CAFile != "" {
		caCert, err := loadCACert(cfg.CAFile)
		if err != nil {
			return nil, err
		}
		tlsCfg.RootCAs = caCert
	}

	return &http.Transport{
		TLSClientConfig: tlsCfg,
	}, nil
}

// loadCACert reads a PEM-encoded CA certificate file and returns a cert pool.
func loadCACert(caFile string) (*x509.CertPool, error) {
	caCert, err := os.ReadFile(caFile)
	if err != nil {
		return nil, fmt.Errorf("reading CA certificate: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caCert) {
		return nil, fmt.Errorf("failed to parse CA certificate from %s", caFile)
	}
	return pool, nil
}

// headerTransport is an http.RoundTripper that injects a static header
// into every outgoing request.
type headerTransport struct {
	base        http.RoundTripper
	headerName  string
	headerValue string
}

func (t *headerTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	// Clone to avoid mutating the original request
	clone := req.Clone(req.Context())
	clone.Header.Set(t.headerName, t.headerValue)
	return t.base.RoundTrip(clone)
}
