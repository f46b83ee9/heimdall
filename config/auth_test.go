package config

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"
)

func TestAuthConfig_Validate(t *testing.T) {
	tests := []struct {
		name    string
		cfg     AuthConfig
		wantErr bool
	}{
		{name: "none/empty", cfg: AuthConfig{}, wantErr: false},
		{name: "none/explicit", cfg: AuthConfig{Type: AuthTypeNone}, wantErr: false},
		{name: "basic/valid", cfg: AuthConfig{Type: AuthTypeBasic, Username: "u", Password: "p"}, wantErr: false},
		{name: "basic/missing_username", cfg: AuthConfig{Type: AuthTypeBasic, Password: "p"}, wantErr: true},
		{name: "basic/missing_password", cfg: AuthConfig{Type: AuthTypeBasic, Username: "u"}, wantErr: true},
		{name: "bearer/valid", cfg: AuthConfig{Type: AuthTypeBearer, Token: "tok"}, wantErr: false},
		{name: "bearer/missing_token", cfg: AuthConfig{Type: AuthTypeBearer}, wantErr: true},
		{name: "oauth2/valid", cfg: AuthConfig{
			Type: AuthTypeOAuth2, ClientID: "c", ClientSecret: "s", TokenURL: "http://tok",
		}, wantErr: false},
		{name: "oauth2/missing_client_id", cfg: AuthConfig{
			Type: AuthTypeOAuth2, ClientSecret: "s", TokenURL: "http://tok",
		}, wantErr: true},
		{name: "oauth2/missing_token_url", cfg: AuthConfig{
			Type: AuthTypeOAuth2, ClientID: "c", ClientSecret: "s",
		}, wantErr: true},
		{name: "api_key/valid", cfg: AuthConfig{Type: AuthTypeAPIKey, APIKey: "key123"}, wantErr: false},
		{name: "api_key/missing_key", cfg: AuthConfig{Type: AuthTypeAPIKey}, wantErr: true},
		{name: "mtls/valid", cfg: AuthConfig{Type: AuthTypeMTLS, CertFile: "cert.pem", KeyFile: "key.pem"}, wantErr: false},
		{name: "mtls/missing_cert", cfg: AuthConfig{Type: AuthTypeMTLS, KeyFile: "key.pem"}, wantErr: true},
		{name: "mtls/missing_key", cfg: AuthConfig{Type: AuthTypeMTLS, CertFile: "cert.pem"}, wantErr: true},
		{name: "unsupported_type", cfg: AuthConfig{Type: "magic"}, wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.cfg.Validate()
			if (err != nil) != tt.wantErr {
				t.Errorf("Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestNewAuthTransport_None(t *testing.T) {
	tr, err := NewAuthTransport(AuthConfig{}, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if tr != nil {
		t.Error("expected nil transport for AuthTypeNone")
	}
}

func TestNewAuthTransport_Basic(t *testing.T) {
	cfg := AuthConfig{
		Type:     AuthTypeBasic,
		Username: "admin",
		Password: "secret",
	}
	tr, err := NewAuthTransport(cfg, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Verify the transport injects the correct header
	var gotHeader string
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotHeader = r.Header.Get("Authorization")
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	client := &http.Client{Transport: tr}
	resp, err := client.Get(ts.URL)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	resp.Body.Close()

	expected := "Basic " + base64.StdEncoding.EncodeToString([]byte("admin:secret"))
	if gotHeader != expected {
		t.Errorf("got header %q, want %q", gotHeader, expected)
	}
}

func TestNewAuthTransport_Bearer(t *testing.T) {
	cfg := AuthConfig{
		Type:  AuthTypeBearer,
		Token: "my-token-123",
	}
	tr, err := NewAuthTransport(cfg, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var gotHeader string
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotHeader = r.Header.Get("Authorization")
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	client := &http.Client{Transport: tr}
	resp, err := client.Get(ts.URL)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	resp.Body.Close()

	if gotHeader != "Bearer my-token-123" {
		t.Errorf("got header %q, want %q", gotHeader, "Bearer my-token-123")
	}
}

func TestNewAuthTransport_OAuth2(t *testing.T) {
	// Mock token endpoint
	tokenServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"access_token":"mock-access-token","token_type":"bearer","expires_in":3600}`)
	}))
	defer tokenServer.Close()

	cfg := AuthConfig{
		Type:         AuthTypeOAuth2,
		ClientID:     "test-client",
		ClientSecret: "test-secret",
		TokenURL:     tokenServer.URL,
		Scopes:       []string{"read"},
	}
	tr, err := NewAuthTransport(cfg, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var gotHeader string
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotHeader = r.Header.Get("Authorization")
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	client := &http.Client{Transport: tr}
	resp, err := client.Get(ts.URL)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	resp.Body.Close()

	if gotHeader != "Bearer mock-access-token" {
		t.Errorf("got header %q, want %q", gotHeader, "Bearer mock-access-token")
	}
}

func TestNewAuthTransport_InvalidConfig(t *testing.T) {
	_, err := NewAuthTransport(AuthConfig{Type: AuthTypeBasic}, false) // missing username/password
	if err == nil {
		t.Error("expected error for invalid basic auth config")
	}
}

func TestNewAuthTransport_APIKey_DefaultHeader(t *testing.T) {
	cfg := AuthConfig{
		Type:   AuthTypeAPIKey,
		APIKey: "secret-key-42",
	}
	tr, err := NewAuthTransport(cfg, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var gotHeader string
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotHeader = r.Header.Get("X-API-Key")
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	client := &http.Client{Transport: tr}
	resp, err := client.Get(ts.URL)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	resp.Body.Close()

	if gotHeader != "secret-key-42" {
		t.Errorf("got header %q, want %q", gotHeader, "secret-key-42")
	}
}

func TestNewAuthTransport_APIKey_CustomHeader(t *testing.T) {
	cfg := AuthConfig{
		Type:         AuthTypeAPIKey,
		APIKey:       "custom-key",
		APIKeyHeader: "X-Custom-Auth",
	}
	tr, err := NewAuthTransport(cfg, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var gotHeader string
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotHeader = r.Header.Get("X-Custom-Auth")
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	client := &http.Client{Transport: tr}
	resp, err := client.Get(ts.URL)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	resp.Body.Close()

	if gotHeader != "custom-key" {
		t.Errorf("got header %q, want %q", gotHeader, "custom-key")
	}
}

func TestNewAuthTransport_MTLS(t *testing.T) {
	// Generate a self-signed CA + client cert for testing
	certFile, keyFile, cleanup := generateTestCert(t)
	defer cleanup()

	cfg := AuthConfig{
		Type:     AuthTypeMTLS,
		CertFile: certFile,
		KeyFile:  keyFile,
	}
	tr, err := NewAuthTransport(cfg, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if tr == nil {
		t.Fatal("expected non-nil transport for mTLS")
	}
}

func TestNewAuthTransport_MTLS_InvalidFiles(t *testing.T) {
	cfg := AuthConfig{
		Type:     AuthTypeMTLS,
		CertFile: "/nonexistent/cert.pem",
		KeyFile:  "/nonexistent/key.pem",
	}
	_, err := NewAuthTransport(cfg, false)
	if err == nil {
		t.Error("expected error for nonexistent cert files")
	}
}

func TestNewAuthTransport_MTLS_WithCA(t *testing.T) {
	certFile, keyFile, cleanup := generateTestCert(t)
	defer cleanup()

	// Use the cert as its own CA (self-signed)
	cfg := AuthConfig{
		Type:     AuthTypeMTLS,
		CertFile: certFile,
		KeyFile:  keyFile,
		CAFile:   certFile,
	}
	tr, err := NewAuthTransport(cfg, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if tr == nil {
		t.Fatal("expected non-nil transport for mTLS with CA")
	}
}

func TestNewAuthTransport_SkipVerify(t *testing.T) {
	cfg := AuthConfig{Type: AuthTypeNone}
	tr, err := NewAuthTransport(cfg, true)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if tr == nil {
		t.Fatal("expected non-nil transport when skipVerify is true")
	}

	// Verify it's an otelhttp transport
	_, ok := tr.(*otelhttp.Transport)
	if !ok {
		t.Errorf("expected *otelhttp.Transport, got %T", tr)
		return
	}
}

func TestLoadCACert_InvalidFile(t *testing.T) {
	_, err := loadCACert("/nonexistent/ca.pem")
	if err == nil {
		t.Error("expected error for nonexistent CA file")
	}
}

func TestLoadCACert_InvalidPEM(t *testing.T) {
	f, err := os.CreateTemp("", "bad-ca-*.pem")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(f.Name())
	f.Write([]byte("not a certificate"))
	f.Close()

	_, err = loadCACert(f.Name())
	if err == nil {
		t.Error("expected error for invalid PEM content")
	}
}

// generateTestCert creates a self-signed cert+key pair in temp files.
func generateTestCert(t *testing.T) (certPath, keyPath string, cleanup func()) {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generating key: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(1 * time.Hour),
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("creating certificate: %v", err)
	}

	certF, err := os.CreateTemp("", "test-cert-*.pem")
	if err != nil {
		t.Fatalf("creating cert file: %v", err)
	}
	pem.Encode(certF, &pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	certF.Close()

	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatalf("marshaling key: %v", err)
	}
	keyF, err := os.CreateTemp("", "test-key-*.pem")
	if err != nil {
		t.Fatalf("creating key file: %v", err)
	}
	pem.Encode(keyF, &pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	keyF.Close()

	return certF.Name(), keyF.Name(), func() {
		os.Remove(certF.Name())
		os.Remove(keyF.Name())
	}
}
