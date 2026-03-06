package otel

// protects: Invariant[Observability] - Traces and metrics must be propagated through the system.
// protects: Invariant[Configuration] - SDK must be correctly initialized based on environment config.

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/f46b83ee9/heimdall/config"
)

func generateTestCert(t *testing.T, certPath, keyPath string) {
	priv, _ := rsa.GenerateKey(rand.Reader, 2048)
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"Test"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		t.Fatal(err)
	}
	certOut, _ := os.Create(certPath)
	pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	certOut.Close()

	keyOut, _ := os.OpenFile(keyPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	pem.Encode(keyOut, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)})
	keyOut.Close()
}

func TestObservability_SDK_Initialization(t *testing.T) {
	ctx := context.Background()

	t.Run("Disabled state", func(t *testing.T) {
		cfg := config.TelemetryConfig{
			Enabled:     false,
			ServiceName: "test",
		}
		p, err := Init(ctx, cfg)
		if err != nil {
			t.Fatalf("Init failed: %v", err)
		}
		if p.tp != nil {
			t.Error("expected nil TracerProvider when disabled")
		}
		if p.mp == nil {
			t.Error("expected non-nil MeterProvider")
		}
		p.Shutdown(ctx)
	})

	t.Run("Basic Auth configuration", func(t *testing.T) {
		cfg := config.TelemetryConfig{
			Enabled:      true,
			ServiceName:  "test",
			OTLPEndpoint: "localhost:4317",
			Auth: config.AuthConfig{
				Type:     config.AuthTypeBasic,
				Username: "u",
				Password: "p",
			},
			InsecureSkipVerify: true,
		}
		p, err := Init(ctx, cfg)
		if err != nil {
			t.Fatalf("Init failed: %v", err)
		}
		if p.tp == nil {
			t.Error("expected non-nil TracerProvider when enabled")
		}
		p.Shutdown(ctx)
	})

	t.Run("Bearer Auth configuration", func(t *testing.T) {
		cfg := config.TelemetryConfig{
			Enabled:      true,
			ServiceName:  "test",
			OTLPEndpoint: "localhost:4317",
			Auth: config.AuthConfig{
				Type:  config.AuthTypeBearer,
				Token: "t",
			},
		}
		p, _ := Init(ctx, cfg)
		if p.tp != nil {
			p.Shutdown(ctx)
		}
	})

	t.Run("APIKey Auth configuration", func(t *testing.T) {
		cfg := config.TelemetryConfig{
			Enabled:      true,
			ServiceName:  "test",
			OTLPEndpoint: "localhost:4317",
			Auth: config.AuthConfig{
				Type:   config.AuthTypeAPIKey,
				APIKey: "k",
			},
		}
		p, _ := Init(ctx, cfg)
		if p.tp != nil {
			p.Shutdown(ctx)
		}
	})

	t.Run("mTLS invalid certificates", func(t *testing.T) {
		tmpDir := t.TempDir()
		certFile := filepath.Join(tmpDir, "cert.pem")
		keyFile := filepath.Join(tmpDir, "key.pem")
		os.WriteFile(certFile, []byte("invalid cert"), 0644)
		os.WriteFile(keyFile, []byte("invalid key"), 0644)

		cfg := config.TelemetryConfig{
			Enabled:      true,
			ServiceName:  "test",
			OTLPEndpoint: "localhost:4317",
			Auth: config.AuthConfig{
				Type:     config.AuthTypeMTLS,
				CertFile: certFile,
				KeyFile:  keyFile,
			},
		}
		_, err := Init(ctx, cfg)
		if err == nil {
			t.Error("expected error for invalid certs")
		}
	})

	t.Run("mTLS with CA success", func(t *testing.T) {
		tmpDir := t.TempDir()
		certFile := filepath.Join(tmpDir, "cert.pem")
		keyFile := filepath.Join(tmpDir, "key.pem")
		caFile := filepath.Join(tmpDir, "ca.pem")

		generateTestCert(t, certFile, keyFile)
		generateTestCert(t, caFile, filepath.Join(tmpDir, "ca.key"))

		cfg := config.TelemetryConfig{
			Enabled: true,
			Auth: config.AuthConfig{
				Type:     config.AuthTypeMTLS,
				CertFile: certFile,
				KeyFile:  keyFile,
				CAFile:   caFile,
			},
		}
		Init(ctx, cfg)
	})
}
