//go:build e2e

package e2e

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// jwksServer starts a mock JWKS server that serves a JWK Set matching our test RSA key.
type jwksServer struct {
	privateKey *rsa.PrivateKey
	port       int
	server     *http.Server
}

// startJWKSServer starts a JWKS mock server on a free port.
// Returns the JWKS URL and the RSA private key for signing JWTs.
func startJWKSServer(t *testing.T) *jwksServer {
	t.Helper()

	// Generate RSA key pair for test JWT signing
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generating RSA key: %v", err)
	}

	// Build JWK Set from the public key
	jwkSet := buildJWKSet(&privateKey.PublicKey)
	jwkSetJSON, err := json.Marshal(jwkSet)
	if err != nil {
		t.Fatalf("marshaling JWK Set: %v", err)
	}

	// Find a free port
	l, err := net.Listen("tcp", "0.0.0.0:0")
	if err != nil {
		t.Fatalf("finding free port for JWKS: %v", err)
	}
	port := l.Addr().(*net.TCPAddr).Port
	l.Close()

	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/jwks.json", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write(jwkSetJSON)
	})

	server := &http.Server{
		Addr:    fmt.Sprintf(":%d", port),
		Handler: mux,
	}

	go func() {
		if listenErr := server.ListenAndServe(); listenErr != nil && listenErr != http.ErrServerClosed {
			// Ignore - we're in a test
		}
	}()

	t.Cleanup(func() {
		server.Close()
	})

	js := &jwksServer{
		privateKey: privateKey,
		port:       port,
		server:     server,
	}

	// Wait for server to be ready
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		resp, err := http.Get(fmt.Sprintf("http://127.0.0.1:%d/.well-known/jwks.json", port))
		if err == nil {
			resp.Body.Close()
			if resp.StatusCode == 200 {
				return js
			}
		}
		time.Sleep(50 * time.Millisecond)
	}

	t.Fatal("JWKS server did not start in time")
	return nil
}

// makeJWT creates a signed JWT using the RSA key.
func (js *jwksServer) makeJWT(t *testing.T, sub string, groups []string) string {
	t.Helper()

	claims := jwt.MapClaims{
		"sub":    sub,
		"iss":    "heimdall-test",
		"aud":    []string{"heimdall"},
		"exp":    time.Now().Add(1 * time.Hour).Unix(),
		"iat":    time.Now().Unix(),
		"groups": groups,
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = "test-key-1"

	tokenStr, err := token.SignedString(js.privateKey)
	if err != nil {
		t.Fatalf("signing JWT: %v", err)
	}
	return tokenStr
}

// jwksURL returns the URL for the JWKS endpoint.
func (js *jwksServer) jwksURL() string {
	return fmt.Sprintf("http://127.0.0.1:%d/.well-known/jwks.json", js.port)
}

// hostJWKSURL returns the URL for the JWKS endpoint accessible from Docker containers.
func (js *jwksServer) hostJWKSURL(hostIP string) string {
	return fmt.Sprintf("http://%s:%d/.well-known/jwks.json", hostIP, js.port)
}

// --- JWK Set building ---

type jwkSetJSON struct {
	Keys []jwkJSON `json:"keys"`
}

type jwkJSON struct {
	Kty string `json:"kty"`
	Use string `json:"use"`
	Kid string `json:"kid"`
	Alg string `json:"alg"`
	N   string `json:"n"`
	E   string `json:"e"`
}

func buildJWKSet(pub *rsa.PublicKey) jwkSetJSON {
	return jwkSetJSON{
		Keys: []jwkJSON{
			{
				Kty: "RSA",
				Use: "sig",
				Kid: "test-key-1",
				Alg: "RS256",
				N:   base64.RawURLEncoding.EncodeToString(pub.N.Bytes()),
				E:   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(pub.E)).Bytes()),
			},
		},
	}
}
