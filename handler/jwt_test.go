package handler

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/f46b83ee9/heimdall/config"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
)

func TestJWTMiddleware_Exhaustive(t *testing.T) {
	gin.SetMode(gin.TestMode)

	// Generate RSA key for signing
	key, _ := rsa.GenerateKey(rand.Reader, 2048)

	// Create a mock JWKS server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// JWKS expects base64url encoded N and E
		n := base64.RawURLEncoding.EncodeToString(key.N.Bytes())
		e := base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.E)).Bytes())

		jwks := map[string]interface{}{
			"keys": []map[string]interface{}{
				{
					"kty": "RSA",
					"alg": "RS256",
					"use": "sig",
					"kid": "test-kid",
					"n":   n,
					"e":   e,
				},
			},
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(jwks)
	}))
	defer server.Close()

	cfg := config.JWTConfig{
		Issuer:      "test-issuer",
		Audience:    "test-audience",
		UserIDClaim: "uid",
		GroupsClaim: "teams",
		JWKSURL:     server.URL,
	}

	createToken := func(claims jwt.MapClaims) string {
		token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
		token.Header["kid"] = "test-kid"
		s, _ := token.SignedString(key)
		return s
	}

	tests := []struct {
		name       string
		authHeader string
		wantStatus int
		wantCode   string
		checkID    func(*Identity) bool
	}{
		{
			name: "valid token with custom claims",
			authHeader: "Bearer " + createToken(jwt.MapClaims{
				"iss":   cfg.Issuer,
				"aud":   cfg.Audience,
				"exp":   time.Now().Add(time.Hour).Unix(),
				"uid":   "alice",
				"teams": []string{"dev", "qa"},
			}),
			wantStatus: http.StatusOK,
			checkID: func(id *Identity) bool {
				return id != nil && id.UserID == "alice" && len(id.Groups) == 2
			},
		},
		{
			name: "valid token with sub fallback",
			authHeader: "Bearer " + createToken(jwt.MapClaims{
				"iss":   cfg.Issuer,
				"aud":   cfg.Audience,
				"exp":   time.Now().Add(time.Hour).Unix(),
				"sub":   "bob",
				"teams": "ops,admin",
			}),
			wantStatus: http.StatusOK,
			checkID: func(id *Identity) bool {
				return id != nil && id.UserID == "bob" && len(id.Groups) == 2 && id.Groups[0] == "ops"
			},
		},
		{
			name: "missing identity claim",
			authHeader: "Bearer " + createToken(jwt.MapClaims{
				"iss": cfg.Issuer,
				"aud": cfg.Audience,
				"exp": time.Now().Add(time.Hour).Unix(),
			}),
			wantStatus: http.StatusUnauthorized,
			wantCode:   "missing_subject",
		},
		{
			name: "invalid issuer",
			authHeader: "Bearer " + createToken(jwt.MapClaims{
				"iss": "wrong",
				"aud": cfg.Audience,
				"exp": time.Now().Add(time.Hour).Unix(),
			}),
			wantStatus: http.StatusUnauthorized,
			wantCode:   "invalid_token",
		},
		{
			name: "expired token",
			authHeader: "Bearer " + createToken(jwt.MapClaims{
				"iss": cfg.Issuer,
				"aud": cfg.Audience,
				"exp": time.Now().Add(-time.Hour).Unix(),
			}),
			wantStatus: http.StatusUnauthorized,
			wantCode:   "invalid_token",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := gin.New()
			r.Use(JWTMiddleware(cfg))
			var capturedID *Identity
			r.GET("/test", func(c *gin.Context) {
				id, _ := GetIdentity(c.Request.Context())
				capturedID = id
				c.Status(http.StatusOK)
			})

			w := httptest.NewRecorder()
			req := httptest.NewRequest("GET", "/test", nil)
			if tt.authHeader != "" {
				req.Header.Set("Authorization", tt.authHeader)
			}
			r.ServeHTTP(w, req)

			if w.Code != tt.wantStatus {
				t.Fatalf("got status %d, want %d (body: %s)", w.Code, tt.wantStatus, w.Body.String())
			}
			if tt.checkID != nil && !tt.checkID(capturedID) {
				t.Errorf("identity check failed for %s", tt.name)
			}
		})
	}
}

func TestMustGetIdentity_Panic_Standalone(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Error("expected panic when identity missing")
		}
	}()
	c, _ := gin.CreateTestContext(httptest.NewRecorder())
	c.Request = httptest.NewRequest("GET", "/", nil)
	MustGetIdentity(c)
}
