package handler

import (
	"context"
	"log/slog"
	"net/http"
	"strings"

	"github.com/MicahParks/keyfunc/v3"
	"github.com/f46b83ee9/heimdall/config"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
)

// Identity holds the user identity extracted from the JWT.
type Identity struct {
	UserID string
	Groups []string
}

type contextKey string

const identityKey contextKey = "heimdall_identity"

// SetIdentity stores the identity in the request context.
func SetIdentity(ctx context.Context, id *Identity) context.Context {
	return context.WithValue(ctx, identityKey, id)
}

// GetIdentity retrieves the identity from the request context.
func GetIdentity(ctx context.Context) (*Identity, bool) {
	id, ok := ctx.Value(identityKey).(*Identity)
	return id, ok
}

// JWTMiddleware creates a Gin middleware that validates JWTs.
// It extracts sub → user_id and the configured groups claim → groups.
// Any validation failure results in a 401.
func JWTMiddleware(cfg config.JWTConfig) gin.HandlerFunc {
	// Initialize JWKS keyfunc
	var jwks keyfunc.Keyfunc
	var initErr error

	jwks, initErr = keyfunc.NewDefault([]string{cfg.JWKSURL})
	if initErr != nil {
		// This will be caught at startup
		slog.Error("failed to initialize JWKS", "error", initErr)
	}

	return func(c *gin.Context) {
		ctx, span := tracer.Start(c.Request.Context(), "jwt.Validate")
		defer span.End()

		if jwks == nil {
			span.RecordError(initErr)
			RespondError(c, http.StatusInternalServerError, "jwks_init_failed", "JWKS initialization failed")
			return
		}

		// Extract Bearer token
		authHeader := c.GetHeader("Authorization")
		if authHeader == "" {
			RespondError(c, http.StatusUnauthorized, "missing_token", "Authorization header is required")
			return
		}

		parts := strings.SplitN(authHeader, " ", 2)
		if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") {
			RespondError(c, http.StatusUnauthorized, "invalid_token_format", "Authorization header must be Bearer <token>")
			return
		}
		tokenStr := parts[1]

		// Parse and validate
		parserOpts := []jwt.ParserOption{
			jwt.WithIssuer(cfg.Issuer),
			jwt.WithAudience(cfg.Audience),
			jwt.WithExpirationRequired(),
			jwt.WithValidMethods([]string{"RS256", "RS384", "RS512", "ES256", "ES384", "ES512"}),
		}

		token, err := jwt.Parse(tokenStr, jwks.KeyfuncCtx(ctx), parserOpts...)
		if err != nil {
			span.RecordError(err)
			slog.WarnContext(ctx, "JWT validation failed", "error", err)
			RespondError(c, http.StatusUnauthorized, "invalid_token", "JWT validation failed")
			return
		}

		claims, ok := token.Claims.(jwt.MapClaims)
		if !ok || !token.Valid {
			RespondError(c, http.StatusUnauthorized, "invalid_claims", "invalid JWT claims")
			return
		}

		// Extract sub → user_id
		sub, err := claims.GetSubject()
		if err != nil || sub == "" {
			RespondError(c, http.StatusUnauthorized, "missing_subject", "JWT must contain sub claim")
			return
		}

		// Extract groups claim
		var groups []string
		groupsClaim := cfg.GroupsClaim
		if groupsClaim == "" {
			groupsClaim = "groups"
		}

		if rawGroups, exists := claims[groupsClaim]; exists {
			switch v := rawGroups.(type) {
			case []interface{}:
				for _, g := range v {
					if gs, ok := g.(string); ok {
						groups = append(groups, gs)
					}
				}
			case string:
				groups = strings.Split(v, ",")
			}
		}

		identity := &Identity{
			UserID: sub,
			Groups: groups,
		}

		// Store in context (never log sensitive JWT data)
		slog.InfoContext(ctx, "JWT validated",
			"user_id", identity.UserID,
			"groups_count", len(identity.Groups),
		)

		c.Request = c.Request.WithContext(SetIdentity(ctx, identity))
		c.Next()
	}
}

// MustGetIdentity retrieves the identity from the HTTP request context or panics.
func MustGetIdentity(c *gin.Context) *Identity {
	id, ok := GetIdentity(c.Request.Context())
	if !ok {
		panic("identity not found in request context")
	}
	return id
}
