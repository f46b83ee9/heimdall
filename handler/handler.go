package handler

import (
	"context"
	"log/slog"
	"net/http"
	"strings"

	"github.com/f46b83ee9/heimdall/config"
	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
)

// TenantLister resolves all known tenant IDs.
// Used for auto-resolving tenants on read requests when X-Scope-OrgID is absent.
type TenantLister interface {
	ListTenantIDs(ctx context.Context) ([]string, error)
}

// Handler holds the dependencies for HTTP request handling.
type Handler struct {
	cfg          *config.Config
	fanOut       *FanOutEngine
	db           *gorm.DB
	tenantLister TenantLister // optional, enables auto-resolve on reads
}

// NewHandler creates a new Handler.
func NewHandler(cfg *config.Config, fanOut *FanOutEngine, db *gorm.DB) *Handler {
	return &Handler{
		cfg:    cfg,
		fanOut: fanOut,
		db:     db,
	}
}

// WithTenantLister enables automatic tenant resolution for read actions
// when the X-Scope-OrgID header is absent.
func (h *Handler) WithTenantLister(tl TenantLister) {
	h.tenantLister = tl
}

// RegisterRoutes sets up the Gin router with all middleware and routes.
func (h *Handler) RegisterRoutes(r *gin.Engine, m *Metrics) {
	// Health check endpoints — no middleware, no auth
	r.GET("/healthz", h.handleHealthz())
	r.GET("/readyz", h.handleReadyz())

	// Global middleware
	r.Use(PanicRecoveryMiddleware())
	r.Use(MetricsMiddleware(m))
	r.Use(TracingMiddleware())
	r.Use(JWTMiddleware(h.cfg.JWT))

	// Mimir API routes
	api := r.Group("/api/v1")
	{
		// Read actions — PromQL query rewriting
		api.GET("/query", h.handleQuery(ActionRead))
		api.POST("/query", h.handleQuery(ActionRead))
		api.GET("/query_range", h.handleQuery(ActionRead))
		api.POST("/query_range", h.handleQuery(ActionRead))
		api.GET("/query_exemplars", h.handleQuery(ActionRead))
		api.POST("/query_exemplars", h.handleQuery(ActionRead))
		api.GET("/series", h.handleQuery(ActionRead))
		api.POST("/series", h.handleQuery(ActionRead))
		api.GET("/labels", h.handleQuery(ActionRead))
		api.POST("/labels", h.handleQuery(ActionRead))
		api.GET("/label/:name/values", h.handleQuery(ActionRead))

		// Response filtering — rules and alerts
		api.GET("/rules", h.handleResponseFilter(ActionRulesRead))
		api.GET("/alerts", h.handleResponseFilter(ActionAlertsRead))

		// Write actions — pass-through (no body mutation)
		api.POST("/push", h.handleWrite(ActionWrite))

		// Rules write
		ruler := r.Group("/api/v1/rules")
		{
			ruler.POST("/:namespace", h.handleWrite(ActionRulesWrite))
			ruler.DELETE("/:namespace/:group", h.handleWrite(ActionRulesWrite))
		}
	}
}

// authorizeAndDispatch runs the shared pipeline: resolve tenants → OPA evaluate → dispatch.
// Returns the response body, status code, filter groups, and any error.
// On error or denial it writes the error response to c and returns handled=true.
func (h *Handler) authorizeAndDispatch(c *gin.Context, action Action, autoResolve bool) (body []byte, status int, groups []filterGroup, handled bool) {
	ctx := c.Request.Context()
	identity := MustGetIdentity(c)

	// In tests, we need to inject the identity into the *http.Request context,
	// not just the gin.Context, since MustGetIdentity now reads from c.Request.Context().
	// The setupRouter helper in each test should ensure this is done if it mocks auth.
	var tenantIDs []string
	var err error

	if autoResolve {
		tenantIDs, err = h.resolveTenantsForRead(c)
		if err != nil {
			slog.ErrorContext(ctx, "tenant resolution failed", "error", err)
			RespondError(c, http.StatusInternalServerError, "tenant_resolution_error", "failed to resolve tenants")
			return nil, 0, nil, true
		}
	} else {
		tenantIDs = resolveTenants(c)
	}

	if len(tenantIDs) == 0 {
		RespondError(c, http.StatusBadRequest, "missing_tenant", "X-Scope-OrgID header is required")
		return nil, 0, nil, true
	}

	groups, err = h.fanOut.EvaluateTenants(ctx, identity, tenantIDs, action, "metrics")
	if err != nil {
		slog.ErrorContext(ctx, "OPA evaluation failed", "error", err)
		RespondError(c, http.StatusInternalServerError, "opa_error", "authorization evaluation failed")
		return nil, 0, nil, true
	}

	if len(groups) == 0 {
		RespondError(c, http.StatusForbidden, "access_denied", "access denied for all requested tenants")
		return nil, 0, nil, true
	}

	body, status, err = h.fanOut.Dispatch(ctx, groups, c.Request, action)
	if err != nil {
		slog.ErrorContext(ctx, "upstream dispatch failed", "error", err)
		if status == http.StatusServiceUnavailable || status == http.StatusGatewayTimeout {
			RespondError(c, status, "fanout_overloaded", err.Error())
			return nil, 0, nil, true
		}
		RespondError(c, http.StatusBadGateway, "upstream_error", "upstream request failed")
		return nil, 0, nil, true
	}

	return body, status, groups, false
}

// handleQuery handles read actions that require PromQL query rewriting.
func (h *Handler) handleQuery(action Action) gin.HandlerFunc {
	return func(c *gin.Context) {
		body, status, _, handled := h.authorizeAndDispatch(c, action, true)
		if handled {
			return
		}
		c.Data(status, "application/json", body)
	}
}

// handleResponseFilter handles rules:read and alerts:read actions
// that require response-mode filtering.
func (h *Handler) handleResponseFilter(action Action) gin.HandlerFunc {
	return func(c *gin.Context) {
		ctx := c.Request.Context()

		body, status, groups, handled := h.authorizeAndDispatch(c, action, true)
		if handled {
			return
		}

		if status != http.StatusOK {
			c.Data(status, "application/json", body)
			return
		}

		// Apply response filtering using the first group's matchers
		var filteredBody []byte
		var err error
		switch action {
		case ActionRulesRead:
			filteredBody, err = FilterRulesResponse(ctx, body, groups[0].Matchers)
		case ActionAlertsRead:
			filteredBody, err = FilterAlertsResponse(ctx, body, groups[0].Matchers)
		default:
			filteredBody = body
		}

		if err != nil {
			slog.ErrorContext(ctx, "response filtering failed", "error", err)
			RespondError(c, http.StatusInternalServerError, "filter_error", "response filtering failed")
			return
		}

		c.Data(http.StatusOK, "application/json", filteredBody)
	}
}

// handleWrite handles write actions (pass-through, no body mutation).
func (h *Handler) handleWrite(action Action) gin.HandlerFunc {
	return func(c *gin.Context) {
		ctx := c.Request.Context()
		identity := MustGetIdentity(c)

		tenantIDs := resolveTenants(c)
		if len(tenantIDs) == 0 {
			RespondError(c, http.StatusBadRequest, "missing_tenant", "X-Scope-OrgID header is required")
			return
		}

		// Authorize write via OPA per tenant
		deniedTenant, err := h.fanOut.AuthorizeWrite(ctx, identity, tenantIDs, action)
		if err != nil {
			slog.ErrorContext(ctx, "OPA evaluation failed for write", "error", err, "tenant", deniedTenant)
			RespondError(c, http.StatusInternalServerError, "opa_error", "authorization evaluation failed")
			return
		}
		if deniedTenant != "" {
			RespondError(c, http.StatusForbidden, "access_denied",
				"write access denied for tenant "+deniedTenant)
			return
		}

		// Forward request byte-for-byte to upstream (no body modification)
		body, status, err := h.fanOut.ForwardWrite(ctx, tenantIDs, c.Request)
		if err != nil {
			slog.ErrorContext(ctx, "upstream write failed", "error", err)
			RespondError(c, http.StatusBadGateway, "upstream_error", "upstream write request failed")
			return
		}

		c.Data(status, "application/json", body)
	}
}

// resolveTenants extracts tenant IDs from the X-Scope-OrgID header.
// Multiple tenants are pipe-separated.
func resolveTenants(c *gin.Context) []string {
	orgID := c.GetHeader("X-Scope-OrgID")
	if orgID == "" {
		return nil
	}

	tenants := strings.Split(orgID, "|")
	result := make([]string, 0, len(tenants))
	for _, t := range tenants {
		t = strings.TrimSpace(t)
		if t != "" {
			result = append(result, t)
		}
	}
	return result
}

// resolveTenantsForRead resolves tenant IDs for read actions.
// If the X-Scope-OrgID header is present, it is used directly.
// If absent and a TenantLister is configured, all known tenants are returned
// so that OPA can filter to only the accessible ones.
func (h *Handler) resolveTenantsForRead(c *gin.Context) ([]string, error) {
	tenantIDs := resolveTenants(c)
	if len(tenantIDs) > 0 {
		return tenantIDs, nil
	}

	// Auto-resolve: list all tenants, OPA will filter to accessible ones
	if h.tenantLister != nil {
		return h.tenantLister.ListTenantIDs(c.Request.Context())
	}

	return nil, nil
}
