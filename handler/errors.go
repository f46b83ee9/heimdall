// Package handler provides HTTP request handling for Heimdall.
package handler

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"runtime/debug"

	"github.com/gin-gonic/gin"
)

// ErrorResponse is the standard JSON error envelope.
// All HTTP errors MUST use this format.
type ErrorResponse struct {
	Error string `json:"error"`
	Code  string `json:"code"`
}

// RespondError writes a standardized JSON error response.
// If the request context is canceled or deadline exceeded, it automatically
// transforms the response to a 499 Client Closed Request mapping to enforce invariants.
func RespondError(c *gin.Context, status int, code, message string) {
	err := c.Request.Context().Err()
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		status = 499
		code = "request_canceled"
		message = "client closed request"
	}

	c.AbortWithStatusJSON(status, ErrorResponse{
		Error: message,
		Code:  code,
	})
}

// PanicRecoveryMiddleware catches panics in request handling
// and converts them to 500 responses via RespondError.
func PanicRecoveryMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		defer func() {
			if r := recover(); r != nil {
				slog.ErrorContext(c.Request.Context(), "panic recovered in request handler",
					"panic", r,
					"stack", string(debug.Stack()),
				)
				RespondError(c, http.StatusInternalServerError, "internal_error", "internal server error")
			}
		}()
		c.Next()
	}
}
