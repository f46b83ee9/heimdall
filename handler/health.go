package handler

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

// handleHealthz returns a liveness probe handler.
// Always returns 200 if the process is alive.
func (h *Handler) handleHealthz() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{
			"status": "ok",
		})
	}
}

// handleReadyz returns a readiness probe handler.
// Checks that the database is reachable.
func (h *Handler) handleReadyz() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Check database connectivity
		if h.db != nil {
			sqlDB, err := h.db.DB()
			if err != nil {
				c.JSON(http.StatusServiceUnavailable, gin.H{
					"status": "not ready",
					"error":  "database connection error",
				})
				return
			}
			if err := sqlDB.Ping(); err != nil {
				c.JSON(http.StatusServiceUnavailable, gin.H{
					"status": "not ready",
					"error":  "database ping failed",
				})
				return
			}
		}

		c.JSON(http.StatusOK, gin.H{
			"status": "ready",
		})
	}
}
