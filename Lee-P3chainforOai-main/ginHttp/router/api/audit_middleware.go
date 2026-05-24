package router

import (
	"bytes"
	"io"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

const (
	CtxAuditTraceID       = "audit_trace_id"
	CtxAuditRawBody       = "audit_raw_body"
	CtxAuditStartedAt     = "audit_started_at"
	CtxAuditSessionID     = "audit_session_id"
	CtxAuditInteractionID = "audit_interaction_id"
)

func AuditContextMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		traceID := uuid.NewString()
		startedAt := time.Now().UTC()

		var rawBody []byte
		if c.Request != nil && c.Request.Body != nil {
			rawBody, _ = io.ReadAll(c.Request.Body)
			c.Request.Body = io.NopCloser(bytes.NewBuffer(rawBody))
		}

		c.Set(CtxAuditTraceID, traceID)
		c.Set(CtxAuditRawBody, rawBody)
		c.Set(CtxAuditStartedAt, startedAt)
		c.Set(CtxAuditSessionID, c.GetHeader("X-Session-ID"))
		c.Set(CtxAuditInteractionID, c.GetHeader("X-Interaction-ID"))
		c.Next()
	}
}
