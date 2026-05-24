package router

import (
	"net/http"
	"p3Chain/api"
	"p3Chain/ginHttp/pkg/app"
	e "p3Chain/ginHttp/pkg/error"
	loglogrus "p3Chain/log_logrus"
	"strconv"
	"strings"

	"github.com/gin-gonic/gin"
)

func GetAuditLogs(auditSvc *api.AuditService) func(*gin.Context) {
	return func(c *gin.Context) {
		appG := app.Gin{C: c}
		if auditSvc == nil {
			appG.Response(http.StatusInternalServerError, e.ERROR, gin.H{
				"error": "audit service is unavailable",
			})
			return
		}

		page, err := parseAuditQueryInt(c.Query("page"), 1)
		if err != nil {
			appG.Response(http.StatusBadRequest, e.INVALID_PARAMS, gin.H{"error": "invalid page"})
			return
		}

		pageSize, err := parseAuditQueryInt(c.Query("pageSize"), 20)
		if err != nil {
			appG.Response(http.StatusBadRequest, e.INVALID_PARAMS, gin.H{"error": "invalid pageSize"})
			return
		}

		query := api.AuditQuery{
			AuditID:        c.Query("auditId"),
			OperatorDID:    c.Query("operatorDid"),
			SubjectDID:     c.Query("subjectDid"),
			PeerDID:        c.Query("peerDid"),
			OperationType:  c.Query("operationType"),
			TargetObjectID: c.Query("targetObjectId"),
			SessionID:      c.Query("sessionId"),
			InteractionID:  c.Query("interactionId"),
			EvidenceLevel:  c.Query("evidenceLevel"),
			StartTime:      c.Query("startTime"),
			EndTime:        c.Query("endTime"),
			Page:           page,
			PageSize:       pageSize,
		}
		logAuditQueryPurpose(c, "list_audit_logs", c.Query("purpose"))

		logs, total, err := auditSvc.QueryAuditLogs(query)
		if err != nil {
			statusCode := http.StatusInternalServerError
			errCode := e.ERROR
			if isAuditQueryClientError(err) {
				statusCode = http.StatusBadRequest
				errCode = e.INVALID_PARAMS
			}
			appG.Response(statusCode, errCode, gin.H{
				"error": err.Error(),
			})
			return
		}

		c.JSON(http.StatusOK, gin.H{
			"auditLogs": logs,
			"page":      page,
			"pageSize":  pageSize,
			"total":     total,
		})
	}
}

func GetAuditLogByID(auditSvc *api.AuditService) func(*gin.Context) {
	return func(c *gin.Context) {
		appG := app.Gin{C: c}
		if auditSvc == nil {
			appG.Response(http.StatusInternalServerError, e.ERROR, gin.H{
				"error": "audit service is unavailable",
			})
			return
		}

		auditID := strings.TrimSpace(c.Param("auditId"))
		if auditID == "" {
			appG.Response(http.StatusBadRequest, e.INVALID_PARAMS, gin.H{
				"error": "auditId is required",
			})
			return
		}
		logAuditQueryPurpose(c, "get_audit_log", c.Query("purpose"))

		logEntry, err := auditSvc.GetAuditLogByID(auditID)
		if err != nil {
			statusCode := http.StatusInternalServerError
			errCode := e.ERROR
			if strings.Contains(strings.ToLower(err.Error()), "not found") {
				statusCode = http.StatusNotFound
			} else if isAuditQueryClientError(err) {
				statusCode = http.StatusBadRequest
				errCode = e.INVALID_PARAMS
			}
			appG.Response(statusCode, errCode, gin.H{
				"error": err.Error(),
			})
			return
		}

		c.JSON(http.StatusOK, logEntry)
	}
}

func parseAuditQueryInt(raw string, defaultValue int) (int, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return defaultValue, nil
	}

	value, err := strconv.Atoi(raw)
	if err != nil || value <= 0 {
		return 0, strconv.ErrSyntax
	}

	return value, nil
}

func isAuditQueryClientError(err error) bool {
	if err == nil {
		return false
	}

	message := strings.ToLower(err.Error())
	return strings.Contains(message, "requires at least one") ||
		strings.Contains(message, "cannot be empty") ||
		strings.Contains(message, "is required") ||
		strings.Contains(message, "invalid starttime") ||
		strings.Contains(message, "invalid endtime") ||
		strings.Contains(message, "starttime cannot be later")
}

func logAuditQueryPurpose(c *gin.Context, action, purpose string) {
	purpose = strings.TrimSpace(purpose)
	if purpose == "" {
		purpose = "unspecified"
	}
	loglogrus.Log.Infof("[Audit] query action=%s callerDID=%s purpose=%s traceID=%s\n",
		action, GetCallerDID(c), purpose, GetAuditTraceID(c))
}
