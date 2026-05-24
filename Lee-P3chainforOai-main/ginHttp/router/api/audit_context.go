package router

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
	"time"

	p3api "p3Chain/api"
	loglogrus "p3Chain/log_logrus"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

var currentAuditService *p3api.AuditService

var auditSensitiveFields = map[string]struct{}{
	"authorization":      {},
	"token":              {},
	"access_token":       {},
	"auth_token":         {},
	"token_plaintext":    {},
	"signature":          {},
	"signature_value":    {},
	"nonce":              {},
	"nonce_value":        {},
	"challenge":          {},
	"private_key":        {},
	"diddocument":        {},
	"did_document_full":  {},
	"publickey":          {},
	"authorization_code": {},
}

func SetAuditService(auditSvc *p3api.AuditService) {
	currentAuditService = auditSvc
}

func GetAuditService() *p3api.AuditService {
	return currentAuditService
}

func GetAuditTraceID(c *gin.Context) string {
	if c == nil {
		return ""
	}

	v, ok := c.Get(CtxAuditTraceID)
	if !ok {
		return ""
	}

	s, _ := v.(string)
	return s
}

func GetAuditRawBody(c *gin.Context) []byte {
	if c == nil {
		return nil
	}

	v, ok := c.Get(CtxAuditRawBody)
	if !ok {
		return nil
	}

	raw, _ := v.([]byte)
	if len(raw) == 0 {
		return nil
	}

	cloned := make([]byte, len(raw))
	copy(cloned, raw)
	return cloned
}

func GetAuditStartedAt(c *gin.Context) time.Time {
	if c == nil {
		return time.Time{}
	}

	v, ok := c.Get(CtxAuditStartedAt)
	if !ok {
		return time.Time{}
	}

	startedAt, _ := v.(time.Time)
	return startedAt
}

func GetAuditSessionID(c *gin.Context) string {
	if c == nil {
		return ""
	}

	v, _ := c.Get(CtxAuditSessionID)
	sessionID, _ := v.(string)
	return firstNonEmpty(sessionID, auditHeader(c, "X-Session-ID"), GetCallerSessionID(c))
}

func GetAuditInteractionID(c *gin.Context) string {
	if c == nil {
		return ""
	}

	v, _ := c.Get(CtxAuditInteractionID)
	interactionID, _ := v.(string)
	return firstNonEmpty(interactionID, auditHeader(c, "X-Interaction-ID"))
}

func GetAuditTokenFingerprint(c *gin.Context) string {
	token := extractBearerToken(c)
	if token == "" {
		return ""
	}

	digest := sha256.Sum256([]byte(token))
	return hex.EncodeToString(digest[:])[:16]
}

func BuildAuditID(operationType string) string {
	normalized := strings.ToUpper(strings.TrimSpace(operationType))
	if normalized == "" {
		normalized = "AUDIT"
	}

	return fmt.Sprintf("%s-%d-%s", normalized, time.Now().UTC().UnixNano(), uuid.NewString())
}

func SanitizeAuditBody(raw []byte) []byte {
	raw = bytesTrimSpace(raw)
	if len(raw) == 0 {
		return nil
	}

	var payload interface{}
	if err := json.Unmarshal(raw, &payload); err != nil {
		return raw
	}

	sanitized := sanitizeAuditValue(payload)
	encoded, err := json.Marshal(sanitized)
	if err != nil {
		return raw
	}

	return encoded
}

func BuildRequestHash(c *gin.Context, operatorDID, targetObjectID string) string {
	if c == nil || c.Request == nil {
		return ""
	}

	method := strings.ToUpper(strings.TrimSpace(c.Request.Method))
	path := requestPath(c)
	query := canonicalQuery(c.Request.URL)
	body := string(SanitizeAuditBody(GetAuditRawBody(c)))

	material := strings.Join([]string{
		method,
		path,
		strings.TrimSpace(operatorDID),
		strings.TrimSpace(targetObjectID),
		query,
		body,
	}, "\n")

	digest := sha256.Sum256([]byte(material))
	return hex.EncodeToString(digest[:])
}

func SubmitAudit(c *gin.Context, auditSvc *p3api.AuditService, event *p3api.AuditEvent) {
	if event == nil {
		return
	}

	if auditSvc == nil {
		loglogrus.Log.Warnf("[Audit] SubmitAudit skipped because audit service is nil, operationType=%s traceID=%s\n",
			event.OperationType, GetAuditTraceID(c))
		return
	}

	if strings.TrimSpace(event.AuditID) == "" {
		event.AuditID = BuildAuditID(event.OperationType)
	}
	if strings.TrimSpace(event.TraceID) == "" {
		event.TraceID = GetAuditTraceID(c)
	}
	if strings.TrimSpace(event.SessionID) == "" {
		event.SessionID = GetAuditSessionID(c)
	}
	if strings.TrimSpace(event.InteractionID) == "" {
		event.InteractionID = GetAuditInteractionID(c)
	}
	if strings.TrimSpace(event.SubjectDID) == "" {
		event.SubjectDID = firstNonEmpty(auditHeader(c, "X-Subject-DID"), event.OperatorDID, GetCallerDID(c))
	}
	if strings.TrimSpace(event.OperatorDID) == "" {
		event.OperatorDID = firstNonEmpty(event.SubjectDID, GetCallerDID(c))
	}
	if strings.TrimSpace(event.PeerDID) == "" {
		event.PeerDID = auditHeader(c, "X-Peer-DID")
	}
	if strings.TrimSpace(event.SubjectNFType) == "" {
		event.SubjectNFType = firstNonEmpty(auditHeader(c, "X-Subject-NF-Type"), GetCallerNFType(c))
	}
	if strings.TrimSpace(event.PeerNFType) == "" {
		event.PeerNFType = auditHeader(c, "X-Peer-NF-Type")
	}
	if strings.TrimSpace(event.EvidenceLevel) == "" {
		event.EvidenceLevel = "index"
	}
	if strings.TrimSpace(event.TokenFingerprint) == "" {
		event.TokenFingerprint = GetAuditTokenFingerprint(c)
	}
	if strings.TrimSpace(event.Method) == "" && c != nil && c.Request != nil {
		event.Method = strings.ToUpper(strings.TrimSpace(c.Request.Method))
	}
	if strings.TrimSpace(event.ResourcePath) == "" {
		event.ResourcePath = requestPath(c)
	}
	if event.Timestamp.IsZero() {
		startedAt := GetAuditStartedAt(c)
		if startedAt.IsZero() {
			event.Timestamp = time.Now().UTC()
		} else {
			event.Timestamp = startedAt.UTC()
		}
	}
	if strings.TrimSpace(event.RequestHash) == "" {
		event.RequestHash = BuildRequestHash(c, event.OperatorDID, event.TargetObjectID)
	}

	if err := auditSvc.Enqueue(event); err != nil {
		loglogrus.Log.Warnf("[Audit] enqueue failed, auditID=%s operatorDID=%s operationType=%s traceID=%s err=%v\n",
			event.AuditID, event.OperatorDID, event.OperationType, event.TraceID, err)
	}
}

func sanitizeAuditValue(value interface{}) interface{} {
	switch v := value.(type) {
	case map[string]interface{}:
		sanitized := make(map[string]interface{}, len(v))
		for key, item := range v {
			if _, blocked := auditSensitiveFields[strings.ToLower(strings.TrimSpace(key))]; blocked {
				continue
			}
			sanitized[key] = sanitizeAuditValue(item)
		}
		return sanitized
	case []interface{}:
		sanitized := make([]interface{}, 0, len(v))
		for _, item := range v {
			sanitized = append(sanitized, sanitizeAuditValue(item))
		}
		return sanitized
	default:
		return value
	}
}

func canonicalQuery(rawURL *url.URL) string {
	if rawURL == nil {
		return ""
	}

	return rawURL.Query().Encode()
}

func requestPath(c *gin.Context) string {
	if c == nil || c.Request == nil || c.Request.URL == nil {
		return ""
	}
	if path := strings.TrimSpace(c.Request.URL.Path); path != "" {
		return path
	}
	return strings.TrimSpace(c.FullPath())
}

func bytesTrimSpace(raw []byte) []byte {
	return []byte(strings.TrimSpace(string(raw)))
}

func extractBearerToken(c *gin.Context) string {
	if c == nil {
		return ""
	}

	authHeader := strings.TrimSpace(auditHeader(c, "Authorization"))
	if !strings.HasPrefix(authHeader, "Bearer ") {
		return ""
	}
	return strings.TrimSpace(strings.TrimPrefix(authHeader, "Bearer "))
}

func auditHeader(c *gin.Context, name string) string {
	if c == nil {
		return ""
	}
	return strings.TrimSpace(c.GetHeader(name))
}
