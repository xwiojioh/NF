package router

import (
	"fmt"
	"net/http"
	"p3Chain/api"
	"strconv"
	"strings"

	"github.com/gin-gonic/gin"
)

type sessionDigestAnchorRequest struct {
	SessionID        string      `json:"session_id"`
	InteractionID    string      `json:"interaction_id"`
	SubjectDID       string      `json:"subject_did"`
	PeerDID          string      `json:"peer_did"`
	SubjectNFType    string      `json:"subject_nf_type"`
	PeerNFType       string      `json:"peer_nf_type"`
	DigestHash       string      `json:"digest_hash"`
	PrevDigestHash   string      `json:"prev_digest_hash"`
	EventCount       int         `json:"event_count"`
	SummarySeq       int         `json:"summary_seq"`
	Stage            string      `json:"stage"`
	SummaryType      string      `json:"summary_type"`
	RelatedTxHashes  []string    `json:"related_tx_hashes"`
	Timestamp        interface{} `json:"timestamp"`
	TokenFingerprint string      `json:"token_fingerprint"`

	LocalDID        string `json:"local_DID"`
	PeerDIDLegacy   string `json:"peer_DID"`
	LocalType       string `json:"local_type"`
	PeerType        string `json:"peer_type"`
	Hash            string `json:"hash"`
	PrevSummaryHash string `json:"prev_summary_hash"`
}

type sessionDigestVerifyRequest struct {
	SessionID         string `json:"session_id"`
	ClaimedDigestHash string `json:"claimed_digest_hash"`
	ClaimedHash       string `json:"claimed_hash"`
	SummarySeq        int    `json:"summary_seq"`
}

func PostSessionDigest(auditSvc *api.AuditService) gin.HandlerFunc {
	return func(c *gin.Context) {
		if auditSvc == nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "audit service is unavailable"})
			return
		}

		var req sessionDigestAnchorRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid JSON body", "detail": err.Error()})
			return
		}

		timestamp, err := parseFlexibleAuditTimestamp(req.Timestamp)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		digest := api.SessionDigest{
			SessionID:        firstNonEmpty(req.SessionID, GetAuditSessionID(c)),
			InteractionID:    firstNonEmpty(req.InteractionID, GetAuditInteractionID(c)),
			SubjectDID:       firstNonEmpty(req.SubjectDID, req.LocalDID, GetCallerDID(c)),
			PeerDID:          firstNonEmpty(req.PeerDID, req.PeerDIDLegacy),
			SubjectNFType:    firstNonEmpty(req.SubjectNFType, req.LocalType, GetCallerNFType(c)),
			PeerNFType:       firstNonEmpty(req.PeerNFType, req.PeerType),
			DigestHash:       firstNonEmpty(req.DigestHash, req.Hash),
			PrevDigestHash:   firstNonEmpty(req.PrevDigestHash, req.PrevSummaryHash),
			EventCount:       req.EventCount,
			SummarySeq:       req.SummarySeq,
			Stage:            req.Stage,
			SummaryType:      req.SummaryType,
			RelatedTxHashes:  req.RelatedTxHashes,
			Timestamp:        timestamp,
			TokenFingerprint: firstNonEmpty(req.TokenFingerprint, GetAuditTokenFingerprint(c)),
		}

		result, err := auditSvc.AnchorSessionDigest(digest)
		if err != nil {
			status := http.StatusInternalServerError
			if isAuditDigestClientError(err) {
				status = http.StatusBadRequest
			}
			c.JSON(status, gin.H{"error": err.Error()})
			return
		}

		c.JSON(http.StatusCreated, gin.H{
			"anchor_tx_hash": result.AnchorTxHash,
			"anchored_at":    result.AnchoredAt,
			"digest":         result.Digest,
		})
	}
}

func GetSessionDigest(auditSvc *api.AuditService) gin.HandlerFunc {
	return func(c *gin.Context) {
		if auditSvc == nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "audit service is unavailable"})
			return
		}

		if did := strings.TrimSpace(c.Query("did")); did != "" {
			logAuditQueryPurpose(c, "list_session_digests_by_did", c.Query("purpose"))
			digests, err := auditSvc.GetSessionDigestsByDID(did)
			if err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
				return
			}
			c.JSON(http.StatusOK, gin.H{"sessionDigests": digests})
			return
		}
		if interactionID := strings.TrimSpace(c.Query("interactionId")); interactionID != "" {
			logAuditQueryPurpose(c, "list_session_digests_by_interaction", c.Query("purpose"))
			digests, err := auditSvc.GetSessionDigestsByInteraction(interactionID)
			if err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
				return
			}
			c.JSON(http.StatusOK, gin.H{"sessionDigests": digests})
			return
		}

		sessionID := strings.TrimSpace(c.Param("sessionId"))
		if sessionID == "" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "sessionId is required"})
			return
		}

		summarySeq, err := parseOptionalPositiveInt(c.Query("summarySeq"))
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "summarySeq must be a positive integer"})
			return
		}
		logAuditQueryPurpose(c, "get_session_digest", c.Query("purpose"))

		digest, err := auditSvc.GetSessionDigest(sessionID, summarySeq)
		if err != nil {
			status := http.StatusInternalServerError
			if strings.Contains(strings.ToLower(err.Error()), "not found") {
				status = http.StatusNotFound
			} else if isAuditDigestClientError(err) {
				status = http.StatusBadRequest
			}
			c.JSON(status, gin.H{"error": err.Error()})
			return
		}

		c.JSON(http.StatusOK, digest)
	}
}

func VerifySessionDigest(auditSvc *api.AuditService) gin.HandlerFunc {
	return func(c *gin.Context) {
		if auditSvc == nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "audit service is unavailable"})
			return
		}

		var req sessionDigestVerifyRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid JSON body", "detail": err.Error()})
			return
		}

		result, err := auditSvc.VerifySessionDigest(
			req.SessionID,
			firstNonEmpty(req.ClaimedDigestHash, req.ClaimedHash),
			req.SummarySeq,
		)
		if err != nil {
			status := http.StatusInternalServerError
			if isAuditDigestClientError(err) {
				status = http.StatusBadRequest
			} else if strings.Contains(strings.ToLower(err.Error()), "not found") {
				status = http.StatusNotFound
			}
			c.JSON(status, gin.H{"error": err.Error()})
			return
		}

		c.JSON(http.StatusOK, result)
	}
}

func VerifySessionEvents(auditSvc *api.AuditService) gin.HandlerFunc {
	return func(c *gin.Context) {
		if auditSvc == nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "audit service is unavailable"})
			return
		}

		var req api.VerifyEventsRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid JSON body", "detail": err.Error()})
			return
		}

		result, err := auditSvc.VerifySessionEvents(req)
		if err != nil {
			status := http.StatusInternalServerError
			if isAuditDigestClientError(err) {
				status = http.StatusBadRequest
			} else if strings.Contains(strings.ToLower(err.Error()), "not found") {
				status = http.StatusNotFound
			}
			c.JSON(status, gin.H{"error": err.Error()})
			return
		}

		c.JSON(http.StatusOK, result)
	}
}

func parseFlexibleAuditTimestamp(value interface{}) (int64, error) {
	switch v := value.(type) {
	case nil:
		return 0, nil
	case float64:
		return int64(v), nil
	case string:
		v = strings.TrimSpace(v)
		if v == "" {
			return 0, nil
		}
		parsed, err := strconv.ParseInt(v, 10, 64)
		if err != nil {
			return 0, fmt.Errorf("timestamp must be epoch milliseconds")
		}
		return parsed, nil
	default:
		return 0, fmt.Errorf("timestamp must be epoch milliseconds")
	}
}

func parseOptionalPositiveInt(raw string) (int, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return 0, nil
	}
	parsed, err := strconv.Atoi(raw)
	if err != nil || parsed <= 0 {
		return 0, fmt.Errorf("invalid positive integer")
	}
	return parsed, nil
}

func isAuditDigestClientError(err error) bool {
	if err == nil {
		return false
	}
	message := strings.ToLower(err.Error())
	return strings.Contains(message, "is required") ||
		strings.Contains(message, "cannot be empty") ||
		strings.Contains(message, "cannot be negative") ||
		strings.Contains(message, "must be")
}
