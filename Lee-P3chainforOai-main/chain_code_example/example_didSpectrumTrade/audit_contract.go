package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	cc "p3Chain/core/contract/chainCodeSupport"
	"sort"
	"strconv"
	"strings"
	"time"
)

const (
	auditLogKeyPrefix              = "audit:log:"
	auditOperatorKeyPrefix         = "audit:operator:"
	auditOperationKeyPrefix        = "audit:operation:"
	auditDayKeyPrefix              = "audit:day:"
	auditLogSessionKeyPrefix       = "audit:log-session:"
	auditLogSubjectDIDKeyPrefix    = "audit:log-subject:"
	auditLogPeerDIDKeyPrefix       = "audit:log-peer:"
	auditInteractionKeyPrefix      = "audit:interaction:"
	auditSessionDigestKeyPrefix    = "audit:session:"
	auditDIDSessionsKeyPrefix      = "audit:did-sessions:"
	auditPeerSessionsKeyPrefix     = "audit:peer-sessions:"
	auditSessionChainKeyPrefix     = "audit:session-chain:"
	auditInteractionSessionsPrefix = "audit:interaction-sessions:"
)

type AuditChainLog struct {
	AuditID          string            `json:"audit_id"`
	OperatorDID      string            `json:"operator_did"`
	OperationType    string            `json:"operation_type"`
	TargetObjectID   string            `json:"target_object_id"`
	RequestHash      string            `json:"request_hash"`
	Result           string            `json:"result"`
	ResultCode       int               `json:"result_code"`
	Timestamp        string            `json:"timestamp"`
	TxHash           string            `json:"tx_hash"`
	RelatedTxHash    string            `json:"related_tx_hash,omitempty"`
	ResourcePath     string            `json:"resource_path"`
	Method           string            `json:"method"`
	TraceID          string            `json:"trace_id,omitempty"`
	SessionID        string            `json:"session_id,omitempty"`
	InteractionID    string            `json:"interaction_id,omitempty"`
	SubjectDID       string            `json:"subject_did,omitempty"`
	PeerDID          string            `json:"peer_did,omitempty"`
	SubjectNFType    string            `json:"subject_nf_type,omitempty"`
	PeerNFType       string            `json:"peer_nf_type,omitempty"`
	EvidenceLevel    string            `json:"evidence_level,omitempty"`
	TokenFingerprint string            `json:"token_fingerprint,omitempty"`
	Metadata         map[string]string `json:"metadata,omitempty"`
}

type AuditSessionDigest struct {
	SessionID        string   `json:"session_id"`
	InteractionID    string   `json:"interaction_id,omitempty"`
	SubjectDID       string   `json:"subject_did"`
	PeerDID          string   `json:"peer_did,omitempty"`
	SubjectNFType    string   `json:"subject_nf_type,omitempty"`
	PeerNFType       string   `json:"peer_nf_type,omitempty"`
	DigestHash       string   `json:"digest_hash"`
	PrevDigestHash   string   `json:"prev_digest_hash,omitempty"`
	EventCount       int      `json:"event_count"`
	SummarySeq       int      `json:"summary_seq"`
	Stage            string   `json:"stage,omitempty"`
	SummaryType      string   `json:"summary_type"`
	RelatedTxHashes  []string `json:"related_tx_hashes,omitempty"`
	Timestamp        int64    `json:"timestamp,omitempty"`
	AnchoredAt       string   `json:"anchored_at,omitempty"`
	AnchorTxHash     string   `json:"anchor_tx_hash,omitempty"`
	EvidenceLevel    string   `json:"evidence_level,omitempty"`
	TokenFingerprint string   `json:"token_fingerprint,omitempty"`
}

type AuditDigestVerification struct {
	SessionID          string `json:"session_id,omitempty"`
	SummarySeq         int    `json:"summary_seq,omitempty"`
	Verified           bool   `json:"verified"`
	OnChainDigestHash  string `json:"on_chain_digest_hash,omitempty"`
	AnchorTxHash       string `json:"anchor_tx_hash,omitempty"`
	MismatchReason     string `json:"mismatch_reason,omitempty"`
	ClaimedDigestHash  string `json:"claimed_digest_hash,omitempty"`
	OnChainEventCount  int    `json:"on_chain_event_count,omitempty"`
	OnChainAnchoredAt  string `json:"on_chain_anchored_at,omitempty"`
	OnChainSummaryType string `json:"on_chain_summary_type,omitempty"`
}

func CreateAuditLog(args [][]byte, ds cc.DperServicePipe) ([][]byte, error) {
	if len(args) != 2 {
		return nil, fmt.Errorf("CreateAuditLog requires 2 arguments: auditID, auditJSON")
	}

	auditID := strings.TrimSpace(string(args[0]))
	if auditID == "" {
		return nil, fmt.Errorf("auditID cannot be empty")
	}

	logKey := []byte(auditLogKeyPrefix + auditID)
	if existingData, err := ds.GetStatus(logKey); err == nil && len(existingData) > 0 {
		return nil, fmt.Errorf("audit log already exists")
	}

	var logEntry AuditChainLog
	if err := json.Unmarshal(args[1], &logEntry); err != nil {
		return nil, fmt.Errorf("failed to parse audit JSON: %v", err)
	}

	if logEntry.AuditID == "" {
		logEntry.AuditID = auditID
	}
	if logEntry.AuditID != auditID {
		return nil, fmt.Errorf("audit_id in JSON does not match argument")
	}
	if strings.TrimSpace(logEntry.Timestamp) == "" {
		logEntry.Timestamp = time.Now().UTC().Format(time.RFC3339Nano)
	}
	normalizeAuditChainLog(&logEntry)

	dayKey, err := buildAuditDayKey(logEntry.Timestamp)
	if err != nil {
		return nil, err
	}

	normalizedJSON, err := json.Marshal(logEntry)
	if err != nil {
		return nil, fmt.Errorf("failed to normalize audit JSON: %v", err)
	}

	if err := ds.UpdateStatus(logKey, normalizedJSON); err != nil {
		return nil, fmt.Errorf("failed to store audit log: %v", err)
	}

	if logEntry.OperatorDID != "" {
		if err := appendAuditIndexValue(ds, []byte(auditOperatorKeyPrefix+logEntry.OperatorDID), auditID); err != nil {
			return nil, fmt.Errorf("failed to update operator index: %v", err)
		}
	}

	if logEntry.SubjectDID != "" {
		if err := appendAuditIndexValue(ds, []byte(auditLogSubjectDIDKeyPrefix+logEntry.SubjectDID), auditID); err != nil {
			return nil, fmt.Errorf("failed to update subject DID index: %v", err)
		}
	}

	if logEntry.PeerDID != "" {
		if err := appendAuditIndexValue(ds, []byte(auditLogPeerDIDKeyPrefix+logEntry.PeerDID), auditID); err != nil {
			return nil, fmt.Errorf("failed to update peer DID index: %v", err)
		}
	}

	if logEntry.OperationType != "" {
		if err := appendAuditIndexValue(ds, []byte(auditOperationKeyPrefix+logEntry.OperationType), auditID); err != nil {
			return nil, fmt.Errorf("failed to update operation index: %v", err)
		}
	}

	if logEntry.SessionID != "" {
		if err := appendAuditIndexValue(ds, []byte(auditLogSessionKeyPrefix+logEntry.SessionID), auditID); err != nil {
			return nil, fmt.Errorf("failed to update session index: %v", err)
		}
	}

	if logEntry.InteractionID != "" {
		if err := appendAuditIndexValue(ds, []byte(auditInteractionKeyPrefix+logEntry.InteractionID), auditID); err != nil {
			return nil, fmt.Errorf("failed to update interaction index: %v", err)
		}
	}

	if err := appendAuditIndexValue(ds, []byte(dayKey), auditID); err != nil {
		return nil, fmt.Errorf("failed to update day index: %v", err)
	}

	return [][]byte{[]byte(auditID)}, nil
}

func GetAuditLogByID(args [][]byte, ds cc.DperServicePipe) ([][]byte, error) {
	if len(args) != 1 {
		return nil, fmt.Errorf("GetAuditLogByID requires 1 argument: auditID")
	}

	auditID := strings.TrimSpace(string(args[0]))
	if auditID == "" {
		return nil, fmt.Errorf("auditID cannot be empty")
	}

	data, err := ds.GetStatus([]byte(auditLogKeyPrefix + auditID))
	if err != nil || len(data) == 0 {
		return nil, fmt.Errorf("audit log not found")
	}

	return [][]byte{data}, nil
}

func GetAuditLogsByOperator(args [][]byte, ds cc.DperServicePipe) ([][]byte, error) {
	if len(args) != 1 {
		return nil, fmt.Errorf("GetAuditLogsByOperator requires 1 argument: operatorDID")
	}

	operatorDID := strings.TrimSpace(string(args[0]))
	if operatorDID == "" {
		return nil, fmt.Errorf("operatorDID cannot be empty")
	}

	return getAuditIndexValues(ds, []byte(auditOperatorKeyPrefix+operatorDID))
}

func GetAuditLogsByOperation(args [][]byte, ds cc.DperServicePipe) ([][]byte, error) {
	if len(args) != 1 {
		return nil, fmt.Errorf("GetAuditLogsByOperation requires 1 argument: operationType")
	}

	operationType := strings.ToUpper(strings.TrimSpace(string(args[0])))
	if operationType == "" {
		return nil, fmt.Errorf("operationType cannot be empty")
	}

	return getAuditIndexValues(ds, []byte(auditOperationKeyPrefix+operationType))
}

func GetAuditLogsBySession(args [][]byte, ds cc.DperServicePipe) ([][]byte, error) {
	if len(args) != 1 {
		return nil, fmt.Errorf("GetAuditLogsBySession requires 1 argument: sessionID")
	}

	sessionID := strings.TrimSpace(string(args[0]))
	if sessionID == "" {
		return nil, fmt.Errorf("sessionID cannot be empty")
	}

	return getAuditIndexValues(ds, []byte(auditLogSessionKeyPrefix+sessionID))
}

func GetAuditLogsByInteraction(args [][]byte, ds cc.DperServicePipe) ([][]byte, error) {
	if len(args) != 1 {
		return nil, fmt.Errorf("GetAuditLogsByInteraction requires 1 argument: interactionID")
	}

	interactionID := strings.TrimSpace(string(args[0]))
	if interactionID == "" {
		return nil, fmt.Errorf("interactionID cannot be empty")
	}

	return getAuditIndexValues(ds, []byte(auditInteractionKeyPrefix+interactionID))
}

func GetAuditLogsBySubjectDID(args [][]byte, ds cc.DperServicePipe) ([][]byte, error) {
	if len(args) != 1 {
		return nil, fmt.Errorf("GetAuditLogsBySubjectDID requires 1 argument: subjectDID")
	}

	subjectDID := strings.TrimSpace(string(args[0]))
	if subjectDID == "" {
		return nil, fmt.Errorf("subjectDID cannot be empty")
	}

	return getAuditIndexValues(ds, []byte(auditLogSubjectDIDKeyPrefix+subjectDID))
}

func GetAuditLogsByPeerDID(args [][]byte, ds cc.DperServicePipe) ([][]byte, error) {
	if len(args) != 1 {
		return nil, fmt.Errorf("GetAuditLogsByPeerDID requires 1 argument: peerDID")
	}

	peerDID := strings.TrimSpace(string(args[0]))
	if peerDID == "" {
		return nil, fmt.Errorf("peerDID cannot be empty")
	}

	return getAuditIndexValues(ds, []byte(auditLogPeerDIDKeyPrefix+peerDID))
}

func GetAuditLogsByDay(args [][]byte, ds cc.DperServicePipe) ([][]byte, error) {
	if len(args) != 1 {
		return nil, fmt.Errorf("GetAuditLogsByDay requires 1 argument: day")
	}

	day := strings.TrimSpace(string(args[0]))
	if day == "" {
		return nil, fmt.Errorf("day cannot be empty")
	}
	if _, err := time.Parse("2006-01-02", day); err != nil {
		return nil, fmt.Errorf("invalid day format: %v", err)
	}

	return getAuditIndexValues(ds, []byte(auditDayKeyPrefix+day))
}

func SetAuditLogTxHash(args [][]byte, ds cc.DperServicePipe) ([][]byte, error) {
	if len(args) != 2 {
		return nil, fmt.Errorf("SetAuditLogTxHash requires 2 arguments: auditID, txHash")
	}

	auditID := strings.TrimSpace(string(args[0]))
	txHash := strings.TrimSpace(string(args[1]))
	if auditID == "" {
		return nil, fmt.Errorf("auditID cannot be empty")
	}
	if txHash == "" {
		return nil, fmt.Errorf("txHash cannot be empty")
	}

	logKey := []byte(auditLogKeyPrefix + auditID)
	data, err := ds.GetStatus(logKey)
	if err != nil || len(data) == 0 {
		return nil, fmt.Errorf("audit log not found")
	}

	var logEntry AuditChainLog
	if err := json.Unmarshal(data, &logEntry); err != nil {
		return nil, fmt.Errorf("failed to parse stored audit log: %v", err)
	}

	logEntry.TxHash = txHash
	normalizedJSON, err := json.Marshal(logEntry)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal audit log: %v", err)
	}

	if err := ds.UpdateStatus(logKey, normalizedJSON); err != nil {
		return nil, fmt.Errorf("failed to update audit tx hash: %v", err)
	}

	return [][]byte{[]byte("OK")}, nil
}

func AnchorSessionDigest(args [][]byte, ds cc.DperServicePipe) ([][]byte, error) {
	if len(args) != 2 {
		return nil, fmt.Errorf("AnchorSessionDigest requires 2 arguments: sessionID, digestJSON")
	}

	sessionID := strings.TrimSpace(string(args[0]))
	if sessionID == "" {
		return nil, fmt.Errorf("sessionID cannot be empty")
	}

	var digest AuditSessionDigest
	if err := json.Unmarshal(args[1], &digest); err != nil {
		return nil, fmt.Errorf("failed to parse session digest JSON: %v", err)
	}
	if strings.TrimSpace(digest.SessionID) == "" {
		digest.SessionID = sessionID
	}
	if strings.TrimSpace(digest.SessionID) != sessionID {
		return nil, fmt.Errorf("session_id in JSON does not match argument")
	}
	if digest.SummarySeq <= 0 {
		if latest, err := loadAuditSessionDigest(ds, []byte(auditSessionDigestKeyPrefix+sessionID)); err == nil && latest != nil {
			digest.SummarySeq = latest.SummarySeq + 1
		} else {
			digest.SummarySeq = 1
		}
	}
	if err := normalizeAuditSessionDigest(&digest); err != nil {
		return nil, err
	}

	chainKey := []byte(buildAuditSessionChainKey(digest.SessionID, digest.SummarySeq))
	if existing, err := loadAuditSessionDigest(ds, chainKey); err == nil && existing != nil {
		if existing.DigestHash == digest.DigestHash {
			return [][]byte{[]byte(digest.SessionID)}, nil
		}
		return nil, fmt.Errorf("session digest already exists for sessionID=%s summarySeq=%d", digest.SessionID, digest.SummarySeq)
	}

	normalizedJSON, err := json.Marshal(digest)
	if err != nil {
		return nil, fmt.Errorf("failed to normalize session digest JSON: %v", err)
	}

	if err := ds.UpdateStatus(chainKey, normalizedJSON); err != nil {
		return nil, fmt.Errorf("failed to store session digest chain entry: %v", err)
	}
	latestKey := []byte(auditSessionDigestKeyPrefix + digest.SessionID)
	latest, latestErr := loadAuditSessionDigest(ds, latestKey)
	if latestErr != nil || latest == nil || digest.SummarySeq >= latest.SummarySeq {
		if err := ds.UpdateStatus(latestKey, normalizedJSON); err != nil {
			return nil, fmt.Errorf("failed to store latest session digest: %v", err)
		}
	}

	if digest.SubjectDID != "" {
		if err := appendAuditIndexValue(ds, []byte(auditDIDSessionsKeyPrefix+digest.SubjectDID), digest.SessionID); err != nil {
			return nil, fmt.Errorf("failed to update subject session index: %v", err)
		}
	}
	if digest.PeerDID != "" {
		if err := appendAuditIndexValue(ds, []byte(auditPeerSessionsKeyPrefix+digest.PeerDID), digest.SessionID); err != nil {
			return nil, fmt.Errorf("failed to update peer session index: %v", err)
		}
	}
	if digest.InteractionID != "" {
		if err := appendAuditIndexValue(ds, []byte(auditInteractionSessionsPrefix+digest.InteractionID), digest.SessionID); err != nil {
			return nil, fmt.Errorf("failed to update interaction session index: %v", err)
		}
	}

	return [][]byte{[]byte(digest.SessionID)}, nil
}

func GetSessionDigest(args [][]byte, ds cc.DperServicePipe) ([][]byte, error) {
	if len(args) != 1 && len(args) != 2 {
		return nil, fmt.Errorf("GetSessionDigest requires 1 or 2 arguments: sessionID[, summarySeq]")
	}

	sessionID := strings.TrimSpace(string(args[0]))
	if sessionID == "" {
		return nil, fmt.Errorf("sessionID cannot be empty")
	}

	key := []byte(auditSessionDigestKeyPrefix + sessionID)
	if len(args) == 2 {
		summarySeq, err := parsePositiveIntArg(args[1], "summarySeq")
		if err != nil {
			return nil, err
		}
		key = []byte(buildAuditSessionChainKey(sessionID, summarySeq))
	}

	data, err := ds.GetStatus(key)
	if err != nil || len(data) == 0 {
		return nil, fmt.Errorf("session digest not found")
	}

	return [][]byte{data}, nil
}

func GetSessionDigestsByDID(args [][]byte, ds cc.DperServicePipe) ([][]byte, error) {
	if len(args) != 1 {
		return nil, fmt.Errorf("GetSessionDigestsByDID requires 1 argument: did")
	}

	did := strings.TrimSpace(string(args[0]))
	if did == "" {
		return nil, fmt.Errorf("did cannot be empty")
	}

	subjectSessions, err := loadAuditIndexValues(ds, []byte(auditDIDSessionsKeyPrefix+did))
	if err != nil {
		return nil, err
	}
	peerSessions, err := loadAuditIndexValues(ds, []byte(auditPeerSessionsKeyPrefix+did))
	if err != nil {
		return nil, err
	}

	sessionIDs := mergeAuditIndexValues(subjectSessions, peerSessions)
	digests := make([]AuditSessionDigest, 0, len(sessionIDs))
	for _, sessionID := range sessionIDs {
		digest, err := loadAuditSessionDigest(ds, []byte(auditSessionDigestKeyPrefix+sessionID))
		if err != nil || digest == nil {
			continue
		}
		digests = append(digests, *digest)
	}

	sortAuditSessionDigests(digests)
	encoded, err := json.Marshal(digests)
	if err != nil {
		return nil, err
	}
	return [][]byte{encoded}, nil
}

func GetSessionDigestsByInteraction(args [][]byte, ds cc.DperServicePipe) ([][]byte, error) {
	if len(args) != 1 {
		return nil, fmt.Errorf("GetSessionDigestsByInteraction requires 1 argument: interactionID")
	}

	interactionID := strings.TrimSpace(string(args[0]))
	if interactionID == "" {
		return nil, fmt.Errorf("interactionID cannot be empty")
	}

	sessionIDs, err := loadAuditIndexValues(ds, []byte(auditInteractionSessionsPrefix+interactionID))
	if err != nil {
		return nil, err
	}

	digests := make([]AuditSessionDigest, 0, len(sessionIDs))
	for _, sessionID := range sessionIDs {
		digest, err := loadAuditSessionDigest(ds, []byte(auditSessionDigestKeyPrefix+sessionID))
		if err != nil || digest == nil {
			continue
		}
		digests = append(digests, *digest)
	}

	sortAuditSessionDigests(digests)
	encoded, err := json.Marshal(digests)
	if err != nil {
		return nil, err
	}
	return [][]byte{encoded}, nil
}

func VerifySessionDigest(args [][]byte, ds cc.DperServicePipe) ([][]byte, error) {
	if len(args) != 2 && len(args) != 3 {
		return nil, fmt.Errorf("VerifySessionDigest requires 2 or 3 arguments: sessionID, claimedHash[, summarySeq]")
	}

	sessionID := strings.TrimSpace(string(args[0]))
	if sessionID == "" {
		return nil, fmt.Errorf("sessionID cannot be empty")
	}
	claimedHash, err := normalizeAuditSHA256Hex(string(args[1]), "claimedHash")
	if err != nil {
		return nil, err
	}

	key := []byte(auditSessionDigestKeyPrefix + sessionID)
	if len(args) == 3 {
		summarySeq, err := parsePositiveIntArg(args[2], "summarySeq")
		if err != nil {
			return nil, err
		}
		key = []byte(buildAuditSessionChainKey(sessionID, summarySeq))
	}

	digest, err := loadAuditSessionDigest(ds, key)
	if err != nil || digest == nil {
		return nil, fmt.Errorf("session digest not found")
	}

	result := AuditDigestVerification{
		SessionID:          digest.SessionID,
		SummarySeq:         digest.SummarySeq,
		Verified:           digest.DigestHash == claimedHash,
		OnChainDigestHash:  digest.DigestHash,
		AnchorTxHash:       digest.AnchorTxHash,
		ClaimedDigestHash:  claimedHash,
		OnChainEventCount:  digest.EventCount,
		OnChainAnchoredAt:  digest.AnchoredAt,
		OnChainSummaryType: digest.SummaryType,
	}
	if !result.Verified {
		result.MismatchReason = "digest_hash_mismatch"
	}

	encoded, err := json.Marshal(result)
	if err != nil {
		return nil, err
	}
	return [][]byte{encoded}, nil
}

func SetSessionDigestTxHash(args [][]byte, ds cc.DperServicePipe) ([][]byte, error) {
	if len(args) != 3 {
		return nil, fmt.Errorf("SetSessionDigestTxHash requires 3 arguments: sessionID, summarySeq, txHash")
	}

	sessionID := strings.TrimSpace(string(args[0]))
	if sessionID == "" {
		return nil, fmt.Errorf("sessionID cannot be empty")
	}
	summarySeq, err := parsePositiveIntArg(args[1], "summarySeq")
	if err != nil {
		return nil, err
	}
	txHash := strings.TrimSpace(string(args[2]))
	if txHash == "" {
		return nil, fmt.Errorf("txHash cannot be empty")
	}

	chainKey := []byte(buildAuditSessionChainKey(sessionID, summarySeq))
	digest, err := loadAuditSessionDigest(ds, chainKey)
	if err != nil || digest == nil {
		return nil, fmt.Errorf("session digest not found")
	}
	digest.AnchorTxHash = txHash
	encoded, err := json.Marshal(digest)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal session digest: %v", err)
	}
	if err := ds.UpdateStatus(chainKey, encoded); err != nil {
		return nil, fmt.Errorf("failed to update session digest chain tx hash: %v", err)
	}

	latest, err := loadAuditSessionDigest(ds, []byte(auditSessionDigestKeyPrefix+sessionID))
	if err == nil && latest != nil && latest.SummarySeq == summarySeq {
		latest.AnchorTxHash = txHash
		latestEncoded, err := json.Marshal(latest)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal latest session digest: %v", err)
		}
		if err := ds.UpdateStatus([]byte(auditSessionDigestKeyPrefix+sessionID), latestEncoded); err != nil {
			return nil, fmt.Errorf("failed to update latest session digest tx hash: %v", err)
		}
	}

	return [][]byte{[]byte("OK")}, nil
}

func appendAuditIndexValue(ds cc.DperServicePipe, key []byte, auditID string) error {
	values, err := loadAuditIndexValues(ds, key)
	if err != nil {
		return err
	}

	for _, existing := range values {
		if existing == auditID {
			return nil
		}
	}

	values = append(values, auditID)
	sort.Strings(values)

	encoded, err := json.Marshal(values)
	if err != nil {
		return err
	}

	return ds.UpdateStatus(key, encoded)
}

func getAuditIndexValues(ds cc.DperServicePipe, key []byte) ([][]byte, error) {
	values, err := loadAuditIndexValues(ds, key)
	if err != nil {
		return nil, err
	}

	encoded, err := json.Marshal(values)
	if err != nil {
		return nil, err
	}

	return [][]byte{encoded}, nil
}

func loadAuditIndexValues(ds cc.DperServicePipe, key []byte) ([]string, error) {
	indexData, err := ds.GetStatus(key)
	if err != nil || len(indexData) == 0 {
		return []string{}, nil
	}

	var values []string
	if err := json.Unmarshal(indexData, &values); err != nil {
		return nil, err
	}

	return values, nil
}

func normalizeAuditChainLog(logEntry *AuditChainLog) {
	if logEntry == nil {
		return
	}
	logEntry.OperatorDID = strings.TrimSpace(logEntry.OperatorDID)
	logEntry.SubjectDID = strings.TrimSpace(logEntry.SubjectDID)
	logEntry.PeerDID = strings.TrimSpace(logEntry.PeerDID)
	logEntry.SessionID = strings.TrimSpace(logEntry.SessionID)
	logEntry.InteractionID = strings.TrimSpace(logEntry.InteractionID)
	logEntry.SubjectNFType = strings.ToUpper(strings.TrimSpace(logEntry.SubjectNFType))
	logEntry.PeerNFType = strings.ToUpper(strings.TrimSpace(logEntry.PeerNFType))
	logEntry.OperationType = strings.ToUpper(strings.TrimSpace(logEntry.OperationType))
	logEntry.TargetObjectID = strings.TrimSpace(logEntry.TargetObjectID)
	logEntry.RelatedTxHash = strings.TrimSpace(logEntry.RelatedTxHash)
	logEntry.TokenFingerprint = strings.TrimSpace(logEntry.TokenFingerprint)
	logEntry.EvidenceLevel = strings.ToLower(strings.TrimSpace(logEntry.EvidenceLevel))
	if logEntry.EvidenceLevel == "" {
		logEntry.EvidenceLevel = "index"
	}
	if logEntry.SubjectDID == "" {
		logEntry.SubjectDID = logEntry.OperatorDID
	}
	if logEntry.OperatorDID == "" {
		logEntry.OperatorDID = logEntry.SubjectDID
	}
}

func normalizeAuditSessionDigest(digest *AuditSessionDigest) error {
	if digest == nil {
		return fmt.Errorf("session digest is nil")
	}

	digest.SessionID = strings.TrimSpace(digest.SessionID)
	digest.InteractionID = strings.TrimSpace(digest.InteractionID)
	digest.SubjectDID = strings.TrimSpace(digest.SubjectDID)
	digest.PeerDID = strings.TrimSpace(digest.PeerDID)
	digest.SubjectNFType = strings.ToUpper(strings.TrimSpace(digest.SubjectNFType))
	digest.PeerNFType = strings.ToUpper(strings.TrimSpace(digest.PeerNFType))
	digest.Stage = strings.TrimSpace(digest.Stage)
	digest.SummaryType = strings.ToLower(strings.TrimSpace(digest.SummaryType))
	digest.AnchoredAt = strings.TrimSpace(digest.AnchoredAt)
	digest.AnchorTxHash = strings.TrimSpace(digest.AnchorTxHash)
	digest.EvidenceLevel = strings.ToLower(strings.TrimSpace(digest.EvidenceLevel))
	digest.TokenFingerprint = strings.TrimSpace(digest.TokenFingerprint)

	if digest.SessionID == "" {
		return fmt.Errorf("session_id is required")
	}
	if digest.SubjectDID == "" {
		return fmt.Errorf("subject_did is required")
	}
	if digest.EventCount < 0 {
		return fmt.Errorf("event_count cannot be negative")
	}
	if digest.SummarySeq <= 0 {
		digest.SummarySeq = 1
	}
	if digest.SummaryType == "" {
		digest.SummaryType = "checkpoint"
	}
	if digest.SummaryType != "checkpoint" && digest.SummaryType != "final" {
		return fmt.Errorf("summary_type must be checkpoint or final")
	}
	if digest.EvidenceLevel == "" {
		digest.EvidenceLevel = "tier1"
	}
	if digest.AnchoredAt == "" {
		digest.AnchoredAt = time.Now().UTC().Format(time.RFC3339Nano)
	}

	normalizedDigest, err := normalizeAuditSHA256Hex(digest.DigestHash, "digest_hash")
	if err != nil {
		return err
	}
	digest.DigestHash = normalizedDigest

	if strings.TrimSpace(digest.PrevDigestHash) != "" {
		normalizedPrev, err := normalizeAuditSHA256Hex(digest.PrevDigestHash, "prev_digest_hash")
		if err != nil {
			return err
		}
		digest.PrevDigestHash = normalizedPrev
	}

	digest.RelatedTxHashes = normalizeAuditStringList(digest.RelatedTxHashes)
	return nil
}

func buildAuditSessionChainKey(sessionID string, summarySeq int) string {
	return fmt.Sprintf("%s%s:%d", auditSessionChainKeyPrefix, sessionID, summarySeq)
}

func loadAuditSessionDigest(ds cc.DperServicePipe, key []byte) (*AuditSessionDigest, error) {
	data, err := ds.GetStatus(key)
	if err != nil || len(data) == 0 {
		return nil, err
	}

	var digest AuditSessionDigest
	if err := json.Unmarshal(data, &digest); err != nil {
		return nil, err
	}
	return &digest, nil
}

func parsePositiveIntArg(raw []byte, field string) (int, error) {
	value, err := strconv.Atoi(strings.TrimSpace(string(raw)))
	if err != nil || value <= 0 {
		return 0, fmt.Errorf("%s must be a positive integer", field)
	}
	return value, nil
}

func normalizeAuditSHA256Hex(raw, field string) (string, error) {
	normalized := strings.ToLower(strings.TrimSpace(raw))
	normalized = strings.TrimPrefix(normalized, "sha256:")
	normalized = strings.TrimPrefix(normalized, "sha256-")
	if normalized == "" {
		return "", fmt.Errorf("%s is required", field)
	}
	if len(normalized) != sha256.Size*2 {
		return "", fmt.Errorf("%s must be a SHA-256 hex string", field)
	}
	if _, err := hex.DecodeString(normalized); err != nil {
		return "", fmt.Errorf("%s must be valid hex: %v", field, err)
	}
	return normalized, nil
}

func normalizeAuditStringList(values []string) []string {
	if len(values) == 0 {
		return nil
	}

	seen := make(map[string]struct{}, len(values))
	normalized := make([]string, 0, len(values))
	for _, value := range values {
		trimmed := strings.TrimSpace(value)
		if trimmed == "" {
			continue
		}
		if _, ok := seen[trimmed]; ok {
			continue
		}
		seen[trimmed] = struct{}{}
		normalized = append(normalized, trimmed)
	}
	return normalized
}

func mergeAuditIndexValues(left, right []string) []string {
	seen := make(map[string]struct{}, len(left)+len(right))
	for _, value := range append(left, right...) {
		trimmed := strings.TrimSpace(value)
		if trimmed == "" {
			continue
		}
		seen[trimmed] = struct{}{}
	}

	values := make([]string, 0, len(seen))
	for value := range seen {
		values = append(values, value)
	}
	sort.Strings(values)
	return values
}

func sortAuditSessionDigests(digests []AuditSessionDigest) {
	sort.Slice(digests, func(i, j int) bool {
		leftTime, leftErr := parseAuditTimestamp(digests[i].AnchoredAt)
		rightTime, rightErr := parseAuditTimestamp(digests[j].AnchoredAt)
		switch {
		case leftErr == nil && rightErr == nil && !leftTime.Equal(rightTime):
			return leftTime.After(rightTime)
		case leftErr == nil && rightErr != nil:
			return true
		case leftErr != nil && rightErr == nil:
			return false
		default:
			return digests[i].SessionID > digests[j].SessionID
		}
	})
}

func buildAuditDayKey(timestamp string) (string, error) {
	parsedTime, err := parseAuditTimestamp(timestamp)
	if err != nil {
		return "", fmt.Errorf("invalid audit timestamp: %v", err)
	}

	return auditDayKeyPrefix + parsedTime.UTC().Format("2006-01-02"), nil
}

func parseAuditTimestamp(raw string) (time.Time, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return time.Time{}, fmt.Errorf("timestamp is empty")
	}

	for _, layout := range []string{time.RFC3339Nano, time.RFC3339} {
		if parsed, err := time.Parse(layout, raw); err == nil {
			return parsed.UTC(), nil
		}
	}

	return time.Time{}, fmt.Errorf("unsupported timestamp format: %s", raw)
}
