package api

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	loglogrus "p3Chain/log_logrus"
)

type SessionDigest struct {
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

type SessionDigestAnchorResult struct {
	AnchorTxHash string        `json:"anchor_tx_hash"`
	AnchoredAt   string        `json:"anchored_at"`
	Digest       SessionDigest `json:"digest,omitempty"`
}

type SessionDigestVerification struct {
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

type AuditCanonicalEvent struct {
	EventSeq      int    `json:"event_seq"`
	CanonicalJSON string `json:"canonical_json"`
}

type VerifyEventsRequest struct {
	SessionID                    string                `json:"session_id"`
	SummarySeq                   int                   `json:"summary_seq,omitempty"`
	Events                       []AuditCanonicalEvent `json:"events"`
	InitialHash                  string                `json:"initial_hash,omitempty"`
	SummaryMetadataCanonicalJSON string                `json:"summary_metadata_canonical_json,omitempty"`
}

type VerifyEventsResult struct {
	SessionID         string `json:"session_id,omitempty"`
	SummarySeq        int    `json:"summary_seq,omitempty"`
	RecomputedDigest  string `json:"recomputed_digest"`
	OnChainDigest     string `json:"on_chain_digest"`
	Verified          bool   `json:"verified"`
	EventCountMatch   bool   `json:"event_count_match"`
	EventCount        int    `json:"event_count"`
	OnChainEventCount int    `json:"on_chain_event_count"`
}

func (as *AuditService) AnchorSessionDigest(digest SessionDigest) (*SessionDigestAnchorResult, error) {
	if as == nil || as.ds == nil {
		return nil, errors.New("audit service is not initialized with dper service")
	}
	if err := normalizeSessionDigest(&digest); err != nil {
		return nil, err
	}

	payload, err := json.Marshal(digest)
	if err != nil {
		return nil, fmt.Errorf("marshal session digest failed: %w", err)
	}

	invokeCmd := fmt.Sprintf("invoke DID::SPECTRUM::TRADE AnchorSessionDigest -args %s %s",
		QuoteCommandArg(digest.SessionID),
		QuoteCommandArg(string(payload)),
	)
	receipt, err := as.ds.SoftInvoke(invokeCmd)
	if err != nil {
		return nil, err
	}

	txHash := fmt.Sprintf("%x", receipt.TransactionID)
	digest.AnchorTxHash = txHash
	if err := as.patchSessionDigestTxHash(digest.SessionID, digest.SummarySeq, txHash); err != nil {
		loglogrus.Log.Warnf("[Audit] patch session digest tx hash failed, sessionID=%s summarySeq=%d txHash=%s err=%v\n",
			digest.SessionID, digest.SummarySeq, txHash, err)
	}

	return &SessionDigestAnchorResult{
		AnchorTxHash: txHash,
		AnchoredAt:   digest.AnchoredAt,
		Digest:       digest,
	}, nil
}

func (as *AuditService) GetSessionDigest(sessionID string, summarySeq int) (*SessionDigest, error) {
	if as == nil || as.ds == nil {
		return nil, errors.New("audit service is not initialized with dper service")
	}

	sessionID = strings.TrimSpace(sessionID)
	if sessionID == "" {
		return nil, errors.New("session_id is required")
	}

	args := QuoteCommandArg(sessionID)
	if summarySeq > 0 {
		args += " " + QuoteCommandArg(fmt.Sprintf("%d", summarySeq))
	}
	callCmd := fmt.Sprintf("call DID::SPECTRUM::TRADE GetSessionDigest -args %s", args)
	data, err := as.ds.SoftCall(callCmd)
	if err != nil {
		return nil, err
	}
	if len(data) == 0 || strings.TrimSpace(data[0]) == "" {
		return nil, errors.New("session digest not found")
	}

	var digest SessionDigest
	if err := json.Unmarshal([]byte(data[0]), &digest); err != nil {
		return nil, fmt.Errorf("failed to parse session digest: %w", err)
	}

	return &digest, nil
}

func (as *AuditService) GetSessionDigestsByDID(did string) ([]SessionDigest, error) {
	if as == nil || as.ds == nil {
		return nil, errors.New("audit service is not initialized with dper service")
	}

	did = strings.TrimSpace(did)
	if did == "" {
		return nil, errors.New("did is required")
	}

	callCmd := fmt.Sprintf("call DID::SPECTRUM::TRADE GetSessionDigestsByDID -args %s", QuoteCommandArg(did))
	data, err := as.ds.SoftCall(callCmd)
	if err != nil {
		return nil, err
	}
	if len(data) == 0 || strings.TrimSpace(data[0]) == "" {
		return []SessionDigest{}, nil
	}

	var digests []SessionDigest
	if err := json.Unmarshal([]byte(data[0]), &digests); err != nil {
		return nil, fmt.Errorf("failed to parse session digest index: %w", err)
	}

	return digests, nil
}

func (as *AuditService) GetSessionDigestsByInteraction(interactionID string) ([]SessionDigest, error) {
	if as == nil || as.ds == nil {
		return nil, errors.New("audit service is not initialized with dper service")
	}

	interactionID = strings.TrimSpace(interactionID)
	if interactionID == "" {
		return nil, errors.New("interaction_id is required")
	}

	callCmd := fmt.Sprintf("call DID::SPECTRUM::TRADE GetSessionDigestsByInteraction -args %s", QuoteCommandArg(interactionID))
	data, err := as.ds.SoftCall(callCmd)
	if err != nil {
		return nil, err
	}
	if len(data) == 0 || strings.TrimSpace(data[0]) == "" {
		return []SessionDigest{}, nil
	}

	var digests []SessionDigest
	if err := json.Unmarshal([]byte(data[0]), &digests); err != nil {
		return nil, fmt.Errorf("failed to parse interaction session digest index: %w", err)
	}

	return digests, nil
}

func (as *AuditService) VerifySessionDigest(sessionID, claimedHash string, summarySeq int) (*SessionDigestVerification, error) {
	if as == nil || as.ds == nil {
		return nil, errors.New("audit service is not initialized with dper service")
	}

	sessionID = strings.TrimSpace(sessionID)
	claimedHash, err := normalizeSHA256Hex(claimedHash, "claimed_digest_hash")
	if err != nil {
		return nil, err
	}
	if sessionID == "" {
		return nil, errors.New("session_id is required")
	}

	args := QuoteCommandArg(sessionID) + " " + QuoteCommandArg(claimedHash)
	if summarySeq > 0 {
		args += " " + QuoteCommandArg(fmt.Sprintf("%d", summarySeq))
	}
	callCmd := fmt.Sprintf("call DID::SPECTRUM::TRADE VerifySessionDigest -args %s", args)
	data, err := as.ds.SoftCall(callCmd)
	if err != nil {
		return nil, err
	}
	if len(data) == 0 || strings.TrimSpace(data[0]) == "" {
		return nil, errors.New("session digest verification returned empty response")
	}

	var result SessionDigestVerification
	if err := json.Unmarshal([]byte(data[0]), &result); err != nil {
		return nil, fmt.Errorf("failed to parse session digest verification: %w", err)
	}

	return &result, nil
}

func (as *AuditService) VerifySessionEvents(req VerifyEventsRequest) (*VerifyEventsResult, error) {
	req.SessionID = strings.TrimSpace(req.SessionID)
	if req.SessionID == "" {
		return nil, errors.New("session_id is required")
	}

	onChainDigest, err := as.GetSessionDigest(req.SessionID, req.SummarySeq)
	if err != nil {
		return nil, err
	}

	recomputed, err := RecomputeRollingDigest(req.InitialHash, req.Events, req.SummaryMetadataCanonicalJSON)
	if err != nil {
		return nil, err
	}

	onChainHash := strings.ToLower(strings.TrimSpace(onChainDigest.DigestHash))
	eventCountMatch := len(req.Events) == onChainDigest.EventCount
	return &VerifyEventsResult{
		SessionID:         onChainDigest.SessionID,
		SummarySeq:        onChainDigest.SummarySeq,
		RecomputedDigest:  recomputed,
		OnChainDigest:     onChainHash,
		Verified:          eventCountMatch && recomputed == onChainHash,
		EventCountMatch:   eventCountMatch,
		EventCount:        len(req.Events),
		OnChainEventCount: onChainDigest.EventCount,
	}, nil
}

func RecomputeRollingDigest(initialHash string, events []AuditCanonicalEvent, summaryMetadataCanonicalJSON string) (string, error) {
	rolling, err := normalizeInitialHash(initialHash)
	if err != nil {
		return "", err
	}

	ordered := make([]AuditCanonicalEvent, len(events))
	copy(ordered, events)
	sort.SliceStable(ordered, func(i, j int) bool {
		return ordered[i].EventSeq < ordered[j].EventSeq
	})

	for _, event := range ordered {
		canonicalJSON := strings.TrimSpace(event.CanonicalJSON)
		if canonicalJSON == "" {
			return "", fmt.Errorf("canonical_json is required for event_seq=%d", event.EventSeq)
		}
		sum := sha256.Sum256([]byte(rolling + canonicalJSON))
		rolling = hex.EncodeToString(sum[:])
	}

	summaryMetadataCanonicalJSON = strings.TrimSpace(summaryMetadataCanonicalJSON)
	if summaryMetadataCanonicalJSON == "" {
		return rolling, nil
	}

	sum := sha256.Sum256([]byte(rolling + summaryMetadataCanonicalJSON))
	return hex.EncodeToString(sum[:]), nil
}

func (as *AuditService) patchSessionDigestTxHash(sessionID string, summarySeq int, txHash string) error {
	sessionID = strings.TrimSpace(sessionID)
	txHash = strings.TrimSpace(txHash)
	if sessionID == "" || txHash == "" {
		return nil
	}

	invokeCmd := fmt.Sprintf("invoke DID::SPECTRUM::TRADE SetSessionDigestTxHash -args %s %s %s",
		QuoteCommandArg(sessionID),
		QuoteCommandArg(fmt.Sprintf("%d", summarySeq)),
		QuoteCommandArg(txHash),
	)

	var lastErr error
	for attempt := 1; attempt <= 10; attempt++ {
		digest, err := as.GetSessionDigest(sessionID, summarySeq)
		if err == nil && strings.TrimSpace(digest.AnchorTxHash) == txHash {
			return nil
		}
		if err == nil {
			if _, err := as.ds.SoftInvoke(invokeCmd); err != nil {
				lastErr = err
			}
		} else {
			lastErr = err
		}
		time.Sleep(time.Duration(attempt) * 200 * time.Millisecond)
	}

	if digest, err := as.GetSessionDigest(sessionID, summarySeq); err == nil && strings.TrimSpace(digest.AnchorTxHash) == txHash {
		return nil
	}

	return lastErr
}

func normalizeSessionDigest(digest *SessionDigest) error {
	if digest == nil {
		return errors.New("session digest is nil")
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
		return errors.New("session_id is required")
	}
	if digest.SubjectDID == "" {
		return errors.New("subject_did is required")
	}
	if digest.EventCount < 0 {
		return errors.New("event_count cannot be negative")
	}
	if digest.SummarySeq <= 0 {
		digest.SummarySeq = 1
	}
	if digest.SummaryType == "" {
		digest.SummaryType = "checkpoint"
	}
	if digest.SummaryType != "checkpoint" && digest.SummaryType != "final" {
		return errors.New("summary_type must be checkpoint or final")
	}
	if digest.EvidenceLevel == "" {
		digest.EvidenceLevel = "tier1"
	}
	if digest.AnchoredAt == "" {
		digest.AnchoredAt = time.Now().UTC().Format(time.RFC3339Nano)
	}

	normalizedDigest, err := normalizeSHA256Hex(digest.DigestHash, "digest_hash")
	if err != nil {
		return err
	}
	digest.DigestHash = normalizedDigest

	if strings.TrimSpace(digest.PrevDigestHash) != "" {
		normalizedPrev, err := normalizeSHA256Hex(digest.PrevDigestHash, "prev_digest_hash")
		if err != nil {
			return err
		}
		digest.PrevDigestHash = normalizedPrev
	}

	digest.RelatedTxHashes = normalizeStringList(digest.RelatedTxHashes)
	return nil
}

func normalizeStringList(values []string) []string {
	if len(values) == 0 {
		return nil
	}

	deduped := make([]string, 0, len(values))
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		trimmed := strings.TrimSpace(value)
		if trimmed == "" {
			continue
		}
		if _, ok := seen[trimmed]; ok {
			continue
		}
		seen[trimmed] = struct{}{}
		deduped = append(deduped, trimmed)
	}
	return deduped
}

func normalizeInitialHash(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		sum := sha256.Sum256(nil)
		return hex.EncodeToString(sum[:]), nil
	}
	return normalizeSHA256Hex(raw, "initial_hash")
}

func normalizeSHA256Hex(raw, field string) (string, error) {
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
		return "", fmt.Errorf("%s must be valid hex: %w", field, err)
	}
	return normalized, nil
}
