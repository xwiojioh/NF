package api

import (
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	loglogrus "p3Chain/log_logrus"
)

type AuditLog struct {
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

type AuditEvent struct {
	AuditID          string
	OperatorDID      string
	OperationType    string
	TargetObjectID   string
	RequestHash      string
	Result           string
	ResultCode       int
	ResourcePath     string
	Method           string
	TraceID          string
	Timestamp        time.Time
	RelatedTxHash    string
	SessionID        string
	InteractionID    string
	SubjectDID       string
	PeerDID          string
	SubjectNFType    string
	PeerNFType       string
	EvidenceLevel    string
	TokenFingerprint string
	Metadata         map[string]string
}

type AuditQuery struct {
	AuditID        string
	OperatorDID    string
	SubjectDID     string
	PeerDID        string
	OperationType  string
	TargetObjectID string
	SessionID      string
	InteractionID  string
	EvidenceLevel  string
	StartTime      string
	EndTime        string
	Page           int
	PageSize       int
}

type AuditService struct {
	ds          *DperService
	queue       chan *AuditEvent
	workerCount int
	retryLimit  int
	closeCh     chan struct{}
	startOnce   sync.Once
	closeOnce   sync.Once
}

func NewAuditService(ds *DperService, queueSize, workerCount, retryLimit int) *AuditService {
	if queueSize <= 0 {
		queueSize = 1024
	}
	if workerCount <= 0 {
		workerCount = 1
	}
	if retryLimit < 0 {
		retryLimit = 0
	}

	return &AuditService{
		ds:          ds,
		queue:       make(chan *AuditEvent, queueSize),
		workerCount: workerCount,
		retryLimit:  retryLimit,
		closeCh:     make(chan struct{}),
	}
}

func (as *AuditService) Start() {
	if as == nil {
		return
	}

	as.startOnce.Do(func() {
		for i := 0; i < as.workerCount; i++ {
			go as.worker(i + 1)
		}
		loglogrus.Log.Infof("[Audit] AuditService started, queueSize=%d workerCount=%d retryLimit=%d\n", cap(as.queue), as.workerCount, as.retryLimit)
	})
}

func (as *AuditService) Close() {
	if as == nil {
		return
	}

	as.closeOnce.Do(func() {
		close(as.closeCh)
	})
}

func (as *AuditService) Enqueue(event *AuditEvent) error {
	if as == nil {
		return errors.New("audit service is nil")
	}
	if event == nil {
		return errors.New("audit event is nil")
	}

	select {
	case <-as.closeCh:
		return errors.New("audit service is closed")
	case as.queue <- event:
		return nil
	default:
		return fmt.Errorf("audit queue full")
	}
}

func (as *AuditService) WriteAuditLog(logEntry AuditLog) (string, error) {
	if as == nil || as.ds == nil {
		return "", errors.New("audit service is not initialized with dper service")
	}
	if logEntry.AuditID == "" {
		return "", errors.New("audit_id is required")
	}

	normalizeAuditLogDefaults(&logEntry)
	payload, err := json.Marshal(logEntry)
	if err != nil {
		return "", fmt.Errorf("marshal audit log failed: %w", err)
	}

	invokeCmd := fmt.Sprintf("invoke DID::SPECTRUM::TRADE CreateAuditLog -args %s %s",
		QuoteCommandArg(logEntry.AuditID),
		QuoteCommandArg(string(payload)),
	)
	receipt, err := as.ds.SoftInvoke(invokeCmd)
	if err != nil {
		return "", err
	}

	txHash := fmt.Sprintf("%x", receipt.TransactionID)
	if err := as.patchAuditLogTxHash(logEntry.AuditID, txHash); err != nil {
		loglogrus.Log.Warnf("[Audit] patch tx hash failed, auditID=%s txHash=%s err=%v\n", logEntry.AuditID, txHash, err)
	}

	return txHash, nil
}

func (as *AuditService) QueryAuditLogs(query AuditQuery) ([]AuditLog, int, error) {
	if as == nil || as.ds == nil {
		return nil, 0, errors.New("audit service is not initialized with dper service")
	}

	normalizedQuery, startAt, endAt, err := normalizeAuditQuery(query)
	if err != nil {
		return nil, 0, err
	}

	if normalizedQuery.AuditID != "" {
		logEntry, err := as.GetAuditLogByID(normalizedQuery.AuditID)
		if err != nil {
			return nil, 0, err
		}
		if !auditLogMatchesQuery(*logEntry, normalizedQuery, startAt, endAt) {
			return []AuditLog{}, 0, nil
		}
		return paginateAuditLogs([]AuditLog{*logEntry}, normalizedQuery.Page, normalizedQuery.PageSize)
	}

	var (
		candidateIDs map[string]struct{}
		hasIndexHint bool
	)

	if normalizedQuery.OperatorDID != "" {
		ids, err := as.fetchAuditIDsByIndex("GetAuditLogsByOperator", normalizedQuery.OperatorDID)
		if err != nil {
			return nil, 0, err
		}
		candidateIDs = intersectAuditIDSets(candidateIDs, ids)
		hasIndexHint = true
	}

	if normalizedQuery.SubjectDID != "" {
		ids, err := as.fetchAuditIDsByIndex("GetAuditLogsBySubjectDID", normalizedQuery.SubjectDID)
		if err != nil {
			return nil, 0, err
		}
		candidateIDs = intersectAuditIDSets(candidateIDs, ids)
		hasIndexHint = true
	}

	if normalizedQuery.PeerDID != "" {
		ids, err := as.fetchAuditIDsByIndex("GetAuditLogsByPeerDID", normalizedQuery.PeerDID)
		if err != nil {
			return nil, 0, err
		}
		candidateIDs = intersectAuditIDSets(candidateIDs, ids)
		hasIndexHint = true
	}

	if normalizedQuery.OperationType != "" {
		ids, err := as.fetchAuditIDsByIndex("GetAuditLogsByOperation", normalizedQuery.OperationType)
		if err != nil {
			return nil, 0, err
		}
		candidateIDs = intersectAuditIDSets(candidateIDs, ids)
		hasIndexHint = true
	}

	if normalizedQuery.SessionID != "" {
		ids, err := as.fetchAuditIDsByIndex("GetAuditLogsBySession", normalizedQuery.SessionID)
		if err != nil {
			return nil, 0, err
		}
		candidateIDs = intersectAuditIDSets(candidateIDs, ids)
		hasIndexHint = true
	}

	if normalizedQuery.InteractionID != "" {
		ids, err := as.fetchAuditIDsByIndex("GetAuditLogsByInteraction", normalizedQuery.InteractionID)
		if err != nil {
			return nil, 0, err
		}
		candidateIDs = intersectAuditIDSets(candidateIDs, ids)
		hasIndexHint = true
	}

	if startAt != nil || endAt != nil {
		ids, err := as.fetchAuditIDsByTimeRange(startAt, endAt)
		if err != nil {
			return nil, 0, err
		}
		candidateIDs = intersectAuditIDSets(candidateIDs, ids)
		hasIndexHint = true
	}

	if !hasIndexHint {
		return nil, 0, errors.New("audit query requires at least one indexed filter: auditId, operatorDid, subjectDid, peerDid, operationType, sessionId, interactionId, startTime or endTime")
	}

	idList := auditIDsFromSet(candidateIDs)
	logs := make([]AuditLog, 0, len(idList))
	for _, auditID := range idList {
		logEntry, err := as.GetAuditLogByID(auditID)
		if err != nil {
			loglogrus.Log.Warnf("[Audit] skip auditID=%s while querying logs: %v\n", auditID, err)
			continue
		}
		if !auditLogMatchesQuery(*logEntry, normalizedQuery, startAt, endAt) {
			continue
		}
		logs = append(logs, *logEntry)
	}

	sort.Slice(logs, func(i, j int) bool {
		return auditLogLess(logs[i], logs[j])
	})

	return paginateAuditLogs(logs, normalizedQuery.Page, normalizedQuery.PageSize)
}

func (as *AuditService) GetAuditLogByID(auditID string) (*AuditLog, error) {
	if as == nil || as.ds == nil {
		return nil, errors.New("audit service is not initialized with dper service")
	}

	auditID = strings.TrimSpace(auditID)
	if auditID == "" {
		return nil, errors.New("auditID cannot be empty")
	}

	callCmd := fmt.Sprintf("call DID::SPECTRUM::TRADE GetAuditLogByID -args %s", quoteAuditCommandArg(auditID))
	data, err := as.ds.SoftCall(callCmd)
	if err != nil {
		return nil, err
	}
	if len(data) == 0 || strings.TrimSpace(data[0]) == "" {
		return nil, errors.New("audit log not found")
	}

	var logEntry AuditLog
	if err := json.Unmarshal([]byte(data[0]), &logEntry); err != nil {
		return nil, fmt.Errorf("failed to parse audit log: %w", err)
	}

	return &logEntry, nil
}

func (as *AuditService) worker(workerID int) {
	for {
		select {
		case <-as.closeCh:
			loglogrus.Log.Infof("[Audit] worker-%d stopped\n", workerID)
			return
		case event := <-as.queue:
			if event == nil {
				continue
			}
			as.handleEvent(workerID, event)
		}
	}
}

func (as *AuditService) handleEvent(workerID int, event *AuditEvent) {
	logEntry := AuditLog{
		AuditID:          event.AuditID,
		OperatorDID:      event.OperatorDID,
		OperationType:    event.OperationType,
		TargetObjectID:   event.TargetObjectID,
		RequestHash:      event.RequestHash,
		Result:           event.Result,
		ResultCode:       event.ResultCode,
		Timestamp:        event.Timestamp.UTC().Format(time.RFC3339Nano),
		RelatedTxHash:    event.RelatedTxHash,
		ResourcePath:     event.ResourcePath,
		Method:           event.Method,
		TraceID:          event.TraceID,
		SessionID:        event.SessionID,
		InteractionID:    event.InteractionID,
		SubjectDID:       event.SubjectDID,
		PeerDID:          event.PeerDID,
		SubjectNFType:    event.SubjectNFType,
		PeerNFType:       event.PeerNFType,
		EvidenceLevel:    event.EvidenceLevel,
		TokenFingerprint: event.TokenFingerprint,
		Metadata:         cloneAuditMetadata(event.Metadata),
	}
	normalizeAuditLogDefaults(&logEntry)

	maxAttempts := as.retryLimit + 1
	for attempt := 1; attempt <= maxAttempts; attempt++ {
		txHash, err := as.WriteAuditLog(logEntry)
		if err == nil {
			loglogrus.Log.Infof("[Audit] worker-%d wrote audit log successfully, auditID=%s txHash=%s attempt=%d\n",
				workerID, logEntry.AuditID, txHash, attempt)
			return
		}

		loglogrus.Log.Warnf("[Audit] worker-%d write audit log failed, auditID=%s attempt=%d/%d err=%v\n",
			workerID, logEntry.AuditID, attempt, maxAttempts, err)

		if attempt < maxAttempts {
			time.Sleep(time.Duration(attempt) * 200 * time.Millisecond)
		}
	}

	loglogrus.Log.Warnf("[Audit] worker-%d exhausted retries, auditID=%s operatorDID=%s operationType=%s traceID=%s\n",
		workerID, logEntry.AuditID, logEntry.OperatorDID, logEntry.OperationType, logEntry.TraceID)
}

func cloneAuditMetadata(metadata map[string]string) map[string]string {
	if len(metadata) == 0 {
		return nil
	}

	cloned := make(map[string]string, len(metadata))
	for k, v := range metadata {
		cloned[k] = v
	}

	return cloned
}

func (as *AuditService) patchAuditLogTxHash(auditID, txHash string) error {
	if as == nil || as.ds == nil {
		return errors.New("audit service is not initialized with dper service")
	}
	auditID = strings.TrimSpace(auditID)
	txHash = strings.TrimSpace(txHash)
	if auditID == "" || txHash == "" {
		return nil
	}

	invokeCmd := fmt.Sprintf("invoke DID::SPECTRUM::TRADE SetAuditLogTxHash -args %s %s",
		QuoteCommandArg(auditID),
		QuoteCommandArg(txHash),
	)

	var lastErr error
	for attempt := 1; attempt <= 10; attempt++ {
		logEntry, err := as.GetAuditLogByID(auditID)
		if err == nil && strings.TrimSpace(logEntry.TxHash) == txHash {
			return nil
		}
		if err != nil {
			lastErr = err
			time.Sleep(time.Duration(attempt) * 200 * time.Millisecond)
			continue
		}

		if _, err := as.ds.SoftInvoke(invokeCmd); err != nil {
			lastErr = err
		}
		time.Sleep(time.Duration(attempt) * 200 * time.Millisecond)
	}

	if logEntry, err := as.GetAuditLogByID(auditID); err == nil && strings.TrimSpace(logEntry.TxHash) == txHash {
		return nil
	}

	return lastErr
}

func (as *AuditService) fetchAuditIDsByIndex(contractMethod, arg string) ([]string, error) {
	callCmd := fmt.Sprintf("call DID::SPECTRUM::TRADE %s -args %s", contractMethod, QuoteCommandArg(arg))
	data, err := as.ds.SoftCall(callCmd)
	if err != nil {
		return nil, err
	}
	if len(data) == 0 || strings.TrimSpace(data[0]) == "" {
		return []string{}, nil
	}

	var idList []string
	if err := json.Unmarshal([]byte(data[0]), &idList); err != nil {
		return nil, fmt.Errorf("failed to parse audit index %s: %w", contractMethod, err)
	}

	return idList, nil
}

func (as *AuditService) fetchAuditIDsByTimeRange(startAt, endAt *time.Time) ([]string, error) {
	if startAt == nil && endAt == nil {
		return nil, nil
	}

	rangeStart := time.Now().UTC()
	if startAt != nil {
		rangeStart = startAt.UTC()
	}

	rangeEnd := rangeStart
	if endAt != nil {
		rangeEnd = endAt.UTC()
	}

	dayCursor := time.Date(rangeStart.Year(), rangeStart.Month(), rangeStart.Day(), 0, 0, 0, 0, time.UTC)
	dayEnd := time.Date(rangeEnd.Year(), rangeEnd.Month(), rangeEnd.Day(), 0, 0, 0, 0, time.UTC)

	collected := make(map[string]struct{})
	for !dayCursor.After(dayEnd) {
		ids, err := as.fetchAuditIDsByIndex("GetAuditLogsByDay", dayCursor.Format("2006-01-02"))
		if err != nil {
			return nil, err
		}
		for _, auditID := range ids {
			if trimmed := strings.TrimSpace(auditID); trimmed != "" {
				collected[trimmed] = struct{}{}
			}
		}
		dayCursor = dayCursor.Add(24 * time.Hour)
	}

	return auditIDsFromSet(collected), nil
}

func normalizeAuditQuery(query AuditQuery) (AuditQuery, *time.Time, *time.Time, error) {
	query.AuditID = strings.TrimSpace(query.AuditID)
	query.OperatorDID = strings.TrimSpace(query.OperatorDID)
	query.SubjectDID = strings.TrimSpace(query.SubjectDID)
	query.PeerDID = strings.TrimSpace(query.PeerDID)
	query.OperationType = strings.ToUpper(strings.TrimSpace(query.OperationType))
	query.TargetObjectID = strings.TrimSpace(query.TargetObjectID)
	query.SessionID = strings.TrimSpace(query.SessionID)
	query.InteractionID = strings.TrimSpace(query.InteractionID)
	query.EvidenceLevel = strings.ToLower(strings.TrimSpace(query.EvidenceLevel))
	query.StartTime = strings.TrimSpace(query.StartTime)
	query.EndTime = strings.TrimSpace(query.EndTime)

	if query.Page <= 0 {
		query.Page = 1
	}
	if query.PageSize <= 0 {
		query.PageSize = 20
	}
	if query.PageSize > 200 {
		query.PageSize = 200
	}

	var (
		startAt *time.Time
		endAt   *time.Time
	)

	if query.StartTime != "" {
		parsed, err := parseAuditQueryTime(query.StartTime, false)
		if err != nil {
			return query, nil, nil, fmt.Errorf("invalid startTime: %w", err)
		}
		startAt = &parsed
	}

	if query.EndTime != "" {
		parsed, err := parseAuditQueryTime(query.EndTime, true)
		if err != nil {
			return query, nil, nil, fmt.Errorf("invalid endTime: %w", err)
		}
		endAt = &parsed
	}

	if startAt == nil && endAt != nil {
		startOfDay := time.Date(endAt.Year(), endAt.Month(), endAt.Day(), 0, 0, 0, 0, time.UTC)
		startAt = &startOfDay
	}
	if startAt != nil && endAt == nil {
		now := time.Now().UTC()
		endAt = &now
	}

	if startAt != nil && endAt != nil && startAt.After(*endAt) {
		return query, nil, nil, errors.New("startTime cannot be later than endTime")
	}

	if query.AuditID == "" && query.OperatorDID == "" && query.SubjectDID == "" && query.PeerDID == "" &&
		query.OperationType == "" && query.SessionID == "" && query.InteractionID == "" && startAt == nil && endAt == nil {
		return query, nil, nil, errors.New("audit query requires at least one filter")
	}

	return query, startAt, endAt, nil
}

func parseAuditQueryTime(raw string, isEnd bool) (time.Time, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return time.Time{}, errors.New("time value is empty")
	}

	if len(raw) == len("2006-01-02") {
		parsed, err := time.Parse("2006-01-02", raw)
		if err != nil {
			return time.Time{}, err
		}
		parsed = parsed.UTC()
		if isEnd {
			parsed = parsed.Add(24*time.Hour - time.Nanosecond)
		}
		return parsed, nil
	}

	for _, layout := range []string{time.RFC3339Nano, time.RFC3339} {
		if parsed, err := time.Parse(layout, raw); err == nil {
			return parsed.UTC(), nil
		}
	}

	return time.Time{}, fmt.Errorf("unsupported time format: %s", raw)
}

func auditLogMatchesQuery(logEntry AuditLog, query AuditQuery, startAt, endAt *time.Time) bool {
	if query.OperatorDID != "" && strings.TrimSpace(logEntry.OperatorDID) != query.OperatorDID {
		return false
	}
	if query.SubjectDID != "" && strings.TrimSpace(logEntry.SubjectDID) != query.SubjectDID {
		return false
	}
	if query.PeerDID != "" && strings.TrimSpace(logEntry.PeerDID) != query.PeerDID {
		return false
	}
	if query.OperationType != "" && strings.ToUpper(strings.TrimSpace(logEntry.OperationType)) != query.OperationType {
		return false
	}
	if query.TargetObjectID != "" && strings.TrimSpace(logEntry.TargetObjectID) != query.TargetObjectID {
		return false
	}
	if query.SessionID != "" && strings.TrimSpace(logEntry.SessionID) != query.SessionID {
		return false
	}
	if query.InteractionID != "" && strings.TrimSpace(logEntry.InteractionID) != query.InteractionID {
		return false
	}
	if query.EvidenceLevel != "" && strings.ToLower(strings.TrimSpace(logEntry.EvidenceLevel)) != query.EvidenceLevel {
		return false
	}

	if startAt != nil || endAt != nil {
		timestamp, ok := parseStoredAuditTimestamp(logEntry.Timestamp)
		if !ok {
			return false
		}
		if startAt != nil && timestamp.Before(startAt.UTC()) {
			return false
		}
		if endAt != nil && timestamp.After(endAt.UTC()) {
			return false
		}
	}

	return true
}

func paginateAuditLogs(logs []AuditLog, page, pageSize int) ([]AuditLog, int, error) {
	total := len(logs)
	if total == 0 {
		return []AuditLog{}, 0, nil
	}

	start := (page - 1) * pageSize
	if start >= total {
		return []AuditLog{}, total, nil
	}

	end := start + pageSize
	if end > total {
		end = total
	}

	paged := make([]AuditLog, end-start)
	copy(paged, logs[start:end])
	return paged, total, nil
}

func intersectAuditIDSets(existing map[string]struct{}, ids []string) map[string]struct{} {
	next := make(map[string]struct{}, len(ids))
	for _, auditID := range ids {
		if trimmed := strings.TrimSpace(auditID); trimmed != "" {
			next[trimmed] = struct{}{}
		}
	}

	if existing == nil {
		return next
	}

	intersected := make(map[string]struct{})
	for auditID := range existing {
		if _, ok := next[auditID]; ok {
			intersected[auditID] = struct{}{}
		}
	}
	return intersected
}

func auditIDsFromSet(values map[string]struct{}) []string {
	if len(values) == 0 {
		return []string{}
	}

	ids := make([]string, 0, len(values))
	for auditID := range values {
		ids = append(ids, auditID)
	}
	sort.Strings(ids)
	return ids
}

func auditLogLess(left, right AuditLog) bool {
	leftTime, leftOK := parseStoredAuditTimestamp(left.Timestamp)
	rightTime, rightOK := parseStoredAuditTimestamp(right.Timestamp)

	switch {
	case leftOK && rightOK && !leftTime.Equal(rightTime):
		return leftTime.After(rightTime)
	case leftOK != rightOK:
		return leftOK
	default:
		return left.AuditID > right.AuditID
	}
}

func parseStoredAuditTimestamp(raw string) (time.Time, bool) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return time.Time{}, false
	}

	for _, layout := range []string{time.RFC3339Nano, time.RFC3339} {
		if parsed, err := time.Parse(layout, raw); err == nil {
			return parsed.UTC(), true
		}
	}

	return time.Time{}, false
}

func quoteAuditCommandArg(arg string) string {
	return QuoteCommandArg(arg)
}

func normalizeAuditLogDefaults(logEntry *AuditLog) {
	if logEntry == nil {
		return
	}

	logEntry.AuditID = strings.TrimSpace(logEntry.AuditID)
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
