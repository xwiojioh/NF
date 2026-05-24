package router

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"p3Chain/api"
	loglogrus "p3Chain/log_logrus"
	"strings"
	"time"
)

const (
	EventNFRegistered     = "TARGET_NF_REGISTERED"
	EventNFDeregistered   = "TARGET_NF_DEREGISTERED"
	EventNFStatusChanged  = "TARGET_NF_STATUS_CHANGED"
	EventNFProfileUpdated = "TARGET_NF_PROFILE_UPDATED"

	legacyEventNFRegistered     = "NF_REGISTERED"
	legacyEventNFDeregistered   = "NF_DEREGISTERED"
	legacyEventNFStatusChanged  = "NF_STATUS_CHANGED"
	legacyEventNFProfileUpdated = "NF_PROFILE_UPDATED"
)

// NotificationEvent 是向订阅方发送的事件体结构
type NotificationEvent struct {
	Event              string                 `json:"event"`
	SubscriptionID     string                 `json:"subscription_id"`
	TargetNFType       string                 `json:"target_nf_type"`
	TargetNFInstanceID string                 `json:"target_nf_instance_id"`
	TargetNFProfile    map[string]interface{} `json:"target_nf_profile,omitempty"`
}

func normalizeEventType(eventType string) string {
	switch strings.ToUpper(strings.TrimSpace(eventType)) {
	case "", strings.ToUpper(EventNFRegistered), legacyEventNFRegistered:
		return EventNFRegistered
	case strings.ToUpper(EventNFDeregistered), legacyEventNFDeregistered:
		return EventNFDeregistered
	case strings.ToUpper(EventNFStatusChanged), legacyEventNFStatusChanged:
		return EventNFStatusChanged
	case strings.ToUpper(EventNFProfileUpdated), legacyEventNFProfileUpdated:
		return EventNFProfileUpdated
	default:
		return strings.TrimSpace(eventType)
	}
}

func resolveNotificationURL(sub map[string]interface{}) string {
	return getStringField(sub, "notification_uri", "callbackUrl")
}

func resolveSubscriptionID(sub map[string]interface{}) string {
	return getStringField(sub, "subscription_id", "subscriptionId")
}

func subscriptionAcceptsEvent(sub map[string]interface{}, eventType string) bool {
	rawTypes, ok := sub["eventTypes"]
	if !ok {
		return true
	}

	targetEvent := normalizeEventType(eventType)
	switch values := rawTypes.(type) {
	case []interface{}:
		if len(values) == 0 {
			return true
		}
		for _, item := range values {
			if value, ok := item.(string); ok && normalizeEventType(value) == targetEvent {
				return true
			}
		}
	case []string:
		if len(values) == 0 {
			return true
		}
		for _, value := range values {
			if normalizeEventType(value) == targetEvent {
				return true
			}
		}
	default:
		return true
	}

	return false
}

func resolveTargetNFProfile(ds *api.DperService, did, nfType, nfInstanceID string, eventData map[string]interface{}) map[string]interface{} {
	if did != "" {
		if nfData, _, err := getNFProfileByDIDWithFallback(ds, did, 5, 200*time.Millisecond); err == nil {
			profile := flattenNFProfileRecord(nfData)
			if _, ok := profile["did"]; !ok && did != "" {
				profile["did"] = did
			}
			if _, ok := profile["nfType"]; !ok && nfType != "" {
				profile["nfType"] = nfType
			}
			if _, ok := profile["nfInstanceId"]; !ok && nfInstanceID != "" {
				profile["nfInstanceId"] = nfInstanceID
			}
			return profile
		}
	}

	profile := flattenNFProfileRecord(eventData)
	if len(profile) == 0 {
		profile = make(map[string]interface{})
	}
	if did != "" {
		profile["did"] = did
	}
	if nfType != "" {
		profile["nfType"] = nfType
	}
	if nfInstanceID != "" {
		profile["nfInstanceId"] = nfInstanceID
	}

	return profile
}

// sendNotification 向单个 callbackURL 发送 HTTP POST 通知
func sendNotification(callbackURL string, event NotificationEvent) error {
	payload, err := json.Marshal(event)
	if err != nil {
		return fmt.Errorf("marshal event failed: %v", err)
	}

	client := &http.Client{Timeout: 5 * time.Second}
	var lastErr error
	for attempt := 1; attempt <= 3; attempt++ {
		resp, err := client.Post(callbackURL, "application/json", bytes.NewReader(payload))
		if err != nil {
			lastErr = fmt.Errorf("http post to %s failed: %v", callbackURL, err)
		} else {
			body, _ := io.ReadAll(resp.Body)
			resp.Body.Close()

			if resp.StatusCode >= 200 && resp.StatusCode < 300 {
				return nil
			}

			lastErr = fmt.Errorf("callback %s returned HTTP %d: %s", callbackURL, resp.StatusCode, strings.TrimSpace(string(body)))
		}

		if attempt < 3 {
			time.Sleep(time.Duration(attempt) * 500 * time.Millisecond)
		}
	}

	return lastErr
}

// getSubscriptionsByNFType 从链上查询某 nfType 下所有订阅
func getSubscriptionsByNFType(ds *api.DperService, nfType string) ([]map[string]interface{}, error) {
	contractName := "DID::SPECTRUM::TRADE"
	callCmd := "call " + contractName + " GetSubscriptionsByNFType -args " + nfType

	data, err := ds.SoftCall(callCmd)
	if err != nil || len(data) == 0 || data[0] == "" {
		return []map[string]interface{}{}, nil
	}

	var subscriptions []map[string]interface{}
	if err := json.Unmarshal([]byte(data[0]), &subscriptions); err != nil {
		return nil, fmt.Errorf("unmarshal subscriptions failed: %v", err)
	}

	return subscriptions, nil
}

func matchesSubscription(sub map[string]interface{}, eventType, nfType, did string) bool {
	if status := strings.ToUpper(getStringField(sub, "status")); status != "" && status != "ACTIVE" {
		return false
	}

	if targetType := getStringField(sub, "target_nf_type", "targetNfType"); targetType != "" && !strings.EqualFold(targetType, nfType) {
		return false
	}

	if targetDID := getStringField(sub, "target_nf_did", "targetDid"); targetDID != "" && targetDID != did {
		return false
	}

	if !subscriptionAcceptsEvent(sub, eventType) {
		return false
	}

	return resolveNotificationURL(sub) != ""
}

// DispatchNFEvent 在 NF 状态变更后查找匹配的订阅并异步发送通知
// 调用方无需等待通知结果，本函数在 goroutine 内执行所有发送。
func DispatchNFEvent(ds *api.DperService, eventType, nfInstanceID, nfType, did string, eventData map[string]interface{}) {
	normalizedEventType := normalizeEventType(eventType)
	targetNFProfile := resolveTargetNFProfile(ds, did, nfType, nfInstanceID, eventData)

	go func() {
		subscriptions, err := getSubscriptionsByNFType(ds, nfType)
		if err != nil {
			loglogrus.Log.Warnf("DispatchNFEvent: query subscriptions for nfType=%s failed: %v\n", nfType, err)
			return
		}

		if len(subscriptions) == 0 {
			loglogrus.Log.Infof("DispatchNFEvent: no subscriptions for nfType=%s, skip\n", nfType)
			return
		}

		for _, sub := range subscriptions {
			if !matchesSubscription(sub, normalizedEventType, nfType, did) {
				continue
			}

			callbackURL := resolveNotificationURL(sub)
			subID := resolveSubscriptionID(sub)
			notification := NotificationEvent{
				Event:              normalizedEventType,
				SubscriptionID:     subID,
				TargetNFType:       nfType,
				TargetNFInstanceID: nfInstanceID,
				TargetNFProfile:    targetNFProfile,
			}

			go func(url, sid string, payload NotificationEvent) {
				lowerURL := strings.ToLower(url)
				if !strings.HasPrefix(lowerURL, "http://") && !strings.HasPrefix(lowerURL, "https://") {
					loglogrus.Log.Warnf("DispatchNFEvent: skip invalid callback url for sub=%s url=%s\n", sid, url)
					return
				}
				if err := sendNotification(url, payload); err != nil {
					loglogrus.Log.Warnf("DispatchNFEvent: notify sub=%s url=%s failed: %v\n", sid, url, err)
				} else {
					loglogrus.Log.Infof("DispatchNFEvent: notify sent to sub=%s url=%s event=%s\n", sid, url, normalizedEventType)
				}
			}(callbackURL, subID, notification)
		}
	}()
}
