package router

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"p3Chain/api"
	"p3Chain/ginHttp/pkg/app"
	e "p3Chain/ginHttp/pkg/error"
	loglogrus "p3Chain/log_logrus"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
)

func getSubscriptionsBySubscriber(ds *api.DperService, subscriberDID string) ([]map[string]interface{}, error) {
	contractName := "DID::SPECTRUM::TRADE"
	callCmd := "call " + contractName + " GetSubscriptions -args " + subscriberDID

	data, err := ds.SoftCall(callCmd)
	if err != nil || len(data) == 0 || data[0] == "" {
		return []map[string]interface{}{}, nil
	}

	var subscriptions []map[string]interface{}
	if err := json.Unmarshal([]byte(data[0]), &subscriptions); err != nil {
		return nil, err
	}

	return subscriptions, nil
}

func findSubscriptionByID(subscriptions []map[string]interface{}, subscriptionID string) map[string]interface{} {
	for _, sub := range subscriptions {
		if id := getStringField(sub, "subscription_id", "subscriptionId"); id == subscriptionID {
			return sub
		}
	}

	return nil
}

func getSubscriptionByID(ds *api.DperService, subscriptionID string) (map[string]interface{}, error) {
	contractName := "DID::SPECTRUM::TRADE"
	callCmd := "call " + contractName + " GetSubscriptionByID -args " + subscriptionID

	data, err := ds.SoftCall(callCmd)
	if err != nil || len(data) == 0 || data[0] == "" {
		return nil, fmt.Errorf("subscription not found")
	}

	var subscription map[string]interface{}
	if err := json.Unmarshal([]byte(data[0]), &subscription); err != nil {
		return nil, err
	}

	return subscription, nil
}

func waitForSubscription(ds *api.DperService, subscriptionID string, attempts int, interval time.Duration) (map[string]interface{}, error) {
	for i := 0; i < attempts; i++ {
		sub, err := getSubscriptionByID(ds, subscriptionID)
		if err == nil {
			return sub, nil
		}
		if i < attempts-1 {
			time.Sleep(interval)
		}
	}

	return nil, fmt.Errorf("subscription not available yet")
}

type CreateSubscriptionRequest struct {
	SubscriberDID string   `json:"subscriberDid"`
	TargetNFType  string   `json:"targetNfType"`
	TargetDID     string   `json:"targetDid"`
	CallbackURL   string   `json:"callbackUrl"`
	EventTypes    []string `json:"eventTypes"`

	// OAI/AMF compatibility aliases
	SubscriberNFDID        string `json:"subscriber_nf_did"`
	SubscriberNFType       string `json:"subscriber_nf_type"`
	SubscriberNFInstanceID string `json:"subscriber_nf_instance_id"`
	TargetNFTypeAlias      string `json:"target_nf_type"`
	NotificationURI        string `json:"notification_uri"`
	NotificationTransport  string `json:"notification_transport"`
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if trimmed := strings.TrimSpace(value); trimmed != "" {
			return trimmed
		}
	}

	return ""
}

func normalizeEventTypes(eventTypes []string) []string {
	if len(eventTypes) == 0 {
		return nil
	}

	normalized := make([]string, 0, len(eventTypes))
	seen := make(map[string]struct{})
	for _, eventType := range eventTypes {
		trimmed := strings.TrimSpace(eventType)
		if trimmed == "" {
			continue
		}
		if _, exists := seen[trimmed]; exists {
			continue
		}
		seen[trimmed] = struct{}{}
		normalized = append(normalized, trimmed)
	}

	if len(normalized) == 0 {
		return nil
	}

	return normalized
}

func (r *CreateSubscriptionRequest) normalize(callerDID string) {
	if callerDID != "" {
		r.SubscriberDID = callerDID
	} else {
		r.SubscriberDID = firstNonEmpty(r.SubscriberDID, r.SubscriberNFDID)
	}

	r.TargetNFType = firstNonEmpty(r.TargetNFType, r.TargetNFTypeAlias)
	r.CallbackURL = firstNonEmpty(r.CallbackURL, r.NotificationURI)
	r.TargetDID = firstNonEmpty(r.TargetDID)
	r.EventTypes = normalizeEventTypes(r.EventTypes)
}

func getSubscriberDIDFromContextOrQuery(c *gin.Context) string {
	if callerDID := GetCallerDID(c); callerDID != "" {
		return callerDID
	}
	return c.Query("subscriber-did")
}

func canAccessSubscription(c *gin.Context, sub map[string]interface{}) bool {
	callerDID := getSubscriberDIDFromContextOrQuery(c)
	ownerDID := getStringField(sub, "subscriberDid", "subscriber_nf_did")
	return callerDID != "" && callerDID == ownerDID
}

func isValidCallbackURL(raw string) bool {
	if strings.TrimSpace(raw) == "" {
		return false
	}
	u, err := url.ParseRequestURI(raw)
	if err != nil {
		return false
	}
	return u.Scheme == "http" || u.Scheme == "https"
}

func CreateSubscription(ds *api.DperService) func(*gin.Context) {
	return func(c *gin.Context) {
		appG := app.Gin{C: c}

		var req CreateSubscriptionRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			appG.Response(http.StatusBadRequest, e.INVALID_PARAMS, gin.H{
				"error": "invalid request body",
			})
			return
		}

		// 优先使用 token 中提取的 DID，没有 token 时兼容 AMF 发来的 snake_case 字段
		req.normalize(GetCallerDID(c))

		if req.SubscriberDID == "" || req.TargetNFType == "" {
			appG.Response(http.StatusBadRequest, e.INVALID_PARAMS, gin.H{
				"error": "subscriberDid and targetNfType are required",
			})
			return
		}
		if !isValidCallbackURL(req.CallbackURL) {
			appG.Response(http.StatusBadRequest, e.INVALID_PARAMS, gin.H{
				"error": "callbackUrl must be a valid http/https URL",
			})
			return
		}

		subscriptionID := fmt.Sprintf("sub-%d", time.Now().UnixNano())
		now := time.Now().Format(time.RFC3339)
		notificationTransport := firstNonEmpty(req.NotificationTransport, "auto")

		subscription := map[string]interface{}{
			"subscriptionId":         subscriptionID,
			"subscription_id":        subscriptionID,
			"subscriberDid":          req.SubscriberDID,
			"targetNfType":           req.TargetNFType,
			"targetDid":              req.TargetDID,
			"callbackUrl":            req.CallbackURL,
			"status":                 "ACTIVE",
			"createdAt":              now,
			"updatedAt":              now,
			"subscriber_nf_did":      req.SubscriberDID,
			"target_nf_type":         req.TargetNFType,
			"notification_uri":       req.CallbackURL,
			"notification_transport": notificationTransport,
		}
		if req.SubscriberNFType != "" {
			subscription["subscriber_nf_type"] = req.SubscriberNFType
		}
		if req.SubscriberNFInstanceID != "" {
			subscription["subscriber_nf_instance_id"] = req.SubscriberNFInstanceID
		}
		if len(req.EventTypes) > 0 {
			subscription["eventTypes"] = req.EventTypes
		}

		valueJSON, err := json.Marshal(subscription)
		if err != nil {
			appG.Response(http.StatusInternalServerError, e.ERROR, gin.H{
				"error": "failed to build subscription json",
			})
			return
		}

		contractName := "DID::SPECTRUM::TRADE"
		invokeCmd := "invoke " + contractName + " CreateSubscription -args " +
			api.QuoteCommandArg(subscriptionID) + " " + api.QuoteCommandArg(string(valueJSON))

		loglogrus.Log.Infof("CreateSubscription invokeCmd: %s\n", invokeCmd)

		receipt, err := ds.SoftInvoke(invokeCmd)
		if err != nil {
			appG.Response(http.StatusInternalServerError, e.ERROR, gin.H{
				"error": "failed to create subscription",
			})
			return
		}

		if !receipt.Valid {
			loglogrus.Log.Infof("CreateSubscription: transaction submitted without confirmed receipt yet, txId=%x\n", receipt.TransactionID)
		}

		if _, waitErr := waitForSubscription(ds, subscriptionID, 10, 300*time.Millisecond); waitErr != nil {
			loglogrus.Log.Warnf("CreateSubscription: subscription not visible on chain yet, subscriptionID=%s txId=%x err=%v\n",
				subscriptionID, receipt.TransactionID, waitErr)
		}

		targetNFList, queryErr := getRegisteredNFProfilesByType(ds, req.TargetNFType)
		if queryErr != nil {
			loglogrus.Log.Warnf("CreateSubscription: query current target NF list failed for nfType=%s: %v\n", req.TargetNFType, queryErr)
			targetNFList = []map[string]interface{}{}
		}

		SubmitAudit(c, GetAuditService(), &api.AuditEvent{
			OperatorDID:    req.SubscriberDID,
			OperationType:  "SUBSCRIPTION_CREATE",
			TargetObjectID: subscriptionID,
			Result:         "SUCCESS",
			ResultCode:     http.StatusCreated,
			RelatedTxHash:  fmt.Sprintf("%x", receipt.TransactionID),
			Metadata: map[string]string{
				"target_nf_type": req.TargetNFType,
				"target_did":     req.TargetDID,
			},
		})

		c.JSON(http.StatusCreated, gin.H{
			"success":                true,
			"subscription_id":        subscriptionID,
			"target_nf_list":         targetNFList,
			"notification_transport": notificationTransport,
		})
	}
}

func GetSubscriptions(ds *api.DperService) func(*gin.Context) {
	return func(c *gin.Context) {
		appG := app.Gin{C: c}

		subscriberDID := getSubscriberDIDFromContextOrQuery(c)
		if subscriberDID == "" {
			appG.Response(http.StatusBadRequest, e.INVALID_PARAMS, gin.H{
				"error": "Missing required subscriber identity",
			})
			return
		}

		subscriptions, err := getSubscriptionsBySubscriber(ds, subscriberDID)
		if err != nil {
			c.JSON(http.StatusOK, gin.H{
				"subscriptions": []interface{}{},
			})
			SubmitAudit(c, GetAuditService(), &api.AuditEvent{
				OperatorDID:    subscriberDID,
				OperationType:  "SUBSCRIPTION_QUERY",
				TargetObjectID: subscriberDID,
				Result:         "SUCCESS",
				ResultCode:     http.StatusOK,
				Metadata: map[string]string{
					"result_count": "0",
				},
			})
			return
		}

		SubmitAudit(c, GetAuditService(), &api.AuditEvent{
			OperatorDID:    subscriberDID,
			OperationType:  "SUBSCRIPTION_QUERY",
			TargetObjectID: subscriberDID,
			Result:         "SUCCESS",
			ResultCode:     http.StatusOK,
			Metadata: map[string]string{
				"result_count": fmt.Sprintf("%d", len(subscriptions)),
			},
		})

		c.JSON(http.StatusOK, gin.H{
			"subscriptions": subscriptions,
		})
	}
}

func GetSubscriptionByID(ds *api.DperService) func(*gin.Context) {
	return func(c *gin.Context) {
		appG := app.Gin{C: c}

		subscriptionID := c.Param("subscriptionId")
		if subscriptionID == "" {
			appG.Response(http.StatusBadRequest, e.INVALID_PARAMS, gin.H{
				"error": "subscriptionId is required",
			})
			return
		}

		subscription, err := getSubscriptionByID(ds, subscriptionID)
		if err != nil {
			appG.Response(http.StatusNotFound, e.ERROR, gin.H{
				"error": "subscription not found",
			})
			return
		}
		if !canAccessSubscription(c, subscription) {
			appG.Response(http.StatusForbidden, e.ERROR, gin.H{
				"error": "forbidden: subscription does not belong to caller",
			})
			return
		}

		SubmitAudit(c, GetAuditService(), &api.AuditEvent{
			OperatorDID:    getSubscriberDIDFromContextOrQuery(c),
			OperationType:  "SUBSCRIPTION_QUERY",
			TargetObjectID: subscriptionID,
			Result:         "SUCCESS",
			ResultCode:     http.StatusOK,
		})

		c.JSON(http.StatusOK, subscription)
	}
}

func DeleteSubscription(ds *api.DperService) func(*gin.Context) {
	return func(c *gin.Context) {
		appG := app.Gin{C: c}

		subscriptionID := c.Param("subscriptionId")
		subscriberDID := getSubscriberDIDFromContextOrQuery(c)

		if subscriptionID == "" || subscriberDID == "" {
			appG.Response(http.StatusBadRequest, e.INVALID_PARAMS, gin.H{
				"error": "subscriptionId and subscriber identity are required",
			})
			return
		}

		contractName := "DID::SPECTRUM::TRADE"
		invokeCmd := "invoke " + contractName + " DeleteSubscription -args " + subscriptionID + " " + subscriberDID

		receipt, err := ds.SoftInvoke(invokeCmd)
		if err != nil {
			if strings.Contains(err.Error(), "subscriberDID does not match subscription owner") {
				appG.Response(http.StatusForbidden, e.ERROR, gin.H{
					"error": "failed to delete subscription: subscriberDID does not match subscription owner",
				})
				return
			}
			if strings.Contains(err.Error(), "subscription not found") {
				appG.Response(http.StatusNotFound, e.ERROR, gin.H{
					"error": "subscription not found",
				})
				return
			}

			appG.Response(http.StatusInternalServerError, e.ERROR, gin.H{
				"error": "failed to delete subscription",
			})
			return
		}

		if !receipt.Valid {
			for i := 0; i < 10; i++ {
				time.Sleep(300 * time.Millisecond)
				latestSub, queryErr := getSubscriptionByID(ds, subscriptionID)
				if queryErr != nil {
					continue
				}

				if status, _ := latestSub["status"].(string); status == "INACTIVE" {
					SubmitAudit(c, GetAuditService(), &api.AuditEvent{
						OperatorDID:    subscriberDID,
						OperationType:  "SUBSCRIPTION_DELETE",
						TargetObjectID: subscriptionID,
						Result:         "SUCCESS",
						ResultCode:     http.StatusNoContent,
						RelatedTxHash:  fmt.Sprintf("%x", receipt.TransactionID),
					})
					c.Status(http.StatusNoContent)
					return
				}
			}

			appG.Response(http.StatusAccepted, e.SUCCESS, gin.H{
				"subscriptionId": subscriptionID,
				"txId":           fmt.Sprintf("%x", receipt.TransactionID),
				"status":         "PENDING",
			})
			SubmitAudit(c, GetAuditService(), &api.AuditEvent{
				OperatorDID:    subscriberDID,
				OperationType:  "SUBSCRIPTION_DELETE",
				TargetObjectID: subscriptionID,
				Result:         "SUCCESS",
				ResultCode:     http.StatusAccepted,
				RelatedTxHash:  fmt.Sprintf("%x", receipt.TransactionID),
				Metadata: map[string]string{
					"status": "PENDING",
				},
			})
			return
		}

		SubmitAudit(c, GetAuditService(), &api.AuditEvent{
			OperatorDID:    subscriberDID,
			OperationType:  "SUBSCRIPTION_DELETE",
			TargetObjectID: subscriptionID,
			Result:         "SUCCESS",
			ResultCode:     http.StatusNoContent,
			RelatedTxHash:  fmt.Sprintf("%x", receipt.TransactionID),
		})
		c.Status(http.StatusNoContent)
	}
}
