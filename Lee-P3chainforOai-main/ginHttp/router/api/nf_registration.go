package router

import (
	"encoding/json"
	"fmt"
	"net/http"
	"p3Chain/api"
	"p3Chain/ginHttp/pkg/app"
	e "p3Chain/ginHttp/pkg/error"
	loglogrus "p3Chain/log_logrus"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
)

// NFRegistrationRequest - NF注册请求结构（支持3GPP NRF标准字段）
type NFRegistrationRequest struct {
	DID               string                 `json:"did"`
	DIDDocument       map[string]interface{} `json:"didDocument"`
	NFInstanceID      string                 `json:"nfInstanceId"`
	NFType            string                 `json:"nfType"`
	NFStatus          string                 `json:"nfStatus"`
	HeartBeatTimer    int                    `json:"heartBeatTimer"`
	Capacity          int                    `json:"capacity"`
	Priority          int                    `json:"priority"`
	PlmnList          []interface{}          `json:"plmnList"`
	SNssais           []interface{}          `json:"sNssais"`
	PerPlmnSnssaiList []interface{}          `json:"perPlmnSnssaiList"`
	RecoveryTime      string                 `json:"recoveryTime"`
	AmfInfo           map[string]interface{} `json:"amfInfo,omitempty"`
	SmfInfo           map[string]interface{} `json:"smfInfo,omitempty"`
	// 3GPP NRF 标准扩展字段
	Fqdn          string        `json:"fqdn,omitempty"`
	Ipv4Addresses []string      `json:"ipv4Addresses,omitempty"`
	Ipv6Addresses []string      `json:"ipv6Addresses,omitempty"`
	NFServices    []interface{} `json:"nfServices,omitempty"`
}

// NFStorageData - 存储到链上的数据结构
type NFStorageData struct {
	NFProfile    map[string]interface{} `json:"nfProfile"`
	DIDDocument  map[string]interface{} `json:"didDocument"`
	RegisteredAt string                 `json:"registeredAt"`
	UpdatedAt    string                 `json:"updatedAt"`
}

func hasVerificationMethod(didDocument map[string]interface{}) bool {
	if didDocument == nil {
		return false
	}
	verificationMethod, ok := didDocument["verificationMethod"].([]interface{})
	return ok && len(verificationMethod) > 0
}

func isValidNFStatus(status string) bool {
	switch strings.ToUpper(strings.TrimSpace(status)) {
	case "REGISTERED", "SUSPENDED", "UNDISCOVERABLE", "DEREGISTERED":
		return true
	default:
		return false
	}
}

func waitForNFProfileAvailability(ds *api.DperService, did string, attempts int, interval time.Duration) error {
	for i := 0; i < attempts; i++ {
		if _, err := getNFProfileByDID(ds, did); err == nil {
			return nil
		}
		if i < attempts-1 {
			time.Sleep(interval)
		}
	}

	return fmt.Errorf("nf profile not available yet")
}

const (
	nfProfileVisibilityAttempts = 150
	nfProfileVisibilityInterval = 100 * time.Millisecond
)

// RegisterNF - 处理NF注册请求 (PUT /nbcf-management/v1/nf-instances/:nfInstanceId)
func RegisterNF(ds *api.DperService) func(*gin.Context) {
	return func(c *gin.Context) {
		loglogrus.Log.Infof("Http: Get user request -- RegisterNF\n")
		appG := app.Gin{C: c}

		// 从 URL 路径获取 nfInstanceId
		nfInstanceId := c.Param("nfInstanceId")
		if nfInstanceId == "" {
			loglogrus.Log.Errorf("Missing nfInstanceId in URL\n")
			appG.Response(http.StatusBadRequest, e.ERROR, gin.H{
				"error": "Missing nfInstanceId in URL path",
			})
			return
		}
		loglogrus.Log.Infof("RegisterNF: nfInstanceId from URL = %s\n", nfInstanceId)

		// 1. 解析JSON请求体
		var req NFRegistrationRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			loglogrus.Log.Errorf("Failed to parse JSON: %v\n", err)
			appG.Response(http.StatusBadRequest, e.ERROR, gin.H{
				"error":  "Invalid JSON format",
				"detail": err.Error(),
			})
			return
		}

		// 如果请求体中没有 nfInstanceId，使用 URL 中的
		if req.NFInstanceID == "" {
			req.NFInstanceID = nfInstanceId
		} else if req.NFInstanceID != nfInstanceId {
			loglogrus.Log.Errorf("nfInstanceId mismatch: path=%s body=%s\n", nfInstanceId, req.NFInstanceID)
			appG.Response(http.StatusBadRequest, e.ERROR, gin.H{
				"error": "nfInstanceId in body must match URL path",
			})
			return
		}

		// 2. 验证必填字段
		if req.DID == "" || req.DIDDocument == nil {
			loglogrus.Log.Errorf("Missing required fields: did or didDocument\n")
			appG.Response(http.StatusBadRequest, e.ERROR, gin.H{
				"error": "Missing required fields: did, didDocument",
			})
			return
		}
		if strings.TrimSpace(req.NFType) == "" {
			loglogrus.Log.Errorf("Missing required field: nfType\n")
			appG.Response(http.StatusBadRequest, e.ERROR, gin.H{
				"error": "Missing required field: nfType",
			})
			return
		}
		if strings.TrimSpace(req.NFStatus) == "" {
			req.NFStatus = "REGISTERED"
		}
		if !isValidNFStatus(req.NFStatus) {
			loglogrus.Log.Errorf("Invalid nfStatus: %s\n", req.NFStatus)
			appG.Response(http.StatusBadRequest, e.ERROR, gin.H{
				"error": "Invalid nfStatus",
			})
			return
		}
		if !hasVerificationMethod(req.DIDDocument) {
			loglogrus.Log.Errorf("didDocument.verificationMethod is missing or empty\n")
			appG.Response(http.StatusBadRequest, e.ERROR, gin.H{
				"error": "didDocument.verificationMethod is required",
			})
			return
		}

		loglogrus.Log.Infof("RegisterNF: DID = %s, NFType = %s\n", req.DID, req.NFType)

		// 3. 检查DID是否已存在（判断是注册还是更新）
		contractName := "DID::SPECTRUM::TRADE"
		functionName := "GetNFProfile"
		checkCmd := "call " + contractName + " " + functionName + " -args " + req.DID
		existData, _ := ds.SoftCall(checkCmd)
		isUpdate := len(existData) > 0 && existData[0] != ""
		oldStatus := ""
		if isUpdate {
			var existing map[string]interface{}
			if err := json.Unmarshal([]byte(existData[0]), &existing); err == nil {
				if existingProfile, ok := existing["nfProfile"].(map[string]interface{}); ok {
					oldStatus, _ = existingProfile["nfStatus"].(string)
				}
			}
		}

		// 4. 构造存储数据（包含所有3GPP NRF标准字段）
		now := time.Now().UTC().Format(time.RFC3339)
		nfProfile := map[string]interface{}{
			"nfInstanceId":      nfInstanceId,
			"nfType":            req.NFType,
			"nfStatus":          req.NFStatus,
			"heartBeatTimer":    req.HeartBeatTimer,
			"capacity":          req.Capacity,
			"priority":          req.Priority,
			"plmnList":          req.PlmnList,
			"sNssais":           req.SNssais,
			"perPlmnSnssaiList": req.PerPlmnSnssaiList,
			"recoveryTime":      req.RecoveryTime,
		}

		// 添加NF特定信息
		if req.AmfInfo != nil {
			nfProfile["amfInfo"] = req.AmfInfo
		}
		if req.SmfInfo != nil {
			nfProfile["smfInfo"] = req.SmfInfo
		}
		// 添加3GPP扩展字段
		if req.Fqdn != "" {
			nfProfile["fqdn"] = req.Fqdn
		}
		if len(req.Ipv4Addresses) > 0 {
			nfProfile["ipv4Addresses"] = req.Ipv4Addresses
		}
		if len(req.Ipv6Addresses) > 0 {
			nfProfile["ipv6Addresses"] = req.Ipv6Addresses
		}
		if len(req.NFServices) > 0 {
			nfProfile["nfServices"] = req.NFServices
		}

		storageData := NFStorageData{
			NFProfile:   nfProfile,
			DIDDocument: req.DIDDocument,
			UpdatedAt:   now,
		}
		if !isUpdate {
			storageData.RegisteredAt = now
		}

		pendingProfileData := map[string]interface{}{
			"did":         req.DID,
			"nfProfile":   storageData.NFProfile,
			"didDocument": storageData.DIDDocument,
			"updatedAt":   storageData.UpdatedAt,
		}
		if storageData.RegisteredAt != "" {
			pendingProfileData["registeredAt"] = storageData.RegisteredAt
		}

		// 5. 序列化并存储到链上
		valueJSON, err := json.Marshal(storageData)
		if err != nil {
			loglogrus.Log.Errorf("Failed to marshal storage data: %v\n", err)
			appG.Response(http.StatusInternalServerError, e.ERROR, gin.H{
				"error": "Failed to serialize data",
			})
			return
		}

		args := api.QuoteCommandArg(req.DID) + " " + api.QuoteCommandArg(string(valueJSON))
		invokeCmd := "invoke " + contractName + " SetNFProfile -args " + args

		loglogrus.Log.Infof("RegisterNF: Invoking contract with DID = %s\n", req.DID)
		loglogrus.Log.Infof("RegisterNF: Invoke command = %s\n", invokeCmd)
		result, err := ds.SoftInvoke(invokeCmd)
		if err != nil {
			loglogrus.Log.Errorf("Blockchain storage failed: %v\n", err)
			appG.Response(http.StatusInternalServerError, e.ERROR, gin.H{
				"error":  "Blockchain storage failed",
				"detail": err.Error(),
			})
			return
		}

		rememberPendingNFProfile(req.DID, pendingProfileData)

		if result.Valid {
			loglogrus.Log.Infof("RegisterNF: Blockchain transaction confirmed, TransactionID=%x, Valid=%v\n",
				result.TransactionID, result.Valid)
		} else {
			loglogrus.Log.Infof("RegisterNF: Transaction submitted without confirmed receipt yet, TransactionID=%x, Valid=%v\n",
				result.TransactionID, result.Valid)
		}

		// Registration is considered successful only when the profile becomes
		// readable from blockchain state. Pending-cache visibility is not enough
		// for management/discovery semantics.
		if waitErr := waitForNFProfileAvailability(
			ds, req.DID, nfProfileVisibilityAttempts, nfProfileVisibilityInterval,
		); waitErr != nil {
			forgetPendingNFProfile(req.DID)
			loglogrus.Log.Errorf(
				"RegisterNF: NF profile is still not visible on chain after waiting. TransactionID=%x, err=%v\n",
				result.TransactionID, waitErr,
			)
			appG.Response(http.StatusInternalServerError, e.ERROR, gin.H{
				"error":  "Blockchain storage not visible",
				"detail": waitErr.Error(),
				"txId":   fmt.Sprintf("%x", result.TransactionID),
			})
			return
		}
		loglogrus.Log.Infof(
			"RegisterNF: NF profile became available on chain after polling, TransactionID=%x\n",
			result.TransactionID,
		)
		forgetPendingNFProfile(req.DID)

		// 6. 返回响应（符合3GPP NRF标准）
		response := gin.H{
			"nfInstanceId": nfInstanceId,
			"did":          req.DID,
			"nfStatus":     req.NFStatus,
			"nfType":       req.NFType,
		}

		auditEvent := &api.AuditEvent{
			OperatorDID:    req.DID,
			OperationType:  "NF_REGISTER",
			TargetObjectID: nfInstanceId,
			Result:         "SUCCESS",
			ResultCode:     http.StatusCreated,
			RelatedTxHash:  fmt.Sprintf("%x", result.TransactionID),
			Metadata: map[string]string{
				"nf_type":   req.NFType,
				"is_update": fmt.Sprintf("%t", isUpdate),
			},
		}

		if isUpdate {
			loglogrus.Log.Infof("NF updated successfully: %s\n", req.DID)
			c.JSON(http.StatusOK, response)
			auditEvent.ResultCode = http.StatusOK
			eventType := EventNFProfileUpdated
			if oldStatus != "" && oldStatus != req.NFStatus {
				eventType = EventNFStatusChanged
			}
			SubmitAudit(c, GetAuditService(), auditEvent)
			eventData := cloneNFProfileData(pendingProfileData)
			eventData["previousStatus"] = oldStatus
			DispatchNFEvent(ds, eventType, nfInstanceId, req.NFType, req.DID, eventData)
		} else {
			loglogrus.Log.Infof("NF registered successfully: %s\n", req.DID)
			c.JSON(http.StatusCreated, response)
			SubmitAudit(c, GetAuditService(), auditEvent)
			DispatchNFEvent(ds, EventNFRegistered, nfInstanceId, req.NFType, req.DID, cloneNFProfileData(pendingProfileData))
		}
	}
}

// DeregisterNF - 处理NF注销请求 (DELETE /nbcf-management/v1/nf-instances/:nfInstanceId)
func DeregisterNF(ds *api.DperService) func(*gin.Context) {
	return func(c *gin.Context) {
		loglogrus.Log.Infof("Http: Get user request -- DeregisterNF\n")
		appG := app.Gin{C: c}

		// 从 URL 路径获取 nfInstanceId
		nfInstanceId := c.Param("nfInstanceId")
		if nfInstanceId == "" {
			appG.Response(http.StatusBadRequest, e.ERROR, gin.H{
				"error": "Missing nfInstanceId in URL path",
			})
			return
		}

		// 从 query 参数获取 DID
		did := c.Query("did")
		if did == "" {
			appG.Response(http.StatusBadRequest, e.ERROR, gin.H{
				"error": "Missing did query parameter",
			})
			return
		}

		loglogrus.Log.Infof("DeregisterNF: nfInstanceId = %s, did = %s\n", nfInstanceId, did)

		contractName := "DID::SPECTRUM::TRADE"

		// 先查 profile 拿 nfType，以便注销后能正确分发通知
		nfType := ""
		checkCmd := "call " + contractName + " GetNFProfile -args " + did
		profileData, profileErr := ds.SoftCall(checkCmd)
		if profileErr == nil && len(profileData) > 0 && profileData[0] != "" {
			var profileMap map[string]interface{}
			if err := json.Unmarshal([]byte(profileData[0]), &profileMap); err == nil {
				if nfProf, ok := profileMap["nfProfile"].(map[string]interface{}); ok {
					nfType, _ = nfProf["nfType"].(string)
				}
			}
		}

		invokeCmd := "invoke " + contractName + " DeregisterNF -args " + did
		receipt, err := ds.SoftInvoke(invokeCmd)
		if err != nil {
			loglogrus.Log.Errorf("Deregistration failed: %v\n", err)
			appG.Response(http.StatusNotFound, e.ERROR, gin.H{
				"error": "NF not found",
			})
			return
		}

		loglogrus.Log.Infof("NF deregistered successfully: %s (instanceId: %s)\n", did, nfInstanceId)
		forgetPendingNFProfile(did)
		c.Status(http.StatusNoContent)
		SubmitAudit(c, GetAuditService(), &api.AuditEvent{
			OperatorDID:    did,
			OperationType:  "NF_DEREGISTER",
			TargetObjectID: nfInstanceId,
			Result:         "SUCCESS",
			ResultCode:     http.StatusNoContent,
			RelatedTxHash:  fmt.Sprintf("%x", receipt.TransactionID),
			Metadata: map[string]string{
				"nf_type": nfType,
			},
		})

		if nfType != "" {
			DispatchNFEvent(ds, EventNFDeregistered, nfInstanceId, nfType, did, nil)
		}
	}
}

// GetNFInstance - 查询单个NF (GET /bcf/nf-instances/:nfInstanceId)
func GetNFInstance(ds *api.DperService) func(*gin.Context) {
	return func(c *gin.Context) {
		loglogrus.Log.Infof("Http: Get user request -- GetNFInstance\n")
		appG := app.Gin{C: c}
		did := c.Query("did") // 需要提供DID来查询

		if did == "" {
			appG.Response(http.StatusBadRequest, e.ERROR, gin.H{
				"error": "Missing did parameter",
			})
			return
		}

		contractName := "DID::SPECTRUM::TRADE"
		callCmd := "call " + contractName + " GetNFProfile -args " + did

		data, err := ds.SoftCall(callCmd)
		if err != nil || len(data) == 0 || data[0] == "" {
			loglogrus.Log.Errorf("NF not found: %s\n", did)
			appG.Response(http.StatusNotFound, e.ERROR, gin.H{
				"error": "NF not found",
			})
			return
		}

		c.JSON(http.StatusOK, gin.H{"data": data[0]})
	}
}

// GetPublicKey - 根据DID获取公钥 (GET /bcf/pubkey/:did)
func GetPublicKey(ds *api.DperService) func(*gin.Context) {
	return func(c *gin.Context) {
		loglogrus.Log.Infof("Http: Get user request -- GetPublicKey\n")
		appG := app.Gin{C: c}
		did := c.Param("did")

		// 查询NF Profile
		contractName := "DID::SPECTRUM::TRADE"
		callCmd := "call " + contractName + " GetNFProfile -args " + did
		data, err := ds.SoftCall(callCmd)

		if err != nil || len(data) == 0 || data[0] == "" {
			appG.Response(http.StatusNotFound, e.ERROR, gin.H{
				"error": "DID not found",
			})
			return
		}

		// 解析didDocument提取公钥
		var nfData map[string]interface{}
		if err := json.Unmarshal([]byte(data[0]), &nfData); err != nil {
			appG.Response(http.StatusInternalServerError, e.ERROR, gin.H{
				"error": "Failed to parse NF profile",
			})
			return
		}

		didDoc, ok := nfData["didDocument"].(map[string]interface{})
		if !ok {
			appG.Response(http.StatusNotFound, e.ERROR, gin.H{
				"error": "DID document not found",
			})
			return
		}

		verificationMethod, ok := didDoc["verificationMethod"].([]interface{})
		if !ok || len(verificationMethod) == 0 {
			appG.Response(http.StatusNotFound, e.ERROR, gin.H{
				"error": "No public key found",
			})
			return
		}

		// 提取公钥信息
		keyInfo, ok := verificationMethod[0].(map[string]interface{})
		if !ok {
			appG.Response(http.StatusInternalServerError, e.ERROR, gin.H{
				"error": "Invalid key format",
			})
			return
		}

		c.JSON(http.StatusOK, gin.H{
			"did":                did,
			"publicKeyMultibase": keyInfo["publicKeyMultibase"],
			"type":               keyInfo["type"],
			"controller":         keyInfo["controller"],
		})
	}
}
