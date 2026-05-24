package router

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"p3Chain/api"
	"p3Chain/common"
	"p3Chain/crypto"
	"p3Chain/ginHttp/pkg/app"
	e "p3Chain/ginHttp/pkg/error"
	loglogrus "p3Chain/log_logrus"
	"strings"
	"time"
	"unicode"

	"github.com/gin-gonic/gin"
)

type CreateChallengeRequest struct {
	DID          string `json:"did"`
	NFInstanceID string `json:"nfInstanceId"`
}

type VerifyChallengeRequest struct {
	DID         string `json:"did"`
	ChallengeID string `json:"challengeId"`
	Nonce       string `json:"nonce"`
	Signature   string `json:"signature"`
}

type authChallengeRecord struct {
	DID         string `json:"did"`
	ChallengeID string `json:"challengeId"`
	Nonce       string `json:"nonce"`
	IssuedAt    string `json:"issuedAt"`
	ExpiresAt   string `json:"expiresAt"`
	Status      string `json:"status"`
}

type authStateRecord struct {
	DID           string   `json:"did"`
	ChallengeID   string   `json:"challengeId"`
	AuthStatus    string   `json:"authStatus"`
	Signature     string   `json:"signature,omitempty"`
	VerifiedAt    string   `json:"verifiedAt,omitempty"`
	ExpiresAt     string   `json:"expiresAt,omitempty"`
	FailureReason string   `json:"failureReason,omitempty"`
	Permissions   []string `json:"permissions,omitempty"`
	TokenID       string   `json:"tokenId,omitempty"`
}

func randomHex(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

func getNFProfileByDID(ds *api.DperService, did string) (map[string]interface{}, error) {
	contractName := "DID::SPECTRUM::TRADE"
	callCmd := "call " + contractName + " GetNFProfile -args " + did
	data, err := ds.SoftCall(callCmd)
	if err != nil {
		return nil, err
	}
	if len(data) == 0 || data[0] == "" {
		return nil, errNFProfileNotFound
	}

	var profile map[string]interface{}
	if err := json.Unmarshal([]byte(data[0]), &profile); err != nil {
		return nil, err
	}
	return profile, nil
}

func getStoredAuthChallenge(ds *api.DperService, did string) (*authChallengeRecord, error) {
	contractName := "DID::SPECTRUM::TRADE"
	callCmd := "call " + contractName + " GetAuthChallenge -args " + did
	data, err := ds.SoftCall(callCmd)
	if err != nil || len(data) == 0 || data[0] == "" {
		return nil, fmt.Errorf("auth challenge not found")
	}

	var challenge authChallengeRecord
	if err := json.Unmarshal([]byte(data[0]), &challenge); err != nil {
		return nil, err
	}
	return &challenge, nil
}

func extractAddressFromNFProfile(profile map[string]interface{}) (string, error) {
	didDoc, ok := profile["didDocument"].(map[string]interface{})
	if !ok {
		return "", fmt.Errorf("didDocument not found")
	}

	vms, ok := didDoc["verificationMethod"].([]interface{})
	if !ok || len(vms) == 0 {
		return "", fmt.Errorf("verificationMethod not found")
	}

	for _, item := range vms {
		vm, ok := item.(map[string]interface{})
		if !ok {
			continue
		}
		if addr, ok := vm["blockchainAccountId"].(string); ok && strings.TrimSpace(addr) != "" {
			return strings.TrimSpace(addr), nil
		}
	}

	return "", fmt.Errorf("blockchainAccountId not found in didDocument.verificationMethod")
}

func authSigningContent(did, challengeID, nonce string) string {
	return did + ":" + challengeID + ":" + nonce
}

func normalizeHexSignature(sig string) string {
	sig = strings.TrimSpace(sig)
	sig = strings.TrimPrefix(sig, "0x")
	sig = strings.TrimPrefix(sig, "0X")
	return sig
}

func looksLikeHex(s string) bool {
	if len(s) == 0 {
		return false
	}
	for _, r := range s {
		if !unicode.IsDigit(r) && (r < 'a' || r > 'f') && (r < 'A' || r > 'F') {
			return false
		}
	}
	return true
}

func permissionsForNFProfile(profile map[string]interface{}) []string {
	permissions := []string{PermServiceDiscovery, PermAuditRead, PermAuditAnchor}

	nfProfile, _ := profile["nfProfile"].(map[string]interface{})
	nfType, _ := nfProfile["nfType"].(string)
	nfType = strings.ToUpper(strings.TrimSpace(nfType))

	switch nfType {
	case "AMF", "SMF", "AUSF", "UDM", "UDR", "NSSF", "PCF", "NEF", "AF":
		permissions = append(permissions,
			PermSubscriptionCreate,
			PermSubscriptionManage,
			PermSubscriptionDelete,
		)
	default:
		// 未识别类型至少保留发现权限，避免签发全空权限 token
	}

	return permissions
}

func CreateChallenge(ds *api.DperService) func(*gin.Context) {
	return func(c *gin.Context) {
		appG := app.Gin{C: c}

		var req CreateChallengeRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			appG.Response(http.StatusBadRequest, e.INVALID_PARAMS, gin.H{"error": "invalid request body"})
			return
		}
		if req.DID == "" {
			appG.Response(http.StatusBadRequest, e.INVALID_PARAMS, gin.H{"error": "did is required"})
			return
		}

		if _, _, err := getNFProfileByDIDWithFallback(ds, req.DID, 5, 200*time.Millisecond); err != nil {
			appG.Response(http.StatusNotFound, e.ERROR, gin.H{"error": "NF profile not found for did"})
			return
		}

		nonce, err := randomHex(16)
		if err != nil {
			appG.Response(http.StatusInternalServerError, e.ERROR, gin.H{"error": "failed to generate nonce"})
			return
		}
		challengeSuffix, err := randomHex(8)
		if err != nil {
			appG.Response(http.StatusInternalServerError, e.ERROR, gin.H{"error": "failed to generate challenge id"})
			return
		}

		now := time.Now().UTC()
		challenge := authChallengeRecord{
			DID:         req.DID,
			ChallengeID: "chal-" + challengeSuffix,
			Nonce:       nonce,
			IssuedAt:    now.Format(time.RFC3339),
			ExpiresAt:   now.Add(5 * time.Minute).Format(time.RFC3339),
			Status:      "PENDING",
		}

		challengeJSON, err := json.Marshal(challenge)
		if err != nil {
			appG.Response(http.StatusInternalServerError, e.ERROR, gin.H{"error": "failed to marshal challenge"})
			return
		}

		invokeCmd := "invoke DID::SPECTRUM::TRADE CreateAuthChallenge -args " +
			api.QuoteCommandArg(req.DID) + " " + api.QuoteCommandArg(string(challengeJSON))
		receipt, err := ds.SoftInvoke(invokeCmd)
		if err != nil {
			appG.Response(http.StatusInternalServerError, e.ERROR, gin.H{"error": "failed to store auth challenge", "detail": err.Error()})
			return
		}

		loglogrus.Log.Infof("CreateChallenge: did=%s challengeId=%s valid=%v\n", req.DID, challenge.ChallengeID, receipt.Valid)
		c.JSON(http.StatusCreated, challenge)
	}
}

func VerifyChallenge(ds *api.DperService) func(*gin.Context) {
	return func(c *gin.Context) {
		appG := app.Gin{C: c}

		var req VerifyChallengeRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			appG.Response(http.StatusBadRequest, e.INVALID_PARAMS, gin.H{"error": "invalid request body"})
			return
		}
		if req.DID == "" || req.ChallengeID == "" || req.Nonce == "" || req.Signature == "" {
			appG.Response(http.StatusBadRequest, e.INVALID_PARAMS, gin.H{"error": "did, challengeId, nonce and signature are required"})
			return
		}

		challenge, err := getStoredAuthChallenge(ds, req.DID)
		if err != nil {
			appG.Response(http.StatusNotFound, e.ERROR, gin.H{"error": "auth challenge not found"})
			return
		}
		if challenge.ChallengeID != req.ChallengeID || challenge.Nonce != req.Nonce {
			appG.Response(http.StatusUnauthorized, e.ERROR, gin.H{"error": "challenge does not match"})
			return
		}
		if challenge.Status != "PENDING" {
			appG.Response(http.StatusUnauthorized, e.ERROR, gin.H{"error": "challenge is not pending", "status": challenge.Status})
			return
		}

		expiresAt, err := time.Parse(time.RFC3339, challenge.ExpiresAt)
		if err != nil {
			appG.Response(http.StatusInternalServerError, e.ERROR, gin.H{"error": "invalid challenge expiry format"})
			return
		}
		if time.Now().UTC().After(expiresAt) {
			state := authStateRecord{
				DID:           req.DID,
				ChallengeID:   req.ChallengeID,
				AuthStatus:    "FAILED",
				FailureReason: "challenge expired",
			}
			stateJSON, _ := json.Marshal(state)
			_, _ = ds.SoftInvoke("invoke DID::SPECTRUM::TRADE VerifyAuthChallenge -args " +
				api.QuoteCommandArg(req.DID) + " " + api.QuoteCommandArg(string(stateJSON)))
			appG.Response(http.StatusUnauthorized, e.ERROR, gin.H{"error": "challenge expired"})
			return
		}

		profile, _, err := getNFProfileByDIDWithFallback(ds, req.DID, 5, 200*time.Millisecond)
		if err != nil {
			appG.Response(http.StatusNotFound, e.ERROR, gin.H{"error": "NF profile not found for did"})
			return
		}

		addressStr, err := extractAddressFromNFProfile(profile)
		if err != nil {
			appG.Response(http.StatusBadRequest, e.ERROR, gin.H{"error": "no blockchainAccountId found in didDocument", "detail": err.Error()})
			return
		}

		signingContent := authSigningContent(req.DID, req.ChallengeID, req.Nonce)
		hash := crypto.Sha3Hash([]byte(signingContent))
		normalizedSig := normalizeHexSignature(req.Signature)
		if !looksLikeHex(normalizedSig) {
			appG.Response(http.StatusBadRequest, e.INVALID_PARAMS, gin.H{"error": "signature must be hex string"})
			return
		}
		sig := common.Hex2Bytes(normalizedSig)
		ok, err := crypto.SignatureValid(common.HexToAddress(addressStr), sig, hash)
		if err != nil || !ok {
			state := authStateRecord{
				DID:           req.DID,
				ChallengeID:   req.ChallengeID,
				AuthStatus:    "FAILED",
				Signature:     req.Signature,
				FailureReason: "signature verification failed",
			}
			stateJSON, _ := json.Marshal(state)
			_, _ = ds.SoftInvoke("invoke DID::SPECTRUM::TRADE VerifyAuthChallenge -args " +
				api.QuoteCommandArg(req.DID) + " " + api.QuoteCommandArg(string(stateJSON)))
			appG.Response(http.StatusUnauthorized, e.ERROR, gin.H{"error": "signature verification failed"})
			return
		}

		permissions := permissionsForNFProfile(profile)
		token, err := GenerateNFToken(req.DID, permissions)
		if err != nil {
			appG.Response(http.StatusInternalServerError, e.ERROR, gin.H{"error": "failed to generate token"})
			return
		}

		verifiedAt := time.Now().UTC()
		tokenID, _ := randomHex(8)
		state := authStateRecord{
			DID:         req.DID,
			ChallengeID: req.ChallengeID,
			AuthStatus:  "AUTHENTICATED",
			Signature:   req.Signature,
			VerifiedAt:  verifiedAt.Format(time.RFC3339),
			ExpiresAt:   verifiedAt.Add(1 * time.Hour).Format(time.RFC3339),
			Permissions: permissions,
			TokenID:     "tok-" + tokenID,
		}
		stateJSON, err := json.Marshal(state)
		if err != nil {
			appG.Response(http.StatusInternalServerError, e.ERROR, gin.H{"error": "failed to marshal auth state"})
			return
		}

		_, err = ds.SoftInvoke("invoke DID::SPECTRUM::TRADE VerifyAuthChallenge -args " +
			api.QuoteCommandArg(req.DID) + " " + api.QuoteCommandArg(string(stateJSON)))
		if err != nil {
			appG.Response(http.StatusInternalServerError, e.ERROR, gin.H{"error": "failed to persist auth state", "detail": err.Error()})
			return
		}

		SubmitAudit(c, GetAuditService(), &api.AuditEvent{
			OperatorDID:    req.DID,
			OperationType:  "AUTH_VERIFY",
			TargetObjectID: req.ChallengeID,
			Result:         "SUCCESS",
			ResultCode:     http.StatusOK,
			Metadata: map[string]string{
				"verify_mode": "challenge",
				"token_id":    state.TokenID,
			},
		})

		c.JSON(http.StatusOK, gin.H{
			"did":         req.DID,
			"authStatus":  "AUTHENTICATED",
			"challengeId": req.ChallengeID,
			"token":       token,
			"tokenType":   "Bearer",
			"expiresIn":   3600,
		})
	}
}

func GetAuthState(ds *api.DperService) func(*gin.Context) {
	return func(c *gin.Context) {
		appG := app.Gin{C: c}
		did := c.Param("did")
		if did == "" {
			appG.Response(http.StatusBadRequest, e.INVALID_PARAMS, gin.H{"error": "did is required"})
			return
		}

		callCmd := "call DID::SPECTRUM::TRADE GetAuthState -args " + did
		data, err := ds.SoftCall(callCmd)
		if err != nil || len(data) == 0 || data[0] == "" {
			appG.Response(http.StatusNotFound, e.ERROR, gin.H{"error": "auth state not found"})
			return
		}

		var state map[string]interface{}
		if err := json.Unmarshal([]byte(data[0]), &state); err != nil {
			appG.Response(http.StatusInternalServerError, e.ERROR, gin.H{"error": "failed to parse auth state"})
			return
		}

		c.JSON(http.StatusOK, state)
	}
}
