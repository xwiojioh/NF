package router

import (
	"crypto"
	"crypto/ecdsa"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	loglogrus "p3Chain/log_logrus"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

// 权限常量
const (
	PermServiceDiscovery   = "service_discovery"
	PermAuditRead          = "audit_read"
	PermAuditAnchor        = "audit_anchor"
	PermSubscriptionCreate = "subscription_create"
	PermSubscriptionManage = "subscription_manage"
	PermSubscriptionDelete = "subscription_delete"

	bcfJWTIssuer               = "BCF"
	bcfJWTKeyID                = "bcf-key-001"
	defaultBCFJWTPrivateKeyHex = "4c0883a69102937d6231471b5dbb6204fe5129617082791b7b1b8a5de8c3c6d1"

	ctxCallerDID         = "caller_did"
	ctxCallerNFType      = "caller_nf_type"
	ctxCallerSessionID   = "caller_session_id"
	ctxCallerPermissions = "caller_permissions"
)

// NFTokenClaims 同时兼容旧版 HS256 token 与新版 ES256K BCF auth token。
type NFTokenClaims struct {
	DID         string   `json:"did,omitempty"`
	Permissions []string `json:"permissions,omitempty"`
	NFDID       string   `json:"nf_did,omitempty"`
	NFType      string   `json:"nf_type,omitempty"`
	SessionID   string   `json:"session_id,omitempty"`
	Scope       []string `json:"scope,omitempty"`
	jwt.RegisteredClaims
}

var (
	es256kSigningMethod     *jwt.SigningMethodECDSA
	es256kSigningMethodOnce sync.Once
	bcfJWTPrivateKey        *ecdsa.PrivateKey
	bcfJWTPrivateKeyErr     error
	bcfJWTPrivateKeyOnce    sync.Once

	ErrTokenExpired   = errors.New("token has expired")
	ErrTokenSignature = errors.New("token signature verification failed")
)

func ensureES256KSigningMethod() *jwt.SigningMethodECDSA {
	es256kSigningMethodOnce.Do(func() {
		es256kSigningMethod = &jwt.SigningMethodECDSA{
			Name:      "ES256K",
			Hash:      crypto.SHA256,
			KeySize:   32,
			CurveBits: 256,
		}
		jwt.RegisterSigningMethod(es256kSigningMethod.Alg(), func() jwt.SigningMethod {
			return es256kSigningMethod
		})
	})

	return es256kSigningMethod
}

func loadBCFJWTPrivateKey() (*ecdsa.PrivateKey, error) {
	bcfJWTPrivateKeyOnce.Do(func() {
		ensureES256KSigningMethod()

		rawHex := strings.TrimSpace(os.Getenv("BCF_JWT_PRIVATE_KEY_HEX"))
		if rawHex == "" {
			rawHex = defaultBCFJWTPrivateKeyHex
		}
		rawHex = strings.TrimPrefix(strings.TrimPrefix(rawHex, "0x"), "0X")

		keyBytes, err := hex.DecodeString(rawHex)
		if err != nil {
			bcfJWTPrivateKeyErr = fmt.Errorf("failed to decode BCF_JWT_PRIVATE_KEY_HEX: %w", err)
			return
		}
		if len(keyBytes) != 32 {
			bcfJWTPrivateKeyErr = fmt.Errorf("BCF_JWT_PRIVATE_KEY_HEX must be 32 bytes, got %d", len(keyBytes))
			return
		}

		curve := secp256k1.S256()
		d := new(big.Int).SetBytes(keyBytes)
		if d.Sign() <= 0 || d.Cmp(curve.Params().N) >= 0 {
			bcfJWTPrivateKeyErr = errors.New("BCF_JWT_PRIVATE_KEY_HEX is out of secp256k1 range")
			return
		}

		x, y := curve.ScalarBaseMult(keyBytes)
		bcfJWTPrivateKey = &ecdsa.PrivateKey{
			PublicKey: ecdsa.PublicKey{Curve: curve, X: x, Y: y},
			D:         d,
		}
	})

	return bcfJWTPrivateKey, bcfJWTPrivateKeyErr
}

func getBCFJWTPublicKey() (*ecdsa.PublicKey, error) {
	privKey, err := loadBCFJWTPrivateKey()
	if err != nil {
		return nil, err
	}

	return &privKey.PublicKey, nil
}

// getJWTSecret 从环境变量 JWT_SECRET 读取密钥，未配置时使用开发默认密钥
func getJWTSecret() []byte {
	if s := os.Getenv("JWT_SECRET"); s != "" {
		return []byte(s)
	}
	return []byte("p3chain-dev-secret-2026")
}

// isJWTAuthEnabled 返回是否开启强制鉴权（环境变量 ENABLE_JWT_AUTH=true）
func isJWTAuthEnabled() bool {
	return strings.ToLower(os.Getenv("ENABLE_JWT_AUTH")) == "true"
}

func audienceAndScopeForNFType(nfType string) ([]string, []string, error) {
	switch strings.ToUpper(strings.TrimSpace(nfType)) {
	case "AMF":
		return []string{"AUSF", "UDM", "SMF"}, []string{
			"nausf-auth:ue-authentications",
			"nudm-ueau:generate-auth-data",
			"nsmf-pdusession:create-sm-context",
		}, nil
	case "AUSF":
		return []string{"UDM"}, []string{"nudm-ueau:generate-auth-data"}, nil
	default:
		return nil, nil, fmt.Errorf("unsupported nf_type: %s", nfType)
	}
}

func defaultPermissionsForNFType(nfType string) []string {
	permissions := []string{PermServiceDiscovery, PermAuditRead, PermAuditAnchor}

	switch strings.ToUpper(strings.TrimSpace(nfType)) {
	case "AMF", "SMF", "AUSF", "UDM", "UDR", "NSSF", "PCF", "NEF", "AF":
		permissions = append(permissions,
			PermSubscriptionCreate,
			PermSubscriptionManage,
			PermSubscriptionDelete,
		)
	}

	return permissions
}

func (c *NFTokenClaims) EffectiveDID() string {
	return firstNonEmpty(strings.TrimSpace(c.NFDID), strings.TrimSpace(c.DID))
}

func (c *NFTokenClaims) EffectivePermissions() []string {
	if len(c.Permissions) > 0 {
		permissions := make([]string, len(c.Permissions))
		copy(permissions, c.Permissions)
		return permissions
	}

	return defaultPermissionsForNFType(c.NFType)
}

// GenerateBCFAuthToken 生成 BCF /nbcf_auth/v1/auth/verify 使用的 ES256K JWT。
func GenerateBCFAuthToken(nfDID, nfInstanceID, nfType, sessionID string) (string, time.Time, time.Time, error) {
	nfDID = strings.TrimSpace(nfDID)
	nfInstanceID = strings.TrimSpace(nfInstanceID)
	nfType = strings.ToUpper(strings.TrimSpace(nfType))
	sessionID = strings.TrimSpace(sessionID)

	if nfDID == "" || nfInstanceID == "" || nfType == "" || sessionID == "" {
		return "", time.Time{}, time.Time{}, errors.New("nf_did, nf_instance_id, nf_type and session_id are required")
	}

	audience, scope, err := audienceAndScopeForNFType(nfType)
	if err != nil {
		return "", time.Time{}, time.Time{}, err
	}

	issuedAt := time.Now().UTC()
	expiresAt := issuedAt.Add(1 * time.Hour)
	claims := NFTokenClaims{
		NFDID:     nfDID,
		NFType:    nfType,
		SessionID: sessionID,
		Scope:     scope,
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    bcfJWTIssuer,
			Subject:   nfInstanceID,
			Audience:  jwt.ClaimStrings(audience),
			IssuedAt:  jwt.NewNumericDate(issuedAt),
			NotBefore: jwt.NewNumericDate(issuedAt),
			ExpiresAt: jwt.NewNumericDate(expiresAt),
			ID:        uuid.NewString(),
		},
	}

	token := jwt.NewWithClaims(ensureES256KSigningMethod(), claims)
	token.Header["kid"] = bcfJWTKeyID
	token.Header["typ"] = "JWT"

	privateKey, err := loadBCFJWTPrivateKey()
	if err != nil {
		return "", time.Time{}, time.Time{}, err
	}

	signedToken, err := token.SignedString(privateKey)
	if err != nil {
		return "", time.Time{}, time.Time{}, fmt.Errorf("failed to sign ES256K token: %w", err)
	}

	return signedToken, issuedAt, expiresAt, nil
}

// GenerateNFToken 保留旧认证流程所需的 HS256 token 生成逻辑，但改为使用 jwt/v5。
func GenerateNFToken(did string, permissions []string) (string, error) {
	did = strings.TrimSpace(did)
	if did == "" {
		return "", errors.New("did cannot be empty")
	}

	now := time.Now().UTC()
	claims := NFTokenClaims{
		DID:         did,
		Permissions: permissions,
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    "p3chain-bcf",
			Subject:   did,
			IssuedAt:  jwt.NewNumericDate(now),
			NotBefore: jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(1 * time.Hour)),
			ID:        uuid.NewString(),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	token.Header["typ"] = "JWT"

	signedToken, err := token.SignedString(getJWTSecret())
	if err != nil {
		return "", fmt.Errorf("failed to sign HS256 token: %w", err)
	}

	return signedToken, nil
}

// ParseNFToken 同时支持新版 ES256K 与旧版 HS256 token。
func ParseNFToken(tokenStr string) (*NFTokenClaims, error) {
	tokenStr = strings.TrimSpace(tokenStr)
	if tokenStr == "" {
		return nil, errors.New("token cannot be empty")
	}

	ensureES256KSigningMethod()
	token, err := jwt.ParseWithClaims(tokenStr, &NFTokenClaims{}, func(token *jwt.Token) (interface{}, error) {
		switch token.Method.Alg() {
		case jwt.SigningMethodHS256.Alg():
			return getJWTSecret(), nil
		case ensureES256KSigningMethod().Alg():
			return getBCFJWTPublicKey()
		default:
			return nil, fmt.Errorf("unsupported signing algorithm: %s", token.Method.Alg())
		}
	}, jwt.WithValidMethods([]string{jwt.SigningMethodHS256.Alg(), ensureES256KSigningMethod().Alg()}))
	if err != nil {
		switch {
		case errors.Is(err, jwt.ErrTokenExpired), errors.Is(err, jwt.ErrTokenNotValidYet):
			return nil, ErrTokenExpired
		case errors.Is(err, jwt.ErrTokenSignatureInvalid):
			return nil, ErrTokenSignature
		default:
			return nil, err
		}
	}

	claims, ok := token.Claims.(*NFTokenClaims)
	if !ok || !token.Valid {
		return nil, errors.New("invalid token claims")
	}
	if claims.EffectiveDID() == "" {
		return nil, errors.New("token missing required did/nf_did claim")
	}

	return claims, nil
}

// hasPermission 判断 claims 是否包含指定权限
func hasPermission(claims *NFTokenClaims, required string) bool {
	for _, p := range claims.EffectivePermissions() {
		if p == required {
			return true
		}
	}
	return false
}

// GetCallerDID 从 gin.Context 取出由中间件注入的调用方 DID
// 若中间件未注入（禁用鉴权且无 token），返回空字符串
func GetCallerDID(c *gin.Context) string {
	v, _ := c.Get(ctxCallerDID)
	s, _ := v.(string)
	return s
}

func GetCallerNFType(c *gin.Context) string {
	v, _ := c.Get(ctxCallerNFType)
	s, _ := v.(string)
	return s
}

func GetCallerSessionID(c *gin.Context) string {
	v, _ := c.Get(ctxCallerSessionID)
	s, _ := v.(string)
	return s
}

// TokenAuthMiddleware 是 JWT 鉴权中间件
//
// requiredPerm：本路由要求的权限常量（空字符串 = 只做身份识别，不检查权限）
//
// 运行模式：
//   - ENABLE_JWT_AUTH=true  → 强制模式：无 token 或无效 token 一律 401，权限不足 403
//   - 其他（默认）          → 宽松模式：有 token 就解析并注入 DID，无 token 放行（兼容旧测试）
func TokenAuthMiddleware(requiredPerm string) gin.HandlerFunc {
	return func(c *gin.Context) {
		authHeader := c.GetHeader("Authorization")
		tokenStr := ""
		if strings.HasPrefix(authHeader, "Bearer ") {
			tokenStr = strings.TrimPrefix(authHeader, "Bearer ")
			tokenStr = strings.TrimSpace(tokenStr)
		}

		strictMode := isJWTAuthEnabled()

		if !strictMode {
			// 宽松模式：有 token 就解析注入，无 token 直接放行
			if tokenStr != "" {
				if claims, err := ParseNFToken(tokenStr); err == nil {
					c.Set(ctxCallerDID, claims.EffectiveDID())
					c.Set(ctxCallerNFType, strings.ToUpper(strings.TrimSpace(claims.NFType)))
					c.Set(ctxCallerSessionID, strings.TrimSpace(claims.SessionID))
					c.Set(ctxCallerPermissions, claims.EffectivePermissions())
					loglogrus.Log.Infof("TokenAuth(loose): caller DID=%s\n", claims.EffectiveDID())
				} else {
					loglogrus.Log.Warnf("TokenAuth(loose): token parse failed: %v\n", err)
				}
			}
			c.Next()
			return
		}

		// 严格模式
		if tokenStr == "" {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
				"error":   "MISSING_TOKEN",
				"message": "Authorization: Bearer <token> header is required",
			})
			return
		}

		claims, err := ParseNFToken(tokenStr)
		if err != nil {
			errCode := "INVALID_TOKEN"
			if errors.Is(err, ErrTokenExpired) {
				errCode = "TOKEN_EXPIRED"
			} else if errors.Is(err, ErrTokenSignature) {
				errCode = "INVALID_SIGNATURE"
			}
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
				"error":   errCode,
				"message": err.Error(),
			})
			return
		}

		if requiredPerm != "" && !hasPermission(claims, requiredPerm) {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{
				"error":   "INSUFFICIENT_PERMISSIONS",
				"message": "Token does not have required permission: " + requiredPerm,
			})
			return
		}

		c.Set(ctxCallerDID, claims.EffectiveDID())
		c.Set(ctxCallerNFType, strings.ToUpper(strings.TrimSpace(claims.NFType)))
		c.Set(ctxCallerSessionID, strings.TrimSpace(claims.SessionID))
		c.Set(ctxCallerPermissions, claims.EffectivePermissions())
		loglogrus.Log.Infof("TokenAuth: caller DID=%s perm=%s\n", claims.EffectiveDID(), requiredPerm)
		c.Next()
	}
}
