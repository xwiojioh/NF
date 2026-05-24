package router

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/asn1"
	"encoding/hex"
	"math/big"
	"net/http"
	"strings"
	"sync"
	"time"

	"p3Chain/api"
	loglogrus "p3Chain/log_logrus"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

// =============================================================================
// 会话存储（内存，进程内有效）
// =============================================================================

type bcfAuthSession struct {
	NFDID        string
	NFType       string
	NFInstanceID string
	Challenge    string // hex 编码的随机挑战值
	ExpiresAt    time.Time
}

var (
	bcfSessionStore = make(map[string]*bcfAuthSession)
	bcfSessionMu    sync.Mutex
)

// =============================================================================
// Base58 解码（用于解析 multibase z-prefix 公钥）
// =============================================================================

const base58AlphabetStr = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

func base58Decode(s string) ([]byte, error) {
	alphabet := []byte(base58AlphabetStr)
	alphabetIdx := make(map[byte]int)
	for i, c := range alphabet {
		alphabetIdx[c] = i
	}

	n := new(big.Int)
	base := big.NewInt(58)
	for i := 0; i < len(s); i++ {
		idx, ok := alphabetIdx[s[i]]
		if !ok {
			return nil, nil
		}
		n.Mul(n, base)
		n.Add(n, big.NewInt(int64(idx)))
	}

	decoded := n.Bytes()

	// 计算前导 1（对应 0x00 字节）
	leading := 0
	for _, c := range []byte(s) {
		if c == '1' {
			leading++
		} else {
			break
		}
	}

	result := make([]byte, leading+len(decoded))
	copy(result[leading:], decoded)
	return result, nil
}

// multibaseToBytes 将 multibase 编码的公钥转换为字节 (仅支持 z-prefix = base58btc)
func multibaseToBytes(multibase string) ([]byte, error) {
	if len(multibase) == 0 || multibase[0] != 'z' {
		return nil, nil
	}
	return base58Decode(multibase[1:])
}

// =============================================================================
// secp256k1 压缩公钥解压缩
// =============================================================================

var (
	// secp256k1 曲线参数
	secp256k1P, _  = new(big.Int).SetString("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F", 16)
	secp256k1N, _  = new(big.Int).SetString("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141", 16)
	secp256k1B     = big.NewInt(7)
	secp256k1Gx, _ = new(big.Int).SetString("79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798", 16)
	secp256k1Gy, _ = new(big.Int).SetString("483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8", 16)
)

// decompressSecp256k1Point 解压缩 secp256k1 压缩公钥
// 输入：33 字节（02/03 + 32字节x坐标）
// 输出：x, y 坐标
func decompressSecp256k1Point(compressed []byte) (x, y *big.Int) {
	if len(compressed) != 33 {
		return nil, nil
	}
	prefix := compressed[0]
	if prefix != 0x02 && prefix != 0x03 {
		return nil, nil
	}

	p := secp256k1P
	x = new(big.Int).SetBytes(compressed[1:])

	// y² = x³ + 7 (mod p)
	y2 := new(big.Int).Mul(x, x)
	y2.Mod(y2, p)
	y2.Mul(y2, x)
	y2.Mod(y2, p)
	y2.Add(y2, secp256k1B)
	y2.Mod(y2, p)

	// y = y2^((p+1)/4) mod p  （secp256k1 的 p ≡ 3 mod 4）
	exp := new(big.Int).Add(p, big.NewInt(1))
	exp.Rsh(exp, 2)
	y = new(big.Int).Exp(y2, exp, p)

	// 根据前缀调整奇偶性
	yIsOdd := y.Bit(0) == 1
	if (prefix == 0x02 && yIsOdd) || (prefix == 0x03 && !yIsOdd) {
		y.Sub(p, y)
	}

	return x, y
}

// =============================================================================
// ECDSA secp256k1 DER 签名验证
// =============================================================================

type ecdsaSig struct {
	R, S *big.Int
}

// verifySecp256k1DER 验证 secp256k1 ECDSA DER 编码的签名
// challengeHex: hex 编码的挑战值
// signatureHex: hex 编码的 DER 格式签名
// pubKeyBytes:  33字节压缩或65字节非压缩公钥
func verifySecp256k1DER(challengeHex, signatureHex string, pubKeyBytes []byte) bool {
	// Step 1: challenge hex → 字节
	challengeBytes, err := hex.DecodeString(challengeHex)
	if err != nil {
		loglogrus.Log.Errorf("[BCF Auth] Failed to decode challenge hex: %v", err)
		return false
	}

	// Step 2: SHA256(challenge_bytes)
	hashBytes := sha256.Sum256(challengeBytes)
	hash := hashBytes[:]

	// Step 3: 解码 DER 签名 hex
	sigBytes, err := hex.DecodeString(signatureHex)
	if err != nil {
		loglogrus.Log.Errorf("[BCF Auth] Failed to decode signature hex: %v", err)
		return false
	}

	// Step 4: 解析 ASN1/DER 编码的签名，提取 r, s
	var sig ecdsaSig
	if _, err := asn1.Unmarshal(sigBytes, &sig); err != nil {
		loglogrus.Log.Errorf("[BCF Auth] Failed to parse DER signature: %v", err)
		return false
	}

	// Step 5: 解析公钥
	var xCoord, yCoord *big.Int
	switch len(pubKeyBytes) {
	case 33:
		xCoord, yCoord = decompressSecp256k1Point(pubKeyBytes)
	case 65:
		if pubKeyBytes[0] != 0x04 {
			loglogrus.Log.Errorf("[BCF Auth] Invalid uncompressed pubkey prefix: %02x", pubKeyBytes[0])
			return false
		}
		xCoord = new(big.Int).SetBytes(pubKeyBytes[1:33])
		yCoord = new(big.Int).SetBytes(pubKeyBytes[33:65])
	default:
		loglogrus.Log.Errorf("[BCF Auth] Invalid pubkey length: %d", len(pubKeyBytes))
		return false
	}

	if xCoord == nil || yCoord == nil {
		loglogrus.Log.Errorf("[BCF Auth] Failed to parse public key point")
		return false
	}

	// Step 6: secp256k1 ECDSA verify（手动实现，不依赖 elliptic.Curve 接口）
	return secp256k1ECDSAVerify(hash, sig.R, sig.S, xCoord, yCoord)
}

// secp256k1ECDSAVerify 手动实现 secp256k1 ECDSA 验签
// 标准验签算法：https://en.wikipedia.org/wiki/Elliptic_Curve_Digital_Signature_Algorithm
func secp256k1ECDSAVerify(hash []byte, r, s, pubX, pubY *big.Int) bool {
	p := secp256k1P
	n := secp256k1N
	gx := secp256k1Gx
	gy := secp256k1Gy

	// 基本检查
	if r.Sign() <= 0 || r.Cmp(n) >= 0 {
		return false
	}
	if s.Sign() <= 0 || s.Cmp(n) >= 0 {
		return false
	}

	// e = hash（作为整数）
	e := new(big.Int).SetBytes(hash)

	// w = s^{-1} mod n
	w := new(big.Int).ModInverse(s, n)
	if w == nil {
		return false
	}

	// u1 = e*w mod n, u2 = r*w mod n
	u1 := new(big.Int).Mul(e, w)
	u1.Mod(u1, n)
	u2 := new(big.Int).Mul(r, w)
	u2.Mod(u2, n)

	// (x1, y1) = u1*G + u2*Q
	x1g, y1g := scalarMult(gx, gy, u1.Bytes(), p)
	x2q, y2q := scalarMult(pubX, pubY, u2.Bytes(), p)
	x1, _ := pointAdd(x1g, y1g, x2q, y2q, p)

	if x1 == nil {
		return false
	}

	x1.Mod(x1, n)
	return x1.Cmp(r) == 0
}

// pointAdd 椭圆曲线点加法（仿射坐标）
func pointAdd(x1, y1, x2, y2, p *big.Int) (*big.Int, *big.Int) {
	if x1 == nil {
		return x2, y2
	}
	if x2 == nil {
		return x1, y1
	}

	if x1.Cmp(x2) == 0 {
		if y1.Cmp(y2) != 0 {
			return nil, nil // 无穷远点
		}
		return pointDouble(x1, y1, p)
	}

	// λ = (y2-y1) / (x2-x1) mod p
	dy := new(big.Int).Sub(y2, y1)
	dx := new(big.Int).Sub(x2, x1)
	invDx := new(big.Int).ModInverse(dx, p)
	if invDx == nil {
		return nil, nil
	}
	lam := new(big.Int).Mul(dy, invDx)
	lam.Mod(lam, p)

	// x3 = λ²-x1-x2
	x3 := new(big.Int).Mul(lam, lam)
	x3.Sub(x3, x1)
	x3.Sub(x3, x2)
	x3.Mod(x3, p)

	// y3 = λ(x1-x3) - y1
	y3 := new(big.Int).Sub(x1, x3)
	y3.Mul(lam, y3)
	y3.Sub(y3, y1)
	y3.Mod(y3, p)

	return x3, y3
}

// pointDouble 椭圆曲线点倍加（仿射坐标，secp256k1 a=0）
func pointDouble(x, y, p *big.Int) (*big.Int, *big.Int) {
	// λ = 3x²/(2y) mod p
	x2 := new(big.Int).Mul(x, x)
	x2.Mul(x2, big.NewInt(3))
	x2.Mod(x2, p)

	inv2y := new(big.Int).Mul(big.NewInt(2), y)
	inv2y.ModInverse(inv2y, p)

	lam := new(big.Int).Mul(x2, inv2y)
	lam.Mod(lam, p)

	x3 := new(big.Int).Mul(lam, lam)
	x3.Sub(x3, x)
	x3.Sub(x3, x)
	x3.Mod(x3, p)

	y3 := new(big.Int).Sub(x, x3)
	y3.Mul(lam, y3)
	y3.Sub(y3, y)
	y3.Mod(y3, p)

	return x3, y3
}

// scalarMult 标量乘法（double-and-add）
func scalarMult(bx, by *big.Int, scalar []byte, p *big.Int) (*big.Int, *big.Int) {
	var rx, ry *big.Int
	tx, ty := new(big.Int).Set(bx), new(big.Int).Set(by)

	for _, b := range scalar {
		for i := 7; i >= 0; i-- {
			if rx != nil {
				rx, ry = pointDouble(rx, ry, p)
			}
			if (b>>uint(i))&1 == 1 {
				if rx == nil {
					rx, ry = new(big.Int).Set(tx), new(big.Int).Set(ty)
				} else {
					rx, ry = pointAdd(rx, ry, tx, ty, p)
				}
			}
		}
	}
	return rx, ry
}

// =============================================================================
// 从 NF Profile JSON 中提取公钥 multibase
// =============================================================================

func extractPublicKeyMultibase(nfData map[string]interface{}) string {
	// nfData 结构：{ "nfProfile": {...}, "didDocument": {...} }
	// didDocument.verificationMethod[0].publicKeyMultibase

	didDoc, ok := nfData["didDocument"].(map[string]interface{})
	if !ok {
		// 有时候整个数据直接是 NFStorageData 的 JSON，需要再解析一层
		return ""
	}

	vmList, ok := didDoc["verificationMethod"].([]interface{})
	if !ok || len(vmList) == 0 {
		return ""
	}

	vm, ok := vmList[0].(map[string]interface{})
	if !ok {
		return ""
	}

	pkm, ok := vm["publicKeyMultibase"].(string)
	if !ok {
		return ""
	}

	return pkm
}

func extractRegisteredNFIdentity(nfData map[string]interface{}) (string, string) {
	nfProfile, ok := nfData["nfProfile"].(map[string]interface{})
	if !ok || nfProfile == nil {
		return "", ""
	}

	nfType := strings.ToUpper(strings.TrimSpace(getStringField(nfProfile, "nfType", "nf_type")))
	nfInstanceID := strings.TrimSpace(getStringField(nfProfile, "nfInstanceId", "nf_instance_id"))
	return nfType, nfInstanceID
}

// =============================================================================
// Handler: POST /nbcf_auth/v1/auth/init
// =============================================================================

// BcfAuthInit 处理 NF 认证初始化请求
// 验证 DID 是否已注册，返回随机挑战值（challenge）
func BcfAuthInit(ds *api.DperService) func(*gin.Context) {
	return func(c *gin.Context) {
		loglogrus.Log.Infof("[BCF Auth] Received auth/init request\n")

		var req struct {
			NFDID        string `json:"nf_did"`
			NFType       string `json:"nf_type"`
			NFInstanceID string `json:"nf_instance_id"`
			TimestampMs  uint64 `json:"timestamp_ms"`
		}

		if err := c.ShouldBindJSON(&req); err != nil {
			loglogrus.Log.Errorf("[BCF Auth] auth/init: invalid request body: %v\n", err)
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request body"})
			return
		}

		if req.NFDID == "" {
			loglogrus.Log.Errorf("[BCF Auth] auth/init: missing nf_did\n")
			c.JSON(http.StatusBadRequest, gin.H{"error": "missing nf_did"})
			return
		}

		req.NFType = strings.ToUpper(strings.TrimSpace(req.NFType))
		req.NFInstanceID = strings.TrimSpace(req.NFInstanceID)

		loglogrus.Log.Infof("[BCF Auth] auth/init: nf_did=%s, nf_type=%s\n", req.NFDID, req.NFType)

		_, profileSource, err := getNFProfileByDIDWithFallback(ds, req.NFDID, 5, 200*time.Millisecond)
		if err != nil {
			if err == errNFProfileNotFound {
				loglogrus.Log.Errorf("[BCF Auth] auth/init: DID not found in blockchain or pending cache: %s\n", req.NFDID)
				c.JSON(http.StatusNotFound, gin.H{"error": "DID not registered in BCF"})
				return
			}

			loglogrus.Log.Errorf("[BCF Auth] auth/init: failed to resolve DID %s: %v\n", req.NFDID, err)
			c.JSON(http.StatusServiceUnavailable, gin.H{"error": "BCF blockchain not ready", "details": err.Error()})
			return
		}

		loglogrus.Log.Infof("[BCF Auth] auth/init: NF profile resolved via %s for DID %s\n", profileSource, req.NFDID)

		if profileSource == "pending-cache" {
			loglogrus.Log.Warnf("[BCF Auth] auth/init: using pending cached NF profile for DID %s while waiting for blockchain visibility\n", req.NFDID)
		}

		// 生成 32 字节随机挑战值
		challengeRaw := make([]byte, 32)
		if _, err := rand.Read(challengeRaw); err != nil {
			loglogrus.Log.Errorf("[BCF Auth] auth/init: failed to generate challenge: %v\n", err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "internal error"})
			return
		}
		challengeHex := hex.EncodeToString(challengeRaw)

		// 创建会话（30秒有效期）
		sessionID := uuid.New().String()
		expiresAt := time.Now().Add(30 * time.Second)

		bcfSessionMu.Lock()
		bcfSessionStore[sessionID] = &bcfAuthSession{
			NFDID:        req.NFDID,
			NFType:       req.NFType,
			NFInstanceID: req.NFInstanceID,
			Challenge:    challengeHex,
			ExpiresAt:    expiresAt,
		}
		bcfSessionMu.Unlock()

		now := uint64(time.Now().UnixMilli())
		loglogrus.Log.Infof("[BCF Auth] auth/init: session_id=%s created for did=%s\n", sessionID, req.NFDID)

		c.JSON(http.StatusOK, gin.H{
			"session_id":           sessionID,
			"challenge":            challengeHex,
			"challenge_expires_ms": now + 30000,
			"timestamp_ms":         now,
		})
	}
}

// =============================================================================
// Handler: POST /nbcf_auth/v1/auth/verify
// =============================================================================

// BcfAuthVerify 处理 NF 认证验证请求
// 验证 NF 对 challenge 的签名，成功则签发 auth_token
func BcfAuthVerify(ds *api.DperService) func(*gin.Context) {
	return func(c *gin.Context) {
		loglogrus.Log.Infof("[BCF Auth] Received auth/verify request\n")

		var req struct {
			SessionID          string `json:"session_id"`
			NFDID              string `json:"nf_did"`
			NFType             string `json:"nf_type"`
			NFInstanceID       string `json:"nf_instance_id"`
			ChallengeSignature string `json:"challenge_signature"`
			TimestampMs        uint64 `json:"timestamp_ms"`
		}

		if err := c.ShouldBindJSON(&req); err != nil {
			loglogrus.Log.Errorf("[BCF Auth] auth/verify: invalid request body: %v\n", err)
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request body"})
			return
		}

		req.NFDID = strings.TrimSpace(req.NFDID)
		req.NFType = strings.ToUpper(strings.TrimSpace(req.NFType))
		req.NFInstanceID = strings.TrimSpace(req.NFInstanceID)

		if req.SessionID == "" || req.NFDID == "" || req.ChallengeSignature == "" {
			loglogrus.Log.Errorf("[BCF Auth] auth/verify: missing required fields (session_id/nf_did/challenge_signature)\n")
			c.JSON(http.StatusBadRequest, gin.H{"error": "missing required fields"})
			return
		}

		loglogrus.Log.Infof("[BCF Auth] auth/verify: session_id=%s, nf_did=%s, nf_type=%s, nf_instance_id=%s\n",
			req.SessionID, req.NFDID, req.NFType, req.NFInstanceID)

		// 查找并取出会话（一次性消费）
		bcfSessionMu.Lock()
		session, ok := bcfSessionStore[req.SessionID]
		if ok {
			delete(bcfSessionStore, req.SessionID)
		}
		bcfSessionMu.Unlock()

		if !ok {
			loglogrus.Log.Errorf("[BCF Auth] auth/verify: session not found: %s\n", req.SessionID)
			c.JSON(http.StatusNotFound, gin.H{
				"success":       false,
				"error_code":    "SESSION_NOT_FOUND",
				"error_message": "session not found or already used",
			})
			return
		}

		// 检查会话是否过期
		if time.Now().After(session.ExpiresAt) {
			loglogrus.Log.Errorf("[BCF Auth] auth/verify: session expired: %s\n", req.SessionID)
			c.JSON(http.StatusGone, gin.H{
				"success":       false,
				"error_code":    "CHALLENGE_EXPIRED",
				"error_message": "challenge has expired",
			})
			return
		}

		// 验证 DID 一致性
		if session.NFDID != req.NFDID {
			loglogrus.Log.Errorf("[BCF Auth] auth/verify: DID mismatch: session=%s, req=%s\n", session.NFDID, req.NFDID)
			c.JSON(http.StatusUnauthorized, gin.H{
				"success":       false,
				"error_code":    "DID_MISMATCH",
				"error_message": "DID does not match session",
			})
			return
		}

		if req.NFType == "" && session.NFType != "" {
			// OAI C++ 客户端 verify 阶段不发送 nf_type，从 init 阶段的 session 中回填
			req.NFType = strings.ToUpper(session.NFType)
			loglogrus.Log.Infof("[BCF Auth] auth/verify: nf_type not provided by client, using session value: %s\n", req.NFType)
		} else if session.NFType != "" && !strings.EqualFold(session.NFType, req.NFType) {
			loglogrus.Log.Errorf("[BCF Auth] auth/verify: nf_type mismatch: session=%s, req=%s\n", session.NFType, req.NFType)
			c.JSON(http.StatusUnauthorized, gin.H{
				"success":       false,
				"error_code":    "NF_TYPE_MISMATCH",
				"error_message": "nf_type does not match session",
			})
			return
		}

		// nf_instance_id 由 session 权威提供，客户端无需在 verify 阶段发送
		if session.NFInstanceID != "" {
			if req.NFInstanceID != "" && req.NFInstanceID != session.NFInstanceID {
				loglogrus.Log.Errorf("[BCF Auth] auth/verify: nf_instance_id mismatch: session=%s, req=%s\n", session.NFInstanceID, req.NFInstanceID)
				c.JSON(http.StatusUnauthorized, gin.H{
					"success":       false,
					"error_code":    "NF_INSTANCE_MISMATCH",
					"error_message": "nf_instance_id does not match session",
				})
				return
			}
			req.NFInstanceID = session.NFInstanceID
		}

		nfData, profileSource, err := getNFProfileByDIDWithFallback(ds, req.NFDID, 5, 200*time.Millisecond)
		if err != nil {
			if err == errNFProfileNotFound {
				loglogrus.Log.Errorf("[BCF Auth] auth/verify: DID not found in blockchain or pending cache: %s\n", req.NFDID)
				c.JSON(http.StatusNotFound, gin.H{
					"success":       false,
					"error_code":    "DID_NOT_FOUND",
					"error_message": "DID not found in blockchain",
				})
				return
			}

			loglogrus.Log.Errorf("[BCF Auth] auth/verify: failed to resolve DID %s: %v\n", req.NFDID, err)
			c.JSON(http.StatusServiceUnavailable, gin.H{
				"success":       false,
				"error_code":    "BLOCKCHAIN_NOT_READY",
				"error_message": err.Error(),
			})
			return
		}

		loglogrus.Log.Infof("[BCF Auth] auth/verify: NF profile resolved via %s for DID %s\n", profileSource, req.NFDID)
		if profileSource == "pending-cache" {
			loglogrus.Log.Warnf("[BCF Auth] auth/verify: using pending cached NF profile for DID %s while waiting for blockchain visibility\n", req.NFDID)
		}

		registeredNFType, registeredNFInstanceID := extractRegisteredNFIdentity(nfData)
		if req.NFType == "" && registeredNFType != "" {
			// session 中也没有 nf_type，降级从链上注册的 NF Profile 中获取
			req.NFType = registeredNFType
			loglogrus.Log.Infof("[BCF Auth] auth/verify: nf_type resolved from registered NF profile: %s\n", req.NFType)
		} else if registeredNFType != "" && !strings.EqualFold(registeredNFType, req.NFType) {
			loglogrus.Log.Errorf("[BCF Auth] auth/verify: nf_type mismatch with registered profile: registered=%s, req=%s\n", registeredNFType, req.NFType)
			c.JSON(http.StatusUnauthorized, gin.H{
				"success":       false,
				"error_code":    "NF_TYPE_MISMATCH",
				"error_message": "nf_type does not match registered NF profile",
			})
			return
		}
		if req.NFType == "" {
			loglogrus.Log.Errorf("[BCF Auth] auth/verify: cannot determine nf_type for DID: %s\n", req.NFDID)
			c.JSON(http.StatusBadRequest, gin.H{
				"success":       false,
				"error_code":    "NF_TYPE_UNKNOWN",
				"error_message": "nf_type could not be determined from session or registered profile",
			})
			return
		}
		if registeredNFInstanceID != "" && registeredNFInstanceID != req.NFInstanceID {
			loglogrus.Log.Errorf("[BCF Auth] auth/verify: nf_instance_id mismatch with registered profile: registered=%s, req=%s\n", registeredNFInstanceID, req.NFInstanceID)
			c.JSON(http.StatusUnauthorized, gin.H{
				"success":       false,
				"error_code":    "NF_INSTANCE_MISMATCH",
				"error_message": "nf_instance_id does not match registered NF profile",
			})
			return
		}

		publicKeyMultibase := extractPublicKeyMultibase(nfData)
		if publicKeyMultibase == "" {
			// 尝试从 DID 字符串本身提取公钥（备用方案）
			loglogrus.Log.Warnf("[BCF Auth] auth/verify: publicKeyMultibase not found in DID document, trying DID string\n")
			publicKeyMultibase = extractPublicKeyFromDIDString(req.NFDID)
		}

		if publicKeyMultibase == "" {
			loglogrus.Log.Errorf("[BCF Auth] auth/verify: cannot extract public key for DID: %s\n", req.NFDID)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "public key not found"})
			return
		}

		loglogrus.Log.Infof("[BCF Auth] auth/verify: publicKeyMultibase=%s...\n",
			publicKeyMultibase[:min(len(publicKeyMultibase), 16)])

		// 将 multibase 公钥解码为字节
		pubKeyBytes, err := multibaseToBytes(publicKeyMultibase)
		if err != nil || len(pubKeyBytes) == 0 {
			loglogrus.Log.Errorf("[BCF Auth] auth/verify: failed to decode public key: %v\n", err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to decode public key"})
			return
		}

		loglogrus.Log.Infof("[BCF Auth] auth/verify: pubkey bytes len=%d, first_byte=0x%02x\n",
			len(pubKeyBytes), pubKeyBytes[0])

		// 验签：sha256(hex_decode(challenge)) → ECDSA secp256k1 DER verify
		if !verifySecp256k1DER(session.Challenge, req.ChallengeSignature, pubKeyBytes) {
			loglogrus.Log.Errorf("[BCF Auth] auth/verify: signature verification FAILED for DID: %s\n", req.NFDID)
			c.JSON(http.StatusUnauthorized, gin.H{
				"success":       false,
				"error_code":    "SIGNATURE_INVALID",
				"error_message": "challenge signature verification failed",
			})
			return
		}

		// 验签成功，签发符合师兄规范的 ES256K JWT。
		authToken, issuedAt, expiresAt, err := GenerateBCFAuthToken(req.NFDID, req.NFInstanceID, req.NFType, req.SessionID)
		if err != nil {
			statusCode := http.StatusInternalServerError
			errorCode := "TOKEN_GENERATION_FAILED"
			if strings.Contains(err.Error(), "unsupported nf_type") {
				statusCode = http.StatusBadRequest
				errorCode = "UNSUPPORTED_NF_TYPE"
			}

			loglogrus.Log.Errorf("[BCF Auth] auth/verify: failed to generate auth token: %v\n", err)
			c.JSON(statusCode, gin.H{
				"success":       false,
				"error_code":    errorCode,
				"error_message": err.Error(),
			})
			return
		}

		expiresIn := int(expiresAt.Sub(issuedAt).Seconds())

		loglogrus.Log.Infof("[BCF Auth] auth/verify: SUCCESS, issued token for DID: %s\n", req.NFDID)
		SubmitAudit(c, GetAuditService(), &api.AuditEvent{
			OperatorDID:    req.NFDID,
			OperationType:  "AUTH_VERIFY",
			TargetObjectID: req.SessionID,
			Result:         "SUCCESS",
			ResultCode:     http.StatusOK,
			Metadata: map[string]string{
				"verify_mode":    "bcf_auth",
				"nf_type":        req.NFType,
				"nf_instance_id": req.NFInstanceID,
			},
		})

		c.JSON(http.StatusOK, gin.H{
			"access_token":        authToken,
			"auth_token":          authToken,
			"expires_at_ms":       expiresAt.UnixMilli(),
			"expires_in":          expiresIn,
			"newly_authenticated": true,
			"nf_did":              req.NFDID,
			"nf_instance_id":      req.NFInstanceID,
			"session_id":          req.SessionID,
			"success":             true,
			"timestamp_ms":        issuedAt.UnixMilli(),
			"token_type":          "Bearer",
		})
	}
}

// =============================================================================
// 辅助函数
// =============================================================================

// extractPublicKeyFromDIDString 从 DID 字符串中提取公钥 hex（备用方案）
// DID 格式：did:oai5gc:<binding_hash>:<public_key_hex> 或 did:oai5gc:<public_key_hex>
func extractPublicKeyFromDIDString(did string) string {
	prefix := "did:oai5gc:"
	if !strings.HasPrefix(did, prefix) {
		return ""
	}
	remainder := did[len(prefix):]
	colonIdx := strings.Index(remainder, ":")
	if colonIdx == 32 {
		// 新格式：did:oai5gc:<32位绑定哈希>:<公钥hex>
		return remainder[colonIdx+1:]
	}
	// 旧格式：did:oai5gc:<公钥hex>
	return remainder
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
