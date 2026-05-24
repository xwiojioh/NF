package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"p3Chain/common"
	cc "p3Chain/core/contract/chainCodeSupport"
	"p3Chain/crypto"
	"strings"
	"time"
)

var (
	ERROR_FUNCTION_ARGS = fmt.Errorf("unmatched arguments")
)

var (
	CONTRACT_NAME = "DID::SPECTRUM::TRADE"
)

var dataList [][]byte

type VC struct {
	Identifier     string   `json:"identifier"`     // VC ID
	Subject        string   `json:"subject"`        // SP DID
	Issuer         string   `json:"issuer"`         // UE DID
	Validity       string   `json:"validity"`       // Valid time
	Purpose        string   `json:"purpose"`        // 用途
	Signature      string   `json:"signature"`      // UE Signature
	Reassign       string   `json:"reassign"`       // 是否允许二次转让
	IssuerAddress  string   `json:"IssuerAddress"`  // issuer address
	SubjectAddress string   `json:"SubjectAddress"` // subject address
	Transfer       Transfer `json:"transfer"`       // subject address
}

type Transfer struct {
	Recipient        string `json:"recipient"`        // SP2 DID
	RecipientPurpose string `json:"purpose"`          // 用途
	RecipientAddress string `json:"recipientaddress"` // subject address
	DonorSignature   string `json:"signature"`        // UE Signature
	Timestamp        string `json:"timestamp"`        // time

}

func isDateExpired(dateStr string) (bool, error) {
	// 解析日期字符串
	expiryDate, err := time.Parse("2006-01-02", dateStr)
	if err != nil {
		return false, fmt.Errorf("invalid date format: %v", err)
	}

	// 获取当前日期（去除时分秒）
	currentDate := time.Now().Truncate(24 * time.Hour)

	// 如果expiryDate在currentDate之前，则认为已过期
	return expiryDate.Before(currentDate), nil
}

func StringToMap(str string) (map[string]string, error) {
	resultMap := make(map[string]string)

	// 特殊处理 Transfer 字段
	var transferStr string
	if idx := strings.Index(str, "Transfer:{"); idx != -1 {
		endIdx := strings.Index(str[idx:], "}") + idx + 1
		if endIdx > idx {
			transferStr = str[idx:endIdx]
			str = str[:idx] + str[endIdx:]
		} else {
			return nil, fmt.Errorf("invalid transfer structure")
		}
	}

	// 处理其他键值对
	pairs := strings.Split(str, ",")
	for _, pair := range pairs {
		pair = strings.TrimSpace(pair) // 移除键值对周围的空格
		idx := strings.Index(pair, ":")
		if idx == -1 {
			return nil, fmt.Errorf("invalid pair (no colon found): %s", pair)
		}

		key := strings.TrimSpace(pair[:idx])     // 移除键周围的空格
		value := strings.TrimSpace(pair[idx+1:]) // 移除值周围的空格
		resultMap[key] = value
	}

	// 添加 Transfer 字段
	if transferStr != "" {
		resultMap["Transfer"] = transferStr
	}

	return resultMap, nil
}

func VCValid(args [][]byte, ds cc.DperServicePipe) ([][]byte, error) {
	if len(args) != 1 {
		return nil, ERROR_FUNCTION_ARGS
	}
	str1 := string(args[0])
	mymap, _ := StringToMap(str1)

	// 提取并创建 Credential 结构体
	var vc VC
	var exists bool

	if vc.Identifier, exists = mymap["Identifier"]; !exists {
		result := [][]byte{[]byte(fmt.Sprintf("noid"))}
		return result, nil
	}
	if vc.Subject, exists = mymap["Subject"]; !exists {
		result := [][]byte{[]byte(fmt.Sprintf("nosubject"))}
		return result, nil
	}
	if vc.Issuer, exists = mymap["Issuer"]; !exists {
		result := [][]byte{[]byte(fmt.Sprintf("noissuer"))}
		return result, nil
	}
	if vc.Validity, exists = mymap["Validity"]; !exists {
		result := [][]byte{[]byte(fmt.Sprintf("novalidity"))}
		return result, nil
	}
	if vc.Purpose, exists = mymap["Purpose"]; !exists {
		result := [][]byte{[]byte(fmt.Sprintf("nopurpose"))}
		return result, nil
	}
	if vc.Signature, exists = mymap["Signature"]; !exists {
		result := [][]byte{[]byte(fmt.Sprintf("nosignature"))}
		return result, nil
	}
	if vc.Reassign, exists = mymap["Reassign"]; !exists {
		result := [][]byte{[]byte(fmt.Sprintf("noreassign"))}
		return result, nil
	}
	if vc.IssuerAddress, exists = mymap["IssuerAddress"]; !exists {
		result := [][]byte{[]byte(fmt.Sprintf("no issueraddress"))}
		return result, nil
	}
	if vc.SubjectAddress, exists = mymap["SubjectAddress"]; !exists {
		result := [][]byte{[]byte(fmt.Sprintf("no subjectaddress"))}
		return result, nil
	}

	// 在这里添加有关 Credential 的验证
	expired, err := isDateExpired(vc.Validity)
	if err != nil {
		result := [][]byte{[]byte(fmt.Sprintf("expired error"))}
		return result, nil
	}
	if expired {
		return nil, nil
	}
	//再验证签名
	signature := vc.Signature
	address := vc.IssuerAddress
	// 假设地址是返回数组的第一个元素
	msg := crypto.Sha3Hash([]byte(vc.Identifier))
	sig := common.Hex2Bytes(signature)
	add := common.HexToAddress(address)
	ok, err := crypto.SignatureValid(add, sig, msg)
	// 示例：返回 Credential 结构体的字符串表示
	if err != nil {
		result := [][]byte{[]byte(fmt.Sprintf("signaturevalid wrong: %+v", vc))}
		return result, nil
	} else {
		if ok {
			// 序列化 Credential 数据为 JSON
			jsonData, err := json.Marshal(vc)
			if err != nil {
				// 处理序列化错误
				return nil, fmt.Errorf("error marshalling VC: %v", err)
			}

			// 将序列化后的数据保存到区块链
			// 假设我们使用 vc.Identifier 作为存储的键
			if err := ds.UpdateStatus([]byte(vc.Identifier), jsonData); err != nil {
				// 处理 UpdateStatus 的错误
				return nil, fmt.Errorf("failed to update status: %v", err)
			}
			result := [][]byte{[]byte(fmt.Sprintf("Credential: %+v", vc))}
			return result, nil
		} else {
			return nil, nil
		}
	}
}

func ResetVC(args [][]byte, ds cc.DperServicePipe) ([][]byte, error) {
	if len(args) != 1 {
		return nil, ERROR_FUNCTION_ARGS
	}
	str1 := string(args[0])
	mymap, _ := StringToMap(str1)

	// 提取并创建 VC 结构体
	var vc VC
	var exists bool

	if vc.Identifier, exists = mymap["Identifier"]; !exists {
		result := [][]byte{[]byte(fmt.Sprintf("noidentifier"))}
		return result, nil
	}
	if vc.Subject, exists = mymap["Subject"]; !exists {
		result := [][]byte{[]byte(fmt.Sprintf("nosubject"))}
		return result, nil
	}
	if vc.Issuer, exists = mymap["Issuer"]; !exists {
		result := [][]byte{[]byte(fmt.Sprintf("noissuer"))}
		return result, nil
	}
	if vc.Validity, exists = mymap["Validity"]; !exists {
		result := [][]byte{[]byte(fmt.Sprintf("novalidity"))}
		return result, nil
	}
	if vc.Purpose, exists = mymap["Purpose"]; !exists {
		result := [][]byte{[]byte(fmt.Sprintf("nopurpose"))}
		return result, nil
	}
	if vc.Signature, exists = mymap["Signature"]; !exists {
		result := [][]byte{[]byte(fmt.Sprintf("nosignature"))}
		return result, nil
	}
	if vc.Reassign, exists = mymap["Reassign"]; !exists {
		result := [][]byte{[]byte(fmt.Sprintf("noreassign"))}
		return result, nil
	}
	if vc.IssuerAddress, exists = mymap["IssuerAddress"]; !exists {
		result := [][]byte{[]byte(fmt.Sprintf("no issueraddress"))}
		return result, nil
	}
	if vc.SubjectAddress, exists = mymap["SubjectAddress"]; !exists {
		result := [][]byte{[]byte(fmt.Sprintf("no subjectaddress"))}
		return result, nil
	}

	//transfer的内容

	vc.Transfer.Recipient, exists = mymap["Recipient"]
	if !exists {
		return [][]byte{[]byte("无接收者")}, nil
	}
	vc.Transfer.RecipientPurpose, exists = mymap["RecipientPurpose"]
	if !exists {
		return [][]byte{[]byte("无目的")}, nil
	}
	vc.Transfer.RecipientAddress, exists = mymap["RecipientAddress"]
	if !exists {
		return [][]byte{[]byte("无接收者地址")}, nil
	}
	vc.Transfer.DonorSignature, exists = mymap["DonorSignature"]
	if !exists {
		return [][]byte{[]byte("无签名")}, nil
	}
	currentDate := time.Now().Truncate(24 * time.Hour)
	vc.Transfer.Timestamp = currentDate.Format("2006-01-02")

	// 在这里添加有关 new VC 的验证
	timeok, err := IsTime1BeforeTime2(vc.Transfer.Timestamp, vc.Validity)
	if err != nil {
		result := [][]byte{[]byte(fmt.Sprintf("expired error"))}
		return result, nil
	}
	if !timeok {
		return [][]byte{[]byte("时间已经过期")}, nil
	}
	// 再验证签名
	signature := vc.Transfer.DonorSignature
	address := vc.SubjectAddress
	// 假设地址是返回数组的第一个元素
	msg := crypto.Sha3Hash([]byte(vc.Identifier))
	sig := common.Hex2Bytes(signature)
	add := common.HexToAddress(address)
	ok, err := crypto.SignatureValid(add, sig, msg)
	// 示例：返回 Credential 结构体的字符串表示
	if err != nil {
		result := [][]byte{[]byte(fmt.Sprintf("signaturevalid wrong: %+v", vc))}
		return result, nil
	} else {
		if ok {
			// 序列化 Credential 数据为 JSON
			jsonData, err := json.Marshal(vc)
			if err != nil {
				result := [][]byte{[]byte(fmt.Sprintf("jsondata wrong: %+v", vc))}
				return result, fmt.Errorf("error marshalling VC: %v", err)
			}
			// 将序列化后的数据保存到区块链
			// 假设我们使用 vc.Identifier 作为存储的键
			if err := ds.UpdateStatus([]byte(vc.Identifier), jsonData); err != nil {
				result := [][]byte{[]byte(fmt.Sprintf("upstatus wrong: %+v", vc))}
				return result, fmt.Errorf("failed to update status: %v", err)
			}
			result := [][]byte{[]byte(fmt.Sprintf("Credential: %+v", vc))}
			return result, nil
		} else {
			result := [][]byte{[]byte(fmt.Sprintf("sign wrong: vc=%+v signature=%s address=%s msg=%x", vc, signature, address, msg))}
			return result, nil
		}
	}
}

func GetVC(args [][]byte, ds cc.DperServicePipe) ([][]byte, error) {
	if len(args) != 1 {
		result := [][]byte{[]byte(fmt.Sprintf("sGetVC requires exactly 1 argumentign wrong"))}
		return result, fmt.Errorf("GetVC requires exactly 1 argument, got %d", len(args))
	}
	// 使用 Identifier 作为键来获取 Credential 数据
	storedData, err := ds.GetStatus(args[0])
	if err != nil {
		result := [][]byte{[]byte(fmt.Sprintf("getvc error"))}
		return result, fmt.Errorf("error getting VC status: %v", err)
	}

	// 直接返回检索到的 JSON 字符串
	return [][]byte{storedData}, nil
}

func SetDID(args [][]byte, ds cc.DperServicePipe) ([][]byte, error) {
	if len(args) != 2 {
		return nil, fmt.Errorf("SetDID requires exactly 2 arguments, got %d", len(args))
	}

	str1 := string(args[0])

	if len(str1) < 4 || str1[:4] != "DID:" {
		return nil, fmt.Errorf("invalid argument format")
	}

	if err := ds.UpdateStatus(args[0], args[1]); err != nil {
		// 处理 UpdateStatus 的错误
		return nil, fmt.Errorf("failed to update status: %v", err)
	}

	// 注意：dataList 的使用可能需要考虑线程安全性
	dataList = append(dataList, args[0], args[1])

	// Returning args[0] and args[1]
	return [][]byte{args[0], args[1]}, nil
}

func SetDID_baseline_experiment(args [][]byte, ds cc.DperServicePipe) ([][]byte, error) {
	if len(args) != 2 {
		return nil, fmt.Errorf("SetDID requires exactly 2 arguments, got %d", len(args))
	}

	str1 := string(args[0])

	if len(str1) < 4 || str1[:4] != "DID:" {
		return nil, fmt.Errorf("invalid argument format")
	}

	if err := ds.UpdateStatus(args[0], args[1]); err != nil {
		// 处理 UpdateStatus 的错误
		return nil, fmt.Errorf("failed to update status: %v", err)
	}

	// 注意：dataList 的使用可能需要考虑线程安全性
	dataList = append(dataList, args[0], args[1])

	// Returning args[0] and args[1]
	return [][]byte{args[0], args[1]}, nil
}

func GetAddress(args [][]byte, ds cc.DperServicePipe) ([][]byte, error) {
	if len(args) != 1 {
		return nil, ERROR_FUNCTION_ARGS
	}
	value, err := ds.GetStatus(args[0])
	if err != nil {
		return nil, err
	}
	result := [][]byte{value}
	return result, nil
}

func GetDIDList(args [][]byte, ds cc.DperServicePipe) ([][]byte, error) {
	data := dataList
	return data, nil
}

type Subscription struct {
	SubscriptionID         string   `json:"subscriptionId,omitempty"`
	SubscriptionIDAlias    string   `json:"subscription_id,omitempty"`
	SubscriberDID          string   `json:"subscriberDid,omitempty"`
	SubscriberNFDID        string   `json:"subscriber_nf_did,omitempty"`
	SubscriberNFType       string   `json:"subscriber_nf_type,omitempty"`
	SubscriberNFInstanceID string   `json:"subscriber_nf_instance_id,omitempty"`
	TargetNFType           string   `json:"targetNfType,omitempty"`
	TargetNFTypeAlias      string   `json:"target_nf_type,omitempty"`
	TargetDID              string   `json:"targetDid,omitempty"`
	TargetNFDID            string   `json:"target_nf_did,omitempty"`
	CallbackURL            string   `json:"callbackUrl,omitempty"`
	NotificationURI        string   `json:"notification_uri,omitempty"`
	NotificationTransport  string   `json:"notification_transport,omitempty"`
	EventTypes             []string `json:"eventTypes,omitempty"`
	Status                 string   `json:"status,omitempty"`
	CreatedAt              string   `json:"createdAt,omitempty"`
	UpdatedAt              string   `json:"updatedAt,omitempty"`
}

type AuthChallenge struct {
	DID         string `json:"did"`
	ChallengeID string `json:"challengeId"`
	Nonce       string `json:"nonce"`
	IssuedAt    string `json:"issuedAt"`
	ExpiresAt   string `json:"expiresAt"`
	Status      string `json:"status"`
}

type AuthState struct {
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

// ==================== 新增：NF Profile 管理函数 ====================

// SetNFProfile - 存储完整的NF Profile (包含didDocument和amfInfo)
func SetNFProfile(args [][]byte, ds cc.DperServicePipe) ([][]byte, error) {
	if len(args) != 2 {
		return nil, fmt.Errorf("SetNFProfile requires 2 arguments: DID, NFProfileJSON")
	}

	did := args[0]
	nfProfileJSON := args[1]

	if len(did) < 4 || string(did[:4]) != "did:" {
		return nil, fmt.Errorf("invalid DID format")
	}

	// 第一步：存 DID → Profile
	err := ds.UpdateStatus(did, nfProfileJSON)
	if err != nil {
		return nil, fmt.Errorf("failed to store NF profile: %v", err)
	}

	// 第二步：从 JSON 里解析出 nfType
	var profileData map[string]interface{}
	if err := json.Unmarshal(nfProfileJSON, &profileData); err == nil {
		nfProfile, _ := profileData["nfProfile"].(map[string]interface{})
		if nfProfile != nil {
			nfType, _ := nfProfile["nfType"].(string)
			if nfType != "" {
				// 第三步：读出当前该类型的 DID 索引列表
				indexKey := []byte("NFTYPE_INDEX:" + nfType)
				var didList []string

				existingData, err := ds.GetStatus(indexKey)
				if err == nil && len(existingData) > 0 {
					json.Unmarshal(existingData, &didList)
				}

				// 第四步：去重后追加当前 DID
				didStr := string(did)
				found := false
				for _, d := range didList {
					if d == didStr {
						found = true
						break
					}
				}
				if !found {
					didList = append(didList, didStr)
				}

				// 第五步：写回索引
				indexJSON, _ := json.Marshal(didList)
				ds.UpdateStatus(indexKey, indexJSON)
			}
		}
	}

	return [][]byte{did, []byte("OK")}, nil
}

// DiscoverNFByType - 按 nfType 查询所有可用的 NF 实例
func DiscoverNFByType(args [][]byte, ds cc.DperServicePipe) ([][]byte, error) {
	if len(args) != 1 {
		return nil, fmt.Errorf("DiscoverNFByType requires 1 argument: nfType")
	}

	nfType := string(args[0])
	if nfType == "" {
		return nil, fmt.Errorf("nfType cannot be empty")
	}

	// 1. 读索引，拿到该类型下所有 DID
	indexKey := []byte("NFTYPE_INDEX:" + nfType)
	indexData, err := ds.GetStatus(indexKey)
	if err != nil || len(indexData) == 0 {
		emptyList, _ := json.Marshal([]interface{}{})
		return [][]byte{emptyList}, nil
	}

	var didList []string
	if err := json.Unmarshal(indexData, &didList); err != nil {
		return nil, fmt.Errorf("failed to parse index: %v", err)
	}

	// 2. 逐个取 Profile，只保留状态为 REGISTERED 的
	var results []map[string]interface{}
	for _, did := range didList {
		profileData, err := ds.GetStatus([]byte(did))
		if err != nil || len(profileData) == 0 {
			continue
		}

		var profile map[string]interface{}
		if err := json.Unmarshal(profileData, &profile); err != nil {
			continue
		}

		nfProfile, _ := profile["nfProfile"].(map[string]interface{})
		if nfProfile == nil {
			continue
		}

		status, _ := nfProfile["nfStatus"].(string)
		if status != "REGISTERED" {
			continue
		}

		profile["did"] = did
		results = append(results, profile)
	}

	// 3. 打包成 JSON 数组返回
	resultJSON, err := json.Marshal(results)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal results: %v", err)
	}

	return [][]byte{resultJSON}, nil
}

func CreateAuthChallenge(args [][]byte, ds cc.DperServicePipe) ([][]byte, error) {
	if len(args) != 2 {
		return nil, fmt.Errorf("CreateAuthChallenge requires 2 arguments: did, challengeJSON")
	}

	did := string(args[0])
	challengeJSON := args[1]
	if did == "" {
		return nil, fmt.Errorf("did cannot be empty")
	}

	var challenge AuthChallenge
	if err := json.Unmarshal(challengeJSON, &challenge); err != nil {
		return nil, fmt.Errorf("failed to parse challenge JSON: %v", err)
	}
	if challenge.DID == "" {
		challenge.DID = did
	}
	if challenge.DID != did {
		return nil, fmt.Errorf("challenge did does not match argument")
	}
	if challenge.Status == "" {
		challenge.Status = "PENDING"
	}

	normalizedJSON, err := json.Marshal(challenge)
	if err != nil {
		return nil, fmt.Errorf("failed to normalize challenge JSON: %v", err)
	}

	if err := ds.UpdateStatus([]byte("AUTH_CHALLENGE:"+did), normalizedJSON); err != nil {
		return nil, fmt.Errorf("failed to store auth challenge: %v", err)
	}

	return [][]byte{[]byte("OK")}, nil
}

func GetAuthChallenge(args [][]byte, ds cc.DperServicePipe) ([][]byte, error) {
	if len(args) != 1 {
		return nil, fmt.Errorf("GetAuthChallenge requires 1 argument: did")
	}

	did := string(args[0])
	if did == "" {
		return nil, fmt.Errorf("did cannot be empty")
	}

	data, err := ds.GetStatus([]byte("AUTH_CHALLENGE:" + did))
	if err != nil || len(data) == 0 {
		return nil, fmt.Errorf("auth challenge not found")
	}

	return [][]byte{data}, nil
}

func VerifyAuthChallenge(args [][]byte, ds cc.DperServicePipe) ([][]byte, error) {
	if len(args) != 2 {
		return nil, fmt.Errorf("VerifyAuthChallenge requires 2 arguments: did, authStateJSON")
	}

	did := string(args[0])
	authStateJSON := args[1]
	if did == "" {
		return nil, fmt.Errorf("did cannot be empty")
	}

	var authState AuthState
	if err := json.Unmarshal(authStateJSON, &authState); err != nil {
		return nil, fmt.Errorf("failed to parse auth state JSON: %v", err)
	}
	if authState.DID == "" {
		authState.DID = did
	}
	if authState.DID != did {
		return nil, fmt.Errorf("auth state did does not match argument")
	}

	normalizedStateJSON, err := json.Marshal(authState)
	if err != nil {
		return nil, fmt.Errorf("failed to normalize auth state JSON: %v", err)
	}

	if err := ds.UpdateStatus([]byte("AUTH_STATE:"+did), normalizedStateJSON); err != nil {
		return nil, fmt.Errorf("failed to store auth state: %v", err)
	}

	challengeKey := []byte("AUTH_CHALLENGE:" + did)
	challengeData, err := ds.GetStatus(challengeKey)
	if err == nil && len(challengeData) > 0 {
		var challenge AuthChallenge
		if json.Unmarshal(challengeData, &challenge) == nil {
			if authState.ChallengeID == "" || authState.ChallengeID == challenge.ChallengeID {
				switch authState.AuthStatus {
				case "AUTHENTICATED":
					challenge.Status = "USED"
				case "FAILED":
					challenge.Status = "FAILED"
				}
				updatedChallengeJSON, _ := json.Marshal(challenge)
				ds.UpdateStatus(challengeKey, updatedChallengeJSON)
			}
		}
	}

	return [][]byte{[]byte(authState.AuthStatus)}, nil
}

func GetAuthState(args [][]byte, ds cc.DperServicePipe) ([][]byte, error) {
	if len(args) != 1 {
		return nil, fmt.Errorf("GetAuthState requires 1 argument: did")
	}

	did := string(args[0])
	if did == "" {
		return nil, fmt.Errorf("did cannot be empty")
	}

	data, err := ds.GetStatus([]byte("AUTH_STATE:" + did))
	if err != nil || len(data) == 0 {
		return nil, fmt.Errorf("auth state not found")
	}

	return [][]byte{data}, nil
}

func CreateSubscription(args [][]byte, ds cc.DperServicePipe) ([][]byte, error) {
	if len(args) != 2 {
		return nil, fmt.Errorf("CreateSubscription requires 2 arguments: subscriptionID, subscriptionJSON")
	}

	subscriptionID := string(args[0])
	subscriptionJSON := args[1]

	if subscriptionID == "" {
		return nil, fmt.Errorf("subscriptionID cannot be empty")
	}

	var sub Subscription
	if err := json.Unmarshal(subscriptionJSON, &sub); err != nil {
		return nil, fmt.Errorf("failed to parse subscription JSON: %v", err)
	}

	if sub.SubscriptionID == "" {
		sub.SubscriptionID = sub.SubscriptionIDAlias
	}
	if sub.SubscriptionID != "" && sub.SubscriptionID != subscriptionID {
		return nil, fmt.Errorf("subscriptionId in JSON does not match argument")
	}
	sub.SubscriptionID = subscriptionID
	sub.SubscriptionIDAlias = subscriptionID

	if sub.SubscriberDID == "" {
		sub.SubscriberDID = sub.SubscriberNFDID
	}
	if sub.SubscriberNFDID == "" {
		sub.SubscriberNFDID = sub.SubscriberDID
	}
	if sub.TargetNFType == "" {
		sub.TargetNFType = sub.TargetNFTypeAlias
	}
	if sub.TargetNFTypeAlias == "" {
		sub.TargetNFTypeAlias = sub.TargetNFType
	}
	if sub.CallbackURL == "" {
		sub.CallbackURL = sub.NotificationURI
	}
	if sub.NotificationURI == "" {
		sub.NotificationURI = sub.CallbackURL
	}
	if sub.NotificationTransport == "" {
		sub.NotificationTransport = "auto"
	}
	if sub.Status == "" {
		sub.Status = "ACTIVE"
	}

	if sub.SubscriberDID == "" {
		return nil, fmt.Errorf("subscriberDid cannot be empty")
	}
	if sub.TargetNFType == "" {
		return nil, fmt.Errorf("targetNfType cannot be empty")
	}

	normalizedJSON, err := json.Marshal(sub)
	if err != nil {
		return nil, fmt.Errorf("failed to normalize subscription JSON: %v", err)
	}

	// 主记录
	subKey := []byte("SUBSCRIPTION:" + subscriptionID)
	if err := ds.UpdateStatus(subKey, normalizedJSON); err != nil {
		return nil, fmt.Errorf("failed to store subscription: %v", err)
	}

	// 订阅者索引
	indexKey := []byte("SUBSCRIPTION_BY_SUBSCRIBER:" + sub.SubscriberDID)
	var idList []string

	existingData, err := ds.GetStatus(indexKey)
	if err == nil && len(existingData) > 0 {
		json.Unmarshal(existingData, &idList)
	}

	found := false
	for _, id := range idList {
		if id == subscriptionID {
			found = true
			break
		}
	}
	if !found {
		idList = append(idList, subscriptionID)
	}

	indexJSON, _ := json.Marshal(idList)
	if err := ds.UpdateStatus(indexKey, indexJSON); err != nil {
		return nil, fmt.Errorf("failed to update subscriber index: %v", err)
	}

	// targetNfType 索引（通知分发时按 nfType 查匹配订阅）
	if sub.TargetNFType != "" {
		nfTypeIndexKey := []byte("SUBSCRIPTION_BY_NFTYPE:" + sub.TargetNFType)
		var nfTypeIDList []string

		nfTypeData, err := ds.GetStatus(nfTypeIndexKey)
		if err == nil && len(nfTypeData) > 0 {
			json.Unmarshal(nfTypeData, &nfTypeIDList)
		}

		ntFound := false
		for _, id := range nfTypeIDList {
			if id == subscriptionID {
				ntFound = true
				break
			}
		}
		if !ntFound {
			nfTypeIDList = append(nfTypeIDList, subscriptionID)
		}

		nfTypeIndexJSON, _ := json.Marshal(nfTypeIDList)
		ds.UpdateStatus(nfTypeIndexKey, nfTypeIndexJSON)
	}

	return [][]byte{[]byte(subscriptionID)}, nil
}

// GetSubscriptionsByNFType - 按 targetNfType 查询所有 ACTIVE 订阅（用于通知分发）
func GetSubscriptionsByNFType(args [][]byte, ds cc.DperServicePipe) ([][]byte, error) {
	if len(args) != 1 {
		return nil, fmt.Errorf("GetSubscriptionsByNFType requires 1 argument: nfType")
	}

	nfType := string(args[0])
	if nfType == "" {
		return nil, fmt.Errorf("nfType cannot be empty")
	}

	nfTypeIndexKey := []byte("SUBSCRIPTION_BY_NFTYPE:" + nfType)
	indexData, err := ds.GetStatus(nfTypeIndexKey)
	if err != nil || len(indexData) == 0 {
		emptyList, _ := json.Marshal([]interface{}{})
		return [][]byte{emptyList}, nil
	}

	var idList []string
	if err := json.Unmarshal(indexData, &idList); err != nil {
		return nil, fmt.Errorf("failed to parse nftype subscription index: %v", err)
	}

	var results []map[string]interface{}
	for _, id := range idList {
		subData, err := ds.GetStatus([]byte("SUBSCRIPTION:" + id))
		if err != nil || len(subData) == 0 {
			continue
		}

		var sub map[string]interface{}
		if err := json.Unmarshal(subData, &sub); err != nil {
			continue
		}

		results = append(results, sub)
	}

	resultJSON, err := json.Marshal(results)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal results: %v", err)
	}

	return [][]byte{resultJSON}, nil
}

func GetSubscriptions(args [][]byte, ds cc.DperServicePipe) ([][]byte, error) {
	if len(args) != 1 {
		return nil, fmt.Errorf("GetSubscriptions requires 1 argument: subscriberDID")
	}

	subscriberDID := string(args[0])
	if subscriberDID == "" {
		return nil, fmt.Errorf("subscriberDID cannot be empty")
	}

	indexKey := []byte("SUBSCRIPTION_BY_SUBSCRIBER:" + subscriberDID)
	indexData, err := ds.GetStatus(indexKey)
	if err != nil || len(indexData) == 0 {
		emptyList, _ := json.Marshal([]interface{}{})
		return [][]byte{emptyList}, nil
	}

	var idList []string
	if err := json.Unmarshal(indexData, &idList); err != nil {
		return nil, fmt.Errorf("failed to parse subscription index: %v", err)
	}

	var results []map[string]interface{}
	for _, id := range idList {
		subData, err := ds.GetStatus([]byte("SUBSCRIPTION:" + id))
		if err != nil || len(subData) == 0 {
			continue
		}

		var sub map[string]interface{}
		if err := json.Unmarshal(subData, &sub); err != nil {
			continue
		}

		results = append(results, sub)
	}

	resultJSON, err := json.Marshal(results)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal subscription results: %v", err)
	}

	return [][]byte{resultJSON}, nil
}

func GetSubscriptionByID(args [][]byte, ds cc.DperServicePipe) ([][]byte, error) {
	if len(args) != 1 {
		return nil, fmt.Errorf("GetSubscriptionByID requires 1 argument: subscriptionID")
	}

	subscriptionID := string(args[0])
	if subscriptionID == "" {
		return nil, fmt.Errorf("subscriptionID cannot be empty")
	}

	subData, err := ds.GetStatus([]byte("SUBSCRIPTION:" + subscriptionID))
	if err != nil || len(subData) == 0 {
		return nil, fmt.Errorf("subscription not found")
	}

	return [][]byte{subData}, nil
}

func DeleteSubscription(args [][]byte, ds cc.DperServicePipe) ([][]byte, error) {
	if len(args) != 2 {
		return nil, fmt.Errorf("DeleteSubscription requires 2 arguments: subscriptionID, subscriberDID")
	}

	subscriptionID := string(args[0])
	subscriberDID := string(args[1])

	if subscriptionID == "" {
		return nil, fmt.Errorf("subscriptionID cannot be empty")
	}
	if subscriberDID == "" {
		return nil, fmt.Errorf("subscriberDID cannot be empty")
	}

	// 删除主记录：这里先不真正删除，改成 status=INACTIVE 更稳
	subKey := []byte("SUBSCRIPTION:" + subscriptionID)
	subData, err := ds.GetStatus(subKey)
	if err != nil || len(subData) == 0 {
		return nil, fmt.Errorf("subscription not found")
	}

	var sub map[string]interface{}
	if err := json.Unmarshal(subData, &sub); err != nil {
		return nil, fmt.Errorf("failed to parse subscription data: %v", err)
	}

	storedSubscriberDID, _ := sub["subscriberDid"].(string)
	if storedSubscriberDID != subscriberDID {
		return nil, fmt.Errorf("subscriberDID does not match subscription owner")
	}

	sub["status"] = "INACTIVE"
	sub["updatedAt"] = time.Now().Format(time.RFC3339)

	updatedJSON, err := json.Marshal(sub)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal updated subscription: %v", err)
	}

	if err := ds.UpdateStatus(subKey, updatedJSON); err != nil {
		return nil, fmt.Errorf("failed to update subscription status: %v", err)
	}

	return [][]byte{[]byte("INACTIVE")}, nil
}

// GetNFProfile - 获取NF Profile
func GetNFProfile(args [][]byte, ds cc.DperServicePipe) ([][]byte, error) {
	if len(args) != 1 {
		return nil, fmt.Errorf("GetNFProfile requires 1 argument: DID")
	}

	value, err := ds.GetStatus(args[0])
	if err != nil {
		return nil, fmt.Errorf("NF profile not found: %v", err)
	}

	if len(value) == 0 {
		return nil, fmt.Errorf("NF profile is empty")
	}

	return [][]byte{value}, nil
}

// DeregisterNF - 注销NF (将nfStatus改为DEREGISTERED)
func DeregisterNF(args [][]byte, ds cc.DperServicePipe) ([][]byte, error) {
	if len(args) != 1 {
		return nil, fmt.Errorf("DeregisterNF requires 1 argument: DID")
	}

	// 获取现有数据
	value, err := ds.GetStatus(args[0])
	if err != nil || len(value) == 0 {
		return nil, fmt.Errorf("NF not found")
	}

	// 解析并更新状态
	var data map[string]interface{}
	if err := json.Unmarshal(value, &data); err != nil {
		return nil, fmt.Errorf("failed to parse NF profile: %v", err)
	}

	// 更新nfStatus
	if nfProfile, ok := data["nfProfile"].(map[string]interface{}); ok {
		nfProfile["nfStatus"] = "DEREGISTERED"
	} else {
		return nil, fmt.Errorf("invalid NF profile structure")
	}

	// 重新序列化并保存
	updatedJSON, err := json.Marshal(data)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal updated profile: %v", err)
	}

	err = ds.UpdateStatus(args[0], updatedJSON)
	if err != nil {
		return nil, fmt.Errorf("failed to update status: %v", err)
	}

	return [][]byte{[]byte("DEREGISTERED")}, nil
}

func main() {
	local_pipe := flag.String("local_pipe", "", "")
	Dper_pipe := flag.String("dper_pipe", "", "")
	flag.Parse()
	funcMap := map[string]cc.ContractFuncPipe{
		"SetDID_baseline":                SetDID_baseline_experiment,
		"SetDID":                         SetDID,
		"GetAddress":                     GetAddress,
		"GetDIDList":                     GetDIDList,
		"VCValid":                        VCValid,
		"GetVC":                          GetVC,
		"ResetVC":                        ResetVC,
		"SetNFProfile":                   SetNFProfile,
		"GetNFProfile":                   GetNFProfile,
		"DeregisterNF":                   DeregisterNF,
		"DiscoverNFByType":               DiscoverNFByType,
		"CreateAuthChallenge":            CreateAuthChallenge,
		"GetAuthChallenge":               GetAuthChallenge,
		"VerifyAuthChallenge":            VerifyAuthChallenge,
		"GetAuthState":                   GetAuthState,
		"CreateSubscription":             CreateSubscription,
		"GetSubscriptions":               GetSubscriptions,
		"GetSubscriptionByID":            GetSubscriptionByID,
		"GetSubscriptionsByNFType":       GetSubscriptionsByNFType,
		"DeleteSubscription":             DeleteSubscription,
		"CreateAuditLog":                 CreateAuditLog,
		"GetAuditLogByID":                GetAuditLogByID,
		"GetAuditLogsByOperator":         GetAuditLogsByOperator,
		"GetAuditLogsByOperation":        GetAuditLogsByOperation,
		"GetAuditLogsBySession":          GetAuditLogsBySession,
		"GetAuditLogsByInteraction":      GetAuditLogsByInteraction,
		"GetAuditLogsBySubjectDID":       GetAuditLogsBySubjectDID,
		"GetAuditLogsByPeerDID":          GetAuditLogsByPeerDID,
		"GetAuditLogsByDay":              GetAuditLogsByDay,
		"SetAuditLogTxHash":              SetAuditLogTxHash,
		"AnchorSessionDigest":            AnchorSessionDigest,
		"GetSessionDigest":               GetSessionDigest,
		"GetSessionDigestsByDID":         GetSessionDigestsByDID,
		"GetSessionDigestsByInteraction": GetSessionDigestsByInteraction,
		"VerifySessionDigest":            VerifySessionDigest,
		"SetSessionDigestTxHash":         SetSessionDigestTxHash,
	}
	err := cc.InstallContractPipe(CONTRACT_NAME, funcMap, *Dper_pipe)
	if err != nil {
		fmt.Print(err)
	} else {
		fmt.Print("install success")
	}
	cc.ContractExecutePipe(*Dper_pipe, *local_pipe, funcMap)
}

func IsTime1BeforeTime2(timeStr1 string, timeStr2 string) (bool, error) {
	t1, err := time.Parse("2006-01-02", timeStr1)
	if err != nil {
		return false, err
	}
	t2, err := time.Parse("2006-01-02", timeStr2)
	if err != nil {
		return false, err
	}
	return t1.Before(t2), nil
}
