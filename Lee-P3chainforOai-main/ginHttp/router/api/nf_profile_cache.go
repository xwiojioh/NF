package router

import (
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"time"

	"p3Chain/api"
	loglogrus "p3Chain/log_logrus"
)

var errNFProfileNotFound = errors.New("nf profile not found")

type pendingNFProfile struct {
	Data      map[string]interface{}
	ExpiresAt time.Time
}

var (
	pendingNFProfiles   = make(map[string]*pendingNFProfile)
	pendingNFProfilesMu sync.RWMutex
)

const pendingNFProfileTTL = 2 * time.Minute

func cloneNFProfileData(data map[string]interface{}) map[string]interface{} {
	if data == nil {
		return nil
	}

	raw, err := json.Marshal(data)
	if err != nil {
		return data
	}

	var cloned map[string]interface{}
	if err := json.Unmarshal(raw, &cloned); err != nil {
		return data
	}

	return cloned
}

func rememberPendingNFProfile(did string, data map[string]interface{}) {
	if did == "" || data == nil {
		return
	}

	pendingNFProfilesMu.Lock()
	pendingNFProfiles[did] = &pendingNFProfile{
		Data:      cloneNFProfileData(data),
		ExpiresAt: time.Now().Add(pendingNFProfileTTL),
	}
	pendingNFProfilesMu.Unlock()

	loglogrus.Log.Infof("[NF Cache] Stored pending NF profile for DID: %s\n", did)
}

func forgetPendingNFProfile(did string) {
	if did == "" {
		return
	}

	pendingNFProfilesMu.Lock()
	delete(pendingNFProfiles, did)
	pendingNFProfilesMu.Unlock()
}

func getPendingNFProfile(did string) (map[string]interface{}, bool) {
	if did == "" {
		return nil, false
	}

	pendingNFProfilesMu.RLock()
	entry, ok := pendingNFProfiles[did]
	pendingNFProfilesMu.RUnlock()
	if !ok {
		return nil, false
	}

	if time.Now().After(entry.ExpiresAt) {
		forgetPendingNFProfile(did)
		return nil, false
	}

	return cloneNFProfileData(entry.Data), true
}

func getPendingNFProfilesByType(nfType string) []map[string]interface{} {
	nfType = strings.TrimSpace(nfType)
	if nfType == "" {
		return []map[string]interface{}{}
	}

	now := time.Now()
	expiredDIDs := make([]string, 0)
	profiles := make([]map[string]interface{}, 0)

	pendingNFProfilesMu.RLock()
	for did, entry := range pendingNFProfiles {
		if entry == nil {
			continue
		}
		if now.After(entry.ExpiresAt) {
			expiredDIDs = append(expiredDIDs, did)
			continue
		}

		profileData := cloneNFProfileData(entry.Data)
		nfProfile, _ := profileData["nfProfile"].(map[string]interface{})
		if nfProfile == nil {
			continue
		}

		currentType, _ := nfProfile["nfType"].(string)
		if !strings.EqualFold(strings.TrimSpace(currentType), nfType) {
			continue
		}

		status, _ := nfProfile["nfStatus"].(string)
		if !strings.EqualFold(strings.TrimSpace(status), "REGISTERED") {
			continue
		}

		if strings.TrimSpace(getStringField(profileData, "did")) == "" {
			profileData["did"] = did
		}

		profiles = append(profiles, profileData)
	}
	pendingNFProfilesMu.RUnlock()

	for _, did := range expiredDIDs {
		forgetPendingNFProfile(did)
	}

	return profiles
}

func getNFProfileByDIDWithFallback(ds *api.DperService, did string, attempts int, interval time.Duration) (map[string]interface{}, string, error) {
	if attempts < 1 {
		attempts = 1
	}

	var lastErr error
	for i := 0; i < attempts; i++ {
		profile, err := getNFProfileByDID(ds, did)
		if err == nil {
			forgetPendingNFProfile(did)
			return profile, "blockchain", nil
		}

		lastErr = err

		if cached, ok := getPendingNFProfile(did); ok {
			loglogrus.Log.Warnf("[NF Cache] Using pending cached NF profile for DID: %s while blockchain state is not yet readable\n", did)
			return cached, "pending-cache", nil
		}

		if i < attempts-1 {
			time.Sleep(interval)
		}
	}

	return nil, "", lastErr
}