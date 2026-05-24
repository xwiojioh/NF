package router

import (
	"encoding/json"
	"fmt"
	"strings"

	"p3Chain/api"
)

func getStringField(data map[string]interface{}, keys ...string) string {
	if data == nil {
		return ""
	}

	values := make([]string, 0, len(keys))
	for _, key := range keys {
		if value, ok := data[key].(string); ok {
			values = append(values, value)
		}
	}

	return firstNonEmpty(values...)
}

func flattenNFProfileRecord(record map[string]interface{}) map[string]interface{} {
	flattened := make(map[string]interface{})
	if record == nil {
		return flattened
	}

	if nfProfile, ok := record["nfProfile"].(map[string]interface{}); ok {
		for key, value := range nfProfile {
			flattened[key] = value
		}
	}

	if did := getStringField(record, "did"); did != "" {
		flattened["did"] = did
	}
	if didDocument, ok := record["didDocument"]; ok && didDocument != nil {
		flattened["didDocument"] = didDocument
	}
	if registrationTime := getStringField(record, "registeredAt", "registrationTime"); registrationTime != "" {
		flattened["registrationTime"] = registrationTime
	}
	if lastUpdateTime := getStringField(record, "updatedAt", "lastUpdateTime"); lastUpdateTime != "" {
		flattened["lastUpdateTime"] = lastUpdateTime
	}

	if len(flattened) == 0 {
		for key, value := range record {
			if key == "nfProfile" {
				continue
			}
			flattened[key] = value
		}
	}

	return flattened
}

func flattenNFProfileList(records []map[string]interface{}) []map[string]interface{} {
	if len(records) == 0 {
		return []map[string]interface{}{}
	}

	flattened := make([]map[string]interface{}, 0, len(records))
	for _, record := range records {
		flattened = append(flattened, flattenNFProfileRecord(record))
	}

	return flattened
}

func isRegisteredNFProfileRecord(record map[string]interface{}, nfType string) bool {
	if record == nil {
		return false
	}

	current := record
	if nfProfile, ok := record["nfProfile"].(map[string]interface{}); ok && nfProfile != nil {
		current = nfProfile
	}

	currentType := getStringField(current, "nfType", "nf_type", "target_nf_type")
	if nfType != "" && !strings.EqualFold(strings.TrimSpace(currentType), strings.TrimSpace(nfType)) {
		return false
	}

	status := getStringField(current, "nfStatus", "nf_status", "status")
	return strings.EqualFold(strings.TrimSpace(status), "REGISTERED")
}

func appendUniqueRegisteredNFProfile(results []map[string]interface{}, seen map[string]struct{}, record map[string]interface{}, nfType string) []map[string]interface{} {
	if !isRegisteredNFProfileRecord(record, nfType) {
		return results
	}

	flattened := flattenNFProfileRecord(record)
	identityKey := firstNonEmpty(
		getStringField(flattened, "did"),
		getStringField(flattened, "nfInstanceId", "nf_instance_id"),
	)
	if identityKey == "" {
		identityKey = fmt.Sprintf("%s-%d", strings.ToUpper(strings.TrimSpace(nfType)), len(results))
	}

	if _, exists := seen[identityKey]; exists {
		return results
	}

	seen[identityKey] = struct{}{}
	return append(results, flattened)
}

func getRegisteredNFProfilesByType(ds *api.DperService, nfType string) ([]map[string]interface{}, error) {
	nfType = strings.TrimSpace(nfType)
	if nfType == "" {
		return []map[string]interface{}{}, nil
	}

	results := make([]map[string]interface{}, 0)
	seen := make(map[string]struct{})

	callCmd := "call DID::SPECTRUM::TRADE DiscoverNFByType -args " + nfType
	data, err := ds.SoftCall(callCmd)
	if err == nil && len(data) > 0 && strings.TrimSpace(data[0]) != "" {
		var nfInstances []map[string]interface{}
		if err := json.Unmarshal([]byte(data[0]), &nfInstances); err == nil {
			for _, record := range nfInstances {
				results = appendUniqueRegisteredNFProfile(results, seen, record, nfType)
			}
		}
	}

	for _, record := range getPendingNFProfilesByType(nfType) {
		results = appendUniqueRegisteredNFProfile(results, seen, record, nfType)
	}

	return results, nil
}
