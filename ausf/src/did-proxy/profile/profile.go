/*
 * Licensed to the OpenAirInterface (OAI) Software Alliance under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The OpenAirInterface Software Alliance licenses this file to You under
 * the OAI Public License, Version 1.1  (the "License"); you may not use this
 * file except in compliance with the License. You may obtain a copy of the
 * License at
 *
 *      http://www.openairinterface.org/?page_id=698
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *-------------------------------------------------------------------------------
 * For more information about the OpenAirInterface (OAI) Software Alliance:
 *      contact@openairinterface.org
 */

package profile

import (
	"encoding/json"
	"time"

	"github.com/oai/did-proxy/config"
	"github.com/oai/did-proxy/did"
)

// NFProfile represents a 3GPP NF Profile
// Based on 3GPP TS 29.510 NRF NFProfile schema
type NFProfile struct {
	NFInstanceID               string                 `json:"nfInstanceId"`
	NFType                     string                 `json:"nfType"`
	NFStatus                   string                 `json:"nfStatus"`
	HeartBeatTimer             int                    `json:"heartBeatTimer,omitempty"`
	PlmnList                   []PlmnID               `json:"plmnList,omitempty"`
	SNSSAIs                    []SNSSAI               `json:"sNssais,omitempty"`
	PerPlmnSnssaiList          []PlmnSnssai           `json:"perPlmnSnssaiList,omitempty"`
	NSIList                    []string               `json:"nsiList,omitempty"`
	FQDN                       string                 `json:"fqdn,omitempty"`
	InterPlmnFQDN              string                 `json:"interPlmnFqdn,omitempty"`
	IPv4Addresses              []string               `json:"ipv4Addresses,omitempty"`
	IPv6Addresses              []string               `json:"ipv6Addresses,omitempty"`
	AllowedPlmns               []PlmnID               `json:"allowedPlmns,omitempty"`
	AllowedNFTypes             []string               `json:"allowedNfTypes,omitempty"`
	AllowedNSSAIs              []SNSSAI               `json:"allowedNssais,omitempty"`
	Priority                   int                    `json:"priority,omitempty"`
	Capacity                   int                    `json:"capacity,omitempty"`
	Load                       int                    `json:"load,omitempty"`
	LoadTimeStamp              string                 `json:"loadTimeStamp,omitempty"`
	Locality                   string                 `json:"locality,omitempty"`
	NFServices                 []NFService            `json:"nfServices,omitempty"`
	NFProfileChangesSupportInd bool                   `json:"nfProfileChangesSupportInd,omitempty"`
	NFProfileChangesInd        bool                   `json:"nfProfileChangesInd,omitempty"`
	AUSFInfo                   *AUSFInfo              `json:"ausfInfo,omitempty"`
	RecoveryTime               string                 `json:"recoveryTime,omitempty"`
	NFServicePersistence       bool                   `json:"nfServicePersistence,omitempty"`
	CustomInfo                 map[string]interface{} `json:"customInfo,omitempty"`
}

// PlmnID represents a PLMN identifier
type PlmnID struct {
	MCC string `json:"mcc"`
	MNC string `json:"mnc"`
}

// SNSSAI represents a Single Network Slice Selection Assistance Information
type SNSSAI struct {
	SST int    `json:"sst"`
	SD  string `json:"sd,omitempty"`
}

// PlmnSnssai represents PLMN-specific S-NSSAI information
type PlmnSnssai struct {
	PlmnID  PlmnID   `json:"plmnId"`
	SNSSAIs []SNSSAI `json:"sNssaiList"`
}

// NFService represents an NF service
type NFService struct {
	ServiceInstanceID string             `json:"serviceInstanceId"`
	ServiceName       string             `json:"serviceName"`
	Versions          []NFServiceVersion `json:"versions"`
	Scheme            string             `json:"scheme"`
	NFServiceStatus   string             `json:"nfServiceStatus"`
	FQDN              string             `json:"fqdn,omitempty"`
	InterPlmnFQDN     string             `json:"interPlmnFqdn,omitempty"`
	IPEndPoints       []IPEndPoint       `json:"ipEndPoints,omitempty"`
	APIPrefix         string             `json:"apiPrefix,omitempty"`
	AllowedPlmns      []PlmnID           `json:"allowedPlmns,omitempty"`
	AllowedNFTypes    []string           `json:"allowedNfTypes,omitempty"`
	AllowedNSSAIs     []SNSSAI           `json:"allowedNssais,omitempty"`
	Priority          int                `json:"priority,omitempty"`
	Capacity          int                `json:"capacity,omitempty"`
	Load              int                `json:"load,omitempty"`
	LoadTimeStamp     string             `json:"loadTimeStamp,omitempty"`
	RecoveryTime      string             `json:"recoveryTime,omitempty"`
	SupportedFeatures string             `json:"supportedFeatures,omitempty"`
}

// NFServiceVersion represents version information for an NF service
type NFServiceVersion struct {
	APIVersionInURI string `json:"apiVersionInUri"`
	APIFullVersion  string `json:"apiFullVersion"`
	Expiry          string `json:"expiry,omitempty"`
	RetireTime      string `json:"retirementTime,omitempty"`
}

// IPEndPoint represents an IP endpoint
type IPEndPoint struct {
	IPv4Address string `json:"ipv4Address,omitempty"`
	IPv6Address string `json:"ipv6Address,omitempty"`
	Transport   string `json:"transport,omitempty"`
	Port        int    `json:"port,omitempty"`
}

// AUSFInfo represents AUSF-specific information
type AUSFInfo struct {
	GroupID           string   `json:"groupId,omitempty"`
	SupiRanges        []string `json:"supiRanges,omitempty"`
	RoutingIndicators []string `json:"routingIndicators,omitempty"`
}

// ExtendedNFProfile extends NFProfile with DID information
type ExtendedNFProfile struct {
	NFProfile
	DID         string                 `json:"did"`
	DIDDocument map[string]interface{} `json:"didDocument"`
}

// GenerateNFProfile creates a standard 3GPP NF Profile from configuration
func GenerateNFProfile(cfg *config.Config) *NFProfile {
	profile := &NFProfile{
		NFInstanceID:   cfg.AUSF.NFInstanceID,
		NFType:         "AUSF",
		NFStatus:       "REGISTERED",
		HeartBeatTimer: 50,
		Priority:       1,
		Capacity:       100,
		RecoveryTime:   time.Now().UTC().Format(time.RFC3339),
	}

	// Set AUSF-specific information
	profile.AUSFInfo = &AUSFInfo{
		GroupID: "ausf-group-001",
	}

	// Set IP addresses and services from configuration
	// Priority: 1. Top-level cfg.AUSF (OAI config format)
	//           2. cfg.NFs.AUSF (legacy format)

	var ausfHost string
	var ausfPort int
	var ausfAPIVersion string

	// Try top-level AUSF config first (OAI 5GC format)
	if cfg.AUSF != nil && cfg.AUSF.Host != "" {
		ausfHost = cfg.AUSF.Host
		if cfg.AUSF.SBI != nil {
			ausfPort = cfg.AUSF.SBI.Port
			ausfAPIVersion = cfg.AUSF.SBI.APIVersion
		}
	}

	// Fallback to nfs.ausf if top-level not available
	if ausfHost == "" && cfg.NFs.AUSF != nil {
		ausfHost = cfg.NFs.AUSF.Host
		if cfg.NFs.AUSF.SBI != nil {
			ausfPort = cfg.NFs.AUSF.SBI.Port
			ausfAPIVersion = cfg.NFs.AUSF.SBI.APIVersion
		}
	}

	// Set defaults
	if ausfPort == 0 {
		ausfPort = 8081 // Default AUSF port
	}
	if ausfAPIVersion == "" {
		ausfAPIVersion = "v1"
	}

	// Set FQDN and IP addresses
	if ausfHost != "" {
		profile.FQDN = ausfHost
		profile.IPv4Addresses = []string{ausfHost}

		ipEndpoint := IPEndPoint{
			IPv4Address: ausfHost,
			Port:        ausfPort,
			Transport:   "TCP",
		}

		// Add NF services for AUSF
		profile.NFServices = []NFService{
			{
				ServiceInstanceID: cfg.AUSF.NFInstanceID,
				ServiceName:       "nausf-auth",
				Versions: []NFServiceVersion{
					{
						APIVersionInURI: ausfAPIVersion,
						APIFullVersion:  "1.0.0",
					},
				},
				Scheme:          "http",
				NFServiceStatus: "REGISTERED",
				IPEndPoints:     []IPEndPoint{ipEndpoint},
			},
			{
				ServiceInstanceID: "nausf-sorprotection",
				ServiceName:       "nausf-sorprotection",
				Versions: []NFServiceVersion{
					{
						APIVersionInURI: ausfAPIVersion,
						APIFullVersion:  "1.0.0",
					},
				},
				Scheme:          "http",
				NFServiceStatus: "REGISTERED",
				IPEndPoints:     []IPEndPoint{ipEndpoint},
			},
			{
				ServiceInstanceID: "nausf-upuprotection",
				ServiceName:       "nausf-upuprotection",
				Versions: []NFServiceVersion{
					{
						APIVersionInURI: ausfAPIVersion,
						APIFullVersion:  "1.0.0",
					},
				},
				Scheme:          "http",
				NFServiceStatus: "REGISTERED",
				IPEndPoints:     []IPEndPoint{ipEndpoint},
			},
		}
	}

	return profile
}

// ToMap converts the NFProfile to a map for DID generation
func (p *NFProfile) ToMap() map[string]interface{} {
	data, _ := json.Marshal(p)
	var result map[string]interface{}
	json.Unmarshal(data, &result)
	return result
}

// NewExtendedNFProfile creates an extended NF Profile with DID information
func NewExtendedNFProfile(nfProfile *NFProfile, didID string, didDocument *did.DIDDocument) *ExtendedNFProfile {
	return &ExtendedNFProfile{
		NFProfile:   *nfProfile,
		DID:         didID,
		DIDDocument: didDocument.ToMap(),
	}
}

// ToJSON converts the extended profile to JSON
func (e *ExtendedNFProfile) ToJSON() string {
	data, err := json.MarshalIndent(e, "", "  ")
	if err != nil {
		return "{}"
	}
	return string(data)
}

// ToBytes converts the extended profile to bytes
func (e *ExtendedNFProfile) ToBytes() []byte {
	data, _ := json.Marshal(e)
	return data
}
