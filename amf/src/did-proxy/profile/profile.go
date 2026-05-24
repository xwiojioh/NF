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
	AMFInfo                    *AMFInfo               `json:"amfInfo,omitempty"`
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

// AMFInfo represents AMF-specific information
type AMFInfo struct {
	AMFSetID             string              `json:"amfSetId"`
	AMFRegionID          string              `json:"amfRegionId"`
	GUAMIList            []GUAMI             `json:"guamiList,omitempty"`
	TAIList              []TAI               `json:"taiList,omitempty"`
	TAIRangeList         []TAIRange          `json:"taiRangeList,omitempty"`
	BackupInfoAMFFailure []GUAMI             `json:"backupInfoAmfFailure,omitempty"`
	BackupInfoAMFRemoval []GUAMI             `json:"backupInfoAmfRemoval,omitempty"`
	N2InterfaceAMFInfo   *N2InterfaceAMFInfo `json:"n2InterfaceAmfInfo,omitempty"`
}

// GUAMI represents Globally Unique AMF Identifier
type GUAMI struct {
	PlmnID PlmnID `json:"plmnId"`
	AMFId  string `json:"amfId"`
}

// TAI represents Tracking Area Identity
type TAI struct {
	PlmnID PlmnID `json:"plmnId"`
	TAC    string `json:"tac"`
}

// TAIRange represents a range of TAIs
type TAIRange struct {
	PlmnID   PlmnID     `json:"plmnId"`
	TACRange []TACRange `json:"tacRangeList"`
}

// TACRange represents a range of TACs
type TACRange struct {
	Start string `json:"start"`
	End   string `json:"end"`
}

// N2InterfaceAMFInfo represents N2 interface information
type N2InterfaceAMFInfo struct {
	IPv4EndpointAddresses []string `json:"ipv4EndpointAddress,omitempty"`
	IPv6EndpointAddresses []string `json:"ipv6EndpointAddress,omitempty"`
	AMFName               string   `json:"amfName,omitempty"`
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
		NFInstanceID:   cfg.AMF.NFInstanceID,
		NFType:         "AMF",
		NFStatus:       "REGISTERED",
		HeartBeatTimer: 50,
		Priority:       1,
		Capacity:       cfg.AMF.RelativeCapacity,
		RecoveryTime:   time.Now().UTC().Format(time.RFC3339),
	}

	// Set PLMN list and S-NSSAI from configuration
	for _, plmn := range cfg.AMF.PLMNSupportList {
		plmnID := PlmnID{
			MCC: plmn.MCC,
			MNC: plmn.MNC,
		}
		profile.PlmnList = append(profile.PlmnList, plmnID)

		var snssais []SNSSAI
		for _, nssai := range plmn.NSSAI {
			snssai := SNSSAI{
				SST: nssai.SST,
				SD:  nssai.SD,
			}
			snssais = append(snssais, snssai)
			profile.SNSSAIs = append(profile.SNSSAIs, snssai)
		}

		profile.PerPlmnSnssaiList = append(profile.PerPlmnSnssaiList, PlmnSnssai{
			PlmnID:  plmnID,
			SNSSAIs: snssais,
		})
	}

	// Set AMF-specific information
	if len(cfg.AMF.ServedGUAMIList) > 0 {
		amfInfo := &AMFInfo{
			AMFSetID:    cfg.AMF.ServedGUAMIList[0].AMFSetID,
			AMFRegionID: cfg.AMF.ServedGUAMIList[0].AMFRegionID,
		}

		for _, guami := range cfg.AMF.ServedGUAMIList {
			amfID := guami.AMFRegionID + guami.AMFSetID + guami.AMFPointer
			amfInfo.GUAMIList = append(amfInfo.GUAMIList, GUAMI{
				PlmnID: PlmnID{
					MCC: guami.MCC,
					MNC: guami.MNC,
				},
				AMFId: amfID,
			})
		}

		profile.AMFInfo = amfInfo
	}

	// Set IP addresses and NF services
	// Priority: cfg.AMF.Host/SBI (top-level OAI 5GC format) > cfg.NFs.AMF (nfs section)
	var host string
	var sbi *config.SBIConfig

	if cfg.AMF != nil && cfg.AMF.Host != "" {
		// Use top-level amf config (OAI 5GC format)
		host = cfg.AMF.Host
		sbi = cfg.AMF.SBI
	} else if cfg.NFs.AMF != nil {
		// Fallback to nfs.amf config
		host = cfg.NFs.AMF.Host
		sbi = cfg.NFs.AMF.SBI
	}

	if host != "" {
		profile.FQDN = host
		profile.IPv4Addresses = []string{host}
		if sbi != nil {
			ipEndpoint := IPEndPoint{
				IPv4Address: host,
				Port:        sbi.Port,
				Transport:   "TCP",
			}

			// Add NF services
			profile.NFServices = []NFService{
				{
					ServiceInstanceID: cfg.AMF.NFInstanceID,
					ServiceName:       "namf-comm",
					Versions: []NFServiceVersion{
						{
							APIVersionInURI: sbi.APIVersion,
							APIFullVersion:  "1.0.0",
						},
					},
					Scheme:          "http",
					NFServiceStatus: "REGISTERED",
					IPEndPoints:     []IPEndPoint{ipEndpoint},
				},
				{
					ServiceInstanceID: "namf-evts",
					ServiceName:       "namf-evts",
					Versions: []NFServiceVersion{
						{
							APIVersionInURI: sbi.APIVersion,
							APIFullVersion:  "1.0.0",
						},
					},
					Scheme:          "http",
					NFServiceStatus: "REGISTERED",
					IPEndPoints:     []IPEndPoint{ipEndpoint},
				},
			}
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
