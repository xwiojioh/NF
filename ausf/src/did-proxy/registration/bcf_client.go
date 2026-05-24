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

package registration

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/oai/did-proxy/config"
	"github.com/oai/did-proxy/logger"
	"github.com/oai/did-proxy/profile"
)

// BCFClient handles communication with the BCF (Blockchain Function)
// Following the same pattern as NRF registration in OAI AUSF
type BCFClient struct {
	bcfConfig   *config.BCFConfig
	httpVersion int
	httpClient  *http.Client
	log         *logger.Logger
	registered  bool
}

// NewBCFClient creates a new BCF registration client
func NewBCFClient(bcfCfg *config.BCFConfig, httpVersion int, log *logger.Logger) *BCFClient {
	// Create HTTP client with timeout
	client := &http.Client{
		Timeout: 30 * time.Second,
		Transport: &http.Transport{
			MaxIdleConns:        10,
			MaxIdleConnsPerHost: 10,
			IdleConnTimeout:     90 * time.Second,
		},
	}

	return &BCFClient{
		bcfConfig:   bcfCfg,
		httpVersion: httpVersion,
		httpClient:  client,
		log:         log,
		registered:  false,
	}
}

// RegisterNFProfile registers the extended NF profile with BCF
// Similar to NF registration with NRF (PUT request)
func (c *BCFClient) RegisterNFProfile(extProfile *profile.ExtendedNFProfile) error {
	c.log.Info("Sending NF Instance Registration to BCF")

	uri := fmt.Sprintf("%s/%s", c.bcfConfig.GetURI(), extProfile.NFInstanceID)
	c.log.Debug("BCF Registration URI: %s", uri)

	// Prepare request body
	body := extProfile.ToBytes()
	c.log.Debug("Request body size: %d bytes", len(body))

	// Create PUT request (same as NRF registration)
	req, err := http.NewRequest(http.MethodPut, uri, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	// Send request
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to send request: %w", err)
	}
	defer resp.Body.Close()

	// Read response
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read response: %w", err)
	}

	// Check response status (CREATED or OK indicates success)
	if resp.StatusCode == http.StatusCreated || resp.StatusCode == http.StatusOK {
		c.log.Info("NFRegistration successful, got response from BCF (status: %d)", resp.StatusCode)
		c.log.Debug("Response body: %s", string(respBody))
		c.registered = true
		return nil
	}

	// Handle error response
	c.log.Error("BCF registration failed with status: %d", resp.StatusCode)
	c.log.Debug("Error response: %s", string(respBody))
	return fmt.Errorf("BCF registration failed with status %d: %s", resp.StatusCode, string(respBody))
}

// DeregisterNFProfile deregisters the NF from BCF
// Similar to NF deregistration from NRF (DELETE request)
func (c *BCFClient) DeregisterNFProfile(nfInstanceID string) error {
	if !c.registered {
		c.log.Debug("NF was not registered, skipping deregistration")
		return nil
	}

	c.log.Info("Sending NF Instance Deregistration to BCF")

	uri := fmt.Sprintf("%s/%s", c.bcfConfig.GetURI(), nfInstanceID)
	c.log.Debug("BCF Deregistration URI: %s", uri)

	// Create DELETE request
	req, err := http.NewRequest(http.MethodDelete, uri, nil)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Accept", "application/json")

	// Send request
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to send request: %w", err)
	}
	defer resp.Body.Close()

	// Check response status (NO_CONTENT indicates success)
	if resp.StatusCode == http.StatusNoContent || resp.StatusCode == http.StatusOK {
		c.log.Info("NF Deregistration successful from BCF")
		c.registered = false
		return nil
	}

	return fmt.Errorf("BCF deregistration failed with status %d", resp.StatusCode)
}

// UpdateNFProfile sends a heartbeat/update to BCF
// Similar to NRF heartbeat (PATCH request)
func (c *BCFClient) UpdateNFProfile(nfInstanceID string, patchItems []PatchItem) error {
	c.log.Debug("Sending NF Update to BCF")

	uri := fmt.Sprintf("%s/%s", c.bcfConfig.GetURI(), nfInstanceID)
	c.log.Debug("BCF Update URI: %s", uri)

	// Prepare PATCH body
	body, err := json.Marshal(patchItems)
	if err != nil {
		return fmt.Errorf("failed to marshal patch items: %w", err)
	}

	// Create PATCH request
	req, err := http.NewRequest(http.MethodPatch, uri, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json-patch+json")
	req.Header.Set("Accept", "application/json")

	// Send request
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to send request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusOK || resp.StatusCode == http.StatusNoContent {
		c.log.Debug("NF Update successful")
		return nil
	}

	return fmt.Errorf("BCF update failed with status %d", resp.StatusCode)
}

// Heartbeat sends a periodic heartbeat to BCF
func (c *BCFClient) Heartbeat(nfInstanceID string) error {
	patchItems := []PatchItem{
		{
			Op:    "replace",
			Path:  "/nfStatus",
			Value: "REGISTERED",
		},
	}
	return c.UpdateNFProfile(nfInstanceID, patchItems)
}

// IsRegistered returns whether the NF is currently registered with BCF
func (c *BCFClient) IsRegistered() bool {
	return c.registered
}

// PatchItem represents a JSON Patch item
type PatchItem struct {
	Op    string      `json:"op"`
	Path  string      `json:"path"`
	Value interface{} `json:"value,omitempty"`
	From  string      `json:"from,omitempty"`
}

// RegistrationResponse represents the BCF registration response
type RegistrationResponse struct {
	NFInstanceID   string                 `json:"nfInstanceId"`
	NFStatus       string                 `json:"nfStatus"`
	HeartBeatTimer int                    `json:"heartBeatTimer,omitempty"`
	CustomInfo     map[string]interface{} `json:"customInfo,omitempty"`
}
