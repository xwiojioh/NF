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

package config

import (
	"crypto/rand"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/oai/did-proxy/logger"
	"gopkg.in/yaml.v3"
)

// Config represents the main OAI configuration structure
// Compatible with OAI 5GC config.yaml format
type Config struct {
	LogLevel            LogLevelConfig `yaml:"log_level"`
	RegisterNF          RegisterConfig `yaml:"register_nf"`
	RegisterBCF         RegisterConfig `yaml:"register_bcf"` // BCF registration config (same format as register_nf)
	HTTPVersion         int            `yaml:"http_version"`
	NFs                 NFsConfig      `yaml:"nfs"`
	AUSF                *AUSFConfig    `yaml:"ausf"`
	ExtendedProfilePath string         `yaml:"extended_profile_path"` // Top-level path for extended profile
	KeyStorePath        string         `yaml:"key_store_path"`        // Path for DID key storage
	HardwareIDPath      string         `yaml:"hardware_id_path"`      // Path for hardware ID storage
}

// LogLevelConfig represents log level settings
type LogLevelConfig struct {
	General string `yaml:"general"`
}

// RegisterConfig represents NF registration settings
type RegisterConfig struct {
	General string `yaml:"general"`
}

// NFsConfig represents all NF configurations
type NFsConfig struct {
	AMF  *NFEndpoint `yaml:"amf"`
	SMF  *NFEndpoint `yaml:"smf"`
	UDM  *NFEndpoint `yaml:"udm"`
	UDR  *NFEndpoint `yaml:"udr"`
	AUSF *NFEndpoint `yaml:"ausf"`
	NRF  *NFEndpoint `yaml:"nrf"`
	PCF  *NFEndpoint `yaml:"pcf"`
	NSSF *NFEndpoint `yaml:"nssf"`
	BCF  *NFEndpoint `yaml:"bcf"` // New BCF endpoint
}

// NFEndpoint represents a network function endpoint configuration
type NFEndpoint struct {
	Host string     `yaml:"host"`
	SBI  *SBIConfig `yaml:"sbi"`
}

// SBIConfig represents SBI interface configuration
type SBIConfig struct {
	Port          int    `yaml:"port"`
	APIVersion    string `yaml:"api_version"`
	InterfaceName string `yaml:"interface_name"`
}

// AUSFConfig represents AUSF-specific configuration
type AUSFConfig struct {
	Host               string     `yaml:"host"` // AUSF host/IP address
	SBI                *SBIConfig `yaml:"sbi"`  // SBI interface configuration
	AUSFName           string     `yaml:"ausf_name"`
	NFInstanceID       string     `yaml:"nf_instance_id,omitempty"` // Auto-generated if not set
	NFInstanceIDSource string     `yaml:"-"`                        // Source: "config_file", "extended_profile", or "generated"
}

// BCFConfig represents BCF-specific configuration for registration
type BCFConfig struct {
	Host       string
	Port       int
	APIVersion string
	Scheme     string
}

// NewBCFConfigFromEndpoint creates a BCFConfig from NFEndpoint
func NewBCFConfigFromEndpoint(endpoint *NFEndpoint) *BCFConfig {
	cfg := &BCFConfig{
		Host:       endpoint.Host,
		Port:       8080,
		APIVersion: "v1",
		Scheme:     "http",
	}

	if endpoint.SBI != nil {
		if endpoint.SBI.Port > 0 {
			cfg.Port = endpoint.SBI.Port
		}
		if endpoint.SBI.APIVersion != "" {
			cfg.APIVersion = endpoint.SBI.APIVersion
		}
	}

	return cfg
}

// GetURI returns the BCF NFM API URI for NF registration
func (c *BCFConfig) GetURI() string {
	return fmt.Sprintf("%s://%s:%d/nbcf_nfm/%s/nf_instances",
		c.Scheme, c.Host, c.Port, c.APIVersion)
}

// GetHeartbeatURI returns the BCF heartbeat URI for a specific NF instance
func (c *BCFConfig) GetHeartbeatURI(nfInstanceID string) string {
	return fmt.Sprintf("%s/%s", c.GetURI(), nfInstanceID)
}

// LoadConfig loads the OAI configuration from a YAML file
func LoadConfig(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}

	// Expand environment variables
	expandedData := os.ExpandEnv(string(data))

	var cfg Config
	if err := yaml.Unmarshal([]byte(expandedData), &cfg); err != nil {
		return nil, fmt.Errorf("failed to parse config file: %w", err)
	}

	// Set defaults
	if cfg.HTTPVersion == 0 {
		cfg.HTTPVersion = 2
	}

	// Set default extended profile path if not configured
	// Note: The actual filename with NF type is determined in main.go
	// This is just a fallback for AUSF
	if cfg.ExtendedProfilePath == "" {
		cfg.ExtendedProfilePath = "/usr/local/etc/oai/extended_ausf_profile.json"
	}

	// Set default key store path if not configured
	if cfg.KeyStorePath == "" {
		cfg.KeyStorePath = "/usr/local/etc/oai/keys"
	}

	// Generate NFInstanceID if not set
	// Priority: 1. config file, 2. existing extended profile, 3. generate new UUID
	if cfg.AUSF != nil && cfg.AUSF.NFInstanceID == "" {
		// Try to read from existing extended profile first
		existingID := readNFInstanceIDFromProfile(cfg.ExtendedProfilePath)
		if existingID != "" {
			cfg.AUSF.NFInstanceID = existingID
			cfg.AUSF.NFInstanceIDSource = "extended_profile" // Mark source
		} else {
			cfg.AUSF.NFInstanceID = generateNFInstanceID()
			cfg.AUSF.NFInstanceIDSource = "generated" // Mark source
		}
	} else if cfg.AUSF != nil && cfg.AUSF.NFInstanceID != "" {
		cfg.AUSF.NFInstanceIDSource = "config_file" // From config file
	}

	return &cfg, nil
}

// readNFInstanceIDFromProfile reads nfInstanceId from existing extended profile
func readNFInstanceIDFromProfile(profilePath string) string {
	data, err := os.ReadFile(profilePath)
	if err != nil {
		return "" // File doesn't exist or can't be read
	}

	var profile map[string]interface{}
	if err := json.Unmarshal(data, &profile); err != nil {
		return ""
	}

	if nfInstanceID, ok := profile["nfInstanceId"].(string); ok {
		return nfInstanceID
	}
	return ""
}

// generateNFInstanceID generates a UUID v4 for NF instance
// Same format as AUSF's boost::uuids::random_generator()
func generateNFInstanceID() string {
	// Generate UUID v4 using crypto/rand
	uuid := make([]byte, 16)
	_, err := rand.Read(uuid)
	if err != nil {
		// Fallback to timestamp-based ID
		return fmt.Sprintf("ausf-%d", time.Now().UnixNano())
	}

	// Set version (4) and variant (RFC 4122)
	uuid[6] = (uuid[6] & 0x0f) | 0x40 // Version 4
	uuid[8] = (uuid[8] & 0x3f) | 0x80 // Variant is 10

	// Format as UUID string: xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x",
		uuid[0:4],
		uuid[4:6],
		uuid[6:8],
		uuid[8:10],
		uuid[10:16])
}

// GetBCFConfig extracts BCF configuration from the main config
func (c *Config) GetBCFConfig() *BCFConfig {
	if c.NFs.BCF == nil {
		return nil
	}

	bcfCfg := &BCFConfig{
		Host:       c.NFs.BCF.Host,
		Port:       8080,
		APIVersion: "v1",
		Scheme:     "http",
	}

	if c.NFs.BCF.SBI != nil {
		if c.NFs.BCF.SBI.Port > 0 {
			bcfCfg.Port = c.NFs.BCF.SBI.Port
		}
		if c.NFs.BCF.SBI.APIVersion != "" {
			bcfCfg.APIVersion = c.NFs.BCF.SBI.APIVersion
		}
	}

	return bcfCfg
}

// Display prints the configuration in OAI-style format
func (c *Config) Display(log *logger.Logger) {
	log.Info("==================================================")
	log.Info("                DID Proxy Configuration            ")
	log.Info("==================================================")

	log.Info("Log Level:")
	log.Info("    - General..................: %s", c.LogLevel.General)

	log.Info("HTTP Version...................: %d", c.HTTPVersion)

	if c.AUSF != nil {
		log.Info("AUSF Configuration:")
		log.Info("    - AUSF Name................: %s", c.AUSF.AUSFName)
		log.Info("    - NF Instance ID...........: %s", c.AUSF.NFInstanceID)
		log.Info("    - NF Instance ID Source....: %s", c.AUSF.NFInstanceIDSource)
	}

	if c.NFs.AUSF != nil {
		log.Info("AUSF SBI Endpoint:")
		log.Info("    - Host.....................: %s", c.NFs.AUSF.Host)
		if c.NFs.AUSF.SBI != nil {
			log.Info("    - Port.....................: %d", c.NFs.AUSF.SBI.Port)
			log.Info("    - API Version..............: %s", c.NFs.AUSF.SBI.APIVersion)
		}
	}

	if c.NFs.NRF != nil {
		log.Info("NRF Endpoint:")
		log.Info("    - Host.....................: %s", c.NFs.NRF.Host)
		if c.NFs.NRF.SBI != nil {
			log.Info("    - Port.....................: %d", c.NFs.NRF.SBI.Port)
		}
	}

	if c.NFs.BCF != nil {
		log.Info("BCF (Blockchain Function) Configuration:")
		log.Info("    - Host.....................: %s", c.NFs.BCF.Host)
		if c.NFs.BCF.SBI != nil {
			log.Info("    - Port.....................: %d", c.NFs.BCF.SBI.Port)
			log.Info("    - API Version..............: %s", c.NFs.BCF.SBI.APIVersion)
			log.Info("    - Interface Name...........: %s", c.NFs.BCF.SBI.InterfaceName)
		}
	} else {
		log.Warn("BCF Configuration: NOT CONFIGURED in nfs section")
	}

	log.Info("Register BCF...................: %s", c.RegisterBCF.General)
	log.Info("Extended Profile Path..........: %s", c.ExtendedProfilePath)
	log.Info("Key Store Path.................: %s", c.KeyStorePath)

	log.Info("==================================================")
}

// IsRegisterNFEnabled checks if NF registration is enabled
func (c *Config) IsRegisterNFEnabled() bool {
	return strings.ToLower(c.RegisterNF.General) == "yes"
}

// IsRegisterBCFEnabled checks if BCF registration is enabled from register_bcf config
func (c *Config) IsRegisterBCFEnabled() bool {
	return strings.ToLower(c.RegisterBCF.General) == "yes"
}
