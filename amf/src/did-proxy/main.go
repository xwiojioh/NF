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

package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/oai/did-proxy/config"
	"github.com/oai/did-proxy/did"
	"github.com/oai/did-proxy/logger"
	"github.com/oai/did-proxy/profile"
)

var (
	configPath     = flag.String("config", "/usr/local/etc/oai/config.yaml", "Path to OAI configuration file")
	outputPath     = flag.String("output", "", "Path to save extended NF profile (default: /usr/local/etc/oai/extended_{nf_type}_profile.json)")
	keyPath        = flag.String("keypath", "/usr/local/etc/oai/keys", "Path to key storage directory")
	hardwareIDPath = flag.String("hwid-path", "/usr/local/etc/oai/hardware_id", "Path to hardware ID storage directory")
)

func main() {
	flag.Parse()

	// Initialize logger
	log := logger.NewLogger("did-proxy")
	log.Info("==================================================")
	log.Info("    DID Proxy - Extended Profile Generator        ")
	log.Info("    for OAI 5GC BCF Registration                  ")
	log.Info("==================================================")

	// Step 1: Load OAI configuration (parallel with AMF)
	log.Info("[Step 1] Loading configuration from: %s", *configPath)
	cfg, err := config.LoadConfig(*configPath)
	if err != nil {
		log.Error("Failed to load configuration: %v", err)
		os.Exit(1)
	}
	log.Info("Configuration loaded successfully")

	// Display parsed configuration (OAI style logging)
	cfg.Display(log)

	// Determine NF type for file naming
	nfType := "unknown"
	if cfg.AMF != nil {
		nfType = "amf"
	}
	// Future: add support for other NF types (SMF, UDM, etc.)

	// Use extended_profile_path from top-level config if set
	if cfg.ExtendedProfilePath != "" {
		*outputPath = cfg.ExtendedProfilePath
		log.Info("Using extended_profile_path from config: %s", *outputPath)
	} else if *outputPath == "" {
		// Generate default path with NF type
		*outputPath = fmt.Sprintf("/usr/local/etc/oai/extended_%s_profile.json", nfType)
		log.Info("Using default extended profile path: %s", *outputPath)
	}

	// Use key_store_path from config if set
	if cfg.KeyStorePath != "" {
		*keyPath = cfg.KeyStorePath
		log.Info("Using key_store_path from config: %s", *keyPath)
	}

	// Use hardware_id_path from config if set (or use default)
	if cfg.HardwareIDPath != "" {
		*hardwareIDPath = cfg.HardwareIDPath
		log.Info("Using hardware_id_path from config: %s", *hardwareIDPath)
	}

	// Step 2: Initialize key store
	log.Info("[Step 2] Initializing key store at: %s", *keyPath)
	keyStore, err := did.NewKeyStore(*keyPath)
	if err != nil {
		log.Error("Failed to initialize key store: %v", err)
		os.Exit(1)
	}
	log.Info("Key store initialized successfully")

	// Step 3: Generate NF Profile from configuration (parallel with AMF)
	log.Info("[Step 3] Generating NF Profile from configuration")
	nfProfile := profile.GenerateNFProfile(cfg)
	log.Info("Generated NF Profile:")
	log.Info("    - NF Instance ID: %s", nfProfile.NFInstanceID)
	log.Info("    - NF Type: %s", nfProfile.NFType)
	log.Info("    - NF Status: %s", nfProfile.NFStatus)

	// Step 4: Preparing cryptographic key pair
	log.Info("[Step 4] Preparing cryptographic key pair")
	keyPair, err := keyStore.GetOrCreateKeyPair(nfProfile.NFInstanceID)
	if err != nil {
		log.Error("Failed to get/create key pair: %v", err)
		os.Exit(1)
	}
	log.Info("Key pair ready for NF Instance: %s", nfProfile.NFInstanceID)

	// Step 5: Generate or load hardware identity for this NF
	log.Info("[Step 5] Initializing hardware identity")
	log.Info("    - Hardware ID storage path: %s", *hardwareIDPath)
	log.Info("    - NF Instance ID: %s", nfProfile.NFInstanceID)
	hwManager := did.NewHardwareIDManager(*hardwareIDPath)
	hardwareID, err := hwManager.GetOrGenerateHardwareID(nfType, nfProfile.NFInstanceID)
	if err != nil {
		log.Error("Failed to get/generate hardware ID: %v", err)
		os.Exit(1)
	}

	// Step 6: Generate DID from NF profile + hardware ID with private key signature
	// Process: SHA256(NF_profile + hardware_id) -> Hex encode -> ECDSA sign -> did:oai5gc:xxx format
	log.Info("[Step 6] Generating hardware-bound DID")
	log.Info("    - Input: NF_profile + hardware_id")
	log.Info("    - Process: SHA256 -> Hex encode -> ECDSA signature")
	didGen := did.NewDIDGeneratorWithHardware(nfType, nfProfile.NFInstanceID, hardwareID, keyPair.PrivateKey)
	didID, didDocument, err := didGen.GenerateDID()
	if err != nil {
		log.Error("Failed to generate DID: %v", err)
		os.Exit(1)
	}
	log.Info("Generated DID: %s", didID)
	log.Debug("DID Document:\n%s", didDocument.ToJSON())

	// Step 7: Create Extended NF Profile with DID
	log.Info("[Step 7] Creating Extended NF Profile with DID")
	extendedProfile := profile.NewExtendedNFProfile(nfProfile, didID, didDocument)
	log.Info("Extended NF Profile created successfully")
	log.Info("    - DID embedded in profile")
	log.Info("    - DID Document embedded in profile")

	// Step 8: Save Extended Profile to file
	log.Info("[Step 8] Saving Extended NF Profile to file")
	err = saveExtendedProfile(extendedProfile, *outputPath, log)
	if err != nil {
		log.Error("Failed to save extended profile: %v", err)
		os.Exit(1)
	}

	log.Info("==================================================")
	log.Info("  DID Proxy completed successfully!               ")
	log.Info("  Extended NF Profile saved to:                   ")
	log.Info("    %s", *outputPath)
	log.Info("                                                  ")
	log.Info("  AMF can now read this file for BCF registration ")
	log.Info("==================================================")
}

// saveExtendedProfile saves the extended profile to a JSON file
func saveExtendedProfile(extProfile *profile.ExtendedNFProfile, outputPath string, log *logger.Logger) error {
	// Create directory if it doesn't exist
	dir := filepath.Dir(outputPath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}

	// Marshal to JSON with indentation
	data, err := json.MarshalIndent(extProfile, "", "  ")
	if err != nil {
		return err
	}

	// Write to file
	if err := os.WriteFile(outputPath, data, 0644); err != nil {
		return err
	}

	log.Info("Extended profile saved: %d bytes written", len(data))
	return nil
}
