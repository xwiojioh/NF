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

package did

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"

	"github.com/oai/did-proxy/crypto"
)

// DID Method for OAI 5GC NFs
const DIDMethod = "did:oai5gc"

// DIDDocument represents a W3C DID Document
// Following W3C DID Core Specification: https://www.w3.org/TR/did-core/
type DIDDocument struct {
	Context            []string             `json:"@context"`
	ID                 string               `json:"id"`
	Controller         string               `json:"controller,omitempty"`
	VerificationMethod []VerificationMethod `json:"verificationMethod"`
	Authentication     []string             `json:"authentication,omitempty"`
	AssertionMethod    []string             `json:"assertionMethod,omitempty"`
	Created            string               `json:"created,omitempty"`
	Updated            string               `json:"updated,omitempty"`
}

// VerificationMethod represents a verification method in the DID Document
// Using publicKeyMultibase with compressed secp256k1 public key (33 bytes)
type VerificationMethod struct {
	ID                 string `json:"id"`
	Type               string `json:"type"`
	Controller         string `json:"controller"`
	PublicKeyMultibase string `json:"publicKeyMultibase"` // 压缩格式的公钥 (base58btc encoded)
}

// DIDGenerator generates DIDs and DID Documents for NFs
// Uses nfInstanceId with private key signature for DID generation
type DIDGenerator struct {
	nfType       string
	nfInstanceID string
	hardwareID   string
	privateKey   *ecdsa.PrivateKey
}

// NewDIDGenerator creates a new DID generator (legacy, no hardware binding)
// Input: nfInstanceId (stable identifier) and private key for signing
func NewDIDGenerator(nfInstanceID string, privateKey *ecdsa.PrivateKey) *DIDGenerator {
	return &DIDGenerator{
		nfInstanceID: nfInstanceID,
		privateKey:   privateKey,
	}
}

// NewDIDGeneratorWithHardware creates a new DID generator with hardware binding
// Input: nfType, nfInstanceId, hardwareID, and private key for signing
func NewDIDGeneratorWithHardware(nfType, nfInstanceID, hardwareID string, privateKey *ecdsa.PrivateKey) *DIDGenerator {
	return &DIDGenerator{
		nfType:       nfType,
		nfInstanceID: nfInstanceID,
		hardwareID:   hardwareID,
		privateKey:   privateKey,
	}
}

// GenerateDID generates a DID and DID Document
// If hardwareID is set: DID = did:oai5gc:<binding_hash_32>:<public_key_hex>
// Otherwise (legacy): DID = did:oai5gc:<signature(sha256(nfInstanceId))>
func (g *DIDGenerator) GenerateDID() (string, *DIDDocument, error) {
	// Get public key from private key
	publicKey := &g.privateKey.PublicKey

	// Generate DID identifier
	var didID string
	if g.hardwareID != "" {
		// New format with hardware binding
		uncompressedPK := uncompressPublicKey(publicKey)
		publicKeyHex := hex.EncodeToString(uncompressedPK)
		didID = GenerateDIDWithHardwareBinding(g.nfType, g.nfInstanceID, g.hardwareID, publicKeyHex)
	} else {
		// Legacy format
		didID = g.generateDIDIdentifier()
	}

	// Create verification method with public key
	keyID := fmt.Sprintf("%s#key-1", didID)

	// Create compressed public key for publicKeyMultibase format
	// Compressed format: 0x02/0x03 prefix + X coordinate (33 bytes total)
	compressedPK := compressPublicKey(publicKey)
	pkMultibase := "z" + base58Encode(compressedPK) // 'z' prefix = base58btc

	verificationMethod := VerificationMethod{
		ID:                 keyID,
		Type:               "EcdsaSecp256k1VerificationKey2019", // secp256k1 verification key type
		Controller:         didID,
		PublicKeyMultibase: pkMultibase, // Compressed secp256k1 public key (33 bytes, base58btc encoded)
	}

	// Create DID Document
	now := time.Now().UTC().Format(time.RFC3339)
	didDocument := &DIDDocument{
		Context: []string{
			"https://www.w3.org/ns/did/v1",
			"https://w3id.org/security/suites/secp256k1-2019/v1",
		},
		ID:                 didID,
		Controller:         didID,
		VerificationMethod: []VerificationMethod{verificationMethod},
		Authentication:     []string{keyID},
		AssertionMethod:    []string{keyID},
		Created:            now,
		Updated:            now,
	}

	return didID, didDocument, nil
}

// generateDIDIdentifier generates the DID identifier
// Process: nfInstanceId -> SHA256 hash -> Sign with private key -> Hex encode
func (g *DIDGenerator) generateDIDIdentifier() string {
	// Step 1: SHA256 hash of nfInstanceId
	hash := sha256.Sum256([]byte(g.nfInstanceID))

	// Step 2: Sign the hash with private key
	signature, err := crypto.Sign(hash[:], g.privateKey)
	if err != nil {
		// Fallback to just hash if signing fails
		hashHex := hex.EncodeToString(hash[:])
		return fmt.Sprintf("%s:%s", DIDMethod, hashHex)
	}

	// Step 3: Hex encode the signature
	signatureHex := hex.EncodeToString(signature)

	// DID format: did:oai5gc:<signature>
	return fmt.Sprintf("%s:%s", DIDMethod, signatureHex)
}

// GetNFInstanceID returns the nfInstanceId
func (g *DIDGenerator) GetNFInstanceID() string {
	return g.nfInstanceID
}

// ToJSON converts the DID Document to JSON string
func (d *DIDDocument) ToJSON() string {
	data, err := json.MarshalIndent(d, "", "  ")
	if err != nil {
		return "{}"
	}
	return string(data)
}

// ToMap converts the DID Document to a map
func (d *DIDDocument) ToMap() map[string]interface{} {
	data, _ := json.Marshal(d)
	var result map[string]interface{}
	json.Unmarshal(data, &result)
	return result
}

// Verify verifies the DID Document structure
func (d *DIDDocument) Verify() error {
	if d.ID == "" {
		return fmt.Errorf("DID Document must have an ID")
	}
	if len(d.VerificationMethod) == 0 {
		return fmt.Errorf("DID Document must have at least one verification method")
	}
	return nil
}

// base58Encode encodes bytes to base58 (Bitcoin alphabet)
func base58Encode(data []byte) string {
	const alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

	// Count leading zeros
	leadingZeros := 0
	for _, b := range data {
		if b == 0 {
			leadingZeros++
		} else {
			break
		}
	}

	// Allocate enough space
	size := len(data)*138/100 + 1
	buf := make([]byte, size)

	// Convert to base58
	var carry int
	j := size - 1
	for _, b := range data {
		carry = int(b)
		for k := size - 1; k >= 0; k-- {
			carry += 256 * int(buf[k])
			buf[k] = byte(carry % 58)
			carry /= 58
			if k <= j && carry == 0 {
				break
			}
		}
		for j > 0 && buf[j-1] != 0 {
			j--
		}
	}

	// Build result
	result := make([]byte, leadingZeros+size-j)
	for i := 0; i < leadingZeros; i++ {
		result[i] = '1'
	}
	for i, b := range buf[j:] {
		result[leadingZeros+i] = alphabet[b]
	}

	return string(result)
}

// compressPublicKey compresses a secp256k1 public key to 33 bytes
func compressPublicKey(pub *ecdsa.PublicKey) []byte {
	// Compressed format: 0x02/0x03 prefix + X coordinate (33 bytes total)
	compressed := make([]byte, 33)
	xBytes := pub.X.Bytes()
	// Copy X coordinate, right-aligned
	copy(compressed[33-len(xBytes):], xBytes)
	// Set prefix based on Y coordinate parity
	if pub.Y.Bit(0) == 0 {
		compressed[0] = 0x02
	} else {
		compressed[0] = 0x03
	}
	return compressed
}

// uncompressPublicKey returns uncompressed public key (65 bytes: 04 prefix + X + Y)
func uncompressPublicKey(pub *ecdsa.PublicKey) []byte {
	uncompressed := make([]byte, 65)
	uncompressed[0] = 0x04 // Uncompressed point prefix

	xBytes := pub.X.Bytes()
	yBytes := pub.Y.Bytes()

	// Copy X coordinate (32 bytes, right-aligned starting at offset 1)
	copy(uncompressed[33-len(xBytes):33], xBytes)
	// Copy Y coordinate (32 bytes, right-aligned starting at offset 33)
	copy(uncompressed[65-len(yBytes):65], yBytes)

	return uncompressed
}

// GenerateDIDWithHardwareBinding generates a DID identifier with hardware binding
// Format: did:oai5gc:<binding_hash_32>:<public_key_hex_prefix_16>
// The binding hash binds together: NF type, NF instance ID, hardware ID, and public key
func GenerateDIDWithHardwareBinding(nfType, nfInstanceID, hardwareID, publicKeyHex string) string {
	// Create binding data: combines identity with hardware and cryptographic binding
	bindingData := fmt.Sprintf("%s|%s|%s|%s", nfType, nfInstanceID, hardwareID, publicKeyHex)

	// Hash the binding data
	hash := sha256.Sum256([]byte(bindingData))
	bindingHash := hex.EncodeToString(hash[:16]) // 32 hex chars (16 bytes)

	// Use first 16 bytes of public key hex as identifier suffix
	publicKeyPrefix := publicKeyHex
	if len(publicKeyPrefix) > 32 {
		publicKeyPrefix = publicKeyPrefix[:32]
	}

	return fmt.Sprintf("%s:%s:%s", DIDMethod, bindingHash, publicKeyPrefix)
}
