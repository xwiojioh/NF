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
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"

	"github.com/oai/did-proxy/crypto"
)

// KeyPair represents an asymmetric key pair for DID
// Using secp256k1 curve for compatibility with Ethereum/Bitcoin
type KeyPair struct {
	PrivateKey *ecdsa.PrivateKey
	PublicKey  *ecdsa.PublicKey
}

// KeyStore manages cryptographic keys for DIDs
// Keys are stored in hex format (compatible with Ethereum keystore)
type KeyStore struct {
	basePath string
}

// NewKeyStore creates a new key store at the specified path
func NewKeyStore(basePath string) (*KeyStore, error) {
	if err := os.MkdirAll(basePath, 0700); err != nil {
		return nil, fmt.Errorf("failed to create key store directory: %w", err)
	}
	return &KeyStore{basePath: basePath}, nil
}

// GetOrCreateKeyPair retrieves an existing key pair or creates a new one
func (ks *KeyStore) GetOrCreateKeyPair(nfInstanceID string) (*KeyPair, error) {
	privateKeyPath := filepath.Join(ks.basePath, fmt.Sprintf("%s_private.hex", nfInstanceID))
	publicKeyPath := filepath.Join(ks.basePath, fmt.Sprintf("%s_public.hex", nfInstanceID))

	if _, err := os.Stat(privateKeyPath); err == nil {
		return ks.loadKeyPair(privateKeyPath)
	}

	keyPair, err := ks.generateKeyPair()
	if err != nil {
		return nil, err
	}

	if err := ks.saveKeyPair(keyPair, privateKeyPath, publicKeyPath); err != nil {
		return nil, err
	}

	return keyPair, nil
}

func (ks *KeyStore) generateKeyPair() (*KeyPair, error) {
	privateKey, err := crypto.GenerateKey()
	if err != nil {
		return nil, fmt.Errorf("failed to generate private key: %w", err)
	}
	return &KeyPair{PrivateKey: privateKey, PublicKey: &privateKey.PublicKey}, nil
}

func (ks *KeyStore) saveKeyPair(keyPair *KeyPair, privateKeyPath, publicKeyPath string) error {
	privateKeyHex := hex.EncodeToString(crypto.FromECDSA(keyPair.PrivateKey))
	if err := os.WriteFile(privateKeyPath, []byte(privateKeyHex), 0600); err != nil {
		return fmt.Errorf("failed to write private key: %w", err)
	}

	publicKeyHex := hex.EncodeToString(crypto.FromECDSAPub(keyPair.PublicKey))
	if err := os.WriteFile(publicKeyPath, []byte(publicKeyHex), 0644); err != nil {
		return fmt.Errorf("failed to write public key: %w", err)
	}
	return nil
}

func (ks *KeyStore) loadKeyPair(privateKeyPath string) (*KeyPair, error) {
	privateKey, err := crypto.LoadECDSA(privateKeyPath)
	if err != nil {
		return nil, fmt.Errorf("failed to load private key: %w", err)
	}
	return &KeyPair{PrivateKey: privateKey, PublicKey: &privateKey.PublicKey}, nil
}

func (kp *KeyPair) GetPublicKeyHex() string {
	pubBytes := crypto.FromECDSAPub(kp.PublicKey)
	return hex.EncodeToString(pubBytes)
}

func (kp *KeyPair) GetCompressedPublicKeyHex() string {
	compressedPK := compressPublicKey(kp.PublicKey)
	return hex.EncodeToString(compressedPK)
}

func (kp *KeyPair) GetPublicKeyBytes() []byte {
	return crypto.FromECDSAPub(kp.PublicKey)
}

func (kp *KeyPair) GetCompressedPublicKeyBytes() []byte {
	return compressPublicKey(kp.PublicKey)
}

func (kp *KeyPair) GetPublicKeyBase64() (x, y string, err error) {
	x = base64URLEncode(kp.PublicKey.X.Bytes())
	y = base64URLEncode(kp.PublicKey.Y.Bytes())
	return x, y, nil
}

func base64URLEncode(data []byte) string {
	padded := make([]byte, 32)
	copy(padded[32-len(data):], data)
	return base64.RawURLEncoding.EncodeToString(padded)
}

func (kp *KeyPair) Sign(hash []byte) ([]byte, error) {
	return crypto.Sign(hash, kp.PrivateKey)
}

func (kp *KeyPair) GetAddress() []byte {
	addr := crypto.PubkeyToAddress(*kp.PublicKey)
	return addr[:]
}

func (kp *KeyPair) GetAddressHex() string {
	addr := crypto.PubkeyToAddress(*kp.PublicKey)
	return "0x" + hex.EncodeToString(addr[:])
}
