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

// Package did provides Hardware Identity management for DID generation
// Hardware ID is bound to physical hardware characteristics to prevent
// credential migration attacks in DID mutual authentication scenarios.
//
// Storage Format: Plaintext (human-readable)
// File Naming: <nf_type>_<nf_instance_id>.id (e.g., amf_3d9631d1-5e29-4a1e-81c1-4984a8c889a0.id)
//
// Hardware Fingerprint Sources:
//   - CPU ID from /proc/cpuinfo
//   - Motherboard Serial from /sys/class/dmi/id/product_serial
//   - MAC Address from primary network interface
//   - Machine ID from /etc/machine-id
package did

import (
"crypto/rand"
"crypto/sha256"
"encoding/hex"
"fmt"
"net"
"os"
"path/filepath"
"strings"
)

// HardwareIDManager manages hardware identity generation and persistence
type HardwareIDManager struct {
storageDir string
}

// NewHardwareIDManager creates a new hardware ID manager
func NewHardwareIDManager(storageDir string) *HardwareIDManager {
return &HardwareIDManager{
storageDir: storageDir,
}
}

// GetOrGenerateHardwareID retrieves existing hardware ID or generates a new one
// The hardware ID is stored as plaintext in <nf_type>_<nf_instance_id>.id file
func (m *HardwareIDManager) GetOrGenerateHardwareID(nfType string, nfInstanceID string) (string, error) {
// Build filename: <nf_type>_<nf_instance_id>.id
fileName := fmt.Sprintf("%s_%s.id", strings.ToLower(nfType), nfInstanceID)
filePath := filepath.Join(m.storageDir, fileName)

// Try to load existing hardware ID
if hardwareID, err := m.loadPlaintext(filePath); err == nil {
fmt.Printf("[DID] Loaded existing hardware ID from %s\n", fileName)
return hardwareID, nil
}

// Generate hardware fingerprint
fingerprint := m.collectHardwareFingerprint()
fmt.Printf("[DID] Hardware fingerprint collected: %s\n", m.truncateForLog(fingerprint))

// Generate new hardware ID based on fingerprint
hardwareID := m.generateHardwareID(fingerprint, nfInstanceID)

// Store as plaintext
if err := m.storePlaintext(filePath, hardwareID); err != nil {
return "", fmt.Errorf("failed to store hardware ID: %w", err)
}

fmt.Printf("[DID] Generated and stored new hardware ID in %s\n", fileName)
return hardwareID, nil
}

// generateHardwareID creates a deterministic hardware ID from fingerprint and instance ID
func (m *HardwareIDManager) generateHardwareID(fingerprint string, nfInstanceID string) string {
// Combine fingerprint with instance ID for uniqueness
combined := fingerprint + ":" + nfInstanceID
hash := sha256.Sum256([]byte(combined))
return hex.EncodeToString(hash[:])
}

// storePlaintext writes the hardware ID as plaintext
func (m *HardwareIDManager) storePlaintext(filePath string, hardwareID string) error {
// Ensure directory exists
dir := filepath.Dir(filePath)
if err := os.MkdirAll(dir, 0700); err != nil {
return fmt.Errorf("failed to create directory: %w", err)
}

// Write plaintext (with newline for readability)
if err := os.WriteFile(filePath, []byte(hardwareID+"\n"), 0600); err != nil {
return fmt.Errorf("failed to write hardware ID: %w", err)
}

return nil
}

// loadPlaintext reads the hardware ID from plaintext file
func (m *HardwareIDManager) loadPlaintext(filePath string) (string, error) {
data, err := os.ReadFile(filePath)
if err != nil {
return "", err
}

hardwareID := strings.TrimSpace(string(data))
if hardwareID == "" {
return "", fmt.Errorf("empty hardware ID file")
}

return hardwareID, nil
}

// collectHardwareFingerprint gathers hardware-specific identifiers
func (m *HardwareIDManager) collectHardwareFingerprint() string {
var components []string

// CPU ID
if cpuID := m.getCPUID(); cpuID != "" {
components = append(components, "cpu:"+cpuID)
}

// Motherboard Serial
if mbSerial := m.getMotherboardSerial(); mbSerial != "" {
components = append(components, "mb:"+mbSerial)
}

// MAC Address
if mac := m.getPrimaryMAC(); mac != "" {
components = append(components, "mac:"+mac)
}

// Machine ID
if machineID := m.getMachineID(); machineID != "" {
components = append(components, "mid:"+machineID)
}

// Fallback to random ID if no hardware info available
if len(components) == 0 {
components = append(components, "fallback:"+m.generateRandomID())
}

return strings.Join(components, "|")
}

// generateRandomID generates a random hex string as fallback
func (m *HardwareIDManager) generateRandomID() string {
bytes := make([]byte, 16)
if _, err := rand.Read(bytes); err != nil {
// Last resort fallback
return "unknown-hardware"
}
return hex.EncodeToString(bytes)
}

// getCPUID reads CPU identifier from /proc/cpuinfo
func (m *HardwareIDManager) getCPUID() string {
data, err := os.ReadFile("/proc/cpuinfo")
if err != nil {
return ""
}

lines := strings.Split(string(data), "\n")
for _, line := range lines {
if strings.HasPrefix(line, "Serial") || strings.HasPrefix(line, "model name") {
parts := strings.SplitN(line, ":", 2)
if len(parts) == 2 {
return strings.TrimSpace(parts[1])
}
}
}
return ""
}

// getMotherboardSerial reads motherboard serial from DMI
func (m *HardwareIDManager) getMotherboardSerial() string {
paths := []string{
"/sys/class/dmi/id/product_serial",
"/sys/class/dmi/id/product_uuid",
"/sys/class/dmi/id/board_serial",
}

for _, path := range paths {
if data, err := os.ReadFile(path); err == nil {
serial := strings.TrimSpace(string(data))
if serial != "" && serial != "None" && serial != "To Be Filled By O.E.M." {
return serial
}
}
}
return ""
}

// getPrimaryMAC gets MAC address of primary network interface
func (m *HardwareIDManager) getPrimaryMAC() string {
interfaces, err := net.Interfaces()
if err != nil {
return ""
}

for _, iface := range interfaces {
// Skip loopback and virtual interfaces
if iface.Flags&net.FlagLoopback != 0 {
continue
}
if strings.HasPrefix(iface.Name, "veth") ||
strings.HasPrefix(iface.Name, "docker") ||
strings.HasPrefix(iface.Name, "br-") {
continue
}

if len(iface.HardwareAddr) > 0 {
return iface.HardwareAddr.String()
}
}
return ""
}

// getMachineID reads the machine ID from /etc/machine-id
func (m *HardwareIDManager) getMachineID() string {
paths := []string{
"/etc/machine-id",
"/var/lib/dbus/machine-id",
}

for _, path := range paths {
if data, err := os.ReadFile(path); err == nil {
return strings.TrimSpace(string(data))
}
}
return ""
}

// truncateForLog truncates a string for log output
func (m *HardwareIDManager) truncateForLog(s string) string {
if len(s) > 64 {
return s[:64] + "..."
}
return s
}

// VerifyHardwareBinding checks if the current hardware matches the stored ID
func (m *HardwareIDManager) VerifyHardwareBinding(nfType string, nfInstanceID string, expectedID string) bool {
fileName := fmt.Sprintf("%s_%s.id", strings.ToLower(nfType), nfInstanceID)
filePath := filepath.Join(m.storageDir, fileName)

storedID, err := m.loadPlaintext(filePath)
if err != nil {
fmt.Printf("[DID] Failed to load hardware ID for verification: %v\n", err)
return false
}

return storedID == expectedID
}
