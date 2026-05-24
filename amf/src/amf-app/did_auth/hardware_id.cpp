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

#include "hardware_id.hpp"

#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/sha.h>

#include <cstring>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <sstream>
#include <stdexcept>

#include <dirent.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>

#include "logger.hpp"

namespace oai::amf::did_auth {

//------------------------------------------------------------------------------
// Helper functions
//------------------------------------------------------------------------------
static std::string to_hex(const std::vector<uint8_t>& data) {
  std::stringstream ss;
  ss << std::hex << std::setfill('0');
  for (uint8_t b : data) {
    ss << std::setw(2) << static_cast<int>(b);
  }
  return ss.str();
}

static std::vector<uint8_t> from_hex(const std::string& hex) {
  std::vector<uint8_t> bytes;
  bytes.reserve(hex.size() / 2);
  for (size_t i = 0; i + 1 < hex.size(); i += 2) {
    uint8_t high = 0, low = 0;
    char h = hex[i], l = hex[i + 1];
    if (h >= '0' && h <= '9') high = h - '0';
    else if (h >= 'a' && h <= 'f') high = h - 'a' + 10;
    else if (h >= 'A' && h <= 'F') high = h - 'A' + 10;
    if (l >= '0' && l <= '9') low = l - '0';
    else if (l >= 'a' && l <= 'f') low = l - 'a' + 10;
    else if (l >= 'A' && l <= 'F') low = l - 'A' + 10;
    bytes.push_back((high << 4) | low);
  }
  return bytes;
}

static std::string read_file_content(const std::string& path) {
  std::ifstream file(path);
  if (!file.is_open()) return "";
  std::string content;
  std::getline(file, content);
  // Trim whitespace
  size_t start = content.find_first_not_of(" \t\n\r");
  size_t end = content.find_last_not_of(" \t\n\r");
  if (start == std::string::npos) return "";
  return content.substr(start, end - start + 1);
}

//------------------------------------------------------------------------------
// Hardware fingerprint collection
//------------------------------------------------------------------------------
std::string hardware_id_manager::get_cpu_id() {
  // Try to read from /proc/cpuinfo
  std::ifstream cpuinfo("/proc/cpuinfo");
  if (!cpuinfo.is_open()) return "";
  
  std::string line;
  while (std::getline(cpuinfo, line)) {
    // Look for "Serial" or "model name" or "Hardware"
    if (line.find("Serial") != std::string::npos ||
        line.find("cpu serial") != std::string::npos) {
      size_t pos = line.find(':');
      if (pos != std::string::npos) {
        std::string value = line.substr(pos + 1);
        size_t start = value.find_first_not_of(" \t");
        if (start != std::string::npos) {
          return value.substr(start);
        }
      }
    }
  }
  
  // Fallback: use /sys/class/dmi/id/product_uuid if available (requires root)
  std::string uuid = read_file_content("/sys/class/dmi/id/product_uuid");
  if (!uuid.empty()) return uuid;
  
  // Another fallback: use processor model + microcode
  cpuinfo.clear();
  cpuinfo.seekg(0);
  std::string model, microcode;
  while (std::getline(cpuinfo, line)) {
    if (line.find("model name") != std::string::npos) {
      size_t pos = line.find(':');
      if (pos != std::string::npos) {
        model = line.substr(pos + 1);
      }
    }
    if (line.find("microcode") != std::string::npos) {
      size_t pos = line.find(':');
      if (pos != std::string::npos) {
        microcode = line.substr(pos + 1);
      }
    }
  }
  
  return model + microcode;
}

std::string hardware_id_manager::get_motherboard_serial() {
  // Try DMI baseboard serial
  std::string serial = read_file_content("/sys/class/dmi/id/board_serial");
  if (!serial.empty() && serial != "None") return serial;
  
  // Try product serial
  serial = read_file_content("/sys/class/dmi/id/product_serial");
  if (!serial.empty() && serial != "None") return serial;
  
  // Try chassis serial
  serial = read_file_content("/sys/class/dmi/id/chassis_serial");
  if (!serial.empty() && serial != "None") return serial;
  
  return "";
}

std::string hardware_id_manager::get_primary_mac_address() {
  int sock = socket(AF_INET, SOCK_DGRAM, 0);
  if (sock < 0) return "";
  
  std::string result;
  
  // Try common interface names
  const char* interfaces[] = {"eth0", "ens33", "enp0s3", "enp0s31f6", "wlan0", "wlp2s0"};
  
  struct ifreq ifr;
  for (const char* iface : interfaces) {
    std::memset(&ifr, 0, sizeof(ifr));
    std::strncpy(ifr.ifr_name, iface, IFNAMSIZ - 1);
    
    if (ioctl(sock, SIOCGIFHWADDR, &ifr) == 0) {
      unsigned char* mac = (unsigned char*)ifr.ifr_hwaddr.sa_data;
      std::stringstream ss;
      ss << std::hex << std::setfill('0');
      for (int i = 0; i < 6; ++i) {
        ss << std::setw(2) << static_cast<int>(mac[i]);
      }
      result = ss.str();
      break;
    }
  }
  
  // If common names failed, try to find any interface
  if (result.empty()) {
    DIR* dir = opendir("/sys/class/net");
    if (dir) {
      struct dirent* entry;
      while ((entry = readdir(dir)) != nullptr) {
        if (entry->d_name[0] != '.' && 
            strcmp(entry->d_name, "lo") != 0) {
          std::memset(&ifr, 0, sizeof(ifr));
          std::strncpy(ifr.ifr_name, entry->d_name, IFNAMSIZ - 1);
          
          if (ioctl(sock, SIOCGIFHWADDR, &ifr) == 0) {
            unsigned char* mac = (unsigned char*)ifr.ifr_hwaddr.sa_data;
            std::stringstream ss;
            ss << std::hex << std::setfill('0');
            for (int i = 0; i < 6; ++i) {
              ss << std::setw(2) << static_cast<int>(mac[i]);
            }
            result = ss.str();
            break;
          }
        }
      }
      closedir(dir);
    }
  }
  
  close(sock);
  return result;
}

std::string hardware_id_manager::get_machine_id() {
  // Linux machine-id
  std::string machine_id = read_file_content("/etc/machine-id");
  if (!machine_id.empty()) return machine_id;
  
  // Alternative location
  machine_id = read_file_content("/var/lib/dbus/machine-id");
  return machine_id;
}

std::string hardware_id_manager::collect_hardware_fingerprint() {
  std::stringstream fingerprint;
  
  // Collect all available hardware identifiers
  std::string cpu_id = get_cpu_id();
  std::string mb_serial = get_motherboard_serial();
  std::string mac_addr = get_primary_mac_address();
  std::string machine_id = get_machine_id();
  
  Logger::amf_app().debug(
      "Hardware fingerprint components: cpu_id=%s, mb_serial=%s, mac=%s, machine_id=%s",
      cpu_id.empty() ? "(empty)" : cpu_id.substr(0, 20).c_str(),
      mb_serial.empty() ? "(empty)" : mb_serial.c_str(),
      mac_addr.empty() ? "(empty)" : mac_addr.c_str(),
      machine_id.empty() ? "(empty)" : machine_id.substr(0, 20).c_str());
  
  // Concatenate all identifiers with separators
  fingerprint << "OAI5GC_HW_FP|";
  fingerprint << "CPU:" << cpu_id << "|";
  fingerprint << "MB:" << mb_serial << "|";
  fingerprint << "MAC:" << mac_addr << "|";
  fingerprint << "MID:" << machine_id << "|";
  
  return fingerprint.str();
}

std::string hardware_id_manager::hash_fingerprint(const std::string& fingerprint) {
  unsigned char hash[SHA256_DIGEST_LENGTH];
  SHA256_CTX ctx;
  SHA256_Init(&ctx);
  SHA256_Update(&ctx, fingerprint.c_str(), fingerprint.size());
  SHA256_Final(hash, &ctx);
  
  std::vector<uint8_t> hash_vec(hash, hash + SHA256_DIGEST_LENGTH);
  return to_hex(hash_vec);
}

//------------------------------------------------------------------------------
// Encryption/Decryption
//------------------------------------------------------------------------------
std::vector<uint8_t> hardware_id_manager::derive_encryption_key(
    const std::string& fingerprint) {
  // Use PBKDF2-like key derivation from fingerprint
  // Salt is fixed (could be improved with random salt stored with ciphertext)
  const char* salt = "OAI5GC_HW_ID_SALT_v1";
  
  std::vector<uint8_t> key(32);  // AES-256 key
  
  // Simple HKDF-like derivation using SHA256
  std::string input = fingerprint + salt;
  unsigned char hash[SHA256_DIGEST_LENGTH];
  SHA256_CTX ctx;
  SHA256_Init(&ctx);
  SHA256_Update(&ctx, input.c_str(), input.size());
  SHA256_Final(hash, &ctx);
  
  std::memcpy(key.data(), hash, 32);
  return key;
}

// DEPRECATED: Encryption/storage is now handled by did-proxy (Go)
// This function is kept only for reference and potential future use.
// Hardware ID generation and storage should be done via:
//   ./did-proxy -config /usr/local/etc/oai/amf.conf
bool hardware_id_manager::encrypt_and_store(
    const std::string& /* hardware_id */,
    const std::string& /* storage_path */) {
  Logger::amf_app().warn(
      "encrypt_and_store is DEPRECATED. "
      "Use did-proxy to generate and store hardware ID.");
  return false;
}

std::string hardware_id_manager::decrypt_and_load(const std::string& storage_path) {
  try {
    if (!std::filesystem::exists(storage_path)) {
      return "";
    }
    
    // Read encrypted file
    std::ifstream file(storage_path, std::ios::binary);
    if (!file.is_open()) {
      Logger::amf_app().error("Failed to open storage file for reading: %s", 
                              storage_path.c_str());
      return "";
    }
    
    // Get file size
    file.seekg(0, std::ios::end);
    size_t file_size = file.tellg();
    file.seekg(0, std::ios::beg);
    
    if (file_size < 28) {  // IV (12) + Tag (16) + at least 1 byte ciphertext
      Logger::amf_app().error("Storage file too small");
      return "";
    }
    
    // Read IV
    std::vector<uint8_t> iv(12);
    file.read(reinterpret_cast<char*>(iv.data()), iv.size());
    
    // Read tag
    std::vector<uint8_t> tag(16);
    file.read(reinterpret_cast<char*>(tag.data()), tag.size());
    
    // Read ciphertext
    size_t ciphertext_len = file_size - 28;
    std::vector<uint8_t> ciphertext(ciphertext_len);
    file.read(reinterpret_cast<char*>(ciphertext.data()), ciphertext_len);
    file.close();
    
    // Get decryption key from current hardware fingerprint
    std::string fingerprint = collect_hardware_fingerprint();
    std::vector<uint8_t> key = derive_encryption_key(fingerprint);
    
    // Decrypt using AES-256-GCM
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return "";
    
    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, 
                           key.data(), iv.data()) != 1) {
      EVP_CIPHER_CTX_free(ctx);
      return "";
    }
    
    std::vector<uint8_t> plaintext(ciphertext_len);
    int len = 0;
    
    if (EVP_DecryptUpdate(ctx, plaintext.data(), &len, 
                          ciphertext.data(), ciphertext.size()) != 1) {
      EVP_CIPHER_CTX_free(ctx);
      return "";
    }
    int plaintext_len = len;
    
    // Set expected tag
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, tag.data()) != 1) {
      EVP_CIPHER_CTX_free(ctx);
      return "";
    }
    
    // Verify tag and finalize
    if (EVP_DecryptFinal_ex(ctx, plaintext.data() + len, &len) != 1) {
      EVP_CIPHER_CTX_free(ctx);
      Logger::amf_app().error("Hardware ID decryption failed - tag verification failed");
      Logger::amf_app().error("This may indicate hardware change or file tampering");
      return "";
    }
    plaintext_len += len;
    
    EVP_CIPHER_CTX_free(ctx);
    
    plaintext.resize(plaintext_len);
    return std::string(plaintext.begin(), plaintext.end());
    
  } catch (const std::exception& e) {
    Logger::amf_app().error("Failed to decrypt and load hardware ID: %s", e.what());
    return "";
  }
}

//------------------------------------------------------------------------------
// Public interface
//------------------------------------------------------------------------------

// DEPRECATED: Hardware ID should be read from extended_profile.json (generated by did-proxy)
// This function is kept for backward compatibility and verification purposes only.
// It will try to decrypt and load an existing hardware ID, but will NOT generate new ones.
std::string hardware_id_manager::get_or_generate_hardware_id(
    const std::string& storage_path) {
  Logger::amf_app().info("Loading hardware ID from: %s", 
                         storage_path.c_str());
  
  // Try to load existing hardware ID (generated by did-proxy)
  std::string existing_id = decrypt_and_load(storage_path);
  if (!existing_id.empty()) {
    Logger::amf_app().info("Loaded hardware ID (hash): %s...", 
                           existing_id.substr(0, 16).c_str());
    return existing_id;
  }
  
  // REMOVED: Hardware ID generation is now done by did-proxy (Go)
  // The hardware ID should be stored in extended_profile.json and 
  // loaded via amf_app::read_extended_profile_from_file()
  Logger::amf_app().warn(
      "No hardware ID found at %s. "
      "Please run did-proxy to generate the hardware ID and extended profile.",
      storage_path.c_str());
  
  return "";
}

bool hardware_id_manager::verify_hardware_id(const std::string& storage_path) {
  std::string stored_id = decrypt_and_load(storage_path);
  if (stored_id.empty()) {
    return false;  // No stored ID or decryption failed (hardware changed)
  }
  
  // Generate current hardware ID
  std::string fingerprint = collect_hardware_fingerprint();
  std::string current_id = hash_fingerprint(fingerprint);
  
  bool match = (stored_id == current_id);
  if (!match) {
    Logger::amf_app().error(
        "Hardware ID mismatch! Stored: %s, Current: %s",
        stored_id.substr(0, 16).c_str(), current_id.substr(0, 16).c_str());
  }
  
  return match;
}

std::string hardware_id_manager::generate_did_with_hardware_binding(
    const std::string& nf_type,
    const std::string& nf_instance_id,
    const std::string& hardware_id,
    const std::string& public_key_hex) {
  // Construct DID input: nf_type|nf_instance_id|hardware_id|public_key
  std::stringstream did_input;
  did_input << "OAI5GC_DID|";
  did_input << "NF:" << nf_type << "|";
  did_input << "INST:" << nf_instance_id << "|";
  did_input << "HW:" << hardware_id << "|";
  did_input << "PK:" << public_key_hex;
  
  Logger::amf_app().debug(
      "DID generation input: nf_type=%s, instance=%s, hw_id=%s..., pk=%s...",
      nf_type.c_str(), 
      nf_instance_id.substr(0, 8).c_str(),
      hardware_id.substr(0, 16).c_str(),
      public_key_hex.substr(0, 16).c_str());
  
  // Hash the input
  std::string input = did_input.str();
  unsigned char hash[SHA256_DIGEST_LENGTH];
  SHA256_CTX ctx;
  SHA256_Init(&ctx);
  SHA256_Update(&ctx, input.c_str(), input.size());
  SHA256_Final(hash, &ctx);
  
  // DID format: did:oai5gc:<hash>:<public_key_hex>
  // This allows public key extraction while still binding to hardware
  std::vector<uint8_t> hash_vec(hash, hash + SHA256_DIGEST_LENGTH);
  std::string hash_hex = to_hex(hash_vec);
  
  // Use first 32 chars of hash + full public key for DID
  // Format: did:oai5gc:<binding_hash_16chars>:<public_key>
  std::string did = "did:oai5gc:" + hash_hex.substr(0, 32) + ":" + public_key_hex;
  
  Logger::amf_app().info("Generated hardware-bound DID: %s...", 
                         did.substr(0, 50).c_str());
  
  return did;
}

bool hardware_id_manager::verify_did_hardware_binding(
    const std::string& did,
    const std::string& nf_type,
    const std::string& nf_instance_id,
    const std::string& public_key_hex,
    const std::string& hardware_id) {
  // Validate hardware_id parameter
  if (hardware_id.empty()) {
    Logger::amf_app().error("Failed to verify DID binding: hardware_id is empty");
    return false;
  }
  
  // Regenerate expected DID
  std::string expected_did = generate_did_with_hardware_binding(
      nf_type, nf_instance_id, hardware_id, public_key_hex);
  
  bool match = (did == expected_did);
  if (!match) {
    Logger::amf_app().error(
        "DID hardware binding verification failed!\n"
        "  Expected DID: %s\n"
        "  Actual DID:   %s",
        expected_did.c_str(), did.c_str());
  }
  
  return match;
}

}  // namespace oai::amf::did_auth
