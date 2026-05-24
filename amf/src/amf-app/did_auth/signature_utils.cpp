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

#include "signature_utils.hpp"

#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/evp.h>
#include <openssl/obj_mac.h>
#include <openssl/sha.h>

#include <cstring>
#include <iomanip>
#include <sstream>

#include "logger.hpp"

namespace oai::amf::did_auth {

//------------------------------------------------------------------------------
// Hex encoding/decoding
//------------------------------------------------------------------------------
static const char hex_chars[] = "0123456789abcdef";

std::string signature_utils::to_hex(const std::vector<uint8_t>& data) {
  std::string hex;
  hex.reserve(data.size() * 2);
  for (uint8_t b : data) {
    hex.push_back(hex_chars[(b >> 4) & 0x0F]);
    hex.push_back(hex_chars[b & 0x0F]);
  }
  return hex;
}

std::vector<uint8_t> signature_utils::from_hex(const std::string& hex) {
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

std::string signature_utils::bytes_to_debug_string(
    const std::vector<uint8_t>& data, size_t max_len) {
  std::string hex = to_hex(data);
  if (hex.size() > max_len * 2) {
    return hex.substr(0, max_len * 2) + "...(" + std::to_string(data.size()) + " bytes)";
  }
  return hex + " (" + std::to_string(data.size()) + " bytes)";
}

//------------------------------------------------------------------------------
// SHA256
//------------------------------------------------------------------------------
std::vector<uint8_t> signature_utils::sha256(const std::vector<uint8_t>& data) {
  std::vector<uint8_t> hash(SHA256_DIGEST_LENGTH);
  SHA256_CTX ctx;
  SHA256_Init(&ctx);
  SHA256_Update(&ctx, data.data(), data.size());
  SHA256_Final(hash.data(), &ctx);
  return hash;
}

std::vector<uint8_t> signature_utils::sha256(const std::string& data) {
  return sha256(std::vector<uint8_t>(data.begin(), data.end()));
}

//------------------------------------------------------------------------------
// Payload construction
//------------------------------------------------------------------------------
std::string signature_utils::build_signature_payload(
    const std::string& nonce_hex,
    uint64_t timestamp_ms) {
  // 简化payload：直接使用nonce的二进制数据
  // 这样可以确保签名和验签使用完全相同的数据
  // 如果需要包含时间戳，可以扩展payload结构
  
  // 目前保持简单：payload就是nonce本身（二进制形式）
  // 这与原有sign_challenge/verify_challenge_signature的行为一致
  return nonce_hex;  // 返回hex字符串，调用者会转换为二进制
}

//------------------------------------------------------------------------------
// Public key extraction and normalization
//------------------------------------------------------------------------------
std::string signature_utils::extract_public_key_from_did(const std::string& did) {
  const std::string prefix = "did:oai5gc:";
  
  if (did.find(prefix) != 0) {
    Logger::amf_app().error(
        "[SigUtils] Invalid DID format, expected prefix '%s': %s",
        prefix.c_str(), did.c_str());
    return "";
  }
  
  std::string remainder = did.substr(prefix.length());
  
  // Check if it's the new format with binding hash
  // Format: did:oai5gc:<binding_hash_32chars>:<public_key>
  size_t colon_pos = remainder.find(':');
  if (colon_pos != std::string::npos && colon_pos == 32) {
    // New format with hardware binding
    std::string public_key = remainder.substr(colon_pos + 1);
    Logger::amf_app().debug(
        "[SigUtils] Extracted public key from hardware-bound DID: %s...",
        public_key.substr(0, 32).c_str());
    return public_key;
  }
  
  // Old format: did:oai5gc:<public_key>
  Logger::amf_app().debug(
      "[SigUtils] Extracted public key from legacy DID: %s...",
      remainder.substr(0, 32).c_str());
  return remainder;
}

std::vector<uint8_t> signature_utils::decompress_public_key(
    const std::vector<uint8_t>& compressed_key) {
  if (compressed_key.size() != 33) {
    return {};
  }
  
  // Create EC_KEY with secp256k1
  EC_KEY* ec_key = EC_KEY_new_by_curve_name(NID_secp256k1);
  if (!ec_key) return {};
  
  const EC_GROUP* group = EC_KEY_get0_group(ec_key);
  EC_POINT* point = EC_POINT_new(group);
  
  if (!point) {
    EC_KEY_free(ec_key);
    return {};
  }
  
  // Decompress
  if (EC_POINT_oct2point(group, point, compressed_key.data(), 
                         compressed_key.size(), nullptr) != 1) {
    EC_POINT_free(point);
    EC_KEY_free(ec_key);
    return {};
  }
  
  // Get uncompressed form
  size_t len = EC_POINT_point2oct(group, point, POINT_CONVERSION_UNCOMPRESSED,
                                   nullptr, 0, nullptr);
  std::vector<uint8_t> uncompressed(len);
  EC_POINT_point2oct(group, point, POINT_CONVERSION_UNCOMPRESSED,
                     uncompressed.data(), len, nullptr);
  
  EC_POINT_free(point);
  EC_KEY_free(ec_key);
  
  return uncompressed;
}

std::string signature_utils::normalize_public_key(const std::string& public_key_hex) {
  std::vector<uint8_t> key_bytes = from_hex(public_key_hex);
  
  Logger::amf_app().debug(
      "[SigUtils] Normalizing public key: input length=%zu bytes, hex=%s",
      key_bytes.size(), bytes_to_debug_string(key_bytes, 16).c_str());
  
  if (key_bytes.empty()) {
    Logger::amf_app().error("[SigUtils] Empty public key");
    return "";
  }
  
  // Check format based on first byte and length
  if (key_bytes.size() == 65) {
    // Should be uncompressed format (04 prefix)
    if (key_bytes[0] == 0x04) {
      Logger::amf_app().debug("[SigUtils] Public key is already uncompressed (65 bytes, 04 prefix)");
      return public_key_hex;
    }
    // If 65 bytes but wrong prefix, try to interpret as raw X,Y coordinates
    Logger::amf_app().warn(
        "[SigUtils] 65-byte key without 04 prefix (first byte=0x%02x), adding prefix",
        key_bytes[0]);
    // This might be X||Y without prefix - add 04 prefix
    std::vector<uint8_t> with_prefix;
    with_prefix.push_back(0x04);
    with_prefix.insert(with_prefix.end(), key_bytes.begin(), key_bytes.end() - 1);  // Assume last byte is extra
    return to_hex(with_prefix);
  }
  
  if (key_bytes.size() == 33) {
    // Compressed format (02 or 03 prefix)
    if (key_bytes[0] == 0x02 || key_bytes[0] == 0x03) {
      Logger::amf_app().debug("[SigUtils] Public key is compressed (33 bytes), decompressing...");
      std::vector<uint8_t> uncompressed = decompress_public_key(key_bytes);
      if (uncompressed.empty()) {
        Logger::amf_app().error("[SigUtils] Failed to decompress public key");
        return "";
      }
      std::string result = to_hex(uncompressed);
      Logger::amf_app().debug("[SigUtils] Decompressed to: %s...", result.substr(0, 32).c_str());
      return result;
    }
  }
  
  if (key_bytes.size() == 64) {
    // Raw X||Y coordinates without prefix - add 04 prefix
    Logger::amf_app().debug("[SigUtils] Public key appears to be raw X||Y (64 bytes), adding 04 prefix");
    std::vector<uint8_t> with_prefix;
    with_prefix.push_back(0x04);
    with_prefix.insert(with_prefix.end(), key_bytes.begin(), key_bytes.end());
    return to_hex(with_prefix);
  }
  
  Logger::amf_app().error(
      "[SigUtils] Unsupported public key format: length=%zu, first_byte=0x%02x",
      key_bytes.size(), key_bytes.empty() ? 0 : key_bytes[0]);
  return "";
}

//------------------------------------------------------------------------------
// ECDSA operations
//------------------------------------------------------------------------------
std::string signature_utils::ecdsa_sign(
    const std::vector<uint8_t>& hash,
    const std::vector<uint8_t>& private_key) {
  if (hash.size() != 32 || private_key.size() != 32) {
    Logger::amf_app().error(
        "[SigUtils] Invalid input sizes: hash=%zu, privkey=%zu",
        hash.size(), private_key.size());
    return "";
  }
  
  // Create EC_KEY with secp256k1
  EC_KEY* ec_key = EC_KEY_new_by_curve_name(NID_secp256k1);
  if (!ec_key) {
    Logger::amf_app().error("[SigUtils] Failed to create EC_KEY");
    return "";
  }
  
  // Set private key
  BIGNUM* priv_bn = BN_bin2bn(private_key.data(), private_key.size(), nullptr);
  if (!priv_bn) {
    EC_KEY_free(ec_key);
    Logger::amf_app().error("[SigUtils] Failed to create BIGNUM for private key");
    return "";
  }
  
  if (EC_KEY_set_private_key(ec_key, priv_bn) != 1) {
    BN_free(priv_bn);
    EC_KEY_free(ec_key);
    Logger::amf_app().error("[SigUtils] Failed to set private key");
    return "";
  }
  
  // Sign
  ECDSA_SIG* sig = ECDSA_do_sign(hash.data(), hash.size(), ec_key);
  if (!sig) {
    BN_free(priv_bn);
    EC_KEY_free(ec_key);
    Logger::amf_app().error("[SigUtils] ECDSA_do_sign failed");
    return "";
  }
  
  // Encode to DER format
  unsigned char* der_sig = nullptr;
  int der_len = i2d_ECDSA_SIG(sig, &der_sig);
  
  if (der_len <= 0) {
    ECDSA_SIG_free(sig);
    BN_free(priv_bn);
    EC_KEY_free(ec_key);
    Logger::amf_app().error("[SigUtils] Failed to encode signature to DER");
    return "";
  }
  
  std::vector<uint8_t> sig_bytes(der_sig, der_sig + der_len);
  std::string result = to_hex(sig_bytes);
  
  OPENSSL_free(der_sig);
  ECDSA_SIG_free(sig);
  BN_free(priv_bn);
  EC_KEY_free(ec_key);
  
  return result;
}

bool signature_utils::ecdsa_verify(
    const std::vector<uint8_t>& hash,
    const std::vector<uint8_t>& signature,
    const std::vector<uint8_t>& public_key) {
  if (hash.size() != 32) {
    Logger::amf_app().error("[SigUtils] Invalid hash size: %zu", hash.size());
    return false;
  }
  
  if (public_key.size() != 33 && public_key.size() != 65) {
    Logger::amf_app().error(
        "[SigUtils] Invalid public key size: %zu (expected 33 or 65)",
        public_key.size());
    return false;
  }
  
  // Create EC_KEY with secp256k1
  EC_KEY* ec_key = EC_KEY_new_by_curve_name(NID_secp256k1);
  if (!ec_key) {
    Logger::amf_app().error("[SigUtils] Failed to create EC_KEY");
    return false;
  }
  
  // Set public key
  const EC_GROUP* group = EC_KEY_get0_group(ec_key);
  EC_POINT* pub_point = EC_POINT_new(group);
  
  if (!pub_point) {
    EC_KEY_free(ec_key);
    Logger::amf_app().error("[SigUtils] Failed to create EC_POINT");
    return false;
  }
  
  if (EC_POINT_oct2point(group, pub_point, public_key.data(), 
                         public_key.size(), nullptr) != 1) {
    EC_POINT_free(pub_point);
    EC_KEY_free(ec_key);
    Logger::amf_app().error("[SigUtils] Failed to decode public key point");
    return false;
  }
  
  if (EC_KEY_set_public_key(ec_key, pub_point) != 1) {
    EC_POINT_free(pub_point);
    EC_KEY_free(ec_key);
    Logger::amf_app().error("[SigUtils] Failed to set public key");
    return false;
  }
  
  // Decode DER signature
  const unsigned char* sig_ptr = signature.data();
  ECDSA_SIG* sig = d2i_ECDSA_SIG(nullptr, &sig_ptr, signature.size());
  
  if (!sig) {
    EC_POINT_free(pub_point);
    EC_KEY_free(ec_key);
    Logger::amf_app().error("[SigUtils] Failed to decode DER signature");
    return false;
  }
  
  // Verify
  int result = ECDSA_do_verify(hash.data(), hash.size(), sig, ec_key);
  
  ECDSA_SIG_free(sig);
  EC_POINT_free(pub_point);
  EC_KEY_free(ec_key);
  
  return result == 1;
}

//------------------------------------------------------------------------------
// High-level signing/verification with logging
// [DEBUG MODE] 完整日志输出，与 AUSF 保持一致，用于实验调测
//------------------------------------------------------------------------------
std::string signature_utils::sign_challenge_with_logging(
    const std::string& challenge_hex,
    const std::vector<uint8_t>& private_key_bytes,
    uint64_t timestamp_ms) {
  Logger::amf_app().info("[Crypto] ============ SIGNING CHALLENGE ============");
  Logger::amf_app().info("[Crypto] --- Input Parameters ---");
  Logger::amf_app().info("[Crypto]   challenge (hex, full): %s", challenge_hex.c_str());
  Logger::amf_app().info("[Crypto]   private_key: [REDACTED, %zu bytes]", private_key_bytes.size());
  Logger::amf_app().info("[Crypto]   timestamp_ms: %lu", timestamp_ms);
  
  // Step 1: Convert challenge hex to binary
  std::vector<uint8_t> challenge_bytes = from_hex(challenge_hex);
  Logger::amf_app().info("[Crypto] Step 1: Challenge hex -> bytes");
  Logger::amf_app().info("[Crypto]   challenge_bytes (hex): %s", to_hex(challenge_bytes).c_str());
  Logger::amf_app().info("[Crypto]   challenge_bytes length: %zu bytes", challenge_bytes.size());
  
  // Step 2: Compute SHA256 hash of challenge bytes
  std::vector<uint8_t> hash = sha256(challenge_bytes);
  Logger::amf_app().info("[Crypto] Step 2: SHA256(challenge_bytes)");
  Logger::amf_app().info("[Crypto]   challenge_hash (hex, full): %s", to_hex(hash).c_str());
  
  // Step 3: Sign the hash
  Logger::amf_app().info("[SigUtils] Step 3: ECDSA Sign(hash)");
  std::string signature = ecdsa_sign(hash, private_key_bytes);
  if (signature.empty()) {
    Logger::amf_app().error("[SigUtils] Signing FAILED!");
    return "";
  }
  
  Logger::amf_app().info("[SigUtils]   signature (DER hex, full): %s", signature.c_str());
  Logger::amf_app().info("[SigUtils]   signature length: %zu chars", signature.length());
  Logger::amf_app().info("[SigUtils] ============ SIGNING SUCCESS ============");
  
  return signature;
}

bool signature_utils::verify_challenge_with_logging(
    const std::string& challenge_hex,
    const std::string& signature_hex,
    const std::string& public_key_hex,
    uint64_t timestamp_ms) {
  Logger::amf_app().info("[Crypto] ========== VERIFYING SIGNATURE ==========");
  Logger::amf_app().info("[Crypto] --- Input Parameters (Full) ---");
  Logger::amf_app().info("[Crypto]   challenge (hex, full): %s", challenge_hex.c_str());
  Logger::amf_app().info("[Crypto]   signature (hex, full): %s", signature_hex.c_str());
  Logger::amf_app().info("[Crypto]   public_key (hex, full): %s", public_key_hex.c_str());
  Logger::amf_app().info("[Crypto]   timestamp_ms: %lu", timestamp_ms);
  
  // Step 1: Normalize public key
  Logger::amf_app().info("[Crypto] Step 1: Normalize public key");
  std::string normalized_pk = normalize_public_key(public_key_hex);
  if (normalized_pk.empty()) {
    Logger::amf_app().error("[Crypto] Failed to normalize public key");
    return false;
  }
  Logger::amf_app().info("[Crypto]   normalized_public_key (hex, full): %s", normalized_pk.c_str());
  
  // Step 2: Convert challenge hex to binary
  Logger::amf_app().info("[Crypto] Step 2: Challenge hex -> bytes");
  std::vector<uint8_t> challenge_bytes = from_hex(challenge_hex);
  Logger::amf_app().info("[Crypto]   challenge_bytes (hex): %s", to_hex(challenge_bytes).c_str());
  Logger::amf_app().info("[Crypto]   challenge_bytes length: %zu bytes", challenge_bytes.size());
  
  // Step 3: Compute SHA256 hash of challenge bytes
  Logger::amf_app().info("[Crypto] Step 3: SHA256(challenge_bytes)");
  std::vector<uint8_t> hash = sha256(challenge_bytes);
  Logger::amf_app().info("[Crypto]   challenge_hash (hex, full): %s", to_hex(hash).c_str());
  
  // Step 4: Verify signature
  Logger::amf_app().info("[Crypto] Step 4: ECDSA Verify(hash, signature, public_key)");
  std::vector<uint8_t> sig_bytes = from_hex(signature_hex);
  std::vector<uint8_t> pk_bytes = from_hex(normalized_pk);
  
  Logger::amf_app().info("[Crypto]   signature_bytes length: %zu bytes", sig_bytes.size());
  Logger::amf_app().info("[Crypto]   public_key_bytes length: %zu bytes", pk_bytes.size());
  Logger::amf_app().info("[Crypto]   public_key first byte: 0x%02x (%s)", 
                         pk_bytes.empty() ? 0 : pk_bytes[0],
                         pk_bytes.empty() ? "empty" : 
                         (pk_bytes[0] == 0x04 ? "uncompressed" : 
                          (pk_bytes[0] == 0x02 || pk_bytes[0] == 0x03 ? "compressed" : "unknown")));
  
  bool result = ecdsa_verify(hash, sig_bytes, pk_bytes);
  
  if (result) {
    Logger::amf_app().info("[Crypto] ========== VERIFICATION SUCCESS ==========");
  } else {
    Logger::amf_app().error("[Crypto] ========== VERIFICATION FAILED ==========");
    
    // Additional debug info for failure analysis
    Logger::amf_app().error("[Crypto] --- Failure Debug Summary ---");
    Logger::amf_app().error("[Crypto]   challenge_hex: %s", challenge_hex.c_str());
    Logger::amf_app().error("[Crypto]   challenge_bytes length: %zu bytes", challenge_bytes.size());
    Logger::amf_app().error("[Crypto]   challenge_hash: %s", to_hex(hash).c_str());
    Logger::amf_app().error("[Crypto]   signature_hex: %s", signature_hex.c_str());
    Logger::amf_app().error("[Crypto]   signature_bytes length: %zu bytes", sig_bytes.size());
    Logger::amf_app().error("[Crypto]   public_key_hex: %s", public_key_hex.c_str());
    Logger::amf_app().error("[Crypto]   public_key_bytes length: %zu bytes", pk_bytes.size());
  }
  
  return result;
}

}  // namespace oai::amf::did_auth
