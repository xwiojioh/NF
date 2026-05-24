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

#include "did_crypto.hpp"

#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/evp.h>
#include <openssl/obj_mac.h>
#include <openssl/rand.h>
#include <openssl/sha.h>

#include <cstring>
#include <stdexcept>

namespace oai::amf::did_auth {

//------------------------------------------------------------------------------
// Helper: Hex encoding/decoding
//------------------------------------------------------------------------------
static const char hex_chars[] = "0123456789abcdef";

std::string did_crypto::to_hex(const std::vector<uint8_t>& data) {
  std::string hex;
  hex.reserve(data.size() * 2);
  for (uint8_t b : data) {
    hex.push_back(hex_chars[(b >> 4) & 0x0F]);
    hex.push_back(hex_chars[b & 0x0F]);
  }
  return hex;
}

std::vector<uint8_t> did_crypto::from_hex(const std::string& hex) {
  std::vector<uint8_t> bytes;
  bytes.reserve(hex.size() / 2);

  for (size_t i = 0; i + 1 < hex.size(); i += 2) {
    uint8_t high = 0, low = 0;
    char h = hex[i], l = hex[i + 1];

    if (h >= '0' && h <= '9')
      high = h - '0';
    else if (h >= 'a' && h <= 'f')
      high = h - 'a' + 10;
    else if (h >= 'A' && h <= 'F')
      high = h - 'A' + 10;

    if (l >= '0' && l <= '9')
      low = l - '0';
    else if (l >= 'a' && l <= 'f')
      low = l - 'a' + 10;
    else if (l >= 'A' && l <= 'F')
      low = l - 'A' + 10;

    bytes.push_back((high << 4) | low);
  }
  return bytes;
}

//------------------------------------------------------------------------------
// Constructor / Destructor
//------------------------------------------------------------------------------
did_crypto::did_crypto() : m_private_key(), m_public_key_hex() {}

did_crypto::did_crypto(const std::string& private_key_hex) {
  if (private_key_hex.size() != 64) {
    throw std::invalid_argument(
        "Private key must be 64 hex characters (32 bytes)");
  }

  m_private_key    = from_hex(private_key_hex);
  m_public_key_hex = derive_public_key(private_key_hex);
}

did_crypto::~did_crypto() {
  // Securely clear private key from memory
  if (!m_private_key.empty()) {
    OPENSSL_cleanse(m_private_key.data(), m_private_key.size());
  }
}

//------------------------------------------------------------------------------
// SHA256
//------------------------------------------------------------------------------
std::vector<uint8_t> did_crypto::sha256(const std::vector<uint8_t>& data) {
  std::vector<uint8_t> hash(SHA256_DIGEST_LENGTH);

  SHA256_CTX ctx;
  SHA256_Init(&ctx);
  SHA256_Update(&ctx, data.data(), data.size());
  SHA256_Final(hash.data(), &ctx);

  return hash;
}

std::vector<uint8_t> did_crypto::sha256(const std::string& data) {
  return sha256(
      std::vector<uint8_t>(data.begin(), data.end()));
}

std::string did_crypto::sha256_hex(const std::string& data) {
  return to_hex(sha256(data));
}

//------------------------------------------------------------------------------
// Random number generation
//------------------------------------------------------------------------------
std::vector<uint8_t> did_crypto::generate_random(size_t length) {
  std::vector<uint8_t> random(length);

  if (RAND_bytes(random.data(), static_cast<int>(length)) != 1) {
    throw std::runtime_error("Failed to generate random bytes");
  }

  return random;
}

//------------------------------------------------------------------------------
// Key derivation
//------------------------------------------------------------------------------
std::string did_crypto::derive_public_key(const std::string& private_key_hex) {
  if (private_key_hex.size() != 64) {
    return "";
  }

  std::vector<uint8_t> priv_bytes = from_hex(private_key_hex);

  // Create EC_KEY with secp256k1 curve
  EC_KEY* ec_key = EC_KEY_new_by_curve_name(NID_secp256k1);
  if (!ec_key) {
    return "";
  }

  // Set private key
  BIGNUM* priv_bn = BN_bin2bn(priv_bytes.data(), priv_bytes.size(), nullptr);
  if (!priv_bn) {
    EC_KEY_free(ec_key);
    return "";
  }

  if (EC_KEY_set_private_key(ec_key, priv_bn) != 1) {
    BN_free(priv_bn);
    EC_KEY_free(ec_key);
    return "";
  }

  // Derive public key
  const EC_GROUP* group = EC_KEY_get0_group(ec_key);
  EC_POINT* pub_point   = EC_POINT_new(group);

  if (!pub_point) {
    BN_free(priv_bn);
    EC_KEY_free(ec_key);
    return "";
  }

  if (EC_POINT_mul(group, pub_point, priv_bn, nullptr, nullptr, nullptr) != 1) {
    EC_POINT_free(pub_point);
    BN_free(priv_bn);
    EC_KEY_free(ec_key);
    return "";
  }

  EC_KEY_set_public_key(ec_key, pub_point);

  // Get compressed public key
  EC_KEY_set_conv_form(ec_key, POINT_CONVERSION_COMPRESSED);

  size_t pub_len = EC_POINT_point2oct(
      group, pub_point, POINT_CONVERSION_COMPRESSED, nullptr, 0, nullptr);

  std::vector<uint8_t> pub_bytes(pub_len);
  EC_POINT_point2oct(
      group, pub_point, POINT_CONVERSION_COMPRESSED, pub_bytes.data(), pub_len,
      nullptr);

  EC_POINT_free(pub_point);
  BN_free(priv_bn);
  EC_KEY_free(ec_key);

  return to_hex(pub_bytes);
}

//------------------------------------------------------------------------------
// Key pair generation
//------------------------------------------------------------------------------
bool did_crypto::generate_key_pair(
    std::string& private_key_hex, std::string& public_key_hex) {
  EC_KEY* ec_key = EC_KEY_new_by_curve_name(NID_secp256k1);
  if (!ec_key) {
    return false;
  }

  if (EC_KEY_generate_key(ec_key) != 1) {
    EC_KEY_free(ec_key);
    return false;
  }

  // Get private key
  const BIGNUM* priv_bn = EC_KEY_get0_private_key(ec_key);
  std::vector<uint8_t> priv_bytes(32);
  int priv_len = BN_bn2binpad(priv_bn, priv_bytes.data(), 32);
  if (priv_len != 32) {
    EC_KEY_free(ec_key);
    return false;
  }
  private_key_hex = to_hex(priv_bytes);

  // Get compressed public key
  const EC_GROUP* group     = EC_KEY_get0_group(ec_key);
  const EC_POINT* pub_point = EC_KEY_get0_public_key(ec_key);

  size_t pub_len = EC_POINT_point2oct(
      group, pub_point, POINT_CONVERSION_COMPRESSED, nullptr, 0, nullptr);

  std::vector<uint8_t> pub_bytes(pub_len);
  EC_POINT_point2oct(
      group, pub_point, POINT_CONVERSION_COMPRESSED, pub_bytes.data(), pub_len,
      nullptr);

  public_key_hex = to_hex(pub_bytes);

  // Securely clear and free
  OPENSSL_cleanse(priv_bytes.data(), priv_bytes.size());
  EC_KEY_free(ec_key);

  return true;
}

//------------------------------------------------------------------------------
// Signing
//------------------------------------------------------------------------------
std::string did_crypto::sign(const std::vector<uint8_t>& data) const {
  if (m_private_key.empty()) {
    throw std::runtime_error("Private key not initialized");
  }

  // Hash the data with SHA256
  std::vector<uint8_t> hash = sha256(data);

  return sign_hash(hash);
}

std::string did_crypto::sign(const std::string& data) const {
  return sign(std::vector<uint8_t>(data.begin(), data.end()));
}

std::string did_crypto::sign_hex(const std::string& hex_data) const {
  return sign(from_hex(hex_data));
}

std::string did_crypto::sign_hash(const std::vector<uint8_t>& hash) const {
  if (hash.size() != 32) {
    throw std::invalid_argument("Hash must be 32 bytes");
  }

  // Create EC_KEY
  EC_KEY* ec_key = EC_KEY_new_by_curve_name(NID_secp256k1);
  if (!ec_key) {
    throw std::runtime_error("Failed to create EC_KEY");
  }

  // Set private key
  BIGNUM* priv_bn =
      BN_bin2bn(m_private_key.data(), m_private_key.size(), nullptr);
  if (!priv_bn) {
    EC_KEY_free(ec_key);
    throw std::runtime_error("Failed to create BIGNUM for private key");
  }

  if (EC_KEY_set_private_key(ec_key, priv_bn) != 1) {
    BN_free(priv_bn);
    EC_KEY_free(ec_key);
    throw std::runtime_error("Failed to set private key");
  }

  // Sign
  ECDSA_SIG* sig = ECDSA_do_sign(hash.data(), hash.size(), ec_key);
  if (!sig) {
    BN_free(priv_bn);
    EC_KEY_free(ec_key);
    throw std::runtime_error("ECDSA signing failed");
  }

  // Encode signature to DER format
  unsigned char* der_sig = nullptr;
  int der_len            = i2d_ECDSA_SIG(sig, &der_sig);

  if (der_len <= 0) {
    ECDSA_SIG_free(sig);
    BN_free(priv_bn);
    EC_KEY_free(ec_key);
    throw std::runtime_error("Failed to encode signature to DER");
  }

  std::vector<uint8_t> sig_bytes(der_sig, der_sig + der_len);
  std::string result = to_hex(sig_bytes);

  OPENSSL_free(der_sig);
  ECDSA_SIG_free(sig);
  BN_free(priv_bn);
  EC_KEY_free(ec_key);

  return result;
}

//------------------------------------------------------------------------------
// Verification
//------------------------------------------------------------------------------
bool did_crypto::verify(
    const std::vector<uint8_t>& data, const std::string& signature_hex,
    const std::string& public_key_hex) {
  // Hash the data with SHA256
  std::vector<uint8_t> hash = sha256(data);

  return verify_hash(hash, signature_hex, public_key_hex);
}

bool did_crypto::verify(
    const std::string& data, const std::string& signature_hex,
    const std::string& public_key_hex) {
  return verify(
      std::vector<uint8_t>(data.begin(), data.end()), signature_hex,
      public_key_hex);
}

bool did_crypto::verify_hex(
    const std::string& hex_data, const std::string& signature_hex,
    const std::string& public_key_hex) {
  return verify(from_hex(hex_data), signature_hex, public_key_hex);
}

bool did_crypto::verify_hash(
    const std::vector<uint8_t>& hash, const std::string& signature_hex,
    const std::string& public_key_hex) {
  if (hash.size() != 32) {
    return false;
  }

  std::vector<uint8_t> sig_bytes = from_hex(signature_hex);
  std::vector<uint8_t> pub_bytes = from_hex(public_key_hex);

  if (pub_bytes.size() != 33 && pub_bytes.size() != 65) {
    return false;  // Invalid public key length
  }

  // Create EC_KEY with secp256k1
  EC_KEY* ec_key = EC_KEY_new_by_curve_name(NID_secp256k1);
  if (!ec_key) {
    return false;
  }

  // Set public key
  const EC_GROUP* group = EC_KEY_get0_group(ec_key);
  EC_POINT* pub_point   = EC_POINT_new(group);

  if (!pub_point) {
    EC_KEY_free(ec_key);
    return false;
  }

  if (EC_POINT_oct2point(
          group, pub_point, pub_bytes.data(), pub_bytes.size(), nullptr) != 1) {
    EC_POINT_free(pub_point);
    EC_KEY_free(ec_key);
    return false;
  }

  if (EC_KEY_set_public_key(ec_key, pub_point) != 1) {
    EC_POINT_free(pub_point);
    EC_KEY_free(ec_key);
    return false;
  }

  // Decode DER signature
  const unsigned char* sig_ptr = sig_bytes.data();
  ECDSA_SIG* sig = d2i_ECDSA_SIG(nullptr, &sig_ptr, sig_bytes.size());

  if (!sig) {
    EC_POINT_free(pub_point);
    EC_KEY_free(ec_key);
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
// Validation
//------------------------------------------------------------------------------
bool did_crypto::is_valid_private_key(const std::string& private_key_hex) {
  if (private_key_hex.size() != 64) {
    return false;
  }

  // Check all characters are hex
  for (char c : private_key_hex) {
    if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') ||
          (c >= 'A' && c <= 'F'))) {
      return false;
    }
  }

  // Verify it's a valid secp256k1 private key (1 < key < curve order)
  std::vector<uint8_t> key_bytes = from_hex(private_key_hex);

  BIGNUM* key_bn = BN_bin2bn(key_bytes.data(), key_bytes.size(), nullptr);
  if (!key_bn) {
    return false;
  }

  // Get curve order
  EC_GROUP* group = EC_GROUP_new_by_curve_name(NID_secp256k1);
  if (!group) {
    BN_free(key_bn);
    return false;
  }

  BIGNUM* order = BN_new();
  if (!order || EC_GROUP_get_order(group, order, nullptr) != 1) {
    EC_GROUP_free(group);
    BN_free(key_bn);
    if (order) BN_free(order);
    return false;
  }

  // Check: 0 < key < order
  bool valid = !BN_is_zero(key_bn) && (BN_cmp(key_bn, order) < 0);

  BN_free(order);
  EC_GROUP_free(group);
  BN_free(key_bn);

  return valid;
}

bool did_crypto::is_valid_public_key(const std::string& public_key_hex) {
  // Compressed: 66 chars (33 bytes), Uncompressed: 130 chars (65 bytes)
  if (public_key_hex.size() != 66 && public_key_hex.size() != 130) {
    return false;
  }

  // Check prefix
  if (public_key_hex.size() == 66) {
    // Compressed format should start with 02 or 03
    if (public_key_hex.substr(0, 2) != "02" &&
        public_key_hex.substr(0, 2) != "03") {
      return false;
    }
  } else {
    // Uncompressed format should start with 04
    if (public_key_hex.substr(0, 2) != "04") {
      return false;
    }
  }

  // Verify it's a valid point on the curve
  std::vector<uint8_t> pub_bytes = from_hex(public_key_hex);

  EC_GROUP* group = EC_GROUP_new_by_curve_name(NID_secp256k1);
  if (!group) {
    return false;
  }

  EC_POINT* point = EC_POINT_new(group);
  if (!point) {
    EC_GROUP_free(group);
    return false;
  }

  bool valid = (EC_POINT_oct2point(
                    group, point, pub_bytes.data(), pub_bytes.size(),
                    nullptr) == 1) &&
               (EC_POINT_is_on_curve(group, point, nullptr) == 1);

  EC_POINT_free(point);
  EC_GROUP_free(group);

  return valid;
}

}  // namespace oai::amf::did_auth
