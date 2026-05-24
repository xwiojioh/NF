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

#include "did_auth_types.hpp"

#include <chrono>
#include <ctime>
#include <iomanip>
#include <sstream>

namespace oai::amf::did_auth {

//------------------------------------------------------------------------------
// Helper functions for hex conversion
//------------------------------------------------------------------------------
static const char hex_chars[] = "0123456789abcdef";

static std::string bytes_to_hex(const std::vector<uint8_t>& bytes) {
  std::string hex;
  hex.reserve(bytes.size() * 2);
  for (uint8_t b : bytes) {
    hex.push_back(hex_chars[(b >> 4) & 0x0F]);
    hex.push_back(hex_chars[b & 0x0F]);
  }
  return hex;
}

static std::vector<uint8_t> hex_to_bytes(const std::string& hex) {
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

static std::string get_iso8601_timestamp() {
  auto now    = std::chrono::system_clock::now();
  auto time_t = std::chrono::system_clock::to_time_t(now);
  auto ms     = std::chrono::duration_cast<std::chrono::milliseconds>(
                now.time_since_epoch()) %
            1000;

  std::tm tm_utc;
#ifdef _WIN32
  gmtime_s(&tm_utc, &time_t);
#else
  gmtime_r(&time_t, &tm_utc);
#endif

  std::ostringstream oss;
  oss << std::put_time(&tm_utc, "%Y-%m-%dT%H:%M:%S");
  oss << '.' << std::setfill('0') << std::setw(3) << ms.count() << 'Z';
  return oss.str();
}

//------------------------------------------------------------------------------
// nonce_t implementation
//------------------------------------------------------------------------------
std::string nonce_t::to_hex() const {
  std::string hex = bytes_to_hex(random_bytes);

  // Append timestamp as 16 hex characters (8 bytes)
  for (int i = 7; i >= 0; --i) {
    uint8_t byte = (timestamp_ms >> (i * 8)) & 0xFF;
    hex.push_back(hex_chars[(byte >> 4) & 0x0F]);
    hex.push_back(hex_chars[byte & 0x0F]);
  }
  return hex;
}

nonce_t nonce_t::from_hex(const std::string& hex_str) {
  nonce_t nonce;

  if (hex_str.size() < 16) {
    return nonce;  // Invalid
  }

  // Last 16 characters are the timestamp
  size_t random_len = hex_str.size() - 16;
  std::string random_hex(hex_str.begin(), hex_str.begin() + random_len);
  std::string ts_hex(hex_str.begin() + random_len, hex_str.end());

  nonce.random_bytes = hex_to_bytes(random_hex);

  // Parse timestamp
  nonce.timestamp_ms = 0;
  auto ts_bytes      = hex_to_bytes(ts_hex);
  for (size_t i = 0; i < ts_bytes.size() && i < 8; ++i) {
    nonce.timestamp_ms = (nonce.timestamp_ms << 8) | ts_bytes[i];
  }

  return nonce;
}

bool nonce_t::is_expired(uint64_t timeout_ms) const {
  uint64_t now = current_timestamp_ms();
  return (now > timestamp_ms) && ((now - timestamp_ms) > timeout_ms);
}

uint64_t nonce_t::current_timestamp_ms() {
  return std::chrono::duration_cast<std::chrono::milliseconds>(
             std::chrono::system_clock::now().time_since_epoch())
      .count();
}

//------------------------------------------------------------------------------
// auth_init_request_t implementation
//------------------------------------------------------------------------------
nlohmann::json auth_init_request_t::to_json() const {
  return nlohmann::json{
      {"messageType", "MutualAuthInit"},
      {"sessionId", session_id},
      {"initiator",
       {{"did", did},
        {"nfType", nf_type},
        {"nfInstanceId", nf_instance_id}}},
      {"nonce", nonce},
      {"timestamp", timestamp.empty() ? get_iso8601_timestamp() : timestamp}};
}

auth_init_request_t auth_init_request_t::from_json(const nlohmann::json& j) {
  auth_init_request_t req;

  if (j.contains("sessionId")) {
    req.session_id = j["sessionId"].get<std::string>();
  }
  if (j.contains("nonce")) {
    req.nonce = j["nonce"].get<std::string>();
  }
  if (j.contains("timestamp")) {
    req.timestamp = j["timestamp"].get<std::string>();
  }
  if (j.contains("initiator")) {
    auto& initiator = j["initiator"];
    if (initiator.contains("did")) {
      req.did = initiator["did"].get<std::string>();
    }
    if (initiator.contains("nfType")) {
      req.nf_type = initiator["nfType"].get<std::string>();
    }
    if (initiator.contains("nfInstanceId")) {
      req.nf_instance_id = initiator["nfInstanceId"].get<std::string>();
    }
  }

  return req;
}

//------------------------------------------------------------------------------
// auth_challenge_response_t implementation
//------------------------------------------------------------------------------
nlohmann::json auth_challenge_response_t::to_json() const {
  return nlohmann::json{
      {"messageType", "MutualAuthChallenge"},
      {"sessionId", session_id},
      {"responder",
       {{"did", did},
        {"nfType", nf_type},
        {"nfInstanceId", nf_instance_id}}},
      {"nonce", nonce},
      {"signatureForInitiatorNonce", signature},
      {"timestamp", timestamp.empty() ? get_iso8601_timestamp() : timestamp}};
}

auth_challenge_response_t auth_challenge_response_t::from_json(
    const nlohmann::json& j) {
  auth_challenge_response_t resp;

  if (j.contains("sessionId")) {
    resp.session_id = j["sessionId"].get<std::string>();
  }
  if (j.contains("nonce")) {
    resp.nonce = j["nonce"].get<std::string>();
  }
  if (j.contains("signatureForInitiatorNonce")) {
    resp.signature = j["signatureForInitiatorNonce"].get<std::string>();
  }
  if (j.contains("timestamp")) {
    resp.timestamp = j["timestamp"].get<std::string>();
  }
  if (j.contains("responder")) {
    auto& responder = j["responder"];
    if (responder.contains("did")) {
      resp.did = responder["did"].get<std::string>();
    }
    if (responder.contains("nfType")) {
      resp.nf_type = responder["nfType"].get<std::string>();
    }
    if (responder.contains("nfInstanceId")) {
      resp.nf_instance_id = responder["nfInstanceId"].get<std::string>();
    }
  }

  return resp;
}

//------------------------------------------------------------------------------
// auth_complete_request_t implementation
//------------------------------------------------------------------------------
nlohmann::json auth_complete_request_t::to_json() const {
  return nlohmann::json{
      {"messageType", "MutualAuthComplete"},
      {"sessionId", session_id},
      {"signatureForResponderNonce", signature},
      {"timestamp", timestamp.empty() ? get_iso8601_timestamp() : timestamp}};
}

auth_complete_request_t auth_complete_request_t::from_json(
    const nlohmann::json& j) {
  auth_complete_request_t req;

  if (j.contains("sessionId")) {
    req.session_id = j["sessionId"].get<std::string>();
  }
  if (j.contains("signatureForResponderNonce")) {
    req.signature = j["signatureForResponderNonce"].get<std::string>();
  }
  if (j.contains("timestamp")) {
    req.timestamp = j["timestamp"].get<std::string>();
  }

  return req;
}

//------------------------------------------------------------------------------
// auth_result_response_t implementation
//------------------------------------------------------------------------------
nlohmann::json auth_result_response_t::to_json() const {
  nlohmann::json j = {
      {"messageType", "AuthResult"},
      {"sessionId", session_id},
      {"result", auth_result_to_string(result)},
      {"message", message},
      {"timestamp", timestamp.empty() ? get_iso8601_timestamp() : timestamp}};

  if (!auth_token.empty()) {
    j["authToken"]  = auth_token;
    j["expiresAt"] = expires_at;
  }

  return j;
}

auth_result_response_t auth_result_response_t::from_json(
    const nlohmann::json& j) {
  auth_result_response_t resp;

  if (j.contains("sessionId")) {
    resp.session_id = j["sessionId"].get<std::string>();
  }
  if (j.contains("result")) {
    resp.result = string_to_auth_result(j["result"].get<std::string>());
  }
  if (j.contains("message")) {
    resp.message = j["message"].get<std::string>();
  }
  if (j.contains("authToken")) {
    resp.auth_token = j["authToken"].get<std::string>();
  }
  if (j.contains("expiresAt")) {
    resp.expires_at = j["expiresAt"].get<uint64_t>();
  }
  if (j.contains("timestamp")) {
    resp.timestamp = j["timestamp"].get<std::string>();
  }

  return resp;
}

}  // namespace oai::amf::did_auth
