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

#ifndef _DID_AUTH_TYPES_H_
#define _DID_AUTH_TYPES_H_

#include <chrono>
#include <cstdint>
#include <string>
#include <vector>

#include <nlohmann/json.hpp>

namespace oai::amf::did_auth {

/**
 * @brief 认证会话状态
 */
enum class AuthState {
  IDLE,                   // 空闲状态
  AUTH_PENDING,           // 等待认证
  CHALLENGE_SENT,         // 已发送挑战（作为响应方）
  CHALLENGE_RECEIVED,     // 已收到挑战（作为发起方）
  RESPONSE_SENT,          // 已发送响应
  PEER_VERIFIED,          // 对端已验证（单向完成）
  MUTUAL_AUTH_COMPLETE,   // 双向认证完成
  AUTH_FAILED             // 认证失败
};

/**
 * @brief 认证结果
 */
enum class AuthResult {
  SUCCESS,                  // 认证成功
  MUTUAL_SUCCESS,           // 双向认证成功
  FAILURE_INVALID_DID,      // DID 无效
  FAILURE_KEY_NOT_FOUND,    // 公钥未找到
  FAILURE_SIGNATURE_INVALID,// 签名验证失败
  FAILURE_NONCE_EXPIRED,    // Nonce 过期
  FAILURE_NONCE_REUSED,     // Nonce 重复使用（重放攻击）
  FAILURE_TIMEOUT,          // 认证超时
  FAILURE_BCF_UNAVAILABLE,  // BCF 不可用
  FAILURE_SESSION_NOT_FOUND,// 会话不存在
  FAILURE_SESSION_EXISTS,   // 会话已存在（重复请求）
  FAILURE_SESSION_MISMATCH, // 会话 ID 不匹配（可能的劫持攻击）
  FAILURE_INTERNAL_ERROR,   // 内部错误
  // BCF 单向认证相关（新增）
  FAILURE_TOKEN_INVALID,    // BCF token 无效
  FAILURE_TOKEN_EXPIRED,    // BCF token 已过期
  BCF_AUTH_SUCCESS          // BCF 单向认证成功
};

/**
 * @brief 将 AuthResult 转换为字符串
 */
inline std::string auth_result_to_string(AuthResult result) {
  switch (result) {
    case AuthResult::SUCCESS:
      return "SUCCESS";
    case AuthResult::MUTUAL_SUCCESS:
      return "MUTUAL_SUCCESS";
    case AuthResult::FAILURE_INVALID_DID:
      return "FAILURE_INVALID_DID";
    case AuthResult::FAILURE_KEY_NOT_FOUND:
      return "FAILURE_KEY_NOT_FOUND";
    case AuthResult::FAILURE_SIGNATURE_INVALID:
      return "FAILURE_SIGNATURE_INVALID";
    case AuthResult::FAILURE_NONCE_EXPIRED:
      return "FAILURE_NONCE_EXPIRED";
    case AuthResult::FAILURE_NONCE_REUSED:
      return "FAILURE_NONCE_REUSED";
    case AuthResult::FAILURE_TIMEOUT:
      return "FAILURE_TIMEOUT";
    case AuthResult::FAILURE_BCF_UNAVAILABLE:
      return "FAILURE_BCF_UNAVAILABLE";
    case AuthResult::FAILURE_SESSION_NOT_FOUND:
      return "FAILURE_SESSION_NOT_FOUND";
    case AuthResult::FAILURE_SESSION_EXISTS:
      return "FAILURE_SESSION_EXISTS";
    case AuthResult::FAILURE_SESSION_MISMATCH:
      return "FAILURE_SESSION_MISMATCH";
    case AuthResult::FAILURE_INTERNAL_ERROR:
      return "FAILURE_INTERNAL_ERROR";
    case AuthResult::FAILURE_TOKEN_INVALID:
      return "FAILURE_TOKEN_INVALID";
    case AuthResult::FAILURE_TOKEN_EXPIRED:
      return "FAILURE_TOKEN_EXPIRED";
    case AuthResult::BCF_AUTH_SUCCESS:
      return "BCF_AUTH_SUCCESS";
    default:
      return "UNKNOWN";
  }
}

/**
 * @brief 将字符串转换为 AuthResult
 */
inline AuthResult string_to_auth_result(const std::string& str) {
  if (str == "SUCCESS") return AuthResult::SUCCESS;
  if (str == "MUTUAL_SUCCESS") return AuthResult::MUTUAL_SUCCESS;
  if (str == "FAILURE_INVALID_DID") return AuthResult::FAILURE_INVALID_DID;
  if (str == "FAILURE_KEY_NOT_FOUND") return AuthResult::FAILURE_KEY_NOT_FOUND;
  if (str == "FAILURE_SIGNATURE_INVALID")
    return AuthResult::FAILURE_SIGNATURE_INVALID;
  if (str == "FAILURE_NONCE_EXPIRED") return AuthResult::FAILURE_NONCE_EXPIRED;
  if (str == "FAILURE_NONCE_REUSED") return AuthResult::FAILURE_NONCE_REUSED;
  if (str == "FAILURE_TIMEOUT") return AuthResult::FAILURE_TIMEOUT;
  if (str == "FAILURE_BCF_UNAVAILABLE")
    return AuthResult::FAILURE_BCF_UNAVAILABLE;
  if (str == "FAILURE_SESSION_NOT_FOUND")
    return AuthResult::FAILURE_SESSION_NOT_FOUND;
  if (str == "FAILURE_SESSION_EXISTS")
    return AuthResult::FAILURE_SESSION_EXISTS;
  if (str == "FAILURE_SESSION_MISMATCH")
    return AuthResult::FAILURE_SESSION_MISMATCH;
  if (str == "FAILURE_TOKEN_INVALID")
    return AuthResult::FAILURE_TOKEN_INVALID;
  if (str == "FAILURE_TOKEN_EXPIRED")
    return AuthResult::FAILURE_TOKEN_EXPIRED;
  if (str == "BCF_AUTH_SUCCESS") return AuthResult::BCF_AUTH_SUCCESS;
  return AuthResult::FAILURE_INTERNAL_ERROR;
}

/**
 * @brief Nonce 结构
 * 包含 32 字节随机数和 8 字节时间戳
 */
struct nonce_t {
  std::vector<uint8_t> random_bytes;  // 32 字节随机数
  uint64_t timestamp_ms;              // 毫秒级时间戳

  nonce_t() : timestamp_ms(0) {}

  nonce_t(const std::vector<uint8_t>& random, uint64_t ts)
      : random_bytes(random), timestamp_ms(ts) {}

  /**
   * @brief 转换为 Hex 字符串 (32字节随机数 + 8字节时间戳 = 80字符)
   */
  std::string to_hex() const;

  /**
   * @brief 从 Hex 字符串解析
   */
  static nonce_t from_hex(const std::string& hex_str);

  /**
   * @brief 检查 Nonce 是否过期
   * @param timeout_ms 超时时间（毫秒），默认 5 分钟
   */
  bool is_expired(uint64_t timeout_ms = 300000) const;

  /**
   * @brief 获取当前时间戳（毫秒）
   */
  static uint64_t current_timestamp_ms();
};

/**
 * @brief 认证初始化请求消息
 */
struct auth_init_request_t {
  std::string did;             // 发起方 DID
  std::string nf_type;         // NF 类型 (AMF, SMF, etc.)
  std::string nf_instance_id;  // NF 实例 ID
  std::string nonce;           // 挑战 nonce（Hex 编码）
  std::string session_id;      // 会话 ID
  std::string timestamp;       // ISO 8601 时间戳

  nlohmann::json to_json() const;
  static auth_init_request_t from_json(const nlohmann::json& j);
};

/**
 * @brief 认证挑战响应消息
 */
struct auth_challenge_response_t {
  std::string did;             // 响应方 DID
  std::string nf_type;         // NF 类型
  std::string nf_instance_id;  // NF 实例 ID
  std::string nonce;           // 新的 nonce（用于发起方签名）
  std::string signature;       // 对发起方 nonce 的签名（Hex 编码）
  std::string session_id;      // 会话 ID
  std::string timestamp;       // ISO 8601 时间戳

  nlohmann::json to_json() const;
  static auth_challenge_response_t from_json(const nlohmann::json& j);
};

/**
 * @brief 认证完成请求消息
 */
struct auth_complete_request_t {
  std::string session_id;  // 会话 ID
  std::string signature;   // 对响应方 nonce 的签名（Hex 编码）
  std::string timestamp;   // ISO 8601 时间戳

  nlohmann::json to_json() const;
  static auth_complete_request_t from_json(const nlohmann::json& j);
};

/**
 * @brief 认证结果消息
 */
struct auth_result_response_t {
  std::string session_id;  // 会话 ID
  AuthResult result;       // 认证结果
  std::string message;     // 结果描述
  std::string auth_token;  // 认证令牌（可选，用于后续通信）
  uint64_t expires_at;     // 令牌过期时间（Unix 时间戳毫秒）
  int expires_in;          // 令牌有效期（秒）
  std::string timestamp;   // ISO 8601 时间戳
  std::string peer_did;    // 对端 DID

  auth_result_response_t() : result(AuthResult::FAILURE_INTERNAL_ERROR),
                             expires_at(0), expires_in(0) {}

  nlohmann::json to_json() const;
  static auth_result_response_t from_json(const nlohmann::json& j);
};

/**
 * @brief 认证会话上下文
 */
struct auth_session_t {
  std::string session_id;
  std::string local_did;
  std::string local_nf_type;
  std::string local_nf_instance_id;
  std::string remote_did;
  std::string remote_nf_type;
  std::string remote_nf_instance_id;
  std::string remote_endpoint;
  AuthState state;

  nonce_t local_nonce;                // 本地生成的 nonce
  nonce_t remote_nonce;               // 对端发来的 nonce
  std::string remote_public_key;      // 对端公钥（Hex 编码）

  std::chrono::steady_clock::time_point created_time;
  std::chrono::steady_clock::time_point last_activity;

  bool is_initiator;  // 是否为认证发起方
  bool authenticated; // 是否已完成认证

  std::string auth_token;  // 认证成功后的令牌
  uint64_t token_expires_at;
  uint64_t created_at;     // Unix timestamp for external use

  // Alias for peer_did
  std::string peer_did;

  auth_session_t()
      : state(AuthState::IDLE),
        is_initiator(false),
        authenticated(false),
        token_expires_at(0),
        created_at(0) {}
};

/**
 * @brief NF 基本信息（用于认证消息）
 */
struct nf_info_t {
  std::string did;
  std::string nf_type;
  std::string nf_instance_id;

  nlohmann::json to_json() const {
    return nlohmann::json{
        {"did", did}, {"nfType", nf_type}, {"nfInstanceId", nf_instance_id}};
  }

  static nf_info_t from_json(const nlohmann::json& j) {
    nf_info_t info;
    if (j.contains("did")) info.did = j["did"].get<std::string>();
    if (j.contains("nfType")) info.nf_type = j["nfType"].get<std::string>();
    if (j.contains("nfInstanceId"))
      info.nf_instance_id = j["nfInstanceId"].get<std::string>();
    return info;
  }
};

// =============================================================================
// Simplified types for amf_app integration
// =============================================================================

// =============================================================================
// DID Auth Protocol Field Naming Convention (v2.0)
// =============================================================================
//
// To ensure clarity and avoid ambiguity in logs and messages:
//
// DID Fields:
//   - initiator_did: DID of the authentication initiator (e.g., AMF)
//   - responder_did: DID of the authentication responder (e.g., AUSF)
//   - NEVER use ambiguous "did" alone in protocol messages
//
// Nonce Fields:
//   - initiator_nonce: Nonce generated by initiator (for responder to sign)
//   - responder_nonce: Nonce generated by responder (for initiator to sign)
//   - NEVER use ambiguous "nonce" alone in protocol messages
//
// Signature Fields:
//   - responder_signature: Responder's signature on initiator_nonce
//   - initiator_signature: Initiator's signature on responder_nonce
//   - NEVER use ambiguous "signature" alone in protocol messages
//
// Timestamp:
//   - timestamp_ms: Always use milliseconds as number, not string
//
// =============================================================================

/**
 * @brief POST /mutual_auth/init Request Body
 * 
 * Sent by Initiator (AMF) to Responder (AUSF)
 */
struct auth_init_request_v2_t {
  std::string initiator_did;           // Initiator's DID
  std::string initiator_nf_type;       // "AMF", "SMF", etc.
  std::string initiator_nf_instance_id;// NF Instance UUID
  std::string initiator_nonce;         // Nonce for responder to sign
  std::string session_id;              // Session ID (generated by initiator)
  uint64_t timestamp_ms;               // Milliseconds since epoch
  
  nlohmann::json to_json() const {
    return nlohmann::json{
        {"initiator_did", initiator_did},
        {"initiator_nf_type", initiator_nf_type},
        {"initiator_nf_instance_id", initiator_nf_instance_id},
        {"initiator_nonce", initiator_nonce},
        {"session_id", session_id},
        {"timestamp_ms", timestamp_ms}
    };
  }
  
  static auth_init_request_v2_t from_json(const nlohmann::json& j) {
    auth_init_request_v2_t req;
    req.initiator_did = j.value("initiator_did", "");
    req.initiator_nf_type = j.value("initiator_nf_type", "");
    req.initiator_nf_instance_id = j.value("initiator_nf_instance_id", "");
    req.initiator_nonce = j.value("initiator_nonce", "");
    req.session_id = j.value("session_id", "");
    req.timestamp_ms = j.value("timestamp_ms", 0ULL);
    return req;
  }
};

/**
 * @brief POST /mutual_auth/init Response Body
 * 
 * Sent by Responder (AUSF) back to Initiator (AMF)
 */
struct auth_init_response_v2_t {
  std::string responder_did;           // Responder's DID
  std::string responder_nf_type;       // "AUSF", "UDM", etc.
  std::string responder_nf_instance_id;// NF Instance UUID
  std::string responder_nonce;         // Nonce for initiator to sign
  std::string responder_signature;     // Signature on initiator_nonce
  std::string session_id;              // Echoed session ID
  uint64_t timestamp_ms;               // Milliseconds since epoch
  
  nlohmann::json to_json() const {
    return nlohmann::json{
        {"responder_did", responder_did},
        {"responder_nf_type", responder_nf_type},
        {"responder_nf_instance_id", responder_nf_instance_id},
        {"responder_nonce", responder_nonce},
        {"responder_signature", responder_signature},
        {"session_id", session_id},
        {"timestamp_ms", timestamp_ms}
    };
  }
  
  static auth_init_response_v2_t from_json(const nlohmann::json& j) {
    auth_init_response_v2_t resp;
    resp.responder_did = j.value("responder_did", "");
    resp.responder_nf_type = j.value("responder_nf_type", "");
    resp.responder_nf_instance_id = j.value("responder_nf_instance_id", "");
    resp.responder_nonce = j.value("responder_nonce", "");
    resp.responder_signature = j.value("responder_signature", "");
    resp.session_id = j.value("session_id", "");
    resp.timestamp_ms = j.value("timestamp_ms", 0ULL);
    return resp;
  }
};

/**
 * @brief POST /mutual_auth/complete Request Body
 * 
 * Sent by Initiator (AMF) to Responder (AUSF)
 */
struct auth_complete_request_v2_t {
  std::string session_id;              // Session ID
  std::string initiator_signature;     // Signature on responder_nonce
  uint64_t timestamp_ms;               // Milliseconds since epoch
  
  nlohmann::json to_json() const {
    return nlohmann::json{
        {"session_id", session_id},
        {"initiator_signature", initiator_signature},
        {"timestamp_ms", timestamp_ms}
    };
  }
  
  static auth_complete_request_v2_t from_json(const nlohmann::json& j) {
    auth_complete_request_v2_t req;
    req.session_id = j.value("session_id", "");
    req.initiator_signature = j.value("initiator_signature", "");
    req.timestamp_ms = j.value("timestamp_ms", 0ULL);
    return req;
  }
};

/**
 * @brief POST /mutual_auth/complete Response Body
 * 
 * Sent by Responder (AUSF) back to Initiator (AMF)
 */
struct auth_complete_response_v2_t {
  bool success;                        // Whether auth succeeded
  std::string auth_token;              // Token for subsequent requests
  int expires_in;                      // Token validity in seconds
  std::string initiator_did;           // Echoed initiator DID
  std::string responder_did;           // Responder's DID
  std::string session_id;              // Echoed session ID
  uint64_t timestamp_ms;               // Milliseconds since epoch
  std::string error_message;           // Error message if success=false
  
  auth_complete_response_v2_t() : success(false), expires_in(0), timestamp_ms(0) {}
  
  nlohmann::json to_json() const {
    nlohmann::json j = {
        {"success", success},
        {"auth_token", auth_token},
        {"expires_in", expires_in},
        {"initiator_did", initiator_did},
        {"responder_did", responder_did},
        {"session_id", session_id},
        {"timestamp_ms", timestamp_ms}
    };
    if (!error_message.empty()) {
      j["error_message"] = error_message;
    }
    return j;
  }
  
  static auth_complete_response_v2_t from_json(const nlohmann::json& j) {
    auth_complete_response_v2_t resp;
    resp.success = j.value("success", false);
    resp.auth_token = j.value("auth_token", "");
    resp.expires_in = j.value("expires_in", 0);
    resp.initiator_did = j.value("initiator_did", "");
    resp.responder_did = j.value("responder_did", "");
    resp.session_id = j.value("session_id", "");
    resp.timestamp_ms = j.value("timestamp_ms", 0ULL);
    resp.error_message = j.value("error_message", "");
    return resp;
  }
};

// =============================================================================
// DID Auth Logging Utilities
// =============================================================================

/**
 * @brief Extract short DID for logging (first 16 chars after "did:oai5gc:")
 */
inline std::string short_did(const std::string& full_did) {
  // Format: did:oai5gc:<32-char-hash>:<public-key-hex>
  // Return: did:oai5gc:<first-12-chars>...
  if (full_did.length() <= 24) return full_did;
  
  const std::string prefix = "did:oai5gc:";
  if (full_did.substr(0, prefix.length()) == prefix) {
    std::string hash_part = full_did.substr(prefix.length());
    if (hash_part.length() > 12) {
      return prefix + hash_part.substr(0, 12) + "...";
    }
  }
  return full_did.substr(0, 24) + "...";
}

/**
 * @brief Truncate string for logging with ellipsis
 */
inline std::string truncate_for_log(const std::string& s, size_t max_len = 32) {
  if (s.length() <= max_len) return s;
  return s.substr(0, max_len) + "...";
}

// =============================================================================
// Legacy types (kept for backward compatibility during transition)
// =============================================================================

/**
 * @brief Simplified auth request (from HTTP API)
 * @deprecated Use auth_init_request_v2_t instead
 */
struct auth_request_t {
  std::string initiator_did;
  std::string nonce;
  uint64_t timestamp;
  std::string nf_type;
  std::string nf_instance_id;  // NF 实例 ID
  std::string session_id;      // 会话 ID (由 Initiator 生成)
};

/**
 * @brief Simplified auth challenge (for HTTP API response)
 */
struct auth_challenge_t {
  std::string responder_did;
  std::string challenge_nonce;
  uint64_t challenge_timestamp;
  std::string responder_signature;
};

/**
 * @brief Simplified auth response (from HTTP API)
 */
struct auth_response_t {
  std::string session_id;
  std::string initiator_signature;
};

/**
 * @brief Simplified auth result (for HTTP API response)
 */
struct auth_result_t {
  std::string peer_did;
  std::string auth_token;
  int expires_in;
  std::string error_message;
};

}  // namespace oai::amf::did_auth

#endif  // _DID_AUTH_TYPES_H_
