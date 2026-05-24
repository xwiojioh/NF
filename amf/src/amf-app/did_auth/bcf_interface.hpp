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

/**
 * @file bcf_interface.hpp
 * @brief BCF 回调接口定义 - NF 与 BCF 交互的接口与数据结构
 *
 * 本文件定义 NF 侧与 BCF 交互所需的回调函数类型和数据结构，
 * 包括：
 * - 公钥查询回调
 * - 认证相关回调类型
 * - NF 选择器接口
 *
 * 注意：BCF 的具体实现不在本工程内，本文件仅定义接口。
 */

#ifndef _BCF_INTERFACE_HPP_
#define _BCF_INTERFACE_HPP_

#include <functional>
#include <optional>
#include <string>
#include <vector>

#include <nlohmann/json.hpp>

namespace oai::amf::did_auth {

// =============================================================================
// 公钥查询相关
// =============================================================================

/**
 * @brief 公钥查询响应结构
 */
struct public_key_response_t {
  bool found;                    // 是否查询到
  std::string did;               // 查询的 DID
  std::string public_key;        // 公钥（Hex 编码）
  std::string nf_type;           // NF 类型
  std::string nf_instance_id;    // NF 实例 ID
  std::string error_message;     // 错误信息

  public_key_response_t() : found(false) {}
};

/**
 * @brief 公钥查询回调函数类型
 *
 * 向 BCF 查询指定 DID 的公钥
 *
 * @param did DID 标识符
 * @return 公钥查询响应
 */
using public_key_query_callback_t =
    std::function<public_key_response_t(const std::string& did)>;

// =============================================================================
// BCF 认证相关请求/响应结构（NF 侧）
// =============================================================================

/**
 * @brief BCF 认证初始化请求
 *
 * NF 向 BCF 发起认证初始化
 * POST /nbcf_auth/v1/auth/init
 */
struct bcf_auth_init_request_t {
  std::string nf_did;              // 请求方 NF 的 DID
  std::string nf_type;             // NF 类型 (AMF, SMF, etc.)
  std::string nf_instance_id;      // NF 实例 ID
  std::vector<std::string> target_nf_types;  // 目标 NF 类型列表
  uint64_t timestamp_ms;           // 毫秒级时间戳

  nlohmann::json to_json() const {
    nlohmann::json j = {
        {"nf_did", nf_did},
        {"nf_type", nf_type},
        {"nf_instance_id", nf_instance_id},
        {"timestamp_ms", timestamp_ms}};
    if (!target_nf_types.empty()) {
      j["target_nf_types"] = target_nf_types;
    }
    return j;
  }

  static bcf_auth_init_request_t from_json(const nlohmann::json& j) {
    bcf_auth_init_request_t req;
    req.nf_did          = j.value("nf_did", "");
    req.nf_type         = j.value("nf_type", "");
    req.nf_instance_id  = j.value("nf_instance_id", "");
    if (j.contains("target_nf_types") && j["target_nf_types"].is_array()) {
      req.target_nf_types =
          j["target_nf_types"].get<std::vector<std::string>>();
    } else if (j.contains("target_nf_type")) {
      const auto target_nf_type = j.value("target_nf_type", "");
      if (!target_nf_type.empty()) {
        req.target_nf_types = {target_nf_type};
      }
    }
    req.timestamp_ms    = j.value("timestamp_ms", 0ULL);
    return req;
  }
};

/**
 * @brief BCF 认证初始化响应（含 challenge）
 *
 * BCF 返回 challenge 给 NF
 */
struct bcf_auth_challenge_response_t {
  std::string session_id;          // BCF 分配的认证会话 ID
  std::string challenge;           // challenge（Hex 编码的 nonce）
  uint64_t challenge_expires_ms;   // challenge 过期时间（毫秒时间戳）
  uint64_t timestamp_ms;           // 响应时间戳

  nlohmann::json to_json() const {
    return {
        {"session_id", session_id},
        {"challenge", challenge},
        {"challenge_expires_ms", challenge_expires_ms},
        {"timestamp_ms", timestamp_ms}};
  }

  static bcf_auth_challenge_response_t from_json(const nlohmann::json& j) {
    bcf_auth_challenge_response_t resp;
    resp.session_id          = j.value("session_id", "");
    resp.challenge           = j.value("challenge", "");
    resp.challenge_expires_ms = j.value("challenge_expires_ms", 0ULL);
    resp.timestamp_ms        = j.value("timestamp_ms", 0ULL);
    return resp;
  }
};

/**
 * @brief BCF 认证验证请求（NF 将签名发回 BCF）
 *
 * NF 签名 challenge 后发给 BCF
 * POST /nbcf_auth/v1/auth/verify
 */
struct bcf_auth_verify_request_t {
  std::string session_id;          // BCF 分配的认证会话 ID
  std::string nf_did;              // NF 的 DID
  std::string challenge_signature; // NF 对 challenge 的签名（Hex 编码）
  uint64_t timestamp_ms;           // 时间戳

  nlohmann::json to_json() const {
    return {
        {"session_id", session_id},
        {"nf_did", nf_did},
        {"challenge_signature", challenge_signature},
        {"timestamp_ms", timestamp_ms}};
  }

  static bcf_auth_verify_request_t from_json(const nlohmann::json& j) {
    bcf_auth_verify_request_t req;
    req.session_id          = j.value("session_id", "");
    req.nf_did              = j.value("nf_did", "");
    req.challenge_signature = j.value("challenge_signature", "");
    req.timestamp_ms        = j.value("timestamp_ms", 0ULL);
    return req;
  }
};

/**
 * @brief BCF 认证结果响应
 *
 * BCF 验签后返回认证结果与 token
 */
struct bcf_auth_result_response_t {
  bool success;                    // 认证是否成功
  std::string session_id;         // 会话 ID
  std::string auth_token;         // BCF 签发的认证令牌
  std::string token_type;         // Bearer
  int expires_in;                 // 令牌有效期（秒）
  uint64_t expires_at_ms;         // 令牌过期时间（毫秒时间戳）
  std::string nf_did;             // 请求方 NF 的 DID
  std::string error_code;         // 错误码（认证失败时）
  std::string error_message;      // 错误信息（认证失败时）
  uint64_t timestamp_ms;          // 响应时间戳
  bool authorized;                // 是否已授权（token 签发成功即为已授权）

  bcf_auth_result_response_t()
      : success(false), expires_in(0), expires_at_ms(0), timestamp_ms(0) {}

  nlohmann::json to_json() const {
    nlohmann::json j = {
        {"success", success},
        {"session_id", session_id},
        {"timestamp_ms", timestamp_ms}};
    if (success) {
      j["auth_token"]     = auth_token;
      j["access_token"]   = auth_token;
      j["token_type"]     = token_type;
      j["expires_in"]     = expires_in;
      j["expires_at_ms"]  = expires_at_ms;
      j["nf_did"]         = nf_did;
      j["authorized"]     = authorized;
    } else {
      j["error_code"]    = error_code;
      j["error_message"] = error_message;
    }
    return j;
  }

  static bcf_auth_result_response_t from_json(const nlohmann::json& j) {
    bcf_auth_result_response_t resp;
    resp.success        = j.value("success", false);
    resp.session_id     = j.value("session_id", "");
    resp.auth_token     = j.value("access_token", j.value("auth_token", ""));
    resp.token_type     = j.value("token_type", "");
    resp.expires_in     = j.value("expires_in", 0);
    resp.expires_at_ms  = j.value("expires_at_ms", 0ULL);
    resp.nf_did         = j.value("nf_did", "");
    resp.error_code     = j.value("error_code", "");
    resp.error_message  = j.value("error_message", "");
    resp.timestamp_ms   = j.value("timestamp_ms", 0ULL);
    // authorized := success && auth_token present OR explicit field from server
    if (resp.success && !resp.auth_token.empty()) {
      resp.authorized = true;
    } else {
      resp.authorized = j.value("authorized", false);
    }
    // Ignore target_nf_type even if server still returns it
    return resp;
  }
};

// =============================================================================
// BCF 认证状态枚举
// =============================================================================

/**
 * @brief BCF 认证流程状态
 */
enum class BcfAuthState {
  IDLE,                       // 未开始
  INIT_SENT,                  // 已发送认证初始化请求
  CHALLENGE_RECEIVED,         // 已收到 BCF challenge
  VERIFY_SENT,                // 已发送签名验证请求
  AUTH_SUCCESS,               // 认证成功，已获取 token
  AUTH_FAILED                 // 认证失败
};

/**
 * @brief BCF 认证结果枚举
 */
enum class BcfAuthResult {
  SUCCESS,                    // 认证成功
  FAILURE_BCF_UNREACHABLE,    // BCF 不可达
  FAILURE_INVALID_DID,        // DID 无效或未注册
  FAILURE_CHALLENGE_EXPIRED,  // challenge 已过期
  FAILURE_SIGNATURE_INVALID,  // 签名验证失败
  FAILURE_INTERNAL_ERROR,     // 内部错误
  FAILURE_TIMEOUT,            // 认证超时
  FAILURE_SESSION_NOT_FOUND,  // 会话不存在
  FAILURE_TOKEN_INVALID       // token 无效
};

/**
 * @brief 将 BcfAuthResult 转换为字符串
 */
inline std::string bcf_auth_result_to_string(BcfAuthResult result) {
  switch (result) {
    case BcfAuthResult::SUCCESS:
      return "SUCCESS";
    case BcfAuthResult::FAILURE_BCF_UNREACHABLE:
      return "FAILURE_BCF_UNREACHABLE";
    case BcfAuthResult::FAILURE_INVALID_DID:
      return "FAILURE_INVALID_DID";
    case BcfAuthResult::FAILURE_CHALLENGE_EXPIRED:
      return "FAILURE_CHALLENGE_EXPIRED";
    case BcfAuthResult::FAILURE_SIGNATURE_INVALID:
      return "FAILURE_SIGNATURE_INVALID";
    case BcfAuthResult::FAILURE_INTERNAL_ERROR:
      return "FAILURE_INTERNAL_ERROR";
    case BcfAuthResult::FAILURE_TIMEOUT:
      return "FAILURE_TIMEOUT";
    case BcfAuthResult::FAILURE_SESSION_NOT_FOUND:
      return "FAILURE_SESSION_NOT_FOUND";
    case BcfAuthResult::FAILURE_TOKEN_INVALID:
      return "FAILURE_TOKEN_INVALID";
    default:
      return "UNKNOWN";
  }
}

// =============================================================================
// BCF 认证会话上下文（NF 侧维护）
// =============================================================================

/**
 * @brief NF 侧维护的 BCF 认证会话
 */
struct bcf_auth_session_t {
  std::string session_id;          // BCF 分配的会话 ID
  std::string local_did;           // 本地 NF 的 DID
  std::string local_nf_type;       // 本地 NF 类型
  std::string local_nf_instance_id;// 本地 NF 实例 ID

  BcfAuthState state;              // 当前认证状态
  std::string challenge;           // BCF 下发的 challenge
  uint64_t challenge_expires_ms;   // challenge 过期时间

  std::string auth_token;          // 认证成功后的 token
  int token_expires_in;            // token 有效期（秒）
  uint64_t token_expires_at_ms;    // token 过期时间（毫秒时间戳）

  uint64_t created_at_ms;          // 会话创建时间
  uint64_t last_activity_ms;       // 最近活动时间

  bcf_auth_session_t()
      : state(BcfAuthState::IDLE),
        challenge_expires_ms(0),
        token_expires_in(0),
        token_expires_at_ms(0),
        created_at_ms(0),
        last_activity_ms(0) {}

  /**
   * @brief 检查 token 是否仍然有效
   */
  bool is_token_valid() const;

  /**
   * @brief 检查 challenge 是否已过期
   */
  bool is_challenge_expired() const;
};

// =============================================================================
// NF Token 缓存条目
// =============================================================================

/**
 * @brief NF 侧缓存的 BCF self auth token
 *
 * 用于缓存 NF 自身从 BCF 获取的 token
 */
struct bcf_token_cache_entry_t {
  std::string auth_token;          // BCF 签发的 self token
  uint64_t expires_at_ms;          // 过期时间
  uint64_t obtained_at_ms;         // 获取时间
  bool authorized = false;         // token 签发即表示已授权

  /**
   * @brief 检查 token 是否仍然有效（含安全余量）
   * @param safety_margin_ms 安全余量（毫秒），默认 30 秒
   */
  bool is_valid(uint64_t safety_margin_ms = 30000) const;
};

// =============================================================================
// BCF Subscription / Notification 数据结构（最小可用）
// =============================================================================

/**
 * @brief 目标 NF 信息
 */
struct target_nf_info_t {
  std::string nf_type;          // NF 类型，例如 AMF/AUSF/SMF
  std::string nf_instance_id;   // NF 实例 ID
  std::string nf_did;           // NF 的 DID（可选）
  std::string nf_uri;           // 可访问的 URI（可选）

  nlohmann::json to_json() const {
    return { {"nf_type", nf_type}, {"nf_instance_id", nf_instance_id}, {"nf_did", nf_did}, {"nf_uri", nf_uri} };
  }

  static target_nf_info_t from_json(const nlohmann::json& j) {
    target_nf_info_t t;
    t.nf_type = j.value("nf_type", "");
    t.nf_instance_id = j.value("nf_instance_id", "");
    t.nf_did = j.value("nf_did", "");
    t.nf_uri = j.value("nf_uri", "");
    return t;
  }
};

/**
 * @brief BCF 订阅请求（NF 订阅目标 NF 的事件/列表）
 */
struct bcf_subscription_request_t {
  std::string subscriber_nf_did;        // 订阅者 NF 的 DID
  std::string subscriber_nf_type;       // 订阅者 NF 类型
  std::string subscriber_nf_instance_id;// 订阅者 NF 实例 ID
  std::string notification_uri;         // BCF 推送通知的回调 URI
  std::string target_nf_type;           // 期望订阅的目标 NF 类型（可选）

  nlohmann::json to_json() const {
    return {
      {"subscriber_nf_did", subscriber_nf_did},
      {"subscriber_nf_type", subscriber_nf_type},
      {"subscriber_nf_instance_id", subscriber_nf_instance_id},
      {"notification_uri", notification_uri},
      {"target_nf_type", target_nf_type}
    };
  }

  static bcf_subscription_request_t from_json(const nlohmann::json& j) {
    bcf_subscription_request_t r;
    r.subscriber_nf_did = j.value("subscriber_nf_did", "");
    r.subscriber_nf_type = j.value("subscriber_nf_type", "");
    r.subscriber_nf_instance_id = j.value("subscriber_nf_instance_id", "");
    r.notification_uri = j.value("notification_uri", "");
    r.target_nf_type = j.value("target_nf_type", "");
    return r;
  }
};

/**
 * @brief BCF 订阅响应（创建订阅后返回）
 */
struct bcf_subscription_response_t {
  bool success = false;
  std::string subscription_id;                 // 服务器分配的订阅 ID
  std::vector<target_nf_info_t> target_nf_list; // 如果 BCF 立即返回已授权的目标 NF 列表
  std::string error_message;

  nlohmann::json to_json() const {
    nlohmann::json j;
    j["success"] = success;
    if (success) {
      j["subscription_id"] = subscription_id;
      nlohmann::json arr = nlohmann::json::array();
      for (const auto& t : target_nf_list) arr.push_back(t.to_json());
      j["target_nf_list"] = arr;
    } else {
      j["error_message"] = error_message;
    }
    return j;
  }

  static bcf_subscription_response_t from_json(const nlohmann::json& j) {
    bcf_subscription_response_t r;
    r.success = j.value("success", false);
    r.subscription_id = j.value("subscription_id", "");
    if (j.contains("target_nf_list") && j["target_nf_list"].is_array()) {
      for (const auto& it : j["target_nf_list"]) r.target_nf_list.push_back(target_nf_info_t::from_json(it));
    }
    r.error_message = j.value("error_message", "");
    return r;
  }
};

/**
 * @brief BCF -> Subscriber 推送的通知数据（最小字段）
 */
struct bcf_notification_data_t {
  std::string subscription_id;
  std::string event_type; // 例如 "TARGET_NF_REGISTERED" / "TARGET_NF_DEREGISTERED"
  target_nf_info_t target; 
  uint64_t timestamp_ms;

  nlohmann::json to_json() const {
    return {
      {"subscription_id", subscription_id},
      {"event_type", event_type},
      {"target", target.to_json()},
      {"timestamp_ms", timestamp_ms}
    };
  }

  static bcf_notification_data_t from_json(const nlohmann::json& j) {
    bcf_notification_data_t n;
    n.subscription_id = j.value("subscription_id", "");
    n.event_type = j.value("event_type", "");
    if (j.contains("target")) n.target = target_nf_info_t::from_json(j["target"]);
    n.timestamp_ms = j.value("timestamp_ms", 0ULL);
    return n;
  }
};

}  // namespace oai::amf::did_auth

#endif  // _BCF_INTERFACE_HPP_
