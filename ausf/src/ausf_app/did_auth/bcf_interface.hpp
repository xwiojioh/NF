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

#ifndef _AUSF_BCF_INTERFACE_H_
#define _AUSF_BCF_INTERFACE_H_

#include <functional>
#include <optional>
#include <string>
#include <vector>

#include <nlohmann/json.hpp>

namespace oai::ausf::did_auth {

//==============================================================================
// NF Profile 信息结构 (从 BCF 返回的 NF 信息)
//==============================================================================

/**
 * @brief PLMN ID 结构
 */
struct plmn_id_t {
  std::string mcc;  // Mobile Country Code (3 位)
  std::string mnc;  // Mobile Network Code (2-3 位)
};

/**
 * @brief S-NSSAI 结构 (Single Network Slice Selection Assistance Information)
 */
struct snssai_t {
  uint8_t sst;             // Slice/Service Type (1-255)
  std::string sd;          // Slice Differentiator (可选, 6 位十六进制)
};

/**
 * @brief NF 服务信息
 */
struct nf_service_t {
  std::string service_instance_id;
  std::string service_name;
  std::vector<std::string> versions;
  std::string scheme;      // "http" or "https"
  std::string fqdn;
  std::string ip_endpoint; // IP:Port
  std::string api_prefix;
};

/**
 * @brief NF Profile 结构 (BCF 返回的 NF 信息)
 *
 * 基于 3GPP TS 29.510 NFProfile 定义，选取用于 NF 发现和选择的关键字段
 */
struct nf_profile_t {
  // ===== 必选字段 =====
  std::string nf_instance_id;    // NF 实例 ID (UUID)
  std::string nf_type;           // NF 类型 (AMF, SMF, UDM, etc.)
  std::string nf_status;         // NF 状态 (REGISTERED, SUSPENDED, etc.)

  // ===== DID 相关 (BCF 扩展) =====
  std::string did;               // 去中心化身份标识
  std::string public_key;        // 公钥 (十六进制)

  // ===== 网络标识 =====
  std::vector<plmn_id_t> plmn_list;      // 支持的 PLMN 列表
  std::vector<snssai_t> snssai_list;     // 支持的网络切片列表
  std::vector<std::string> nsi_list;     // Network Slice Instance 列表

  // ===== 访问地址 =====
  std::string fqdn;                      // 完全限定域名
  std::vector<std::string> ipv4_addresses;
  std::vector<std::string> ipv6_addresses;
  std::vector<nf_service_t> nf_services; // NF 服务列表

  // ===== 负载和容量 =====
  int32_t priority;              // 优先级 (0-65535, 越小越优先)
  int32_t capacity;              // 容量 (0-65535)
  int32_t load;                  // 当前负载百分比 (0-100)

  // ===== 位置信息 =====
  std::string locality;          // 地理位置标识

  // ===== 辅助方法 =====

  /**
   * @brief 获取 NF 的 URI
   * @return NF 的访问 URI，优先使用 FQDN，其次 IPv4
   */
  std::string get_uri() const {
    if (!fqdn.empty()) {
      return "https://" + fqdn;
    }
    if (!ipv4_addresses.empty()) {
      return "https://" + ipv4_addresses[0];
    }
    if (!ipv6_addresses.empty()) {
      return "https://[" + ipv6_addresses[0] + "]";
    }
    return "";
  }

  /**
   * @brief 获取指定服务的 URI
   * @param service_name 服务名称
   * @return 服务 URI
   */
  std::string get_service_uri(const std::string& service_name) const {
    for (const auto& svc : nf_services) {
      if (svc.service_name == service_name) {
        if (!svc.fqdn.empty()) {
          return svc.scheme + "://" + svc.fqdn + svc.api_prefix;
        }
        if (!svc.ip_endpoint.empty()) {
          return svc.scheme + "://" + svc.ip_endpoint + svc.api_prefix;
        }
      }
    }
    return get_uri();  // 回退到默认 URI
  }
};

//==============================================================================
// NF 发现请求和响应
//==============================================================================

/**
 * @brief NF 发现查询条件
 *
 * Initiator NF 向 BCF 发送的查询条件，用于筛选符合要求的目标 NF
 */
struct nf_discovery_criteria_t {
  // ===== 必选条件 =====
  std::string target_nf_type;        // 目标 NF 类型 (如 "AMF", "SMF", "UDM")
  std::string requester_nf_type;     // 请求方 NF 类型

  // ===== 可选筛选条件 =====
  std::optional<plmn_id_t> target_plmn;          // 目标 PLMN
  std::optional<snssai_t> target_snssai;         // 目标网络切片
  std::optional<std::string> target_nsi;         // 目标 NSI
  std::optional<std::string> target_locality;    // 目标地理位置
  std::optional<std::string> service_name;       // 所需服务名称

  // ===== 容量和负载要求 =====
  std::optional<int32_t> min_capacity;           // 最小容量要求
  std::optional<int32_t> max_load;               // 最大负载要求 (百分比)

  // ===== 结果限制 =====
  uint32_t max_results = 10;                     // 最大返回数量
};

/**
 * @brief NF 发现响应
 */
struct nf_discovery_response_t {
  bool success;
  std::vector<nf_profile_t> nf_profiles;  // 符合条件的 NF 列表
  std::string error_message;
  uint64_t validity_period;               // 结果有效期 (秒)
};

//==============================================================================
// 公钥查询请求和响应
//==============================================================================

/**
 * @brief 公钥查询响应
 */
struct public_key_response_t {
  bool found;
  std::string did;
  std::string public_key;        // 十六进制格式公钥
  std::string nf_type;
  std::string nf_instance_id;
  std::string error_message;
};

//==============================================================================
// BCF 回调接口定义
//==============================================================================

/**
 * @brief NF 发现回调函数类型
 *
 * Initiator 调用此回调向 BCF 发送 NF 发现请求
 *
 * @param criteria 查询条件
 * @return 发现响应（包含符合条件的 NF 列表）
 */
using nf_discovery_callback_t =
    std::function<nf_discovery_response_t(const nf_discovery_criteria_t& criteria)>;

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

//==============================================================================
// NF 选择策略
//==============================================================================

/**
 * @brief NF 选择策略
 */
enum class NfSelectionStrategy {
  PRIORITY_BASED,      // 基于优先级（priority 值越小越优先）
  LOAD_BASED,          // 基于负载（load 值越小越优先）
  CAPACITY_BASED,      // 基于容量（capacity 值越大越优先）
  ROUND_ROBIN,         // 轮询
  RANDOM,              // 随机选择
  LOCALITY_BASED       // 基于地理位置（优先选择同一 locality）
};

/**
 * @brief NF 选择器
 *
 * 根据策略从 NF 列表中选择一个最优的 NF
 */
class nf_selector {
 public:
  /**
   * @brief 根据策略选择 NF
   * @param nf_list NF 列表
   * @param strategy 选择策略
   * @param local_locality 本地位置（用于 LOCALITY_BASED 策略）
   * @return 选中的 NF，如果列表为空返回 nullopt
   */
  static std::optional<nf_profile_t> select(
      const std::vector<nf_profile_t>& nf_list,
      NfSelectionStrategy strategy = NfSelectionStrategy::PRIORITY_BASED,
      const std::string& local_locality = "");

 private:
  static std::optional<nf_profile_t> select_by_priority(
      const std::vector<nf_profile_t>& nf_list);

  static std::optional<nf_profile_t> select_by_load(
      const std::vector<nf_profile_t>& nf_list);

  static std::optional<nf_profile_t> select_by_capacity(
      const std::vector<nf_profile_t>& nf_list);

  static std::optional<nf_profile_t> select_random(
      const std::vector<nf_profile_t>& nf_list);

  static std::optional<nf_profile_t> select_by_locality(
      const std::vector<nf_profile_t>& nf_list,
      const std::string& local_locality);

  // 轮询索引（静态，用于 ROUND_ROBIN）
  static size_t s_round_robin_index;
};

}  // namespace oai::ausf::did_auth

// =============================================================================
// BCF 认证相关请求/响应结构（NF 侧）
// 从 AMF bcf_interface.hpp 迁移，保持接口一致
// =============================================================================
namespace oai::ausf::did_auth {

/**
 * @brief BCF 认证初始化请求
 *
 * NF 向 BCF 发起认证初始化
 * POST /nbcf_auth/v1/auth/init
 */
struct bcf_auth_init_request_t {
  std::string nf_did;              // 请求方 NF 的 DID
  std::string nf_type;             // NF 类型 (AMF, AUSF, etc.)
  std::string nf_instance_id;      // NF 实例 ID
  std::vector<std::string> target_nf_types;  // 目标 NF 类型列表
  uint64_t timestamp_ms;           // 毫秒级时间戳
  nlohmann::json plmn_list = nlohmann::json::array();  // 向后兼容扩展
  nlohmann::json snssais   = nlohmann::json::array();  // 向后兼容扩展

  nlohmann::json to_json() const {
    nlohmann::json j = {
        {"nf_did", nf_did},
        {"nf_type", nf_type},
        {"nf_instance_id", nf_instance_id},
        {"timestamp_ms", timestamp_ms}};
    if (!target_nf_types.empty()) {
      j["target_nf_types"] = target_nf_types;
    }
    if (plmn_list.is_array() && !plmn_list.empty()) {
      j["plmn_list"] = plmn_list;
    }
    if (snssais.is_array() && !snssais.empty()) {
      j["snssais"] = snssais;
    }
    return j;
  }

  static bcf_auth_init_request_t from_json(const nlohmann::json& j) {
    bcf_auth_init_request_t req;
    req.nf_did          = j.value("nf_did", "");
    req.nf_type         = j.value("nf_type", "");
    req.nf_instance_id  = j.value("nf_instance_id", "");
    req.timestamp_ms    = j.value("timestamp_ms", 0ULL);
    if (j.contains("target_nf_types") && j["target_nf_types"].is_array()) {
      req.target_nf_types =
          j["target_nf_types"].get<std::vector<std::string>>();
    } else if (j.contains("target_nf_type")) {
      const auto target_nf_type = j.value("target_nf_type", "");
      if (!target_nf_type.empty()) {
        req.target_nf_types = {target_nf_type};
      }
    }
    if (j.contains("plmn_list")) {
      req.plmn_list = j["plmn_list"];
    }
    if (j.contains("snssais")) {
      req.snssais = j["snssais"];
    }
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
  nlohmann::json plmn_list = nlohmann::json::array();  // 向后兼容扩展
  nlohmann::json snssais   = nlohmann::json::array();  // 向后兼容扩展

  nlohmann::json to_json() const {
    nlohmann::json j = {
        {"session_id", session_id},
        {"nf_did", nf_did},
        {"challenge_signature", challenge_signature},
        {"timestamp_ms", timestamp_ms}};
    if (plmn_list.is_array() && !plmn_list.empty()) {
      j["plmn_list"] = plmn_list;
    }
    if (snssais.is_array() && !snssais.empty()) {
      j["snssais"] = snssais;
    }
    return j;
  }

  static bcf_auth_verify_request_t from_json(const nlohmann::json& j) {
    bcf_auth_verify_request_t req;
    req.session_id          = j.value("session_id", "");
    req.nf_did              = j.value("nf_did", "");
    req.challenge_signature = j.value("challenge_signature", "");
    req.timestamp_ms        = j.value("timestamp_ms", 0ULL);
    if (j.contains("plmn_list")) {
      req.plmn_list = j["plmn_list"];
    }
    if (j.contains("snssais")) {
      req.snssais = j["snssais"];
    }
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
    // Ignore target_nf_type even if server still returns it
    resp.error_code     = j.value("error_code", "");
    resp.error_message  = j.value("error_message", "");
    resp.timestamp_ms   = j.value("timestamp_ms", 0ULL);
    // authorized := success && auth_token present OR explicit field from server
    if (resp.success && !resp.auth_token.empty()) {
      resp.authorized = true;
    } else {
      resp.authorized = j.value("authorized", false);
    }
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
 * 用于缓存已获取的 self token，避免重复认证
 */
struct bcf_token_cache_entry_t {
  std::string auth_token;          // BCF 签发的 token
  uint64_t expires_at_ms;          // 过期时间
  uint64_t obtained_at_ms;         // 获取时间
  bool authorized = false;         // token 签发即表示已授权

  /**
   * @brief 检查 token 是否仍然有效（含安全余量）
   * @param safety_margin_ms 安全余量（毫秒），默认 30 秒
   */
  bool is_valid(uint64_t safety_margin_ms = 30000) const;
};

}  // namespace oai::ausf::did_auth

#endif  // _AUSF_BCF_INTERFACE_H_
