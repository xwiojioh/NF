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
 * @file did_auth_precheck.hpp
 * @brief DID 双向认证前置校验模块（PreCheck）
 * 
 * 本模块为 DID 双向认证流程提供统一的前置校验能力：
 * - DID 合法性校验（格式、类型匹配、BCF 可解析）
 * - Session ID 一致性与状态机校验
 * - Timestamp 有效期校验（抗重放）
 * - Nonce 有效性校验（随机性、长度、防重放）
 * 
 * 使用位置：
 * - POST /nf_auth/v1/mutual_auth/init（请求入口和响应出口）
 * - POST /nf_auth/v1/mutual_auth/complete（请求入口和响应出口）
 * - 后续带 token 的 SBI 调用
 */

#ifndef _DID_AUTH_PRECHECK_HPP_
#define _DID_AUTH_PRECHECK_HPP_

#include <chrono>
#include <cstdint>
#include <functional>
#include <list>
#include <mutex>
#include <optional>
#include <string>
#include <unordered_map>
#include <unordered_set>

#include <nlohmann/json.hpp>

namespace oai::amf::did_auth {

// =============================================================================
// PreCheck 错误码定义
// =============================================================================

/**
 * @brief PreCheck 错误类型
 */
enum class PreCheckError {
  OK = 0,                           // 校验通过
  
  // DID 校验错误 (4xx)
  INVALID_DID_FORMAT,               // DID 格式不合法
  DID_NOT_FOUND,                    // DID 在 BCF 中未找到
  NF_TYPE_MISMATCH,                 // NF 类型与 DID Document 不匹配
  DID_DOCUMENT_INVALID,             // DID Document 格式无效
  
  // Session 校验错误 (4xx/409)
  INVALID_SESSION_FORMAT,           // Session ID 格式无效
  SESSION_NOT_FOUND,                // Session 不存在
  SESSION_ALREADY_EXISTS,           // Session 已存在（重复 init）
  SESSION_DID_MISMATCH,             // Session 中的 DID 对不匹配
  SESSION_STATE_INVALID,            // Session 状态不允许当前操作
  SESSION_PEER_MISMATCH,            // Session 被其他 peer 复用
  
  // Timestamp 校验错误 (4xx/408)
  TIMESTAMP_MISSING,                // Timestamp 缺失
  TIMESTAMP_INVALID,                // Timestamp 格式无效
  TIMESTAMP_EXPIRED,                // Timestamp 超出有效窗口
  TIMESTAMP_NOT_MONOTONIC,          // Timestamp 非单调递增
  
  // Nonce 校验错误 (4xx)
  NONCE_MISSING,                    // Nonce 缺失
  NONCE_INVALID_FORMAT,             // Nonce 格式无效
  NONCE_INVALID_LENGTH,             // Nonce 长度不合规
  NONCE_REPLAY,                     // Nonce 重放攻击
  NONCE_STALE,                      // Nonce 过期（与 timestamp 不一致）
  
  // 其他
  INTERNAL_ERROR,                   // 内部错误
  BCF_UNAVAILABLE                   // BCF 不可用
};

/**
 * @brief 将 PreCheckError 转换为 HTTP 状态码
 */
inline int precheck_error_to_http_code(PreCheckError error) {
  switch (error) {
    case PreCheckError::OK:
      return 200;
    
    // DID errors -> 400/401/404
    case PreCheckError::INVALID_DID_FORMAT:
    case PreCheckError::DID_DOCUMENT_INVALID:
      return 400;
    case PreCheckError::DID_NOT_FOUND:
      return 404;
    case PreCheckError::NF_TYPE_MISMATCH:
      return 401;
    
    // Session errors -> 400/404/409
    case PreCheckError::INVALID_SESSION_FORMAT:
      return 400;
    case PreCheckError::SESSION_NOT_FOUND:
      return 404;
    case PreCheckError::SESSION_ALREADY_EXISTS:
    case PreCheckError::SESSION_DID_MISMATCH:
    case PreCheckError::SESSION_STATE_INVALID:
    case PreCheckError::SESSION_PEER_MISMATCH:
      return 409;
    
    // Timestamp errors -> 400/408
    case PreCheckError::TIMESTAMP_MISSING:
    case PreCheckError::TIMESTAMP_INVALID:
      return 400;
    case PreCheckError::TIMESTAMP_EXPIRED:
    case PreCheckError::TIMESTAMP_NOT_MONOTONIC:
      return 408;
    
    // Nonce errors -> 400/401
    case PreCheckError::NONCE_MISSING:
    case PreCheckError::NONCE_INVALID_FORMAT:
    case PreCheckError::NONCE_INVALID_LENGTH:
    case PreCheckError::NONCE_STALE:
      return 400;
    case PreCheckError::NONCE_REPLAY:
      return 401;
    
    // Other
    case PreCheckError::BCF_UNAVAILABLE:
      return 503;
    case PreCheckError::INTERNAL_ERROR:
    default:
      return 500;
  }
}

/**
 * @brief 将 PreCheckError 转换为错误码字符串
 */
inline std::string precheck_error_to_string(PreCheckError error) {
  switch (error) {
    case PreCheckError::OK: return "OK";
    case PreCheckError::INVALID_DID_FORMAT: return "INVALID_DID_FORMAT";
    case PreCheckError::DID_NOT_FOUND: return "DID_NOT_FOUND";
    case PreCheckError::NF_TYPE_MISMATCH: return "NF_TYPE_MISMATCH";
    case PreCheckError::DID_DOCUMENT_INVALID: return "DID_DOCUMENT_INVALID";
    case PreCheckError::INVALID_SESSION_FORMAT: return "INVALID_SESSION_FORMAT";
    case PreCheckError::SESSION_NOT_FOUND: return "SESSION_NOT_FOUND";
    case PreCheckError::SESSION_ALREADY_EXISTS: return "SESSION_ALREADY_EXISTS";
    case PreCheckError::SESSION_DID_MISMATCH: return "SESSION_DID_MISMATCH";
    case PreCheckError::SESSION_STATE_INVALID: return "SESSION_STATE_INVALID";
    case PreCheckError::SESSION_PEER_MISMATCH: return "SESSION_PEER_MISMATCH";
    case PreCheckError::TIMESTAMP_MISSING: return "TIMESTAMP_MISSING";
    case PreCheckError::TIMESTAMP_INVALID: return "TIMESTAMP_INVALID";
    case PreCheckError::TIMESTAMP_EXPIRED: return "TIMESTAMP_EXPIRED";
    case PreCheckError::TIMESTAMP_NOT_MONOTONIC: return "TIMESTAMP_NOT_MONOTONIC";
    case PreCheckError::NONCE_MISSING: return "NONCE_MISSING";
    case PreCheckError::NONCE_INVALID_FORMAT: return "NONCE_INVALID_FORMAT";
    case PreCheckError::NONCE_INVALID_LENGTH: return "NONCE_INVALID_LENGTH";
    case PreCheckError::NONCE_REPLAY: return "NONCE_REPLAY";
    case PreCheckError::NONCE_STALE: return "NONCE_STALE";
    case PreCheckError::BCF_UNAVAILABLE: return "BCF_UNAVAILABLE";
    case PreCheckError::INTERNAL_ERROR: return "INTERNAL_ERROR";
    default: return "UNKNOWN_ERROR";
  }
}

// =============================================================================
// PreCheck 结果结构
// =============================================================================

/**
 * @brief PreCheck 结果
 */
struct PreCheckResult {
  bool success;                     // 是否通过校验
  PreCheckError error;              // 错误类型
  std::string error_code;           // 错误码字符串
  std::string detail;               // 详细错误信息
  std::string field;                // 出错字段名
  
  PreCheckResult() : success(true), error(PreCheckError::OK) {}
  
  PreCheckResult(PreCheckError err, const std::string& msg, 
                 const std::string& fld = "")
      : success(err == PreCheckError::OK),
        error(err),
        error_code(precheck_error_to_string(err)),
        detail(msg),
        field(fld) {}
  
  /**
   * @brief 创建成功结果
   */
  static PreCheckResult ok() {
    return PreCheckResult();
  }
  
  /**
   * @brief 创建失败结果
   */
  static PreCheckResult fail(PreCheckError err, const std::string& msg,
                             const std::string& fld = "") {
    return PreCheckResult(err, msg, fld);
  }
  
  /**
   * @brief 转换为 JSON 响应体
   */
  nlohmann::json to_json() const {
    nlohmann::json j = {
        {"success", success},
        {"error", error_code},
        {"detail", detail}
    };
    if (!field.empty()) {
      j["field"] = field;
    }
    return j;
  }
  
  /**
   * @brief 获取 HTTP 状态码
   */
  int http_code() const {
    return precheck_error_to_http_code(error);
  }
};

// =============================================================================
// PreCheck 配置
// =============================================================================

/**
 * @brief PreCheck 配置参数
 */
struct PreCheckConfig {
  // DID 校验配置
  std::string did_method_prefix = "did:oai5gc:";  // DID 方法前缀
  size_t did_min_length = 32;                      // DID 最小长度
  size_t did_max_length = 256;                     // DID 最大长度
  bool verify_did_on_bcf = true;                   // 是否在 BCF 上验证 DID
  
  // Session 校验配置
  size_t session_id_length = 36;                   // UUID 格式 Session ID 长度
  bool allow_non_uuid_session = false;             // 是否允许非 UUID 格式
  
  // Timestamp 校验配置（单位：毫秒）
  uint64_t timestamp_window_ms = 60000;            // 时间窗口（默认 60 秒）
  bool require_monotonic_timestamp = true;         // 是否要求单调递增
  
  // Nonce 校验配置
  size_t nonce_expected_length = 80;               // 期望 Nonce 长度（40字节=80 hex）
  size_t nonce_min_length = 32;                    // 最小 Nonce 长度
  size_t nonce_max_length = 128;                   // 最大 Nonce 长度
  uint64_t nonce_replay_window_ms = 300000;        // Nonce 重放窗口（默认 5 分钟）
  size_t nonce_cache_max_size = 10000;             // Nonce 缓存最大条目数
  
  // 日志标签
  std::string log_tag = "[PreCheck]";
};

// =============================================================================
// Nonce 防重放缓存
// =============================================================================

/**
 * @brief Nonce 防重放缓存（LRU + TTL）
 * 
 * 用于检测 Nonce 重放攻击。
 * - 使用 LRU 策略淘汰旧条目
 * - 使用 TTL 过期机制
 */
class NonceReplayCache {
 public:
  explicit NonceReplayCache(size_t max_size = 10000, 
                           uint64_t ttl_ms = 300000);
  
  /**
   * @brief 检查并记录 Nonce
   * @param nonce Nonce 值
   * @param did 关联的 DID（可选，用于 per-DID 检测）
   * @return true 如果是新 Nonce（未重放），false 如果检测到重放
   */
  bool check_and_record(const std::string& nonce, 
                        const std::string& did = "");
  
  /**
   * @brief 仅检查 Nonce 是否存在（不记录）
   */
  bool exists(const std::string& nonce, const std::string& did = "") const;
  
  /**
   * @brief 清理过期条目
   */
  void cleanup_expired();
  
  /**
   * @brief 清空缓存
   */
  void clear();
  
  /**
   * @brief 重置缓存配置
   * @param max_size 新的最大容量
   * @param ttl_ms 新的 TTL
   */
  void reset(size_t max_size, uint64_t ttl_ms);
  
  /**
   * @brief 获取当前缓存大小
   */
  size_t size() const;
  
 private:
  struct CacheEntry {
    std::string nonce;
    std::string did;
    uint64_t timestamp_ms;
  };
  
  size_t m_max_size;
  uint64_t m_ttl_ms;
  
  mutable std::mutex m_mutex;
  std::list<CacheEntry> m_lru_list;
  // key = nonce + ":" + did (or just nonce if did is empty)
  std::unordered_map<std::string, std::list<CacheEntry>::iterator> m_cache_map;
  
  std::string make_key(const std::string& nonce, const std::string& did) const;
  uint64_t current_time_ms() const;
};

// =============================================================================
// DID Auth PreChecker 核心类
// =============================================================================

/**
 * @brief DID 认证前置校验器
 * 
 * 提供统一的前置校验接口，用于 AMF 和 AUSF。
 */
class DIDAuthPreChecker {
 public:
  /**
   * @brief BCF DID 查询回调
   * @param did DID 标识符
   * @param nf_type 输出参数：NF 类型
   * @param public_key 输出参数：公钥
   * @return true 如果查询成功
   */
  using BcfQueryCallback = std::function<bool(
      const std::string& did, 
      std::string& nf_type, 
      std::string& public_key)>;

  /**
   * @brief Session 查询回调
   * @param session_id 会话 ID
   * @param initiator_did 输出：发起方 DID
   * @param responder_did 输出：响应方 DID
   * @param state 输出：当前状态
   * @param last_timestamp 输出：上次 timestamp
   * @return true 如果 session 存在
   */
  using SessionQueryCallback = std::function<bool(
      const std::string& session_id,
      std::string& initiator_did,
      std::string& responder_did,
      int& state,
      uint64_t& last_timestamp)>;

  explicit DIDAuthPreChecker(const PreCheckConfig& config = PreCheckConfig());
  ~DIDAuthPreChecker() = default;
  
  /**
   * @brief 设置配置
   */
  void set_config(const PreCheckConfig& config);
  
  /**
   * @brief 获取配置
   */
  const PreCheckConfig& get_config() const { return m_config; }
  
  /**
   * @brief 设置 BCF 查询回调
   */
  void set_bcf_query_callback(BcfQueryCallback callback);
  
  /**
   * @brief 设置 Session 查询回调
   */
  void set_session_query_callback(SessionQueryCallback callback);

  // =========================================================================
  // 独立校验方法
  // =========================================================================
  
  /**
   * @brief 校验 DID 格式
   * @param did DID 字符串
   * @param expected_nf_type 期望的 NF 类型（可选）
   * @param verify_on_bcf 是否在 BCF 上验证
   */
  PreCheckResult validate_did(
      const std::string& did,
      const std::string& expected_nf_type = "",
      bool verify_on_bcf = true);
  
  /**
   * @brief 校验 Session ID 格式
   * @param session_id Session ID 字符串
   */
  PreCheckResult validate_session_id_format(const std::string& session_id);
  
  /**
   * @brief 校验 Session 存在性与 DID 匹配
   * @param session_id Session ID
   * @param expected_initiator_did 期望的发起方 DID
   * @param expected_responder_did 期望的响应方 DID
   */
  PreCheckResult validate_session_dids(
      const std::string& session_id,
      const std::string& expected_initiator_did,
      const std::string& expected_responder_did);
  
  /**
   * @brief 校验 Session 状态
   * @param session_id Session ID
   * @param allowed_states 允许的状态列表
   */
  PreCheckResult validate_session_state(
      const std::string& session_id,
      const std::vector<int>& allowed_states);
  
  /**
   * @brief 校验 Timestamp
   * @param timestamp_ms Timestamp 毫秒值
   * @param session_id Session ID（用于单调性检查）
   */
  PreCheckResult validate_timestamp(
      uint64_t timestamp_ms,
      const std::string& session_id = "");
  
  /**
   * @brief 校验 Nonce 格式
   * @param nonce Nonce 字符串（hex 编码）
   */
  PreCheckResult validate_nonce_format(const std::string& nonce);
  
  /**
   * @brief 校验 Nonce 防重放
   * @param nonce Nonce 字符串
   * @param did 关联的 DID（用于 per-DID 检测）
   * @return PreCheckResult
   */
  PreCheckResult validate_nonce_replay(
      const std::string& nonce,
      const std::string& did = "");

  // =========================================================================
  // 复合校验方法（用于完整的 PreCheck 流程）
  // =========================================================================
  
  /**
   * @brief 校验 /mutual_auth/init 请求
   */
  PreCheckResult precheck_auth_init_request(
      const std::string& initiator_did,
      const std::string& initiator_nf_type,
      const std::string& initiator_nonce,
      const std::string& session_id,
      uint64_t timestamp_ms);
  
  /**
   * @brief 校验 /mutual_auth/init 响应
   */
  PreCheckResult precheck_auth_init_response(
      const std::string& responder_did,
      const std::string& responder_nf_type,
      const std::string& responder_nonce,
      const std::string& responder_signature,
      const std::string& session_id,
      uint64_t timestamp_ms);
  
  /**
   * @brief 校验 /mutual_auth/complete 请求
   */
  PreCheckResult precheck_auth_complete_request(
      const std::string& session_id,
      const std::string& initiator_signature,
      uint64_t timestamp_ms,
      const std::string& expected_initiator_did = "",
      const std::string& expected_responder_did = "");
  
  /**
   * @brief 校验 /mutual_auth/complete 响应
   */
  PreCheckResult precheck_auth_complete_response(
      bool success,
      const std::string& auth_token,
      const std::string& initiator_did,
      const std::string& responder_did,
      const std::string& session_id,
      uint64_t timestamp_ms);
  
  /**
   * @brief 清理 Nonce 缓存中的过期条目
   */
  void cleanup_nonce_cache();

 private:
  PreCheckConfig m_config;
  NonceReplayCache m_nonce_cache;
  BcfQueryCallback m_bcf_query_callback;
  SessionQueryCallback m_session_query_callback;
  
  // 用于记录每个 session 的最后 timestamp（单调性检查）
  mutable std::mutex m_session_ts_mutex;
  std::unordered_map<std::string, uint64_t> m_session_last_timestamps;
  
  /**
   * @brief 检查字符串是否为有效的十六进制
   */
  bool is_valid_hex(const std::string& s) const;
  
  /**
   * @brief 检查字符串是否为有效的 UUID
   */
  bool is_valid_uuid(const std::string& s) const;
  
  /**
   * @brief 获取当前时间戳（毫秒）
   */
  uint64_t current_time_ms() const;
  
  /**
   * @brief 输出 PreCheck 日志
   */
  void log_precheck(const std::string& phase, const std::string& field,
                    const PreCheckResult& result) const;
};

// =============================================================================
// 全局单例（可选）
// =============================================================================

/**
 * @brief 获取全局 PreChecker 实例
 */
DIDAuthPreChecker& get_global_prechecker();

}  // namespace oai::amf::did_auth

#endif  // _DID_AUTH_PRECHECK_HPP_
