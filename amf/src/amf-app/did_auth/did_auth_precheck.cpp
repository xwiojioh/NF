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

#include "did_auth_precheck.hpp"

#include <algorithm>
#include <cctype>
#include <chrono>
#include <regex>

#include "logger.hpp"

namespace oai::amf::did_auth {

// =============================================================================
// NonceReplayCache Implementation
// =============================================================================

NonceReplayCache::NonceReplayCache(size_t max_size, uint64_t ttl_ms)
    : m_max_size(max_size), m_ttl_ms(ttl_ms) {}

std::string NonceReplayCache::make_key(const std::string& nonce, 
                                       const std::string& did) const {
  if (did.empty()) {
    return nonce;
  }
  return nonce + ":" + did;
}

uint64_t NonceReplayCache::current_time_ms() const {
  return std::chrono::duration_cast<std::chrono::milliseconds>(
             std::chrono::system_clock::now().time_since_epoch())
      .count();
}

bool NonceReplayCache::check_and_record(const std::string& nonce, 
                                        const std::string& did) {
  std::lock_guard<std::mutex> lock(m_mutex);
  
  std::string key = make_key(nonce, did);
  uint64_t now = current_time_ms();
  
  // 首先检查是否存在且未过期
  auto it = m_cache_map.find(key);
  if (it != m_cache_map.end()) {
    // 检查是否过期
    if (now - it->second->timestamp_ms < m_ttl_ms) {
      // 未过期，检测到重放
      return false;
    }
    // 已过期，删除旧条目
    m_lru_list.erase(it->second);
    m_cache_map.erase(it);
  }
  
  // 清理空间（如果已满）
  while (m_lru_list.size() >= m_max_size) {
    auto oldest = m_lru_list.back();
    std::string old_key = make_key(oldest.nonce, oldest.did);
    m_cache_map.erase(old_key);
    m_lru_list.pop_back();
  }
  
  // 添加新条目到头部
  CacheEntry entry{nonce, did, now};
  m_lru_list.push_front(entry);
  m_cache_map[key] = m_lru_list.begin();
  
  return true;  // 新 Nonce，未重放
}

bool NonceReplayCache::exists(const std::string& nonce, 
                              const std::string& did) const {
  std::lock_guard<std::mutex> lock(m_mutex);
  
  std::string key = make_key(nonce, did);
  auto it = m_cache_map.find(key);
  
  if (it == m_cache_map.end()) {
    return false;
  }
  
  // 检查是否过期
  uint64_t now = current_time_ms();
  return (now - it->second->timestamp_ms) < m_ttl_ms;
}

void NonceReplayCache::cleanup_expired() {
  std::lock_guard<std::mutex> lock(m_mutex);
  
  uint64_t now = current_time_ms();
  
  // 从尾部开始清理（最旧的条目）
  while (!m_lru_list.empty()) {
    auto& oldest = m_lru_list.back();
    if (now - oldest.timestamp_ms >= m_ttl_ms) {
      std::string key = make_key(oldest.nonce, oldest.did);
      m_cache_map.erase(key);
      m_lru_list.pop_back();
    } else {
      break;  // 后面的条目更新，不需要继续
    }
  }
}

void NonceReplayCache::clear() {
  std::lock_guard<std::mutex> lock(m_mutex);
  m_lru_list.clear();
  m_cache_map.clear();
}

void NonceReplayCache::reset(size_t max_size, uint64_t ttl_ms) {
  std::lock_guard<std::mutex> lock(m_mutex);
  m_max_size = max_size;
  m_ttl_ms = ttl_ms;
  m_lru_list.clear();
  m_cache_map.clear();
}

size_t NonceReplayCache::size() const {
  std::lock_guard<std::mutex> lock(m_mutex);
  return m_lru_list.size();
}

// =============================================================================
// DIDAuthPreChecker Implementation
// =============================================================================

DIDAuthPreChecker::DIDAuthPreChecker(const PreCheckConfig& config)
    : m_config(config),
      m_nonce_cache(config.nonce_cache_max_size, config.nonce_replay_window_ms) {
}

void DIDAuthPreChecker::set_config(const PreCheckConfig& config) {
  m_config = config;
  // 重置 nonce 缓存配置
  m_nonce_cache.reset(config.nonce_cache_max_size, config.nonce_replay_window_ms);
}

void DIDAuthPreChecker::set_bcf_query_callback(BcfQueryCallback callback) {
  m_bcf_query_callback = callback;
}

void DIDAuthPreChecker::set_session_query_callback(SessionQueryCallback callback) {
  m_session_query_callback = callback;
}

bool DIDAuthPreChecker::is_valid_hex(const std::string& s) const {
  if (s.empty()) return false;
  return std::all_of(s.begin(), s.end(), [](char c) {
    return std::isxdigit(static_cast<unsigned char>(c));
  });
}

bool DIDAuthPreChecker::is_valid_uuid(const std::string& s) const {
  // UUID format: xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx (36 chars)
  static const std::regex uuid_regex(
      "^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-"
      "[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$");
  return std::regex_match(s, uuid_regex);
}

uint64_t DIDAuthPreChecker::current_time_ms() const {
  return std::chrono::duration_cast<std::chrono::milliseconds>(
             std::chrono::system_clock::now().time_since_epoch())
      .count();
}

void DIDAuthPreChecker::log_precheck(const std::string& phase, 
                                     const std::string& field,
                                     const PreCheckResult& result) const {
  if (result.success) {
    Logger::amf_app().debug(
        "%s %s: field=%s PASSED", 
        m_config.log_tag.c_str(), phase.c_str(), field.c_str());
  } else {
    Logger::amf_app().info(
        "%s %s: field=%s FAILED error=%s detail=%s",
        m_config.log_tag.c_str(), phase.c_str(), field.c_str(),
        result.error_code.c_str(), result.detail.c_str());
  }
}

// =============================================================================
// 独立校验方法
// =============================================================================

PreCheckResult DIDAuthPreChecker::validate_did(
    const std::string& did,
    const std::string& expected_nf_type,
    bool verify_on_bcf) {
  
  // 1. 检查是否为空
  if (did.empty()) {
    auto result = PreCheckResult::fail(
        PreCheckError::INVALID_DID_FORMAT,
        "DID is empty",
        "did");
    log_precheck("DID_VALIDATE", "did", result);
    return result;
  }
  
  // 2. 检查前缀
  if (did.substr(0, m_config.did_method_prefix.length()) != 
      m_config.did_method_prefix) {
    auto result = PreCheckResult::fail(
        PreCheckError::INVALID_DID_FORMAT,
        "DID must start with '" + m_config.did_method_prefix + 
        "', got: " + did.substr(0, 20) + "...",
        "did");
    log_precheck("DID_VALIDATE", "did", result);
    return result;
  }
  
  // 3. 检查长度
  if (did.length() < m_config.did_min_length) {
    auto result = PreCheckResult::fail(
        PreCheckError::INVALID_DID_FORMAT,
        "DID too short: " + std::to_string(did.length()) + 
        " < " + std::to_string(m_config.did_min_length),
        "did");
    log_precheck("DID_VALIDATE", "did", result);
    return result;
  }
  
  if (did.length() > m_config.did_max_length) {
    auto result = PreCheckResult::fail(
        PreCheckError::INVALID_DID_FORMAT,
        "DID too long: " + std::to_string(did.length()) + 
        " > " + std::to_string(m_config.did_max_length),
        "did");
    log_precheck("DID_VALIDATE", "did", result);
    return result;
  }
  
  // 4. 检查字符集（prefix 后应为 hex + ':'）
  std::string did_content = did.substr(m_config.did_method_prefix.length());
  for (char c : did_content) {
    if (!std::isxdigit(static_cast<unsigned char>(c)) && c != ':') {
      auto result = PreCheckResult::fail(
          PreCheckError::INVALID_DID_FORMAT,
          "DID contains invalid character: '" + std::string(1, c) + "'",
          "did");
      log_precheck("DID_VALIDATE", "did", result);
      return result;
    }
  }
  
  // 5. 可选：在 BCF 上验证
  if (verify_on_bcf && m_config.verify_did_on_bcf && m_bcf_query_callback) {
    std::string nf_type, public_key;
    if (!m_bcf_query_callback(did, nf_type, public_key)) {
      auto result = PreCheckResult::fail(
          PreCheckError::DID_NOT_FOUND,
          "DID not found in BCF: " + did.substr(0, 40) + "...",
          "did");
      log_precheck("DID_VALIDATE", "did", result);
      return result;
    }
    
    // 6. 检查 NF 类型匹配
    if (!expected_nf_type.empty() && nf_type != expected_nf_type) {
      auto result = PreCheckResult::fail(
          PreCheckError::NF_TYPE_MISMATCH,
          "NF type mismatch: expected=" + expected_nf_type + 
          ", got=" + nf_type,
          "did");
      log_precheck("DID_VALIDATE", "did", result);
      return result;
    }
  }
  
  Logger::amf_app().debug(
      "%s DID_VALIDATE: did=%s...%s PASSED",
      m_config.log_tag.c_str(),
      did.substr(0, 24).c_str(),
      did.length() > 24 ? "..." : "");
  
  return PreCheckResult::ok();
}

PreCheckResult DIDAuthPreChecker::validate_session_id_format(
    const std::string& session_id) {
  
  if (session_id.empty()) {
    auto result = PreCheckResult::fail(
        PreCheckError::INVALID_SESSION_FORMAT,
        "Session ID is empty",
        "session_id");
    log_precheck("SESSION_VALIDATE", "session_id", result);
    return result;
  }
  
  // 检查 UUID 格式
  if (!m_config.allow_non_uuid_session && !is_valid_uuid(session_id)) {
    auto result = PreCheckResult::fail(
        PreCheckError::INVALID_SESSION_FORMAT,
        "Session ID must be UUID format: " + session_id,
        "session_id");
    log_precheck("SESSION_VALIDATE", "session_id", result);
    return result;
  }
  
  // 长度检查（如果允许非 UUID）
  if (m_config.allow_non_uuid_session) {
    if (session_id.length() < 16 || session_id.length() > 64) {
      auto result = PreCheckResult::fail(
          PreCheckError::INVALID_SESSION_FORMAT,
          "Session ID length invalid: " + std::to_string(session_id.length()),
          "session_id");
      log_precheck("SESSION_VALIDATE", "session_id", result);
      return result;
    }
  }
  
  Logger::amf_app().debug(
      "%s SESSION_VALIDATE: session_id=%s PASSED",
      m_config.log_tag.c_str(), session_id.c_str());
  
  return PreCheckResult::ok();
}

PreCheckResult DIDAuthPreChecker::validate_session_dids(
    const std::string& session_id,
    const std::string& expected_initiator_did,
    const std::string& expected_responder_did) {
  
  if (!m_session_query_callback) {
    // 没有回调，跳过此检查
    return PreCheckResult::ok();
  }
  
  std::string stored_initiator_did, stored_responder_did;
  int state;
  uint64_t last_timestamp;
  
  if (!m_session_query_callback(session_id, stored_initiator_did, 
                                stored_responder_did, state, last_timestamp)) {
    auto result = PreCheckResult::fail(
        PreCheckError::SESSION_NOT_FOUND,
        "Session not found: " + session_id,
        "session_id");
    log_precheck("SESSION_DID_CHECK", "session_id", result);
    return result;
  }
  
  // 检查 DID 匹配
  if (!expected_initiator_did.empty() && 
      stored_initiator_did != expected_initiator_did) {
    auto result = PreCheckResult::fail(
        PreCheckError::SESSION_DID_MISMATCH,
        "Initiator DID mismatch: stored=" + stored_initiator_did.substr(0, 30) + 
        "..., provided=" + expected_initiator_did.substr(0, 30) + "...",
        "initiator_did");
    log_precheck("SESSION_DID_CHECK", "initiator_did", result);
    return result;
  }
  
  if (!expected_responder_did.empty() && 
      !stored_responder_did.empty() &&  // responder_did 在 init 时可能还没设置
      stored_responder_did != expected_responder_did) {
    auto result = PreCheckResult::fail(
        PreCheckError::SESSION_DID_MISMATCH,
        "Responder DID mismatch: stored=" + stored_responder_did.substr(0, 30) + 
        "..., provided=" + expected_responder_did.substr(0, 30) + "...",
        "responder_did");
    log_precheck("SESSION_DID_CHECK", "responder_did", result);
    return result;
  }
  
  Logger::amf_app().debug(
      "%s SESSION_DID_CHECK: session=%s PASSED",
      m_config.log_tag.c_str(), session_id.c_str());
  
  return PreCheckResult::ok();
}

PreCheckResult DIDAuthPreChecker::validate_session_state(
    const std::string& session_id,
    const std::vector<int>& allowed_states) {
  
  if (!m_session_query_callback) {
    return PreCheckResult::ok();
  }
  
  std::string initiator_did, responder_did;
  int state;
  uint64_t last_timestamp;
  
  if (!m_session_query_callback(session_id, initiator_did, responder_did, 
                                state, last_timestamp)) {
    auto result = PreCheckResult::fail(
        PreCheckError::SESSION_NOT_FOUND,
        "Session not found: " + session_id,
        "session_id");
    log_precheck("SESSION_STATE_CHECK", "session_id", result);
    return result;
  }
  
  bool state_valid = std::find(allowed_states.begin(), allowed_states.end(), 
                               state) != allowed_states.end();
  if (!state_valid) {
    auto result = PreCheckResult::fail(
        PreCheckError::SESSION_STATE_INVALID,
        "Session state=" + std::to_string(state) + " not allowed for this operation",
        "session_id");
    log_precheck("SESSION_STATE_CHECK", "session_id", result);
    return result;
  }
  
  Logger::amf_app().debug(
      "%s SESSION_STATE_CHECK: session=%s state=%d PASSED",
      m_config.log_tag.c_str(), session_id.c_str(), state);
  
  return PreCheckResult::ok();
}

PreCheckResult DIDAuthPreChecker::validate_timestamp(
    uint64_t timestamp_ms,
    const std::string& session_id) {
  
  // 1. 检查是否存在
  if (timestamp_ms == 0) {
    auto result = PreCheckResult::fail(
        PreCheckError::TIMESTAMP_MISSING,
        "Timestamp is missing or zero",
        "timestamp_ms");
    log_precheck("TIMESTAMP_VALIDATE", "timestamp_ms", result);
    return result;
  }
  
  // 2. 检查有效窗口
  uint64_t now = current_time_ms();
  int64_t skew = static_cast<int64_t>(now) - static_cast<int64_t>(timestamp_ms);
  uint64_t abs_skew = skew >= 0 ? skew : -skew;
  
  if (abs_skew > m_config.timestamp_window_ms) {
    auto result = PreCheckResult::fail(
        PreCheckError::TIMESTAMP_EXPIRED,
        "Timestamp out of window: skew=" + std::to_string(skew) + 
        "ms, window=" + std::to_string(m_config.timestamp_window_ms) + "ms",
        "timestamp_ms");
    log_precheck("TIMESTAMP_VALIDATE", "timestamp_ms", result);
    return result;
  }
  
  // 3. 单调递增检查（如果启用且有 session_id）
  if (m_config.require_monotonic_timestamp && !session_id.empty()) {
    std::lock_guard<std::mutex> lock(m_session_ts_mutex);
    
    auto it = m_session_last_timestamps.find(session_id);
    if (it != m_session_last_timestamps.end()) {
      if (timestamp_ms <= it->second) {
        auto result = PreCheckResult::fail(
            PreCheckError::TIMESTAMP_NOT_MONOTONIC,
            "Timestamp not monotonically increasing: current=" + 
            std::to_string(timestamp_ms) + ", last=" + std::to_string(it->second),
            "timestamp_ms");
        log_precheck("TIMESTAMP_VALIDATE", "timestamp_ms", result);
        return result;
      }
    }
    // 更新最后时间戳
    m_session_last_timestamps[session_id] = timestamp_ms;
  }
  
  Logger::amf_app().debug(
      "%s TIMESTAMP_VALIDATE: ts=%llu skew=%lldms PASSED",
      m_config.log_tag.c_str(), 
      static_cast<unsigned long long>(timestamp_ms),
      static_cast<long long>(skew));
  
  return PreCheckResult::ok();
}

PreCheckResult DIDAuthPreChecker::validate_nonce_format(const std::string& nonce) {
  // 1. 检查是否为空
  if (nonce.empty()) {
    auto result = PreCheckResult::fail(
        PreCheckError::NONCE_MISSING,
        "Nonce is empty",
        "nonce");
    log_precheck("NONCE_VALIDATE", "nonce", result);
    return result;
  }
  
  // 2. 检查是否为有效 hex
  if (!is_valid_hex(nonce)) {
    auto result = PreCheckResult::fail(
        PreCheckError::NONCE_INVALID_FORMAT,
        "Nonce is not valid hex: " + nonce.substr(0, 20) + "...",
        "nonce");
    log_precheck("NONCE_VALIDATE", "nonce", result);
    return result;
  }
  
  // 3. 检查长度
  if (nonce.length() < m_config.nonce_min_length) {
    auto result = PreCheckResult::fail(
        PreCheckError::NONCE_INVALID_LENGTH,
        "Nonce too short: " + std::to_string(nonce.length()) + 
        " < " + std::to_string(m_config.nonce_min_length),
        "nonce");
    log_precheck("NONCE_VALIDATE", "nonce", result);
    return result;
  }
  
  if (nonce.length() > m_config.nonce_max_length) {
    auto result = PreCheckResult::fail(
        PreCheckError::NONCE_INVALID_LENGTH,
        "Nonce too long: " + std::to_string(nonce.length()) + 
        " > " + std::to_string(m_config.nonce_max_length),
        "nonce");
    log_precheck("NONCE_VALIDATE", "nonce", result);
    return result;
  }
  
  Logger::amf_app().debug(
      "%s NONCE_FORMAT_VALIDATE: nonce=%s... len=%zu PASSED",
      m_config.log_tag.c_str(), 
      nonce.substr(0, 16).c_str(),
      nonce.length());
  
  return PreCheckResult::ok();
}

PreCheckResult DIDAuthPreChecker::validate_nonce_replay(
    const std::string& nonce,
    const std::string& did) {
  
  if (!m_nonce_cache.check_and_record(nonce, did)) {
    auto result = PreCheckResult::fail(
        PreCheckError::NONCE_REPLAY,
        "Nonce replay detected: " + nonce.substr(0, 20) + "... (did=" + 
        (did.empty() ? "global" : did.substr(0, 20) + "...") + ")",
        "nonce");
    log_precheck("NONCE_REPLAY_CHECK", "nonce", result);
    return result;
  }
  
  Logger::amf_app().debug(
      "%s NONCE_REPLAY_CHECK: nonce=%s... PASSED (new)",
      m_config.log_tag.c_str(), nonce.substr(0, 16).c_str());
  
  return PreCheckResult::ok();
}

// =============================================================================
// 复合校验方法
// =============================================================================

PreCheckResult DIDAuthPreChecker::precheck_auth_init_request(
    const std::string& initiator_did,
    const std::string& initiator_nf_type,
    const std::string& initiator_nonce,
    const std::string& session_id,
    uint64_t timestamp_ms) {
  
  Logger::amf_app().info(
      "%s === PreCheck: /mutual_auth/init REQUEST ===",
      m_config.log_tag.c_str());
  Logger::amf_app().info(
      "%s initiator_did=%s..., nf_type=%s, session=%s, ts=%llu",
      m_config.log_tag.c_str(),
      initiator_did.substr(0, 30).c_str(),
      initiator_nf_type.c_str(),
      session_id.c_str(),
      static_cast<unsigned long long>(timestamp_ms));
  
  PreCheckResult result;
  
  // 1. DID 合法性校验
  result = validate_did(initiator_did, initiator_nf_type, m_config.verify_did_on_bcf);
  if (!result.success) return result;
  
  // 2. Session ID 格式校验
  result = validate_session_id_format(session_id);
  if (!result.success) return result;
  
  // 3. Timestamp 校验
  result = validate_timestamp(timestamp_ms, session_id);
  if (!result.success) return result;
  
  // 4. Nonce 格式校验
  result = validate_nonce_format(initiator_nonce);
  if (!result.success) return result;
  
  // 5. Nonce 防重放
  result = validate_nonce_replay(initiator_nonce, initiator_did);
  if (!result.success) return result;
  
  Logger::amf_app().info(
      "%s === PreCheck: /mutual_auth/init REQUEST PASSED ===",
      m_config.log_tag.c_str());
  
  return PreCheckResult::ok();
}

PreCheckResult DIDAuthPreChecker::precheck_auth_init_response(
    const std::string& responder_did,
    const std::string& responder_nf_type,
    const std::string& responder_nonce,
    const std::string& responder_signature,
    const std::string& session_id,
    uint64_t timestamp_ms) {
  
  Logger::amf_app().info(
      "%s === PreCheck: /mutual_auth/init RESPONSE ===",
      m_config.log_tag.c_str());
  Logger::amf_app().info(
      "%s responder_did=%s..., nf_type=%s, session=%s, ts=%llu",
      m_config.log_tag.c_str(),
      responder_did.substr(0, 30).c_str(),
      responder_nf_type.c_str(),
      session_id.c_str(),
      static_cast<unsigned long long>(timestamp_ms));
  
  PreCheckResult result;
  
  // 1. DID 合法性校验
  result = validate_did(responder_did, responder_nf_type, m_config.verify_did_on_bcf);
  if (!result.success) return result;
  
  // 2. Session ID 格式校验
  result = validate_session_id_format(session_id);
  if (!result.success) return result;
  
  // 3. Timestamp 校验
  result = validate_timestamp(timestamp_ms, session_id);
  if (!result.success) return result;
  
  // 4. Nonce 格式校验
  result = validate_nonce_format(responder_nonce);
  if (!result.success) return result;
  
  // 5. Signature 存在性（格式由后续签名验证处理）
  if (responder_signature.empty()) {
    result = PreCheckResult::fail(
        PreCheckError::NONCE_MISSING,  // 复用错误码
        "Responder signature is missing",
        "responder_signature");
    log_precheck("SIGNATURE_CHECK", "responder_signature", result);
    return result;
  }
  
  // 6. Nonce 防重放
  result = validate_nonce_replay(responder_nonce, responder_did);
  if (!result.success) return result;
  
  Logger::amf_app().info(
      "%s === PreCheck: /mutual_auth/init RESPONSE PASSED ===",
      m_config.log_tag.c_str());
  
  return PreCheckResult::ok();
}

PreCheckResult DIDAuthPreChecker::precheck_auth_complete_request(
    const std::string& session_id,
    const std::string& initiator_signature,
    uint64_t timestamp_ms,
    const std::string& expected_initiator_did,
    const std::string& expected_responder_did) {
  
  Logger::amf_app().info(
      "%s === PreCheck: /mutual_auth/complete REQUEST ===",
      m_config.log_tag.c_str());
  Logger::amf_app().info(
      "%s session=%s, ts=%llu",
      m_config.log_tag.c_str(),
      session_id.c_str(),
      static_cast<unsigned long long>(timestamp_ms));
  
  PreCheckResult result;
  
  // 1. Session ID 格式校验
  result = validate_session_id_format(session_id);
  if (!result.success) return result;
  
  // 2. Session DID 一致性校验（如果提供了期望值）
  if (!expected_initiator_did.empty() || !expected_responder_did.empty()) {
    result = validate_session_dids(session_id, expected_initiator_did, 
                                   expected_responder_did);
    if (!result.success) return result;
  }
  
  // 3. Timestamp 校验
  result = validate_timestamp(timestamp_ms, session_id);
  if (!result.success) return result;
  
  // 4. Signature 存在性
  if (initiator_signature.empty()) {
    result = PreCheckResult::fail(
        PreCheckError::NONCE_MISSING,
        "Initiator signature is missing",
        "initiator_signature");
    log_precheck("SIGNATURE_CHECK", "initiator_signature", result);
    return result;
  }
  
  Logger::amf_app().info(
      "%s === PreCheck: /mutual_auth/complete REQUEST PASSED ===",
      m_config.log_tag.c_str());
  
  return PreCheckResult::ok();
}

PreCheckResult DIDAuthPreChecker::precheck_auth_complete_response(
    bool success,
    const std::string& auth_token,
    const std::string& initiator_did,
    const std::string& responder_did,
    const std::string& session_id,
    uint64_t timestamp_ms) {
  
  Logger::amf_app().info(
      "%s === PreCheck: /mutual_auth/complete RESPONSE ===",
      m_config.log_tag.c_str());
  Logger::amf_app().info(
      "%s success=%s, session=%s, ts=%llu",
      m_config.log_tag.c_str(),
      success ? "true" : "false",
      session_id.c_str(),
      static_cast<unsigned long long>(timestamp_ms));
  
  PreCheckResult result;
  
  // 1. Session ID 格式校验
  result = validate_session_id_format(session_id);
  if (!result.success) return result;
  
  // 2. Timestamp 校验
  result = validate_timestamp(timestamp_ms, session_id);
  if (!result.success) return result;
  
  // 3. 如果成功，验证 token 存在
  if (success && auth_token.empty()) {
    result = PreCheckResult::fail(
        PreCheckError::INTERNAL_ERROR,
        "Auth succeeded but token is missing",
        "auth_token");
    log_precheck("TOKEN_CHECK", "auth_token", result);
    return result;
  }
  
  // 4. DID 校验（基本格式）
  if (!initiator_did.empty()) {
    result = validate_did(initiator_did, "", false);  // 不查 BCF
    if (!result.success) return result;
  }
  
  if (!responder_did.empty()) {
    result = validate_did(responder_did, "", false);  // 不查 BCF
    if (!result.success) return result;
  }
  
  Logger::amf_app().info(
      "%s === PreCheck: /mutual_auth/complete RESPONSE PASSED ===",
      m_config.log_tag.c_str());
  
  return PreCheckResult::ok();
}

void DIDAuthPreChecker::cleanup_nonce_cache() {
  m_nonce_cache.cleanup_expired();
}

// =============================================================================
// 全局单例
// =============================================================================

DIDAuthPreChecker& get_global_prechecker() {
  static DIDAuthPreChecker instance;
  return instance;
}

}  // namespace oai::amf::did_auth
