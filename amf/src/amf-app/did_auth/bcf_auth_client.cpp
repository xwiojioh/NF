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

#include "bcf_auth_client.hpp"

#include <algorithm>
#include <cctype>
#include <chrono>
#include <openssl/evp.h>
#include <sstream>

#include "did_crypto.hpp"
#include "logger.hpp"
#include "signature_utils.hpp"

namespace oai::amf::did_auth {

namespace {

std::string normalize_notification_uri_for_bcf_subscription(
    const std::string& uri) {
  if (uri.empty()) {
    return uri;
  }

  if (uri.rfind("http://", 0) == 0 || uri.rfind("https://", 0) == 0) {
    return uri;
  }

  return std::string("http://") + uri;
}

std::string normalize_notification_transport_for_bcf_subscription(
    const std::string& transport) {
  std::string normalized = transport;
  std::transform(
      normalized.begin(), normalized.end(), normalized.begin(),
      [](unsigned char c) { return std::tolower(c); });

  if (normalized.empty() || normalized == "auto") {
    return "auto";
  }
  if (normalized == "h2c" || normalized == "h2c-prior" ||
      normalized == "h2-prior") {
    return "h2c-prior";
  }
  if (normalized == "http1" || normalized == "http1-json" ||
      normalized == "http/1.1" || normalized == "http11") {
    return "http1-json";
  }

  return normalized;
}

std::string base64url_decode_to_string(const std::string& input) {
  if (input.empty()) {
    return "";
  }

  std::string padded = input;
  std::replace(padded.begin(), padded.end(), '-', '+');
  std::replace(padded.begin(), padded.end(), '_', '/');
  while (padded.size() % 4 != 0) {
    padded.push_back('=');
  }

  std::string decoded((padded.size() * 3) / 4 + 4, '\0');
  const int decoded_len = EVP_DecodeBlock(
      reinterpret_cast<unsigned char*>(decoded.data()),
      reinterpret_cast<const unsigned char*>(padded.data()), padded.size());
  if (decoded_len < 0) {
    return "";
  }

  size_t padding_count = 0;
  if (!padded.empty() && padded.back() == '=') padding_count++;
  if (padded.size() > 1 && padded[padded.size() - 2] == '=') padding_count++;
  decoded.resize(decoded_len - padding_count);
  return decoded;
}

std::vector<std::string> json_to_string_vector(const nlohmann::json& value) {
  std::vector<std::string> items;
  if (value.is_array()) {
    for (const auto& entry : value) {
      if (entry.is_string()) {
        items.push_back(entry.get<std::string>());
      }
    }
  } else if (value.is_string()) {
    items.push_back(value.get<std::string>());
  }
  return items;
}

std::string join_strings(const std::vector<std::string>& values) {
  std::ostringstream oss;
  for (size_t i = 0; i < values.size(); ++i) {
    if (i > 0) {
      oss << ",";
    }
    oss << values[i];
  }
  return oss.str();
}

void log_bcf_token_claims(const std::string& token) {
  const auto first_dot = token.find('.');
  if (first_dot == std::string::npos) {
    Logger::amf_app().warn("[AMF][BCF] Token is not in JWT format");
    return;
  }
  const auto second_dot = token.find('.', first_dot + 1);
  if (second_dot == std::string::npos) {
    Logger::amf_app().warn("[AMF][BCF] Token is not in JWT format");
    return;
  }

  try {
    const auto header_json =
        nlohmann::json::parse(base64url_decode_to_string(token.substr(0, first_dot)));
    const auto payload_json = nlohmann::json::parse(
        base64url_decode_to_string(
            token.substr(first_dot + 1, second_dot - first_dot - 1)));

    const std::string alg = header_json.value("alg", "");
    if (alg == "ES256K") {
      Logger::amf_app().info("[AMF][BCF] Received ES256K token");
    } else {
      Logger::amf_app().info(
          "[AMF][BCF] Received token with alg=%s", alg.c_str());
    }

    Logger::amf_app().info(
        "[AMF][BCF] Token claims: iss=%s sub=%s aud=%s scope=%s exp=%lld",
        payload_json.value("iss", "").c_str(),
        payload_json.value("sub", "").c_str(),
        join_strings(payload_json.contains("aud")
                         ? json_to_string_vector(payload_json.at("aud"))
                         : std::vector<std::string>{})
            .c_str(),
        join_strings(payload_json.contains("scope")
                         ? json_to_string_vector(payload_json.at("scope"))
                         : std::vector<std::string>{})
            .c_str(),
        static_cast<long long>(payload_json.value("exp", 0LL)));
  } catch (const std::exception& e) {
    Logger::amf_app().warn(
        "[AMF][BCF] Failed to parse token claims: %s", e.what());
  }
}

}  // namespace

//------------------------------------------------------------------------------
// 构造函数
//------------------------------------------------------------------------------

BcfAuthClient::BcfAuthClient()
    : m_bcf_api_version("v1"),
      m_crypto(nullptr),
      m_http_version(2),
      m_timeout_ms(5000),
      m_notification_transport("auto") {}

//------------------------------------------------------------------------------
// 配置方法
//------------------------------------------------------------------------------

void BcfAuthClient::set_bcf_uri(const std::string& uri) {
  m_bcf_uri = uri;
  // 移除尾部斜杠
  while (!m_bcf_uri.empty() && m_bcf_uri.back() == '/') {
    m_bcf_uri.pop_back();
  }
}

void BcfAuthClient::set_bcf_api_version(const std::string& version) {
  m_bcf_api_version = version;
}

void BcfAuthClient::set_local_nf_info(
    const std::string& did, const std::string& nf_type,
    const std::string& nf_instance_id) {
  m_local_did            = did;
  m_local_nf_type        = nf_type;
  m_local_nf_instance_id = nf_instance_id;
}

void BcfAuthClient::set_crypto(did_crypto* crypto) {
  m_crypto = crypto;
}

void BcfAuthClient::set_http_callback(http_send_callback_t callback) {
  m_http_callback = std::move(callback);
}

void BcfAuthClient::set_http_version(int version) {
  m_http_version = version;
}

void BcfAuthClient::set_timeout(uint32_t timeout_ms) {
  m_timeout_ms = timeout_ms;
}

void BcfAuthClient::set_notification_transport(const std::string& transport) {
  std::string normalized_transport =
      normalize_notification_transport_for_bcf_subscription(transport);
  if (normalized_transport.empty()) {
    normalized_transport = "auto";
  }

  std::lock_guard<std::mutex> lock(m_cache_mutex);
  m_notification_transport = normalized_transport;
  Logger::amf_app().info(
      "[BCF Auth] Set notification transport preference to %s",
      m_notification_transport.c_str());
}

//------------------------------------------------------------------------------
// 核心认证方法
//------------------------------------------------------------------------------

BcfAuthResult BcfAuthClient::authenticate(
    std::string& auth_token) {
  Logger::amf_app().info(
      "[BCF Auth] ========== BEGIN BCF SELF-AUTHENTICATION ==========");
  Logger::amf_app().info(
      "[BCF Auth] local_did=%s, local_nf_type=%s",
      m_local_did.substr(0, 32).c_str(), m_local_nf_type.c_str());

  // 检查前置条件
  if (m_bcf_uri.empty()) {
    Logger::amf_app().error("[BCF Auth] BCF URI not configured");
    return BcfAuthResult::FAILURE_BCF_UNREACHABLE;
  }
  if (m_local_did.empty()) {
    Logger::amf_app().error("[BCF Auth] Local DID not configured");
    return BcfAuthResult::FAILURE_INTERNAL_ERROR;
  }
  if (!m_crypto) {
    Logger::amf_app().error("[BCF Auth] Crypto module not set");
    return BcfAuthResult::FAILURE_INTERNAL_ERROR;
  }

  // Step 1: 发送认证初始化请求，获取 challenge
  Logger::amf_app().info("[BCF Auth] Step 1: Sending auth init to BCF...");
  bcf_auth_challenge_response_t challenge_resp;
  BcfAuthResult init_result = send_auth_init(challenge_resp);

  if (init_result != BcfAuthResult::SUCCESS) {
    Logger::amf_app().error(
        "[BCF Auth] Step 1 FAILED: %s",
        bcf_auth_result_to_string(init_result).c_str());
    return init_result;
  }

  Logger::amf_app().info(
      "[BCF Auth] Step 1 SUCCESS: session_id=%s, challenge_len=%zu",
      challenge_resp.session_id.c_str(), challenge_resp.challenge.size());

  // Step 2: 签名 challenge 并提交验证
  Logger::amf_app().info("[BCF Auth] Step 2: Signing challenge and sending verify...");
  bcf_auth_result_response_t auth_result;
  BcfAuthResult verify_result = send_auth_verify(
      challenge_resp.session_id, challenge_resp.challenge, auth_result);

  if (verify_result != BcfAuthResult::SUCCESS) {
    Logger::amf_app().error(
        "[BCF Auth] Step 2 FAILED: %s",
        bcf_auth_result_to_string(verify_result).c_str());
    return verify_result;
  }

  // Step 3: 验证 BCF 响应并缓存 self token
  if (!auth_result.success) {
    Logger::amf_app().error(
        "[BCF Auth] BCF rejected authentication: error_code=%s, message=%s",
        auth_result.error_code.c_str(), auth_result.error_message.c_str());
    return BcfAuthResult::FAILURE_SIGNATURE_INVALID;
  }

  // 校验 token 格式
  if (auth_result.auth_token.empty()) {
    Logger::amf_app().error("[BCF Auth] BCF returned success but no auth_token");
    return BcfAuthResult::FAILURE_INTERNAL_ERROR;
  }

  // 校验 expires_in
  if (auth_result.expires_in <= 0) {
    Logger::amf_app().warn(
        "[BCF Auth] Invalid expires_in=%d, using default 3600",
        auth_result.expires_in);
    auth_result.expires_in = 3600;
  }

  // 计算 expires_at_ms（如果 BCF 没有返回的话）
  if (auth_result.expires_at_ms == 0) {
    auth_result.expires_at_ms =
        current_time_ms() + (static_cast<uint64_t>(auth_result.expires_in) * 1000);
  }

  // 缓存 self token
  cache_token(auth_result);
  auth_token = auth_result.auth_token;

  Logger::amf_app().info(
      "[BCF Auth] ========== BCF SELF-AUTHENTICATION SUCCESS ==========");
  // Token returned => authorization is considered successful by policy
  Logger::amf_app().info(
    "[BCF Auth] AUTHORIZED: BCF issued token and authorization is complete. token=%s..., expires_in=%d",
    auth_result.auth_token.substr(0, 24).c_str(), auth_result.expires_in);

  return BcfAuthResult::SUCCESS;
}

//------------------------------------------------------------------------------
BcfAuthResult BcfAuthClient::ensure_authenticated(
    std::string& auth_token) {
  // 先检查缓存
  std::string cached = get_cached_token();
  if (!cached.empty()) {
    Logger::amf_app().info(
        "[BCF Auth] Using cached access token (token=%s...) - AUTHORIZED",
        cached.substr(0, 24).c_str());
    auth_token = cached;
    return BcfAuthResult::SUCCESS;
  }

  Logger::amf_app().info(
      "[BCF Auth] No valid cached access token, initiating new auth");

  // 无有效缓存，发起新认证
  return authenticate(auth_token);
}

//------------------------------------------------------------------------------
// 分步认证方法
//------------------------------------------------------------------------------

BcfAuthResult BcfAuthClient::send_auth_init(
    bcf_auth_challenge_response_t& challenge_resp) {
  // 构建请求（self-auth: 只发送自身 NF 信息，不含 target）
  bcf_auth_init_request_t request;
  request.nf_did         = m_local_did;
  request.nf_type        = m_local_nf_type;
  request.nf_instance_id = m_local_nf_instance_id;
  request.target_nf_types = {"AUSF", "UDM", "SMF"};
  request.timestamp_ms   = current_time_ms();

  // 构建 URI
  std::string path = "/nbcf_auth/" + m_bcf_api_version + "/auth/init";

  // HTTP detail logging (method/URL/body) is handled by amf_sbi::send_did_auth_request

  // 发送请求
  nlohmann::json response_json;
  uint32_t http_code = 0;

  bool sent = send_bcf_request(path, "POST", request.to_json(), response_json, http_code);

  if (!sent) {
    Logger::amf_app().error("[BCF Auth] Failed to send auth init to BCF");
    return BcfAuthResult::FAILURE_BCF_UNREACHABLE;
  }

  // Only log HTTP status as business summary; response body is logged by amf_sbi
  Logger::amf_app().info(
      "[BCF Auth] Auth init response: HTTP %d", http_code);

  // 处理响应
  if (http_code == 404) {
    Logger::amf_app().error("[BCF Auth] DID not registered in BCF");
    return BcfAuthResult::FAILURE_INVALID_DID;
  }

  if (http_code != 200 && http_code != 201) {
    Logger::amf_app().error(
        "[BCF Auth] BCF returned HTTP %d for auth init", http_code);
    return BcfAuthResult::FAILURE_BCF_UNREACHABLE;
  }

  // 解析 challenge 响应
  try {
    challenge_resp = bcf_auth_challenge_response_t::from_json(response_json);
  } catch (const std::exception& e) {
    Logger::amf_app().error(
        "[BCF Auth] Failed to parse challenge response: %s", e.what());
    return BcfAuthResult::FAILURE_INTERNAL_ERROR;
  }

  // 验证 challenge 响应字段
  if (challenge_resp.session_id.empty()) {
    Logger::amf_app().error("[BCF Auth] BCF returned empty session_id");
    return BcfAuthResult::FAILURE_INTERNAL_ERROR;
  }
  if (challenge_resp.challenge.empty()) {
    Logger::amf_app().error("[BCF Auth] BCF returned empty challenge");
    return BcfAuthResult::FAILURE_INTERNAL_ERROR;
  }

  // 检查 challenge 是否已过期
  if (challenge_resp.challenge_expires_ms > 0 &&
      current_time_ms() > challenge_resp.challenge_expires_ms) {
    Logger::amf_app().error("[BCF Auth] Challenge already expired");
    return BcfAuthResult::FAILURE_CHALLENGE_EXPIRED;
  }

  return BcfAuthResult::SUCCESS;
}

//------------------------------------------------------------------------------
BcfAuthResult BcfAuthClient::send_auth_verify(
    const std::string& session_id,
    const std::string& challenge,
    bcf_auth_result_response_t& auth_result) {
  // 签名 challenge
  std::string signature = sign_challenge(challenge);
  if (signature.empty()) {
    Logger::amf_app().error("[BCF Auth] Failed to sign challenge");
    return BcfAuthResult::FAILURE_INTERNAL_ERROR;
  }

  Logger::amf_app().debug(
      "[BCF Auth] Challenge signature: %s...", signature.substr(0, 32).c_str());

  // 构建请求
  bcf_auth_verify_request_t request;
  request.session_id          = session_id;
  request.nf_did              = m_local_did;
  request.challenge_signature = signature;
  request.timestamp_ms        = current_time_ms();

  // 构建 URI
  std::string path = "/nbcf_auth/" + m_bcf_api_version + "/auth/verify";

  // HTTP detail logging (method/URL/body) is handled by amf_sbi::send_did_auth_request

  // 发送请求
  nlohmann::json response_json;
  uint32_t http_code = 0;

  bool sent = send_bcf_request(path, "POST", request.to_json(), response_json, http_code);

  if (!sent) {
    Logger::amf_app().error("[BCF Auth] Failed to send auth verify to BCF");
    return BcfAuthResult::FAILURE_BCF_UNREACHABLE;
  }

  // Only log HTTP status as business summary; response body is logged by amf_sbi
  Logger::amf_app().info(
      "[BCF Auth] Auth verify response: HTTP %d", http_code);

  // 处理响应
  if (http_code == 401) {
    Logger::amf_app().error("[BCF Auth] Signature verification failed at BCF");
    return BcfAuthResult::FAILURE_SIGNATURE_INVALID;
  }
  if (http_code == 404) {
    Logger::amf_app().error("[BCF Auth] Session not found at BCF");
    return BcfAuthResult::FAILURE_SESSION_NOT_FOUND;
  }
  if (http_code == 408 || http_code == 410) {
    Logger::amf_app().error("[BCF Auth] Challenge expired at BCF");
    return BcfAuthResult::FAILURE_CHALLENGE_EXPIRED;
  }
  if (http_code != 200) {
    Logger::amf_app().error(
        "[BCF Auth] BCF returned HTTP %d for auth verify", http_code);
    return BcfAuthResult::FAILURE_BCF_UNREACHABLE;
  }

  // 解析认证结果
  try {
    auth_result = bcf_auth_result_response_t::from_json(response_json);
  } catch (const std::exception& e) {
    Logger::amf_app().error(
        "[BCF Auth] Failed to parse auth result: %s", e.what());
    return BcfAuthResult::FAILURE_INTERNAL_ERROR;
  }

  if (!auth_result.auth_token.empty()) {
    log_bcf_token_claims(auth_result.auth_token);
  }

  return BcfAuthResult::SUCCESS;
}

//------------------------------------------------------------------------------
// Token 管理
//------------------------------------------------------------------------------

std::string BcfAuthClient::get_cached_token() const {
  std::lock_guard<std::mutex> lock(m_cache_mutex);

  if (!m_self_token.is_valid()) {
    return "";
  }

  return m_self_token.auth_token;
}

//------------------------------------------------------------------------------
bool BcfAuthClient::has_valid_token() const {
  return !get_cached_token().empty();
}

//------------------------------------------------------------------------------
void BcfAuthClient::invalidate_token() {
  std::lock_guard<std::mutex> lock(m_cache_mutex);
  m_self_token = bcf_token_cache_entry_t();

  Logger::amf_app().debug("[BCF Auth] Invalidated self token");
}

//------------------------------------------------------------------------------
void BcfAuthClient::clear_all_tokens() {
  std::lock_guard<std::mutex> lock(m_cache_mutex);
  m_self_token = bcf_token_cache_entry_t();
  Logger::amf_app().info("[BCF Auth] Cleared self token");
}

//------------------------------------------------------------------------------
size_t BcfAuthClient::cleanup_expired_tokens() {
  std::lock_guard<std::mutex> lock(m_cache_mutex);

  if (!m_self_token.auth_token.empty() && !m_self_token.is_valid()) {
    Logger::amf_app().debug("[BCF Auth] Cleaning expired self token");
    m_self_token = bcf_token_cache_entry_t();
    return 1;
  }

  return 0;
}

//------------------------------------------------------------------------------
nlohmann::json BcfAuthClient::get_cache_stats() const {
  std::lock_guard<std::mutex> lock(m_cache_mutex);

  nlohmann::json stats;
  uint64_t now = current_time_ms();

  bool has_token = !m_self_token.auth_token.empty();
  bool valid     = m_self_token.is_valid();

  stats["has_self_token"] = has_token;
  stats["is_valid"]       = valid;

  if (has_token) {
    if (m_self_token.expires_at_ms > now) {
      stats["ttl_remaining_s"] =
          static_cast<int64_t>(m_self_token.expires_at_ms - now) / 1000;
    } else {
      stats["ttl_remaining_s"] = 0;
    }
  }

  return stats;
}

//------------------------------------------------------------------------------
// 内部方法
//------------------------------------------------------------------------------

void BcfAuthClient::cache_token(
    const bcf_auth_result_response_t& result) {
  std::lock_guard<std::mutex> lock(m_cache_mutex);

  m_self_token.auth_token     = result.auth_token;
  m_self_token.expires_at_ms  = result.expires_at_ms;
  m_self_token.obtained_at_ms = current_time_ms();
  m_self_token.authorized     = result.authorized;

  Logger::amf_app().debug(
      "[BCF Auth] Cached self token, expires_in=%ds", result.expires_in);
}

// Simple setter for notification URI
void BcfAuthClient::set_notification_uri(const std::string& uri) {
  std::string normalized_uri =
      normalize_notification_uri_for_bcf_subscription(uri);

  {
    std::lock_guard<std::mutex> lock(m_cache_mutex);
    m_notification_uri = normalized_uri;
  }

  if (!normalized_uri.empty() && normalized_uri != uri) {
    Logger::amf_app().info(
        "[BCF Auth] Normalized configured notification_uri to %s",
        normalized_uri.c_str());
  }
}

bool BcfAuthClient::send_subscription_request() {
  std::string notification_uri;
  std::string notification_transport;
  {
    std::lock_guard<std::mutex> lock(m_cache_mutex);
    notification_uri = m_notification_uri;
    notification_transport = m_notification_transport;
  }

  if (notification_uri.empty()) {
    Logger::amf_app().warn(
        "[BCF Auth] Cannot create subscription: notification_uri is empty");
    return false;
  }

  std::string normalized_uri =
      normalize_notification_uri_for_bcf_subscription(notification_uri);
  if (normalized_uri != notification_uri) {
    notification_uri = normalized_uri;
    std::lock_guard<std::mutex> lock(m_cache_mutex);
    m_notification_uri = notification_uri;
    Logger::amf_app().info(
        "[BCF Auth] Normalized subscription notification_uri to %s",
        notification_uri.c_str());
  }

  Logger::amf_app().info(
      "[BCF Auth] Creating subscription with notification_uri=%s, "
      "notification_transport=%s",
      notification_uri.c_str(), notification_transport.c_str());

  // Build subscription payload
  nlohmann::json body = {
    {"subscriber_nf_did", m_local_did},
    {"subscriber_nf_type", m_local_nf_type},
    {"subscriber_nf_instance_id", m_local_nf_instance_id},
    {"notification_uri", notification_uri},
    {"notification_transport", notification_transport},
    {"target_nf_type", "AUSF"}  // example: ask for AUSF targets
  };

  std::string path = "/nbcf_management/" + m_bcf_api_version + "/subscriptions";

  nlohmann::json response_json;
  uint32_t http_code = 0;

  // Include Authorization header via HTTP callback if supported - callback interface currently doesn't support headers
  // TODO: if HTTP callback supports headers, add Authorization: Bearer <token>

  bool sent = send_bcf_request(path, "POST", body, response_json, http_code);
  if (!sent) return false;

  // Save last response for later processing by DIDAuth
  {
    std::lock_guard<std::mutex> lock(m_cache_mutex);
    m_last_subscription_response = response_json;
    m_last_subscription_http_code = http_code;
  }

  if (http_code == 201 || (http_code >= 200 && http_code < 300)) return true;
  return false;
}

// New: send_subscription_request that returns response JSON+http code
bool BcfAuthClient::send_subscription_request(nlohmann::json& response_json, uint32_t& http_code) {
  {
    std::lock_guard<std::mutex> lock(m_cache_mutex);
    if (!m_last_subscription_response.is_null()) {
      response_json = m_last_subscription_response;
      http_code = m_last_subscription_http_code;
      return true;
    }
  }

  // Attempt to send a subscription now without holding m_cache_mutex,
  // otherwise the nested cache update path may deadlock.
  bool ok = send_subscription_request();
  if (!ok) return false;

  std::lock_guard<std::mutex> lock(m_cache_mutex);
  response_json = m_last_subscription_response;
  http_code = m_last_subscription_http_code;
  return true;
}

nlohmann::json BcfAuthClient::get_last_subscription_response() const {
  std::lock_guard<std::mutex> lock(m_cache_mutex);
  return m_last_subscription_response;
}

//------------------------------------------------------------------------------
bool BcfAuthClient::create_subscription() {
  // Public wrapper that enforces that subscription is only created when the
  // caller has verified that authentication and authorization completed.
  // Use try-lock to avoid potential deadlocks during shutdown (Ctrl+C) or
  // when other threads hold the cache mutex.
  {
    std::unique_lock<std::mutex> lock(m_cache_mutex, std::try_to_lock);
    if (!lock.owns_lock()) {
      Logger::amf_app().warn(
          "[BCF Auth] create_subscription skipped: cache mutex busy (avoiding deadlock)");
      return false;
    }

    if (m_self_token.auth_token.empty() || !m_self_token.authorized) {
      Logger::amf_app().warn(
          "[BCF Auth] create_subscription called but token not authorized/cached");
      return false;
    }

    if (m_notification_uri.empty()) {
      Logger::amf_app().warn("[BCF Auth] No notification URI configured, skipping subscription");
      return false;
    }
  }

  Logger::amf_app().info("[BCF Auth] Attempting to create BCF subscription...");
  try {
    bool ok = send_subscription_request();
    if (ok) {
      Logger::amf_app().info("[BCF Auth] Subscription request sent successfully");
      return true;
    }
    Logger::amf_app().warn("[BCF Auth] Subscription request failed (non-fatal)");
    return false;
  } catch (const std::exception& e) {
    Logger::amf_app().warn("[BCF Auth] Exception while sending subscription request: %s", e.what());
    return false;
  }
}

//------------------------------------------------------------------------------
bool BcfAuthClient::send_bcf_request(
    const std::string& path,
    const std::string& method,
    const nlohmann::json& body,
    nlohmann::json& response,
    uint32_t& http_code) {
  // 复用 BcfNfDiscoveryClient::send_bcf_request 的风格
  try {
    std::string full_uri = m_bcf_uri + path;
    std::string body_str = body.dump();

    // Detailed HTTP logging is done by amf_sbi::send_did_auth_request (the callback).
    // Only a minimal trace here to track internal dispatch flow.
    Logger::amf_app().trace(
        "[BCF Auth] Dispatching %s %s via HTTP callback", method.c_str(), full_uri.c_str());

    // 优先使用外部 HTTP 回调（复用 amf_sbi 的请求能力）
    if (m_http_callback) {
      std::string response_body;
      uint32_t response_code = 0;

      bool success = m_http_callback(
          full_uri, method, body_str, response_body, response_code);

      http_code = response_code;

      if (!success && response_code == 0) {
        Logger::amf_app().error(
            "[BCF Auth] HTTP callback failed for %s", full_uri.c_str());
        return false;
      }

      if (!response_body.empty()) {
        try {
          response = nlohmann::json::parse(response_body);
        } catch (const std::exception& e) {
          Logger::amf_app().warn(
              "[BCF Auth] Failed to parse response JSON: %s", e.what());
          response = nlohmann::json();
        }
      }

      return success || (http_code >= 200 && http_code < 300);
    }

    // 如果没有 HTTP 回调，则无法发送请求
    Logger::amf_app().error(
        "[BCF Auth] No HTTP callback configured, cannot send request");
    return false;

  } catch (const std::exception& e) {
    Logger::amf_app().error(
        "[BCF Auth] Exception in send_bcf_request: %s", e.what());
    return false;
  }
}

//------------------------------------------------------------------------------
std::string BcfAuthClient::sign_challenge(const std::string& challenge_hex) {
  if (!m_crypto) {
    Logger::amf_app().error("[BCF Auth] Crypto module not available");
    return "";
  }

  Logger::amf_app().info("[BCF Auth] ---- sign_challenge called ----");
  Logger::amf_app().debug(
      "[BCF Auth]   challenge_hex: %s", challenge_hex.c_str());

  // 使用 signature_utils 进行签名
  std::string signature = signature_utils::sign_challenge_with_logging(
      challenge_hex, m_crypto->get_private_key_bytes());

  if (signature.empty()) {
    Logger::amf_app().error(
        "[BCF Auth] Primary signing failed, trying fallback...");
    signature = m_crypto->sign_hex(challenge_hex);
  }

  Logger::amf_app().debug(
      "[BCF Auth]   signature result: %s",
      signature.empty() ? "(empty)" : signature.substr(0, 32).c_str());

  return signature;
}

//------------------------------------------------------------------------------
uint64_t BcfAuthClient::current_time_ms() {
  return std::chrono::duration_cast<std::chrono::milliseconds>(
             std::chrono::system_clock::now().time_since_epoch())
      .count();
}

}  // namespace oai::amf::did_auth
