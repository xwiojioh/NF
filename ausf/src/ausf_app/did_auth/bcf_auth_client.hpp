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
 * @file bcf_auth_client.hpp
 * @brief BCF 认证客户端 - NF 自身认证（AUSF 侧）
 *
 * 本模块提供 AUSF 侧的 BCF 认证功能，实现"NF 自身认证"流程：
 *
 * 流程：
 *   1. AUSF 向 BCF 发起认证初始化  → BCF 返回 challenge
 *   2. AUSF 签名 challenge          → AUSF 将签名发回 BCF
 *   3. BCF 验签并返回 auth_token     → AUSF 缓存 self token
 *   4. AUSF 携带 self token 访问其他 NF → 其他 NF 验证 token
 *
 * 代码风格：
 *   - 严格参考 AMF bcf_auth_client.hpp 的接口与命名
 *   - 复用 did_crypto 的签名能力
 *   - 复用 bcf_interface.hpp 中定义的 BCF 通信数据结构
 */

#ifndef _AUSF_BCF_AUTH_CLIENT_HPP_
#define _AUSF_BCF_AUTH_CLIENT_HPP_

#include <memory>
#include <mutex>
#include <string>

#include <nlohmann/json.hpp>

#include "bcf_interface.hpp"

namespace oai::ausf::did_auth {

// Forward declarations
class did_crypto;

/**
 * @brief BCF 认证客户端（AUSF 侧）
 *
 * 封装 AUSF 与 BCF 之间的认证通信，提供：
 * - 认证初始化（获取 challenge）
 * - challenge 签名与验证提交
 * - token 缓存与有效性检查
 * - 认证会话管理
 *
 * 使用示例:
 * @code
 * BcfAuthClient client;
 * client.set_bcf_uri("http://oai-bcf:8080");
 * client.set_local_nf_info("did:oai5gc:...", "AUSF", "ausf-uuid");
 * client.set_crypto(crypto_ptr);
 *
 * // 认证并获取 token
 * std::string token;
 * auto result = client.authenticate("UDM", "", token);
 * if (result == BcfAuthResult::SUCCESS) {
 *   // 携带 token 访问 UDM
 * }
 * @endcode
 */
class BcfAuthClient {
 public:
  BcfAuthClient();
  ~BcfAuthClient() = default;

  // 禁止拷贝
  BcfAuthClient(const BcfAuthClient&)            = delete;
  BcfAuthClient& operator=(const BcfAuthClient&) = delete;

  // =========================================================================
  // 配置方法
  // =========================================================================

  /**
   * @brief 设置 BCF 基础 URI
   * @param uri BCF 的基础 URI (如 "http://oai-bcf:8080")
   */
  void set_bcf_uri(const std::string& uri);

  /**
   * @brief 设置 BCF 认证 API 版本
   * @param version API 版本 (如 "v1")
   */
  void set_bcf_api_version(const std::string& version);

  /**
   * @brief 设置本地 NF 信息
   * @param did 本地 NF 的 DID
   * @param nf_type 本地 NF 类型 (AUSF)
   * @param nf_instance_id 本地 NF 实例 ID
   */
  void set_local_nf_info(
      const std::string& did,
      const std::string& nf_type,
      const std::string& nf_instance_id);

  /**
   * @brief 设置签名模块
   * @param crypto 签名模块指针（共享，由外部管理生命周期）
   */
  void set_crypto(did_crypto* crypto);

  /**
   * @brief 设置 HTTP 请求回调
   *
   * 复用外部已有的 HTTP 请求发送能力
   *
   * @param callback HTTP 请求回调
   */
  using http_send_callback_t = std::function<bool(
      const std::string& uri, const std::string& method,
      const std::string& body, std::string& response_body,
      uint32_t& response_code)>;
  void set_http_callback(http_send_callback_t callback);

  /**
   * @brief 设置 HTTP 版本
   * @param version HTTP 版本 (1 或 2)
   */
  void set_http_version(int version);

  /**
   * @brief 设置请求超时
   * @param timeout_ms 超时时间（毫秒）
   */
  void set_timeout(uint32_t timeout_ms);

  // =========================================================================
  // 核心认证方法
  // =========================================================================

  /**
   * @brief 执行完整的 BCF 自身认证流程（同步）
   *
   * 完成从 init → challenge → verify → token 的完整流程
   *
   * @param auth_token 输出：认证成功后的 self token
   * @return 认证结果
   */
  BcfAuthResult authenticate(std::string& auth_token);

  /**
   * @brief 确保已认证（有缓存则用缓存，无缓存则发起认证）
   *
   * @param auth_token 输出：认证 token
   * @return 认证结果
   */
  BcfAuthResult ensure_authenticated(std::string& auth_token);

  // =========================================================================
  // 分步认证方法（供高级用途或测试）
  // =========================================================================

  /**
   * @brief 步骤1：发送认证初始化请求
   *
   * POST /nbcf_auth/v1/auth/init
   *
   * @param challenge_resp 输出：BCF 返回的 challenge
   * @return 认证结果
   */
  BcfAuthResult send_auth_init(
      bcf_auth_challenge_response_t& challenge_resp);

  /**
   * @brief 步骤2：签名 challenge 并发送验证请求
   *
   * POST /nbcf_auth/v1/auth/verify
   *
   * @param session_id BCF 分配的会话 ID
   * @param challenge BCF 下发的 challenge（Hex 编码）
   * @param auth_result 输出：BCF 返回的认证结果
   * @return 认证结果
   */
  BcfAuthResult send_auth_verify(
      const std::string& session_id,
      const std::string& challenge,
      bcf_auth_result_response_t& auth_result);

  // =========================================================================
  // Token 管理
  // =========================================================================

  /**
   * @brief 获取缓存的 self token
   * @return token 字符串，无有效缓存则返回空
   */
  std::string get_cached_token() const;

  /**
   * @brief 检查是否有有效的缓存 self token
   * @return true 如果有有效的缓存 token
   */
  bool has_valid_token() const;

  /**
   * @brief 使 self token 失效
   */
  void invalidate_token();

  /**
   * @brief 清除所有缓存的 token
   */
  void clear_all_tokens();

  /**
   * @brief 清理过期的 token
   * @return 清理数量
   */
  size_t cleanup_expired_tokens();

  /**
   * @brief 获取缓存统计
   */
  nlohmann::json get_cache_stats() const;

 private:
  // =========================================================================
  // 内部方法
  // =========================================================================

  /**
   * @brief 缓存 self token
   */
  void cache_token(const bcf_auth_result_response_t& result);

  /**
   * @brief 发送 HTTP 请求到 BCF
   */
  bool send_bcf_request(
      const std::string& path,
      const std::string& method,
      const nlohmann::json& body,
      nlohmann::json& response,
      uint32_t& http_code);

  /**
   * @brief 对 challenge 进行签名
   */
  std::string sign_challenge(const std::string& challenge_hex);

  /**
   * @brief 获取当前毫秒时间戳
   */
  static uint64_t current_time_ms();

  // =========================================================================
  // 成员变量
  // =========================================================================

  std::string m_bcf_uri;               // BCF 基础 URI
  std::string m_bcf_api_version;       // BCF API 版本

  std::string m_local_did;             // 本地 NF DID
  std::string m_local_nf_type;         // 本地 NF 类型
  std::string m_local_nf_instance_id;  // 本地 NF 实例 ID

  did_crypto* m_crypto;                // 签名模块（外部管理生命周期）
  http_send_callback_t m_http_callback;// HTTP 请求回调

  int m_http_version;                  // HTTP 版本
  uint32_t m_timeout_ms;               // 请求超时

  // Self token cache
  bcf_token_cache_entry_t m_self_token;
  mutable std::mutex m_cache_mutex;
};

}  // namespace oai::ausf::did_auth

#endif  // _AUSF_BCF_AUTH_CLIENT_HPP_
