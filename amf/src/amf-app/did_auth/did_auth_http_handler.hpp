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

#ifndef _DID_AUTH_HTTP_HANDLER_H_
#define _DID_AUTH_HTTP_HANDLER_H_

#include "did_auth.hpp"
#include "did_auth_types.hpp"
#include "did_auth_precheck.hpp"

#include <functional>
#include <memory>
#include <string>

namespace oai::amf::did_auth {

/**
 * @brief HTTP 请求处理结果
 */
struct http_response_t {
  int status_code;
  std::string content_type;
  std::string body;
};

/**
 * @brief DID 认证 HTTP 处理器
 *
 * 处理来自其他 NF 的 DID 认证 HTTP 请求
 */
class did_auth_http_handler {
 public:
  /**
   * @brief 构造函数
   * @param auth_module DID 认证模块（共享）
   */
  explicit did_auth_http_handler(
      std::shared_ptr<did_auth_module> auth_module);

  ~did_auth_http_handler();

  /**
   * @brief 处理认证初始化请求
   * POST /nf_auth/v1/mutual_auth/init
   *
   * @deprecated 旧版双向认证，已被 BCF 单向认证替代。
   *             新版 NF 不再需要处理来自其他 NF 的认证请求，
   *             认证由 NF → BCF 完成，目标 NF 仅验证 BCF 签发的 token。
   *
   * @param request_body 请求体 (JSON)
   * @return HTTP 响应
   */
  [[deprecated("Use BCF single-direction auth instead")]]
  http_response_t handle_auth_init(const std::string& request_body);

  /**
   * @brief 处理认证完成请求
   * POST /nf_auth/v1/mutual_auth/complete
   *
   * @deprecated 旧版双向认证，已被 BCF 单向认证替代。
   *
   * @param request_body 请求体 (JSON)
   * @return HTTP 响应
   */
  [[deprecated("Use BCF single-direction auth instead")]]
  http_response_t handle_auth_complete(const std::string& request_body);

  // ============================================================================
  // V2 API with PreCheck Integration (deprecated - mutual auth)
  // ============================================================================

  /**
   * @brief 处理认证初始化请求 (v2 with PreCheck)
   * POST /nf_auth/v2/mutual_auth/init
   *
   * @deprecated 旧版双向认证 v2，已被 BCF 单向认证替代。
   *
   * @param request_body 请求体 (JSON)
   * @return HTTP 响应
   */
  [[deprecated("Use BCF single-direction auth instead")]]
  http_response_t handle_auth_init_v2(const std::string& request_body);

  /**
   * @brief 处理认证完成请求 (v2 with PreCheck)
   * POST /nf_auth/v2/mutual_auth/complete
   *
   * @deprecated 旧版双向认证 v2，已被 BCF 单向认证替代。
   *
   * @param request_body 请求体 (JSON)
   * @return HTTP 响应
   */
  [[deprecated("Use BCF single-direction auth instead")]]
  http_response_t handle_auth_complete_v2(const std::string& request_body);

  /**
   * @brief 处理认证状态查询请求
   * GET /nf_auth/v1/sessions/{session_id}
   *
   * @param session_id 会话 ID
   * @return HTTP 响应
   */
  http_response_t handle_get_session_status(const std::string& session_id);

    /**
     * @brief Handle BCF pushed notification
    * POST /nbcf_management/v1/notifications
     */
    http_response_t handle_bcf_notification(const std::string& request_body);

  /**
   * @brief 验证请求中的认证头
   *
   * 检查 X-DID-Auth-Token 头（旧版双向认证 token）
   *
   * @param auth_token 认证令牌
   * @param did 可选：期望的 DID
   * @return 验证结果
   */
  AuthResult validate_auth_header(
      const std::string& auth_token, const std::string& did = "");

  // ============================================================================
  // BCF Token Validation (新版 - 目标 NF 侧验证 BCF 签发的 token)
  // ============================================================================

  /**
   * @brief 验证 BCF 签发的认证 token
   *
   * 目标 NF 收到请求时，验证请求中携带的 BCF token。
   * Token 由 BCF 签发，包含请求方 DID、目标 NF 类型、过期时间等。
   * 目标 NF 可通过验证 BCF 签名来确认 token 有效性。
   *
   * @param bcf_token BCF 签发的认证令牌
   * @param expected_target_nf_type 期望的目标 NF 类型（如 "AMF"）
   * @param bcf_public_key BCF 的公钥（用于验签，可选，为空则查询 BCF）
   * @return 验证结果
   */
  AuthResult validate_bcf_token(
      const std::string& bcf_token,
      const std::string& expected_target_nf_type = "",
      const std::string& bcf_public_key = "");

  /**
   * @brief 生成错误响应
   * @param status_code HTTP 状态码
   * @param error_code 错误代码
   * @param message 错误消息
   * @return HTTP 响应
   */
  static http_response_t make_error_response(
      int status_code, const std::string& error_code,
      const std::string& message);

  /**
   * @brief 生成成功响应
   * @param body 响应体
   * @return HTTP 响应
   */
  static http_response_t make_success_response(const std::string& body);

  /**
   * @brief 获取 PreChecker 实例
   * @return PreChecker 引用
   */
  DIDAuthPreChecker& get_prechecker() { return m_prechecker; }

  /**
   * @brief 设置 BCF 查询回调（用于 PreCheck DID 验证）
   */
  void set_bcf_query_callback(DIDAuthPreChecker::BcfQueryCallback callback) {
    m_prechecker.set_bcf_query_callback(callback);
  }

  /**
   * @brief 设置 Session 查询回调（用于 PreCheck Session 验证）
   */
  void set_session_query_callback(DIDAuthPreChecker::SessionQueryCallback callback) {
    m_prechecker.set_session_query_callback(callback);
  }

 private:
  std::shared_ptr<did_auth_module> m_auth_module;
  DIDAuthPreChecker m_prechecker;  ///< PreCheck 模块
};

/**
 * @brief DID 认证 HTTP 客户端（旧版 - 双向认证）
 *
 * @deprecated 此客户端用于旧版 NF-A ↔ NF-B 双向认证。
 *             新版认证使用 BcfAuthClient（NF → BCF 单向认证），
 *             参见 bcf_auth_client.hpp。
 *
 * 作为发起方向其他 NF 发送认证请求
 */
class [[deprecated("Use BcfAuthClient for NF→BCF single-direction auth")]]
did_auth_http_client {
 public:
  /**
   * @brief 构造函数
   * @param auth_module DID 认证模块（共享）
   * @param timeout_sec 请求超时（秒）
   */
  explicit did_auth_http_client(
      std::shared_ptr<did_auth_module> auth_module, uint64_t timeout_sec = 10);

  ~did_auth_http_client();

  /**
   * @brief 认证完成回调
   */
  using auth_complete_callback_t = std::function<void(
      bool success, const std::string& session_id,
      const std::string& auth_token, const std::string& error_message)>;

  /**
   * @brief 发起双向认证（异步）
   *
   * @param target_endpoint 目标 NF 的 HTTP 端点
   * @param callback 认证完成回调
   */
  void initiate_mutual_auth_async(
      const std::string& target_endpoint, auth_complete_callback_t callback);

  /**
   * @brief 发起双向认证（同步）
   *
   * @param target_endpoint 目标 NF 的 HTTP 端点
   * @param session_id 输出：会话 ID
   * @param auth_token 输出：认证令牌
   * @return 认证结果
   */
  AuthResult initiate_mutual_auth(
      const std::string& target_endpoint, std::string& session_id,
      std::string& auth_token);

  /**
   * @brief 检查是否需要认证，如果需要则执行认证
   *
   * @param target_endpoint 目标 NF 的 HTTP 端点
   * @param target_did 目标 NF 的 DID（用于查找已有会话）
   * @param auth_token 输出：认证令牌
   * @return 认证结果
   */
  AuthResult ensure_authenticated(
      const std::string& target_endpoint, const std::string& target_did,
      std::string& auth_token);

  /**
   * @brief 设置请求超时
   */
  void set_timeout(uint64_t timeout_sec) { m_timeout_sec = timeout_sec; }

 private:
  std::shared_ptr<did_auth_module> m_auth_module;
  uint64_t m_timeout_sec;

  /**
   * @brief 发送 HTTP POST 请求
   */
  int send_post_request(
      const std::string& url, const std::string& body,
      std::string& response_body);
};

}  // namespace oai::amf::did_auth

#endif  // _DID_AUTH_HTTP_HANDLER_H_
