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

#ifndef _DID_AUTH_H_
#define _DID_AUTH_H_

#include "bcf_auth_client.hpp"
#include "bcf_interface.hpp"
#include "target_nf_cache.hpp"
#include "did_auth_types.hpp"
#include "did_crypto.hpp"
#include "did_nonce_manager.hpp"
#include "did_session_manager.hpp"

#include <functional>
#include <map>
#include <memory>
#include <mutex>
#include <shared_mutex>
#include <string>
#include <unordered_map>

namespace oai::amf::did_auth {

/**
 * @brief 认证完成回调函数类型
 */
using auth_callback_t = std::function<void(
    const std::string& session_id, AuthResult result,
    const std::string& auth_token, const std::string& error_message)>;

/**
 * @brief HTTP 请求回调函数类型
 * 用于发起方发送 HTTP 请求，由外部模块（如 amf_sbi）实现
 * @param uri 请求 URI
 * @param method HTTP 方法 ("POST", "GET", etc.)
 * @param body 请求体（JSON 字符串）
 * @param response_body 输出：响应体
 * @param response_code 输出：HTTP 响应码
 * @return true 如果请求成功
 */
using http_request_callback_t = std::function<bool(
    const std::string& uri, const std::string& method, const std::string& body,
    std::string& response_body, uint32_t& response_code)>;

/**
 * @brief DID 双向认证模块
 *
 * 提供基于 DID 的双向认证功能，支持：
 * - 主动发起认证（作为客户端/发起方）
 * - 被动响应认证（作为服务端/响应方）
 * - 挑战-响应签名验证
 * - 会话管理和超时处理
 * - 认证令牌生成和验证
 *
 * 注意：本模块不包含 BCF 客户端实现，需要通过回调函数与外部 BCF 交互
 */
class did_auth_module {
 public:
  /**
   * @brief 构造函数
   * @param local_did 本地网元的 DID
   * @param local_nf_type 本地 NF 类型 (AMF, SMF, etc.)
   * @param local_nf_instance_id 本地 NF 实例 ID
   * @param private_key_hex 本地私钥（Hex 编码，64 字符）
   */
  did_auth_module(
      const std::string& local_did, const std::string& local_nf_type,
      const std::string& local_nf_instance_id,
      const std::string& private_key_hex);

  ~did_auth_module();

  /**
   * @brief 检查模块是否已正确初始化
   */
  bool is_initialized() const;

  // =========================================================================
  // BCF 回调设置（必须在使用前设置）
  // =========================================================================

  /**
   * @brief 设置公钥查询回调
   * @param callback 公钥查询回调函数（向 BCF 查询 DID 对应的公钥）
   */
  void set_public_key_query_callback(public_key_query_callback_t callback);

    /**
     * @brief 设置用于接收 BCF 通知的本地回调 URI（将传给 BcfAuthClient）
     */
    void set_bcf_notification_uri(const std::string& uri);

    /**
     * @brief 设置 BCF 回调投递的首选传输模式
     */
    void set_bcf_notification_transport(const std::string& transport);

  // =========================================================================
  // NF 地址配置接口（直接从配置文件读取，不使用动态发现）
  // =========================================================================

  /**
   * @brief 配置目标 NF 的 URI（从配置文件读取）
   * 
   * 类似 AMF 直接从配置读取 AUSF、UDM 等 NF 地址的方式，
   * 将目标 NF 的地址直接配置到 DID Auth 模块中。
   * 
   * @param nf_type NF 类型 (如 "SMF", "UDM", "AUSF" 等)
   * @param uri_root NF 的 URI 根路径 (如 "http://192.168.1.10:8080")
   * @param api_version API 版本 (如 "v1")
   */
  void configure_nf_endpoint(
      const std::string& nf_type,
      const std::string& uri_root,
      const std::string& api_version = "v1");

  /**
   * @brief 获取已配置的 NF URI
   * @param nf_type NF 类型
   * @return NF 的 URI 根路径，未配置时返回空字符串
   */
  std::string get_configured_nf_uri(const std::string& nf_type) const;

  /**
   * @brief 构建完整的 NF API URI
   * @param nf_type NF 类型
   * @param api_path API 路径 (如 "/nf_auth/v1/mutual_auth/init")
   * @return 完整的 URI
   */
  std::string build_nf_api_uri(
      const std::string& nf_type,
      const std::string& api_path) const;

  // =========================================================================
  // 发起方（Client/Initiator）接口
  // =========================================================================

  /**
   * @brief 创建认证初始化请求（第一步）
   * @param remote_uri 对端 NF 的 URI（从 NF Profile 获取）
   * @return 认证初始化请求和会话 ID
   */
  std::pair<auth_init_request_t, std::string> create_auth_init_request(
      const std::string& remote_uri);

  /**
   * @brief 处理认证挑战响应（第二步）
   *
   * 验证对端签名，生成对响应方 nonce 的签名
   *
   * @param session_id 会话 ID
   * @param challenge 收到的挑战响应
   * @return 认证完成请求（包含签名）
   */
  std::pair<auth_complete_request_t, AuthResult> process_auth_challenge(
      const std::string& session_id, const auth_challenge_response_t& challenge);

  /**
   * @brief 处理最终认证结果（第三步）
   * @param session_id 会话 ID
   * @param result 收到的认证结果
   */
  void process_auth_result(
      const std::string& session_id, const auth_result_response_t& result);

  // =========================================================================
  // 响应方（Server/Responder）接口
  // =========================================================================

  /**
   * @brief 处理认证初始化请求（作为响应方）
   *
   * 查询发起方公钥，验证 DID，生成挑战
   *
   * @param request 收到的初始化请求
   * @return 挑战响应
   */
  std::pair<auth_challenge_response_t, AuthResult> handle_auth_init(
      const auth_init_request_t& request);

  /**
   * @brief 处理认证完成请求（作为响应方）
   *
   * 验证发起方签名，完成认证
   *
   * @param request 收到的完成请求
   * @return 认证结果响应
   */
  auth_result_response_t handle_auth_complete(
      const auth_complete_request_t& request);

  // =========================================================================
  // 认证状态查询和管理
  // =========================================================================

  /**
   * @brief 验证会话是否已完成双向认证
   * @param session_id 会话 ID
   * @return true 如果双向认证已完成
   */
  bool is_session_authenticated(const std::string& session_id) const;

  /**
   * @brief 获取会话的认证令牌
   * @param session_id 会话 ID
   * @return 认证令牌，失败返回空字符串
   */
  std::string get_auth_token(const std::string& session_id) const;

  /**
   * @brief 验证请求中的认证令牌
   * @param token 认证令牌
   * @param remote_did 可选：期望的远端 DID
   * @return 验证结果
   */
  AuthResult verify_auth_token(
      const std::string& token, const std::string& remote_did = "") const;

  /**
   * @brief 根据远端 DID 查找已认证的会话
   * @param remote_did 远端 DID
   * @return 会话 ID，未找到返回空字符串
   */
  std::string find_authenticated_session(const std::string& remote_did) const;

    /**
    * @brief Handle incoming BCF notification (POST /nbcf_management/v1/notifications)
     * Minimal processing: parse subscription_id/event_type/target and update TargetNfCache.
     */
    bool handle_bcf_notification(const std::string& body_json);

        /**
         * @brief 处理 BCF subscription response，解析 target_nf_list 并缓存完整 profile
         * @param resp_json BCF 返回的 subscription response JSON
         * @return true 如果处理成功
         */
        bool handle_subscription_response(const nlohmann::json& resp_json);

  /**
   * @brief 获取本地缓存的目标 NF 条目
   * @param nf_type 可选 NF 类型过滤，如 "AUSF"
   * @return 缓存条目列表
   */
  std::vector<target_nf_entry_t> get_cached_target_nfs(
      const std::string& nf_type = "") const;

  /**
   * @brief 检查是否需要与指定 NF 进行认证
   * @param remote_did 远端 DID
   * @return true 如果需要（重新）认证
   */
  bool needs_authentication(const std::string& remote_did) const;

  /**
   * @brief 获取会话信息
   * @param session_id 会话 ID
   * @return 会话信息，不存在返回 nullptr
   */
  std::shared_ptr<const auth_session_t> get_session_info(
      const std::string& session_id) const;

  // =========================================================================
  // 维护操作
  // =========================================================================

  /**
   * @brief 清理过期会话和 Nonce
   */
  void cleanup();

  /**
   * @brief 关闭指定会话
   * @param session_id 会话 ID
   */
  void close_session(const std::string& session_id);

  /**
   * @brief 迁移会话到新的 session_id
   *
   * 当 Initiator 收到 Responder 的 challenge 响应后，
   * 使用此方法将会话数据从本地跟踪 ID 迁移到 Responder 提供的规范 session_id。
   *
   * @param old_session_id 旧的会话 ID（本地生成的跟踪 ID）
   * @param new_session_id 新的会话 ID（由 Responder 提供的规范 ID）
   * @return true 如果迁移成功
   */
  bool migrate_session(
      const std::string& old_session_id, const std::string& new_session_id);

  /**
   * @brief 获取统计信息
   */
  struct statistics_t {
    size_t active_sessions;
    size_t authenticated_sessions;
    size_t pending_sessions;
    size_t used_nonces;
    size_t cached_public_keys;
  };

  statistics_t get_statistics() const;

  // =========================================================================
  // 配置接口
  // =========================================================================

  /**
   * @brief 获取本地 DID
   */
  std::string get_local_did() const { return m_local_did; }

  /**
   * @brief 获取本地 NF 类型
   */
  std::string get_local_nf_type() const { return m_local_nf_type; }

  /**
   * @brief 获取本地 NF 实例 ID
   */
  std::string get_local_nf_instance_id() const { return m_local_nf_instance_id; }

  /**
   * @brief 设置本地地理位置（用于 LOCALITY_BASED NF 选择策略）
   * @param locality 地理位置标识（如 "region-1", "dc-east" 等）
   */
  void set_local_locality(const std::string& locality) {
    m_local_locality = locality;
  }

  /**
   * @brief 获取本地地理位置
   */
  std::string get_local_locality() const { return m_local_locality; }

  /**
   * @brief 预加载远端公钥到缓存
   * @param did 远端 DID
   * @param public_key 远端公钥
   */
  void preload_public_key(const std::string& did, const std::string& public_key);

  // =========================================================================
  // BCF 单向认证接口（新版）
  // =========================================================================

  /**
   * @brief 配置 BCF 认证客户端
   * @param bcf_uri BCF 基础 URI
   * @param api_version BCF API 版本
   */
  void configure_bcf_auth(
      const std::string& bcf_uri,
      const std::string& api_version = "v1");

  /**
   * @brief 设置 BCF 认证的 HTTP 回调
   * @param callback HTTP 请求回调
   */
  void set_bcf_auth_http_callback(BcfAuthClient::http_send_callback_t callback);

  /**
   * @brief 向 BCF 发起单向认证（获取访问目标 NF 的 token）
   *
   * 新版认证流程：NF → BCF（challenge-response）→ 获取 self token
   * NF 认证自身身份，获取的 token 代表 NF 自己的 BCF 身份
   *
   * @param auth_token 输出：认证 token
   * @return 认证结果
   */
  BcfAuthResult authenticate_via_bcf(std::string& auth_token);

  /**
   * @brief 确保已通过 BCF 认证（有缓存则用缓存）
   * @param auth_token 输出：认证 token
   * @return 认证结果
   */
  BcfAuthResult ensure_bcf_authenticated(std::string& auth_token);

  /**
   * @brief 获取 BCF 认证客户端（供高级操作）
   */
  BcfAuthClient* get_bcf_auth_client() { return m_bcf_auth_client.get(); }

  /**
   * @brief 获取签名模块的原始指针（供 BCF Auth Client 使用）
   */
  did_crypto* get_crypto() { return m_crypto.get(); }

 private:
  std::string m_local_did;
  std::string m_local_nf_type;
  std::string m_local_nf_instance_id;
  std::string m_local_locality;  // 本地地理位置

  std::unique_ptr<did_crypto> m_crypto;
  std::unique_ptr<did_session_manager> m_session_mgr;
  std::unique_ptr<did_nonce_manager> m_nonce_mgr;
    // Local cache for target NF entries updated by BCF notifications
    std::unique_ptr<TargetNfCache> m_target_nf_cache;

  // BCF 公钥查询回调（由外部设置）
  public_key_query_callback_t m_public_key_query_callback;

  // BCF 认证客户端（新版单向认证）
  std::unique_ptr<BcfAuthClient> m_bcf_auth_client;

  // NF 端点配置（从配置文件读取，key: nf_type, value: {uri_root, api_version}）
  struct nf_endpoint_config_t {
    std::string uri_root;
    std::string api_version;
  };
  std::unordered_map<std::string, nf_endpoint_config_t> m_nf_endpoints;
  mutable std::shared_mutex m_endpoints_mutex;

  // 公钥缓存（避免重复查询）
  std::unordered_map<std::string, std::string> m_public_key_cache;
  mutable std::shared_mutex m_cache_mutex;

  bool m_initialized;

  /**
   * @brief 从 BCF 获取公钥（通过回调）
   * @param did DID 标识符
   * @return 公钥（Hex 编码），失败返回空字符串
   */
  std::string get_public_key_for_did(const std::string& did);

  /**
   * @brief 生成对 challenge 的签名
   * @param challenge_hex Challenge（Hex 编码）
   * @return 签名（Hex 编码）
   */
  std::string sign_challenge(const std::string& challenge_hex);

  /**
   * @brief 验证对 challenge 的签名
   * @param challenge_hex Challenge（Hex 编码）
   * @param signature_hex 签名（Hex 编码）
   * @param public_key_hex 公钥（Hex 编码）
   * @return true 如果签名有效
   */
  bool verify_challenge_signature(
      const std::string& challenge_hex, const std::string& signature_hex,
      const std::string& public_key_hex);
};

// =============================================================================
// DIDAuth - 高级包装类，提供简化的 API 接口
// =============================================================================

/**
 * @brief DID 认证高级接口类
 *
 * 提供简化的 API，用于与 amf_app 集成
 */
class DIDAuth {
 public:
  /**
   * @brief 构造函数
   * @param local_did 本地 DID
   * @param private_key_path 私钥文件路径
   * @param nf_type 本地 NF 类型 (AMF, AUSF, etc.)
   * @param nf_instance_id 本地 NF 实例 ID
   */
  DIDAuth(
      const std::string& local_did,
      const std::string& private_key_path,
      const std::string& nf_type = "AMF",
      const std::string& nf_instance_id = "");

  ~DIDAuth();

  /**
   * @brief 初始化模块
   * @return true 如果初始化成功
   */
  bool initialize();

  /**
   * @brief 设置 HTTP 请求回调（用于发起方模式）
   * @param callback HTTP 请求回调函数
   */
  void set_http_request_callback(http_request_callback_t callback);

  /**
   * @brief 设置公钥查询回调（与 BCF 交互）
   * @param callback 公钥查询回调函数
   */
  void set_public_key_query_callback(public_key_query_callback_t callback);

  /**
   * @brief 配置目标 NF 的 URI（从配置文件读取）
   * 
   * 类似 AMF 直接从配置读取 AUSF、UDM 等 NF 地址的方式
   * 
   * @param nf_type NF 类型 (如 "SMF", "UDM", "AUSF" 等)
   * @param uri_root NF 的 URI 根路径 (如 "http://192.168.1.10:8080")
   * @param api_version API 版本 (如 "v1")
   */
  void configure_nf_endpoint(
      const std::string& nf_type,
      const std::string& uri_root,
      const std::string& api_version = "v1");

  /**
   * @brief 获取已配置的 NF URI
   * @param nf_type NF 类型
   * @return NF 的 URI 根路径，未配置时返回空字符串
   */
  std::string get_configured_nf_uri(const std::string& nf_type) const;

  /**
   * @brief 生成认证挑战（作为响应方）
   * @param request 认证请求
   * @param challenge 输出：生成的挑战
   * @param session_id 输出：会话 ID
   * @return true 如果成功
   */
  bool generate_challenge(
      const auth_request_t& request,
      auth_challenge_t& challenge,
      std::string& session_id);

  /**
   * @brief 处理认证响应（作为响应方）
   * @param response 认证响应
   * @param result 输出：认证结果
   * @return true 如果认证成功
   */
  bool process_auth_response(
      const auth_response_t& response,
      auth_result_t& result);

  /**
   * @brief 获取会话信息
   * @param session_id 会话 ID
   * @param session 输出：会话信息
   * @return true 如果会话存在
   */
  bool get_session(
      const std::string& session_id,
      auth_session_t& session);

  /**
   * @brief 作为发起方发起认证（需要先设置 HTTP 回调）
   * @param remote_endpoint 远端端点
   * @param auth_token 输出：认证令牌
   * @return true 如果认证成功
   */
  bool init_auth_as_initiator(
      const std::string& remote_endpoint,
      std::string& auth_token);

  /**
   * @brief 检查对端是否已认证
   * @param peer_did 对端 DID
   * @return true 如果已认证
   */
  bool is_peer_authenticated(const std::string& peer_did);

  /**
   * @brief 获取对端认证令牌
   * @param peer_did 对端 DID
   * @return 认证令牌
   */
  std::string get_peer_auth_token(const std::string& peer_did);

  /**
   * @brief 清理过期会话
   */
  void cleanup_expired_sessions();

  /**
   * @brief 设置本地地理位置（用于 LOCALITY_BASED NF 选择策略）
   * @param locality 地理位置标识
   */
  void set_local_locality(const std::string& locality) {
    if (m_module) {
      m_module->set_local_locality(locality);
    }
  }

  /**
   * @brief 获取本地 DID
   * @return 本地 DID 字符串
   */
  std::string get_local_did() const { return m_local_did; }

  /**
   * @brief 获取本地 NF 实例 ID
   * @return 本地 NF 实例 ID 字符串
   */
  std::string get_nf_instance_id() const { return m_nf_instance_id; }

  /**
   * @brief 获取本地 NF 类型
   * @return 本地 NF 类型字符串
   */
  std::string get_nf_type() const { return m_nf_type; }

  /**
   * @brief 获取底层模块（用于高级操作）
   */
  did_auth_module* get_module() { return m_module.get(); }

  // =========================================================================
  // BCF 单向认证接口（新版 - 替代旧版双向认证）
  // =========================================================================

  /**
   * @brief 配置 BCF 认证
   * @param bcf_uri BCF 基础 URI
   * @param api_version BCF API 版本
   */
  void configure_bcf_auth(
      const std::string& bcf_uri,
      const std::string& api_version = "v1");

  /**
   * @brief 向 BCF 发起自身认证（获取 NF 自身的 BCF 身份 token）
   *
   * 新版流程：NF → BCF (init) → BCF 返回 challenge → NF 签名 →
   *           NF → BCF (verify) → BCF 返回 token → NF 缓存 token
   *
   * @param auth_token 输出：认证 token
   * @return true 如果认证成功
   */
  bool authenticate_to_bcf(std::string& auth_token);

  /**
   * @brief 确保已通过 BCF 认证（有缓存则用缓存）
   *
   * @param auth_token 输出：认证 token
   * @return true 如果有有效 token
   */
  bool ensure_bcf_auth(std::string& auth_token);

  /**
   * @brief 检查是否有有效的 BCF self token
   * @return true 如果有有效 token
   */
  bool has_valid_bcf_token() const;

  /**
   * @brief 获取 BCF 认证客户端（供高级操作）
   */
  BcfAuthClient* get_bcf_auth_client();

 private:
  std::string m_local_did;
  std::string m_private_key_path;
  std::string m_nf_type;
  std::string m_nf_instance_id;

  std::unique_ptr<did_auth_module> m_module;
    // Local in-memory cache for target NF information (updated by BCF notifications)
    std::unique_ptr<TargetNfCache> m_target_nf_cache;
  bool m_initialized;

  // HTTP request callback for initiator mode
  http_request_callback_t m_http_callback;

  // Session tracking by peer DID (legacy mutual auth)
  std::map<std::string, std::string> m_peer_did_to_session;
  mutable std::mutex m_peer_map_mutex;
};

}  // namespace oai::amf::did_auth

#endif  // _DID_AUTH_H_
