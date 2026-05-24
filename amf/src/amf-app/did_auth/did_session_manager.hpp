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

#ifndef _DID_SESSION_MANAGER_H_
#define _DID_SESSION_MANAGER_H_

#include "did_auth_types.hpp"

#include <chrono>
#include <functional>
#include <memory>
#include <shared_mutex>
#include <string>
#include <unordered_map>

namespace oai::amf::did_auth {

/**
 * @brief 认证会话管理器
 *
 * 管理所有进行中和已完成的认证会话，提供：
 * - 会话创建和销毁
 * - 状态转换
 * - 超时清理
 * - 认证令牌管理
 */
class did_session_manager {
 public:
  /**
   * @brief 构造函数
   * @param session_timeout_sec 会话超时时间（秒），默认 5 分钟
   * @param token_validity_sec 认证令牌有效期（秒），默认 1 小时
   */
  explicit did_session_manager(
      uint64_t session_timeout_sec = 300, uint64_t token_validity_sec = 3600);

  ~did_session_manager();

  /**
   * @brief 创建新会话（自动生成 session_id）
   * @param local_did 本地 DID
   * @param local_nf_type 本地 NF 类型
   * @param local_nf_instance_id 本地 NF 实例 ID
   * @param is_initiator 是否为发起方
   * @return 会话 ID
   */
  std::string create_session(
      const std::string& local_did, const std::string& local_nf_type,
      const std::string& local_nf_instance_id, bool is_initiator);

  /**
   * @brief 使用指定的 session_id 创建会话
   *
   * 用于 Responder 使用 Initiator 提供的 session_id 创建会话
   *
   * @param session_id 指定的会话 ID（由 Initiator 提供）
   * @param local_did 本地 DID
   * @param local_nf_type 本地 NF 类型
   * @param local_nf_instance_id 本地 NF 实例 ID
   * @param is_initiator 是否为发起方
   * @return true 如果创建成功，false 如果 session_id 已存在
   */
  bool create_session_with_id(
      const std::string& session_id, const std::string& local_did,
      const std::string& local_nf_type, const std::string& local_nf_instance_id,
      bool is_initiator);

  /**
   * @brief 获取会话
   * @param session_id 会话 ID
   * @return 会话指针，不存在返回 nullptr
   */
  std::shared_ptr<auth_session_t> get_session(const std::string& session_id);

  /**
   * @brief 获取会话（const 版本）
   */
  std::shared_ptr<const auth_session_t> get_session(
      const std::string& session_id) const;

  /**
   * @brief 更新会话状态
   * @param session_id 会话 ID
   * @param new_state 新状态
   * @return true 如果更新成功
   */
  bool update_state(const std::string& session_id, AuthState new_state);

  /**
   * @brief 设置对端信息
   * @param session_id 会话 ID
   * @param remote_did 对端 DID
   * @param remote_nf_type 对端 NF 类型
   * @param remote_nf_instance_id 对端 NF 实例 ID
   * @param remote_public_key 对端公钥
   */
  bool set_remote_info(
      const std::string& session_id, const std::string& remote_did,
      const std::string& remote_nf_type, const std::string& remote_nf_instance_id,
      const std::string& remote_public_key);

  /**
   * @brief 设置对端端点
   * @param session_id 会话 ID
   * @param endpoint 对端 HTTP 端点
   */
  bool set_remote_endpoint(
      const std::string& session_id, const std::string& endpoint);

  /**
   * @brief 设置本地 Nonce
   * @param session_id 会话 ID
   * @param nonce 本地 nonce
   */
  bool set_local_nonce(const std::string& session_id, const nonce_t& nonce);

  /**
   * @brief 设置远端 Nonce
   * @param session_id 会话 ID
   * @param nonce 远端 nonce
   */
  bool set_remote_nonce(const std::string& session_id, const nonce_t& nonce);

  /**
   * @brief 生成认证令牌
   * @param session_id 会话 ID
   * @return 认证令牌，失败返回空字符串
   */
  std::string generate_auth_token(const std::string& session_id);

  /**
   * @brief 验证认证令牌
   * @param token 认证令牌
   * @param session_id 输出：会话 ID
   * @return true 如果令牌有效
   */
  bool validate_auth_token(
      const std::string& token, std::string& session_id) const;

  /**
   * @brief 删除会话
   * @param session_id 会话 ID
   */
  void remove_session(const std::string& session_id);

  /**
   * @brief 清理过期会话
   * @return 清理的会话数量
   */
  size_t cleanup_expired();

  /**
   * @brief 获取活跃会话数量
   */
  size_t active_session_count() const;

  /**
   * @brief 检查会话是否存在
   */
  bool session_exists(const std::string& session_id) const;

  /**
   * @brief 根据远端 DID 查找已认证的会话
   * @param remote_did 远端 DID
   * @return 会话 ID，未找到返回空字符串
   */
  std::string find_authenticated_session(const std::string& remote_did) const;

  /**
   * @brief 更新会话活动时间
   */
  void touch_session(const std::string& session_id);

  /**
   * @brief 迁移会话到新的 session_id
   * @param old_session_id 旧的会话 ID（本地生成的跟踪 ID）
   * @param new_session_id 新的会话 ID（由 Responder 提供的规范 ID）
   * @return true 如果迁移成功
   *
   * 用于 Initiator 在收到 Responder 的 challenge 响应后，
   * 将会话数据从本地跟踪 ID 迁移到 Responder 提供的规范 session_id。
   */
  bool migrate_session(
      const std::string& old_session_id, const std::string& new_session_id);

 private:
  std::unordered_map<std::string, std::shared_ptr<auth_session_t>> m_sessions;
  std::unordered_map<std::string, std::string> m_token_to_session;  // token -> session_id
  mutable std::shared_mutex m_mutex;

  uint64_t m_session_timeout_sec;
  uint64_t m_token_validity_sec;

  /**
   * @brief 生成会话 ID
   */
  std::string generate_session_id();

  /**
   * @brief 生成安全的认证令牌
   */
  std::string generate_secure_token();
};

}  // namespace oai::amf::did_auth

#endif  // _DID_SESSION_MANAGER_H_
