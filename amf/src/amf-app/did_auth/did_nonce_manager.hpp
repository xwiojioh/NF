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

#ifndef _DID_NONCE_MANAGER_H_
#define _DID_NONCE_MANAGER_H_

#include "did_auth_types.hpp"

#include <chrono>
#include <shared_mutex>
#include <string>
#include <unordered_map>

namespace oai::amf::did_auth {

/**
 * @brief Nonce 管理器
 *
 * 负责：
 * - 生成安全的随机 Nonce
 * - 记录已使用的 Nonce（防重放）
 * - 检测 Nonce 有效性和过期
 */
class did_nonce_manager {
 public:
  /**
   * @brief 构造函数
   * @param nonce_validity_sec Nonce 有效期（秒），默认 5 分钟
   */
  explicit did_nonce_manager(uint64_t nonce_validity_sec = 300);

  ~did_nonce_manager();

  /**
   * @brief 生成新的 Nonce
   * @return 新生成的 Nonce
   */
  nonce_t generate_nonce();

  /**
   * @brief 验证 Nonce 是否有效
   * @param nonce Nonce 值
   * @return 验证结果
   */
  AuthResult validate_nonce(const nonce_t& nonce);

  /**
   * @brief 验证 Nonce（Hex 字符串版本）
   * @param nonce_hex Nonce 的 Hex 表示
   * @return 验证结果
   */
  AuthResult validate_nonce_hex(const std::string& nonce_hex);

  /**
   * @brief 标记 Nonce 为已使用
   * @param nonce_hex Nonce 的 Hex 表示
   */
  void mark_used(const std::string& nonce_hex);

  /**
   * @brief 检查 Nonce 是否已使用
   * @param nonce_hex Nonce 的 Hex 表示
   * @return true 如果已使用
   */
  bool is_used(const std::string& nonce_hex) const;

  /**
   * @brief 清理过期的已用 Nonce 记录
   * @return 清理的记录数量
   */
  size_t cleanup_expired();

  /**
   * @brief 获取 Nonce 有效期（毫秒）
   */
  uint64_t get_validity_ms() const { return m_nonce_validity_sec * 1000; }

  /**
   * @brief 获取已使用 Nonce 的数量
   */
  size_t used_nonce_count() const;

 private:
  uint64_t m_nonce_validity_sec;

  // 已使用的 Nonce 及其时间戳（用于过期清理）
  std::unordered_map<std::string, uint64_t> m_used_nonces;
  mutable std::shared_mutex m_mutex;
};

}  // namespace oai::amf::did_auth

#endif  // _DID_NONCE_MANAGER_H_
