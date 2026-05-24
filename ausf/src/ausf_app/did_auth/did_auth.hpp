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

#ifndef _AUSF_DID_AUTH_H_
#define _AUSF_DID_AUTH_H_

#include "bcf_interface.hpp"
#include "bcf_auth_client.hpp"
#include "did_auth_types.hpp"
#include "did_crypto.hpp"

#include <functional>
#include <map>
#include <memory>
#include <mutex>
#include <shared_mutex>
#include <string>
#include <unordered_map>

namespace oai::ausf::did_auth {

/**
 * @brief HTTP 请求回调函数类型
 * 用于向 BCF 发送 HTTP 请求，由外部模块实现
 */
using http_request_callback_t = std::function<bool(
    const std::string& uri, const std::string& method, const std::string& body,
    std::string& response_body, uint32_t& response_code)>;

/**
 * @brief BCF 认证核心模块
 *
 * 提供基于 DID 的 BCF 自身认证功能：
 * - NF → BCF 自身认证（challenge-response → JWT access token）
 * - DID 密钥管理和签名操作
 * - BCF 公钥查询（通过回调）
 * - NF 端点配置管理
 */
class did_auth_module {
 public:
  did_auth_module(
      const std::string& local_did, const std::string& local_nf_type,
      const std::string& local_nf_instance_id,
      const std::string& private_key_hex);

  ~did_auth_module();

  bool is_initialized() const;

  // =========================================================================
  // BCF 回调设置
  // =========================================================================

  void set_public_key_query_callback(public_key_query_callback_t callback);

  // =========================================================================
  // NF 地址配置接口
  // =========================================================================

  void configure_nf_endpoint(
      const std::string& nf_type,
      const std::string& uri_root,
      const std::string& api_version = "v1");

  std::string get_configured_nf_uri(const std::string& nf_type) const;

  std::string build_nf_api_uri(
      const std::string& nf_type,
      const std::string& api_path) const;

  // =========================================================================
  // 维护操作
  // =========================================================================

  void cleanup();

  std::string get_local_did() const { return m_local_did; }
  std::string get_local_nf_type() const { return m_local_nf_type; }
  std::string get_local_nf_instance_id() const { return m_local_nf_instance_id; }

  void preload_public_key(const std::string& did, const std::string& public_key);

  // =========================================================================
  // BCF 自身认证接口
  // =========================================================================

  void configure_bcf_auth(
      const std::string& bcf_uri,
      const std::string& api_version = "v1");

  void set_bcf_auth_http_callback(BcfAuthClient::http_send_callback_t callback);

  BcfAuthResult authenticate_via_bcf(std::string& auth_token);
  BcfAuthResult ensure_bcf_authenticated(std::string& auth_token);

  BcfAuthClient* get_bcf_auth_client() { return m_bcf_auth_client.get(); }
  did_crypto* get_crypto() { return m_crypto.get(); }

 private:
  std::string m_local_did;
  std::string m_local_nf_type;
  std::string m_local_nf_instance_id;
  std::string m_local_locality;

  std::unique_ptr<did_crypto> m_crypto;

  public_key_query_callback_t m_public_key_query_callback;
  std::unique_ptr<BcfAuthClient> m_bcf_auth_client;

  struct nf_endpoint_config_t {
    std::string uri_root;
    std::string api_version;
  };
  std::unordered_map<std::string, nf_endpoint_config_t> m_nf_endpoints;
  mutable std::shared_mutex m_endpoints_mutex;

  std::unordered_map<std::string, std::string> m_public_key_cache;
  mutable std::shared_mutex m_cache_mutex;

  bool m_initialized;

  std::string get_public_key_for_did(const std::string& did);
  std::string sign_data(const std::string& data_hex);
  bool verify_signature(
      const std::string& data_hex, const std::string& signature_hex,
      const std::string& public_key_hex);
};

// =============================================================================
// DIDAuth - 高级包装类，提供简化的 API 接口
// =============================================================================

/**
 * @brief BCF 认证高级接口类
 *
 * 提供简化的 API，用于与 ausf_app 集成。
 * 仅支持 NF → BCF 自身认证（challenge-response → JWT access token）。
 */
class DIDAuth {
 public:
  DIDAuth(
      const std::string& local_did,
      const std::string& private_key_path,
      const std::string& nf_type = "AUSF",
      const std::string& nf_instance_id = "");

  ~DIDAuth();

  bool initialize();

  void set_http_request_callback(http_request_callback_t callback);
  void set_public_key_query_callback(public_key_query_callback_t callback);

  void configure_nf_endpoint(
      const std::string& nf_type,
      const std::string& uri_root,
      const std::string& api_version = "v1");

  std::string get_configured_nf_uri(const std::string& nf_type) const;

  void cleanup_expired_sessions();

  std::string get_local_did() const { return m_local_did; }
  std::string get_nf_instance_id() const { return m_nf_instance_id; }
  std::string get_nf_type() const { return m_nf_type; }
  did_auth_module* get_module() { return m_module.get(); }

  // =========================================================================
  // BCF 自身认证接口
  // =========================================================================

  void configure_bcf_auth(
      const std::string& bcf_uri,
      const std::string& api_version = "v1");

  bool authenticate_to_bcf(std::string& auth_token);
  bool ensure_bcf_auth(std::string& auth_token);
  bool has_valid_bcf_token() const;
  BcfAuthClient* get_bcf_auth_client();

 private:
  std::string m_local_did;
  std::string m_private_key_path;
  std::string m_nf_type;
  std::string m_nf_instance_id;

  std::unique_ptr<did_auth_module> m_module;
  bool m_initialized;

  http_request_callback_t m_http_callback;
};

}  // namespace oai::ausf::did_auth

#endif  // _AUSF_DID_AUTH_H_
