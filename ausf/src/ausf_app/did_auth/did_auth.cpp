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

#include "did_auth.hpp"

#include <fstream>
#include <stdexcept>

#include <nlohmann/json.hpp>

#include "logger.hpp"
#include "signature_utils.hpp"

namespace oai::ausf::did_auth {

// =============================================================================
// BCF Auth Module Implementation
// =============================================================================

//------------------------------------------------------------------------------
did_auth_module::did_auth_module(
    const std::string& local_did, const std::string& local_nf_type,
    const std::string& local_nf_instance_id, const std::string& private_key_hex)
    : m_local_did(local_did),
      m_local_nf_type(local_nf_type),
      m_local_nf_instance_id(local_nf_instance_id),
      m_initialized(false) {
  try {
    Logger::ausf_app().debug(
        "[Identity] Initializing with DID=%s, key_len=%zu",
        local_did.c_str(), private_key_hex.size());

    // Initialize crypto module with private key
    m_crypto = std::make_unique<did_crypto>(private_key_hex);
    Logger::ausf_app().debug("[Crypto] Crypto module initialized");

    m_initialized = true;
    Logger::ausf_app().info("[BCF Auth] Module initialization complete");
  } catch (const std::exception& e) {
    Logger::ausf_app().error(
        "[BCF Auth] Module initialization failed: %s", e.what());
    m_initialized = false;
  }
}

//------------------------------------------------------------------------------
did_auth_module::~did_auth_module() {}

//------------------------------------------------------------------------------
bool did_auth_module::is_initialized() const {
  return m_initialized && m_crypto && m_crypto->has_private_key();
}

//------------------------------------------------------------------------------
void did_auth_module::set_public_key_query_callback(
    public_key_query_callback_t callback) {
  m_public_key_query_callback = std::move(callback);
}

//------------------------------------------------------------------------------
void did_auth_module::configure_nf_endpoint(
    const std::string& nf_type,
    const std::string& uri_root,
    const std::string& api_version) {
  std::unique_lock<std::shared_mutex> lock(m_endpoints_mutex);
  m_nf_endpoints[nf_type] = {uri_root, api_version};
}

//------------------------------------------------------------------------------
std::string did_auth_module::get_configured_nf_uri(
    const std::string& nf_type) const {
  std::shared_lock<std::shared_mutex> lock(m_endpoints_mutex);
  auto it = m_nf_endpoints.find(nf_type);
  if (it != m_nf_endpoints.end()) {
    return it->second.uri_root;
  }
  return "";
}

//------------------------------------------------------------------------------
std::string did_auth_module::build_nf_api_uri(
    const std::string& nf_type,
    const std::string& api_path) const {
  std::shared_lock<std::shared_mutex> lock(m_endpoints_mutex);
  auto it = m_nf_endpoints.find(nf_type);
  if (it == m_nf_endpoints.end()) {
    return "";
  }
  return it->second.uri_root + api_path;
}

//------------------------------------------------------------------------------
std::string did_auth_module::get_public_key_for_did(const std::string& did) {
  // Check cache first
  {
    std::shared_lock<std::shared_mutex> lock(m_cache_mutex);
    auto it = m_public_key_cache.find(did);
    if (it != m_public_key_cache.end()) {
      return it->second;
    }
  }

  // Query BCF via callback
  if (m_public_key_query_callback) {
    auto response = m_public_key_query_callback(did);
    if (response.found && !response.public_key.empty()) {
      std::unique_lock<std::shared_mutex> lock(m_cache_mutex);
      m_public_key_cache[did] = response.public_key;
      return response.public_key;
    }
  }

  return "";
}

//------------------------------------------------------------------------------
std::string did_auth_module::sign_data(const std::string& data_hex) {
  if (!m_crypto) {
    Logger::ausf_app().error("[BCF Auth] Crypto not initialized");
    return "";
  }

  std::string signature = signature_utils::sign_challenge_with_logging(
      data_hex, m_crypto->get_private_key_bytes());

  if (signature.empty()) {
    Logger::ausf_app().debug("[BCF Auth] Trying fallback signing...");
    signature = m_crypto->sign_hex(data_hex);
  }

  return signature;
}

//------------------------------------------------------------------------------
bool did_auth_module::verify_signature(
    const std::string& data_hex, const std::string& signature_hex,
    const std::string& public_key_hex) {
  bool result = signature_utils::verify_challenge_with_logging(
      data_hex, signature_hex, public_key_hex);
  return result;
}

//------------------------------------------------------------------------------
void did_auth_module::cleanup() {
  // Cleanup expired BCF tokens
  if (m_bcf_auth_client) {
    m_bcf_auth_client->cleanup_expired_tokens();
  }
}

//------------------------------------------------------------------------------
void did_auth_module::preload_public_key(
    const std::string& did, const std::string& public_key) {
  std::unique_lock<std::shared_mutex> lock(m_cache_mutex);
  m_public_key_cache[did] = public_key;
}

// =============================================================================
// BCF 自身认证实现
// =============================================================================

//------------------------------------------------------------------------------
void did_auth_module::configure_bcf_auth(
    const std::string& bcf_uri,
    const std::string& api_version) {
  if (!m_bcf_auth_client) {
    m_bcf_auth_client = std::make_unique<BcfAuthClient>();
  }

  m_bcf_auth_client->set_bcf_uri(bcf_uri);
  m_bcf_auth_client->set_bcf_api_version(api_version);
  m_bcf_auth_client->set_local_nf_info(
      m_local_did, m_local_nf_type, m_local_nf_instance_id);

  if (m_crypto) {
    m_bcf_auth_client->set_crypto(m_crypto.get());
  }

  Logger::ausf_app().info(
      "[BCF Auth] Configured BCF auth client: bcf_uri=%s, api_version=%s",
      bcf_uri.c_str(), api_version.c_str());
}

//------------------------------------------------------------------------------
void did_auth_module::set_bcf_auth_http_callback(
    BcfAuthClient::http_send_callback_t callback) {
  if (!m_bcf_auth_client) {
    m_bcf_auth_client = std::make_unique<BcfAuthClient>();
  }
  m_bcf_auth_client->set_http_callback(std::move(callback));
}

//------------------------------------------------------------------------------
BcfAuthResult did_auth_module::authenticate_via_bcf(
    std::string& auth_token) {
  if (!is_initialized()) {
    Logger::ausf_app().error("[BCF Auth] Module not initialized");
    return BcfAuthResult::FAILURE_INTERNAL_ERROR;
  }

  if (!m_bcf_auth_client) {
    Logger::ausf_app().error(
        "[BCF Auth] BCF auth client not configured. "
        "Call configure_bcf_auth() first");
    return BcfAuthResult::FAILURE_INTERNAL_ERROR;
  }

  return m_bcf_auth_client->authenticate(auth_token);
}

//------------------------------------------------------------------------------
BcfAuthResult did_auth_module::ensure_bcf_authenticated(
    std::string& auth_token) {
  if (!is_initialized()) {
    Logger::ausf_app().error("[BCF Auth] Module not initialized");
    return BcfAuthResult::FAILURE_INTERNAL_ERROR;
  }

  if (!m_bcf_auth_client) {
    Logger::ausf_app().error(
        "[BCF Auth] BCF auth client not configured. "
        "Call configure_bcf_auth() first");
    return BcfAuthResult::FAILURE_INTERNAL_ERROR;
  }

  return m_bcf_auth_client->ensure_authenticated(auth_token);
}

// =============================================================================
// DIDAuth - High-level wrapper class implementation
// =============================================================================

//------------------------------------------------------------------------------
DIDAuth::DIDAuth(
    const std::string& local_did,
    const std::string& private_key_path,
    const std::string& nf_type,
    const std::string& nf_instance_id)
    : m_local_did(local_did),
      m_private_key_path(private_key_path),
      m_nf_type(nf_type),
      m_nf_instance_id(nf_instance_id),
      m_initialized(false) {}

//------------------------------------------------------------------------------
DIDAuth::~DIDAuth() {}

//------------------------------------------------------------------------------
bool DIDAuth::initialize() {
  try {
    std::string private_key_hex;

    std::ifstream key_file(m_private_key_path);
    if (!key_file.is_open()) {
      Logger::ausf_app().warn(
          "Private key file not found: %s, BCF Auth will use placeholder key",
          m_private_key_path.c_str());
      private_key_hex = "0000000000000000000000000000000000000000000000000000000000000001";
    } else {
      std::getline(key_file, private_key_hex);
      key_file.close();

      private_key_hex.erase(0, private_key_hex.find_first_not_of(" \t\n\r"));
      private_key_hex.erase(private_key_hex.find_last_not_of(" \t\n\r") + 1);

      if (private_key_hex.length() != 64) {
        Logger::ausf_app().error(
            "Invalid private key format in %s, expected 64 hex characters, got %zu",
            m_private_key_path.c_str(), private_key_hex.length());
        return false;
      }

      Logger::ausf_app().debug("Read private key from file: %s", m_private_key_path.c_str());
    }

    Logger::ausf_app().debug(
        "[BCF Auth] Creating auth module with nf_type=%s, nf_instance_id=%s",
        m_nf_type.c_str(), m_nf_instance_id.c_str());

    m_module = std::make_unique<did_auth_module>(
        m_local_did,
        m_nf_type,
        m_nf_instance_id,
        private_key_hex);

    m_initialized = m_module && m_module->is_initialized();

    if (!m_initialized) {
      Logger::ausf_app().error("[BCF Auth] Module initialization returned false");
    }

    return m_initialized;

  } catch (const std::exception& e) {
    Logger::ausf_app().error("BCF Auth initialize exception: %s", e.what());
    m_initialized = false;
    return false;
  }
}

//------------------------------------------------------------------------------
void DIDAuth::set_public_key_query_callback(
    public_key_query_callback_t callback) {
  if (m_module) {
    m_module->set_public_key_query_callback(std::move(callback));
  }
}

//------------------------------------------------------------------------------
void DIDAuth::configure_nf_endpoint(
    const std::string& nf_type,
    const std::string& uri_root,
    const std::string& api_version) {
  if (m_module) {
    m_module->configure_nf_endpoint(nf_type, uri_root, api_version);
  }
}

//------------------------------------------------------------------------------
std::string DIDAuth::get_configured_nf_uri(const std::string& nf_type) const {
  if (m_module) {
    return m_module->get_configured_nf_uri(nf_type);
  }
  return "";
}

//------------------------------------------------------------------------------
void DIDAuth::set_http_request_callback(http_request_callback_t callback) {
  m_http_callback = std::move(callback);
  Logger::ausf_app().debug("HTTP request callback set for BCF Auth module");
}

//------------------------------------------------------------------------------
void DIDAuth::cleanup_expired_sessions() {
  if (m_initialized && m_module) {
    m_module->cleanup();
  }

  // Also cleanup BCF auth token cache
  if (m_module && m_module->get_bcf_auth_client()) {
    m_module->get_bcf_auth_client()->cleanup_expired_tokens();
  }
}

// =============================================================================
// DIDAuth - BCF 自身认证接口实现
// =============================================================================

//------------------------------------------------------------------------------
void DIDAuth::configure_bcf_auth(
    const std::string& bcf_uri,
    const std::string& api_version) {
  if (!m_initialized || !m_module) {
    Logger::ausf_app().error("[BCF Auth] Cannot configure BCF auth: module not initialized");
    return;
  }

  m_module->configure_bcf_auth(bcf_uri, api_version);

  // Reuse existing HTTP callback for BCF auth client
  if (m_http_callback && m_module->get_bcf_auth_client()) {
    m_module->get_bcf_auth_client()->set_http_callback(
        [this](const std::string& uri, const std::string& method,
               const std::string& body, std::string& response_body,
               uint32_t& response_code) -> bool {
          return m_http_callback(uri, method, body, response_body, response_code);
        });
  }

  Logger::ausf_app().info(
      "[BCF Auth] BCF authentication configured: bcf_uri=%s",
      bcf_uri.c_str());
}

//------------------------------------------------------------------------------
bool DIDAuth::authenticate_to_bcf(std::string& auth_token) {
  if (!m_initialized || !m_module) {
    Logger::ausf_app().error("[BCF Auth] Module not initialized");
    return false;
  }

  BcfAuthResult result = m_module->authenticate_via_bcf(auth_token);

  if (result != BcfAuthResult::SUCCESS) {
    Logger::ausf_app().error(
        "[BCF Auth] Authentication failed: %s",
        bcf_auth_result_to_string(result).c_str());
    return false;
  }

  return true;
}

//------------------------------------------------------------------------------
bool DIDAuth::ensure_bcf_auth(std::string& auth_token) {
  if (!m_initialized || !m_module) {
    Logger::ausf_app().error("[BCF Auth] Module not initialized");
    return false;
  }

  BcfAuthResult result = m_module->ensure_bcf_authenticated(auth_token);

  return result == BcfAuthResult::SUCCESS;
}

//------------------------------------------------------------------------------
bool DIDAuth::has_valid_bcf_token() const {
  if (!m_initialized || !m_module) {
    return false;
  }

  auto* client = const_cast<did_auth_module*>(m_module.get())->get_bcf_auth_client();
  if (!client) {
    return false;
  }

  return client->has_valid_token();
}

//------------------------------------------------------------------------------
BcfAuthClient* DIDAuth::get_bcf_auth_client() {
  if (!m_module) {
    return nullptr;
  }
  return m_module->get_bcf_auth_client();
}

}  // namespace oai::ausf::did_auth
