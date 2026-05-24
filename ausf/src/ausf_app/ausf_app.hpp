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

#ifndef FILE_AUSF_APP_HPP_SEEN
#define FILE_AUSF_APP_HPP_SEEN
#include <pistache/http.h>

#include <cstdint>
#include <map>
#include <memory>
#include <mutex>
#include <shared_mutex>
#include <string>

#include <nlohmann/json.hpp>

#include "AuthenticationInfo.h"
#include "ConfirmationData.h"
#include "UEAuthenticationCtx.h"
#include "ausf.h"
#include "ausf_event.hpp"
#include "did_auth/did_auth.hpp"

namespace oai::common::audit {
class security_audit;
struct security_audit_summary;
}

namespace oai {
namespace ausf {
namespace app {

using namespace oai::model::ausf;

// =========================================================================
// BCF Lifecycle State Machine
// Enforces strict ordering: INIT → DID_READY → REGISTERING → REGISTERED →
//                           AUTHENTICATING → TOKEN_READY
// =========================================================================
enum class BcfLifecycleState {
  INIT = 0,              // AUSF just started, nothing done yet
  DID_READY,             // DID / local keys loaded successfully
  REGISTRATION_IN_PROGRESS,  // BCF registration request sent, waiting response
  BCF_REGISTERED,        // BCF registration response received (success)
  AUTH_IN_PROGRESS,      // BCF auth request sent, waiting for token
  TOKEN_READY,           // BCF auth token obtained and cached
  FAILED                 // Unrecoverable failure
};

// Utility: convert state to string for logging
inline const char* bcf_state_to_string(BcfLifecycleState s) {
  switch (s) {
    case BcfLifecycleState::INIT:                     return "INIT";
    case BcfLifecycleState::DID_READY:                return "DID_READY";
    case BcfLifecycleState::REGISTRATION_IN_PROGRESS: return "REGISTRATION_IN_PROGRESS";
    case BcfLifecycleState::BCF_REGISTERED:           return "BCF_REGISTERED";
    case BcfLifecycleState::AUTH_IN_PROGRESS:          return "AUTH_IN_PROGRESS";
    case BcfLifecycleState::TOKEN_READY:              return "TOKEN_READY";
    case BcfLifecycleState::FAILED:                   return "FAILED";
    default:                                          return "UNKNOWN";
  }
}

class security_context {
 public:
  security_context() : xres_star() {
    // supi       = {};
    ausf_av_s  = {};
    supi_ausf  = "";
    auth_type  = "";
    serving_nn = "";
    kausf_tmp  = "";
  }

  // supi64_t supi;
  AUSF_AV_s ausf_av_s;
  uint8_t xres_star[16];   // store xres*
  std::string supi_ausf;   // store supi
  std::string auth_type;   // store authType
  std::string serving_nn;  // store serving network name
  std::string kausf_tmp;   // store Kausf(string)
};

// class ausf_config;
class ausf_app {
 public:
  explicit ausf_app(const std::string& config_file, ausf_event& ev);
  ausf_app(ausf_app const&) = delete;
  void operator=(ausf_app const&) = delete;

  virtual ~ausf_app();

  bool start();
  void stop();

  void handle_ue_authentications(
      const AuthenticationInfo& authenticationInfo, nlohmann::json& json_data,
      std::string& location, Pistache::Http::Code& code,
      uint8_t http_version = 1);

  void handle_ue_authentications_confirmation(
      const std::string& authCtxId, const ConfirmationData& confirmation_data,
      nlohmann::json& json_data, Pistache::Http::Code& code);

  bool is_supi_2_security_context(const std::string& supi) const;
  std::shared_ptr<security_context> supi_2_security_context(
      const std::string& supi) const;
  void set_supi_2_security_context(
      const std::string& supi, std::shared_ptr<security_context> sc);

  bool is_contextId_2_security_context(const std::string& contextId) const;
  std::shared_ptr<security_context> contextId_2_security_context(
      const std::string& contextId) const;
  void set_contextId_2_security_context(
      const std::string& contextId, std::shared_ptr<security_context> sc);

 private:
  ausf_event& event_sub;
  std::map<supi64_t, std::shared_ptr<security_context>> imsi2security_context;
  mutable std::shared_mutex m_imsi2security_context;

  std::map<std::string, std::shared_ptr<security_context>>
      supi2security_context;
  mutable std::shared_mutex m_supi2security_context;

  std::map<std::string, std::shared_ptr<security_context>>
      contextId2security_context;
  mutable std::shared_mutex m_contextId2security_context;

  // BCF Authentication Module
  std::unique_ptr<oai::ausf::did_auth::DIDAuth> m_did_auth;
  bool m_did_auth_enabled;
  std::string m_hardware_id;  // Hardware ID from extended profile (generated by did-proxy)
  std::unique_ptr<oai::common::audit::security_audit> m_security_audit;

  // BCF Lifecycle State Machine — protects registration → authentication ordering
  BcfLifecycleState m_bcf_state;
  mutable std::mutex m_bcf_state_mutex;

 public:
  //============================================================================
  // BCF Lifecycle State Machine Accessors
  //============================================================================

  /*
   * Check if BCF authentication is enabled
   * @return true if BCF auth is enabled
   */
  bool is_did_auth_enabled() const { return m_did_auth_enabled; }

  std::string get_local_did() const;
  std::string get_nf_instance_id() const;

  oai::common::audit::security_audit* get_security_audit() const {
    return m_security_audit.get();
  }

  void init_security_audit_module();
  bool submit_security_audit_summary(
      const oai::common::audit::security_audit_summary& summary,
      std::string& response_body,
      std::uint32_t& response_code);

  /*
   * Get current BCF lifecycle state (thread-safe)
   * @return BcfLifecycleState
   */
  BcfLifecycleState get_bcf_state() const;

  /*
   * Check if AUSF is registered with BCF (state >= BCF_REGISTERED and not FAILED)
   * @return true if registered
   */
  bool is_bcf_registered() const;

  /*
   * Trigger BCF authentication after registration is confirmed
   * Called ONLY from the BCF registration response handler
   */
  void trigger_bcf_auth_after_registration();

  /*
   * Get hardware ID loaded from extended profile
   * @return std::string: The hardware ID (64 hex chars), or empty if not loaded
   */
  std::string get_hardware_id() const { return m_hardware_id; }

  /*
   * Initialize BCF authentication module
   * @return true if initialization successful
   */
  bool init_did_auth_module();

  /*
   * Cleanup expired BCF authentication sessions and nonces
   * @return void
   */
  void cleanup_did_auth_sessions();

  // =========================================================================
  // BCF 自身认证接口（新版 - NF 认证自身身份）
  // =========================================================================

  /*
   * 向 BCF 发起自身认证（获取 NF 自身的 BCF 身份 token）
   * @param [std::string&] auth_token: 输出认证 self token
   * @return true 如果认证成功
   */
  bool authenticate_to_bcf(std::string& auth_token);

  /*
   * 确保已通过 BCF 认证（有缓存则用缓存）
   * @param [std::string&] auth_token: 输出认证 self token
   * @return true 如果有有效 token
   */
  bool ensure_bcf_auth(std::string& auth_token);
};
}  // namespace app
}  // namespace ausf
}  // namespace oai
#include "ausf_config.hpp"

#endif /* FILE_AUSF_APP_HPP_SEEN */
