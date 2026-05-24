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

#include <algorithm>
#include <chrono>
#include <cctype>
#include <cstdlib>
#include <fstream>
#include <optional>
#include <stdexcept>

#include "logger.hpp"
#include "signature_utils.hpp"
#include "target_nf_cache.hpp"

namespace oai::amf::did_auth {

namespace {

std::string normalize_target_nf_uri(const std::string& uri) {
  if (uri.empty()) {
    return {};
  }

  if (uri.rfind("http://", 0) == 0 || uri.rfind("https://", 0) == 0) {
    return uri;
  }

  return "http://" + uri;
}

nlohmann::json normalize_target_nf_profile_json(
    const nlohmann::json& target, const std::string& fallback_nf_type) {
  nlohmann::json profile = target.is_object() ? target : nlohmann::json::object();

  if (!profile.contains("nfInstanceId") && profile.contains("nf_instance_id")) {
    profile["nfInstanceId"] = profile["nf_instance_id"];
  }
  if (!profile.contains("nfType") && profile.contains("nf_type")) {
    profile["nfType"] = profile["nf_type"];
  }
  if (!profile.contains("nfStatus") && profile.contains("nf_status")) {
    profile["nfStatus"] = profile["nf_status"];
  }
  if (!profile.contains("did") && profile.contains("nf_did")) {
    profile["did"] = profile["nf_did"];
  }
  if (!profile.contains("publicKey") && profile.contains("public_key")) {
    profile["publicKey"] = profile["public_key"];
  }
  if (!profile.contains("plmnList") && profile.contains("plmn_list")) {
    profile["plmnList"] = profile["plmn_list"];
  }
  if (!profile.contains("sNssais")) {
    if (profile.contains("snssai_list")) {
      profile["sNssais"] = profile["snssai_list"];
    } else if (profile.contains("snssais")) {
      profile["sNssais"] = profile["snssais"];
    }
  }
  if (!profile.contains("perPlmnSnssaiList") &&
      profile.contains("per_plmn_snssai_list")) {
    profile["perPlmnSnssaiList"] = profile["per_plmn_snssai_list"];
  }
  if (!profile.contains("nsiList") && profile.contains("nsi_list")) {
    profile["nsiList"] = profile["nsi_list"];
  }
  if (!profile.contains("ipv4Addresses") &&
      profile.contains("ipv4_addresses")) {
    profile["ipv4Addresses"] = profile["ipv4_addresses"];
  }
  if (!profile.contains("ipv6Addresses") &&
      profile.contains("ipv6_addresses")) {
    profile["ipv6Addresses"] = profile["ipv6_addresses"];
  }
  if (!profile.contains("nfServices") && profile.contains("nf_services")) {
    profile["nfServices"] = profile["nf_services"];
  }
  if (!profile.contains("nfType") && !fallback_nf_type.empty()) {
    profile["nfType"] = fallback_nf_type;
  }

  if (profile.contains("nfServices") && profile["nfServices"].is_array()) {
    for (auto& svc : profile["nfServices"]) {
      if (!svc.is_object()) {
        continue;
      }

      if (!svc.contains("serviceInstanceId") &&
          svc.contains("service_instance_id")) {
        svc["serviceInstanceId"] = svc["service_instance_id"];
      }
      if (!svc.contains("serviceName") && svc.contains("service_name")) {
        svc["serviceName"] = svc["service_name"];
      }
      if (!svc.contains("apiPrefix") && svc.contains("api_prefix")) {
        svc["apiPrefix"] = svc["api_prefix"];
      }
      if (!svc.contains("ipEndPoints") && svc.contains("ip_end_points")) {
        svc["ipEndPoints"] = svc["ip_end_points"];
      }

      if (svc.contains("ipEndPoints") && svc["ipEndPoints"].is_array()) {
        for (auto& endpoint : svc["ipEndPoints"]) {
          if (!endpoint.is_object()) {
            continue;
          }

          if (!endpoint.contains("ipv4Address") &&
              endpoint.contains("ipv4_address")) {
            endpoint["ipv4Address"] = endpoint["ipv4_address"];
          }
          if (!endpoint.contains("ipv6Address") &&
              endpoint.contains("ipv6_address")) {
            endpoint["ipv6Address"] = endpoint["ipv6_address"];
          }
        }
      }
    }
  }

  if (profile.contains("perPlmnSnssaiList") &&
      profile["perPlmnSnssaiList"].is_array()) {
    for (auto& item : profile["perPlmnSnssaiList"]) {
      if (!item.is_object()) {
        continue;
      }

      if (!item.contains("plmnId") && item.contains("plmn_id")) {
        item["plmnId"] = item["plmn_id"];
      }
      if (!item.contains("sNssaiList")) {
        if (item.contains("snssai_list")) {
          item["sNssaiList"] = item["snssai_list"];
        } else if (item.contains("snssais")) {
          item["sNssaiList"] = item["snssais"];
        }
      }
    }
  }

  return profile;
}

std::string extract_target_nf_uri_from_json(const nlohmann::json& target) {
  std::string uri = target.value("nf_uri", target.value("fqdn", ""));

  if (uri.empty() && target.contains("nfServices") &&
      target["nfServices"].is_array()) {
    for (const auto& svc : target["nfServices"]) {
      if (!svc.is_object()) {
        continue;
      }

      std::string service_name = svc.value("serviceName", "");
      if (!service_name.empty() && service_name != "nausf-auth") {
        continue;
      }

      if (svc.contains("apiPrefix") && svc["apiPrefix"].is_string()) {
        uri = svc["apiPrefix"].get<std::string>();
        break;
      }

      if (svc.contains("fqdn") && svc["fqdn"].is_string()) {
        const std::string scheme = svc.value("scheme", "http");
        uri = scheme + "://" + svc["fqdn"].get<std::string>();
        break;
      }

      if (svc.contains("ipEndPoints") && svc["ipEndPoints"].is_array() &&
          !svc["ipEndPoints"].empty() && svc["ipEndPoints"][0].is_object()) {
        const auto& ep = svc["ipEndPoints"][0];
        const std::string scheme = svc.value("scheme", "http");
        const std::string host   = ep.value("ipv4Address", "");
        const int port           = ep.value("port", 0);
        if (!host.empty()) {
          uri = scheme + "://" + host;
          if (port > 0) {
            uri += ":" + std::to_string(port);
          }
          break;
        }
      }
    }
  }

  if (uri.empty() && target.contains("ipv4Addresses") &&
      target["ipv4Addresses"].is_array() && !target["ipv4Addresses"].empty() &&
      target["ipv4Addresses"][0].is_string()) {
    uri = "http://" + target["ipv4Addresses"][0].get<std::string>();
  }

  if (uri.empty() && target.contains("ipEndPoints") &&
      target["ipEndPoints"].is_array() && !target["ipEndPoints"].empty() &&
      target["ipEndPoints"][0].is_object()) {
    const auto& ep          = target["ipEndPoints"][0];
    const std::string host  = ep.value("ipv4Address", "");
    const int port          = ep.value("port", 0);
    if (!host.empty()) {
      uri = "http://" + host;
      if (port > 0) {
        uri += ":" + std::to_string(port);
      }
    }
  }

  return normalize_target_nf_uri(uri);
}

target_nf_entry_t build_target_nf_entry(
    const nlohmann::json& target, const std::string& fallback_nf_type,
    const uint64_t last_seen_ms) {
  target_nf_entry_t entry = {};
  nlohmann::json profile_json =
      normalize_target_nf_profile_json(target, fallback_nf_type);

  if (profile_json.is_object()) {
    entry.nf_profile     = oai::common::bcf::NfProfile::from_json(profile_json);
    entry.has_nf_profile = !entry.nf_profile.nf_instance_id.empty();
  }

  entry.nf_instance_id = target.value(
      "nf_instance_id", profile_json.value("nfInstanceId", ""));
  if (entry.nf_instance_id.empty() && entry.has_nf_profile) {
    entry.nf_instance_id = entry.nf_profile.nf_instance_id;
  }

  entry.nf_type = target.value("nf_type", profile_json.value("nfType", ""));
  if (entry.nf_type.empty() && entry.has_nf_profile) {
    entry.nf_type = oai::common::bcf::nf_type_to_string(entry.nf_profile.nf_type);
  }
  if (entry.nf_type.empty()) {
    entry.nf_type = fallback_nf_type;
  }

  entry.nf_did =
      target.value("nf_did", profile_json.value("did", std::string("")));
  if (entry.nf_did.empty() && entry.has_nf_profile) {
    entry.nf_did = entry.nf_profile.did;
  }

  entry.nf_uri       = extract_target_nf_uri_from_json(target);
  entry.last_seen_ms = last_seen_ms;
  return entry;
}

}  // namespace

//------------------------------------------------------------------------------
did_auth_module::did_auth_module(
    const std::string& local_did, const std::string& local_nf_type,
    const std::string& local_nf_instance_id, const std::string& private_key_hex)
    : m_local_did(local_did),
      m_local_nf_type(local_nf_type),
      m_local_nf_instance_id(local_nf_instance_id),
      m_initialized(false) {
  try {
    Logger::amf_app().debug(
        "[Identity] Initializing with DID=%s, key_len=%zu",
        local_did.c_str(), private_key_hex.size());

    // Initialize crypto module with private key
    m_crypto = std::make_unique<did_crypto>(private_key_hex);
    Logger::amf_app().debug("[Crypto] Crypto module initialized");

    // Initialize session manager (5 min timeout, 1 hour token validity)
    m_session_mgr = std::make_unique<did_session_manager>(300, 3600);
    Logger::amf_app().debug("[Identity] Session manager initialized");

    // Initialize challenge manager (5 min validity)
    m_nonce_mgr = std::make_unique<did_nonce_manager>(300);
    Logger::amf_app().debug("[Identity] Challenge manager initialized");

    // Note: BCF callbacks must be set by caller via set_public_key_query_callback()
    // before using authentication. NF endpoints are configured directly via
    // configure_nf_endpoint() rather than using dynamic discovery.

    m_initialized = true;
    Logger::amf_app().info("[Identity] BCF auth module initialization complete");
    // Initialize target NF cache
    m_target_nf_cache = std::make_unique<TargetNfCache>();
  } catch (const std::exception& e) {
    Logger::amf_app().error(
        "[Identity] BCF auth module initialization failed: %s", e.what());
    m_initialized = false;
  }
}

//------------------------------------------------------------------------------
bool did_auth_module::handle_bcf_notification(const std::string& body_json) {
  try {
    nlohmann::json j = nlohmann::json::parse(body_json);

    Logger::amf_app().info(
        "[BCF Notification] Notification body: %s", body_json.c_str());

    std::string event_type = j.value("event_type", j.value("event", ""));
    auto target = j.value(
        "target_nf_profile", j.value("target", nlohmann::json::object()));
    if (!target.is_object()) {
      target = nlohmann::json::object();
    }

    std::string normalized_event_type = event_type;
    std::transform(
        normalized_event_type.begin(), normalized_event_type.end(),
        normalized_event_type.begin(), [](unsigned char c) {
          return std::toupper(c);
        });
    const bool is_deregister_event =
        normalized_event_type.find("DEREGISTER") != std::string::npos;

    const uint64_t current_time_ms =
        static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::milliseconds>(
                                 std::chrono::system_clock::now().time_since_epoch())
                                 .count());

    if (is_deregister_event && target.is_object()) {
      target["nfStatus"] = "DEREGISTERED";
      if (!target.contains("deregistrationTime")) {
        target["deregistrationTime"] =
            j.value("timestamp_ms", current_time_ms);
      }
    }

    const std::string nf_type = target.value(
        "nf_type", target.value("nfType", j.value("target_nf_type", "")));
    const std::string nf_instance_id = target.value(
        "nf_instance_id", target.value(
                              "nfInstanceId", j.value("target_nf_instance_id", "")));

    if (!nf_instance_id.empty() && !target.contains("nfInstanceId") &&
        !target.contains("nf_instance_id")) {
      target["nfInstanceId"] = nf_instance_id;
    }
    if (!nf_type.empty() && !target.contains("nfType") &&
        !target.contains("nf_type")) {
      target["nfType"] = nf_type;
    }

    const std::string target_nf_did = j.value("target_nf_did", "");
    if (!target_nf_did.empty() && !target.contains("did") &&
        !target.contains("nf_did")) {
      target["did"] = target_nf_did;
    }

    const std::string target_nf_uri = j.value("target_nf_uri", "");
    if (!target_nf_uri.empty() && !target.contains("nf_uri") &&
        !target.contains("fqdn")) {
      target["nf_uri"] = target_nf_uri;
    }

    const uint64_t last_seen_ms =
        static_cast<uint64_t>(j.value("timestamp_ms", current_time_ms));
    target_nf_entry_t entry =
        build_target_nf_entry(target, nf_type, last_seen_ms);

    if (entry.nf_instance_id.empty()) {
      Logger::amf_app().warn("[BCF Notification] Missing target.nf_instance_id");
      return false;
    }

    // On deregistration events, remove from cache; otherwise upsert/update
    if (is_deregister_event) {
      m_target_nf_cache->remove(entry.nf_instance_id);
      Logger::amf_app().info(
          "[BCF Notification] Removed TargetNfCache entry: %s (%s) event=%s",
          entry.nf_instance_id.c_str(), entry.nf_type.c_str(),
          event_type.c_str());
      return true;
    }

    m_target_nf_cache->upsert(entry);
    Logger::amf_app().info(
        "[BCF Notification] Updated TargetNfCache: %s (%s) event=%s",
        entry.nf_instance_id.c_str(), entry.nf_type.c_str(), event_type.c_str());
    return true;
  } catch (const std::exception& e) {
    Logger::amf_app().error("[BCF Notification] Failed to parse/handle notification: %s", e.what());
    return false;
  }
}

//------------------------------------------------------------------------------
bool did_auth_module::handle_subscription_response(const nlohmann::json& resp_json) {
  try {
    if (!resp_json.is_object()) return false;
    if (!resp_json.contains("target_nf_list") || !resp_json["target_nf_list"].is_array()) return false;

    for (const auto& it : resp_json["target_nf_list"]) {
      // Each item may be either a minimal target or a full nfProfile
      nlohmann::json profile = it;
      if (it.is_object() && it.contains("nfProfile")) {
        profile = it["nfProfile"];
      }

      if (!profile.is_object()) continue;

      target_nf_entry_t entry = build_target_nf_entry(
          profile, profile.value("nfType", profile.value("nf_type", "")),
          static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::milliseconds>(
              std::chrono::system_clock::now().time_since_epoch())
              .count()));
      if (entry.nf_instance_id.empty()) continue;

      m_target_nf_cache->upsert(entry);
      Logger::amf_app().info(
          "[BCF Subscription] Cached target NF: %s (%s)",
          entry.nf_instance_id.c_str(), entry.nf_type.c_str());
    }

    return true;
  } catch (const std::exception& e) {
    Logger::amf_app().error("[BCF Subscription] Failed to handle subscription response: %s", e.what());
    return false;
  }
}

//------------------------------------------------------------------------------
did_auth_module::~did_auth_module() {}

//------------------------------------------------------------------------------
std::vector<target_nf_entry_t> did_auth_module::get_cached_target_nfs(
    const std::string& nf_type) const {
  if (!m_target_nf_cache) {
    return {};
  }

  return nf_type.empty() ? m_target_nf_cache->list()
                         : m_target_nf_cache->list_by_nf_type(nf_type);
}

//------------------------------------------------------------------------------
bool did_auth_module::is_initialized() const {
  return m_initialized && m_crypto && m_crypto->has_private_key();
}

//------------------------------------------------------------------------------
void did_auth_module::set_public_key_query_callback(public_key_query_callback_t callback) {
  m_public_key_query_callback = std::move(callback);
}

//------------------------------------------------------------------------------
void did_auth_module::configure_nf_endpoint(
    const std::string& nf_type,
    const std::string& uri_root,
    const std::string& api_version) {
  std::unique_lock<std::shared_mutex> lock(m_endpoints_mutex);
  m_nf_endpoints[nf_type] = {uri_root, api_version};
  Logger::amf_app().debug(
      "Configured NF endpoint: type=%s, uri_root=%s, api_version=%s",
      nf_type.c_str(), uri_root.c_str(), api_version.c_str());
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
  if (it != m_nf_endpoints.end()) {
    // uri_root + api_path (api_path already contains version if needed)
    return it->second.uri_root + api_path;
  }
  return "";
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

  // Query via callback
  if (!m_public_key_query_callback) {
    Logger::amf_app().error(
        "Public key query callback not set, cannot query DID: %s", did.c_str());
    return "";
  }

  auto response = m_public_key_query_callback(did);
  if (response.found) {
    // Update cache
    std::unique_lock<std::shared_mutex> lock(m_cache_mutex);
    m_public_key_cache[did] = response.public_key;
    return response.public_key;
  }

  return "";
}

//------------------------------------------------------------------------------
std::string did_auth_module::sign_challenge(const std::string& challenge_hex) {
  if (!m_crypto) {
    Logger::amf_app().error("[Crypto] Crypto module not initialized");
    return "";
  }

  Logger::amf_app().info("[Crypto] ---- sign_challenge called ----");
  Logger::amf_app().info("[Crypto]   challenge_hex (full): %s", challenge_hex.c_str());
  
  // Use signature_utils for standardized signing with detailed logging
  std::string signature = signature_utils::sign_challenge_with_logging(
      challenge_hex, m_crypto->get_private_key_bytes());
  
  if (signature.empty()) {
    Logger::amf_app().error("[Crypto] Primary signing failed, trying fallback...");
    signature = m_crypto->sign_hex(challenge_hex);
  }
  
  Logger::amf_app().info("[Crypto]   signature result (full): %s", signature.c_str());
  return signature;
}

//------------------------------------------------------------------------------
bool did_auth_module::verify_challenge_signature(
    const std::string& challenge_hex, const std::string& signature_hex,
    const std::string& public_key_hex) {
  Logger::amf_app().info("[Crypto] ---- verify_challenge_signature called ----");
  Logger::amf_app().info("[Crypto]   challenge_hex (full): %s", challenge_hex.c_str());
  Logger::amf_app().info("[Crypto]   signature_hex (full): %s", signature_hex.c_str());
  Logger::amf_app().info("[Crypto]   public_key_hex (full): %s", public_key_hex.c_str());
  
  // Use signature_utils for standardized verification with detailed logging
  bool result = signature_utils::verify_challenge_with_logging(
      challenge_hex, signature_hex, public_key_hex);
  
  if (!result) {
    Logger::amf_app().error("[Crypto] Primary verification FAILED");
    // Fall back to original verification for comparison
    Logger::amf_app().info("[Crypto] Trying fallback verification method...");
    bool original_result = did_crypto::verify_hex(challenge_hex, signature_hex, public_key_hex);
    Logger::amf_app().info("[Crypto]   fallback method result: %s", 
                            original_result ? "SUCCESS" : "FAILED");
  } else {
    Logger::amf_app().info("[Crypto] Verification result: SUCCESS");
  }
  
  return result;
}

//------------------------------------------------------------------------------
// Initiator (Client) interface
//------------------------------------------------------------------------------

std::pair<auth_init_request_t, std::string>
did_auth_module::create_auth_init_request(const std::string& remote_endpoint) {
  auth_init_request_t request;

  if (!is_initialized()) {
    return {request, ""};
  }

  // Initiator generates the canonical session_id that will be used throughout
  // the entire authentication flow by both Initiator and Responder
  std::string session_id = m_session_mgr->create_session(
      m_local_did, m_local_nf_type, m_local_nf_instance_id, true);

  // Generate challenge
  nonce_t nonce = m_nonce_mgr->generate_nonce();
  m_session_mgr->set_local_nonce(session_id, nonce);
  m_session_mgr->set_remote_endpoint(session_id, remote_endpoint);

  // Build request - include session_id generated by Initiator
  request.did            = m_local_did;
  request.nf_type        = m_local_nf_type;
  request.nf_instance_id = m_local_nf_instance_id;
  request.nonce          = nonce.to_hex();
  request.session_id     = session_id;  // Initiator provides the session_id

  return {request, session_id};
}

//------------------------------------------------------------------------------
std::pair<auth_complete_request_t, AuthResult>
did_auth_module::process_auth_challenge(
    const std::string& session_id,
    const auth_challenge_response_t& challenge) {
  auth_complete_request_t complete_request;
  complete_request.session_id = session_id;

  // First verify session exists before any other checks
  // This prevents calling update_state() on non-existent sessions
  auto session = m_session_mgr->get_session(session_id);
  if (!session) {
    Logger::amf_app().error(
        "Session not found: %s", session_id.c_str());
    return {complete_request, AuthResult::FAILURE_SESSION_NOT_FOUND};
  }

  // Verify challenge.session_id matches our session_id
  // This prevents session hijacking attacks where an attacker could
  // send a valid challenge from another session
  if (!challenge.session_id.empty() && challenge.session_id != session_id) {
    Logger::amf_app().error(
        "Session ID mismatch in challenge: expected %s, got %s",
        session_id.c_str(), challenge.session_id.c_str());
    m_session_mgr->update_state(session_id, AuthState::AUTH_FAILED);
    return {complete_request, AuthResult::FAILURE_SESSION_MISMATCH};
  }

  // Get remote public key from BCF
  std::string remote_public_key = get_public_key_for_did(challenge.did);
  if (remote_public_key.empty()) {
    m_session_mgr->update_state(session_id, AuthState::AUTH_FAILED);
    return {complete_request, AuthResult::FAILURE_KEY_NOT_FOUND};
  }

  // Store remote info
  m_session_mgr->set_remote_info(
      session_id, challenge.did, challenge.nf_type, challenge.nf_instance_id,
      remote_public_key);

  // Verify responder's signature on our challenge
  std::string our_nonce_hex = session->local_nonce.to_hex();
  if (!verify_challenge_signature(
          our_nonce_hex, challenge.signature, remote_public_key)) {
    m_session_mgr->update_state(session_id, AuthState::AUTH_FAILED);
    return {complete_request, AuthResult::FAILURE_SIGNATURE_INVALID};
  }

  // Remote is now verified (they proved they have the private key for their DID)
  m_session_mgr->update_state(session_id, AuthState::PEER_VERIFIED);

  // Store remote challenge
  nonce_t remote_nonce = nonce_t::from_hex(challenge.nonce);
  m_session_mgr->set_remote_nonce(session_id, remote_nonce);

  // Validate remote challenge
  AuthResult nonce_result = m_nonce_mgr->validate_nonce(remote_nonce);
  if (nonce_result != AuthResult::SUCCESS) {
    m_session_mgr->update_state(session_id, AuthState::AUTH_FAILED);
    return {complete_request, nonce_result};
  }

  // Sign the remote challenge to prove our identity
  std::string our_signature = sign_challenge(challenge.nonce);
  if (our_signature.empty()) {
    m_session_mgr->update_state(session_id, AuthState::AUTH_FAILED);
    return {complete_request, AuthResult::FAILURE_INTERNAL_ERROR};
  }

  // Mark remote challenge as used
  m_nonce_mgr->mark_used(challenge.nonce);

  // Update state
  m_session_mgr->update_state(session_id, AuthState::RESPONSE_SENT);

  // Build complete request
  complete_request.signature = our_signature;

  return {complete_request, AuthResult::SUCCESS};
}

//------------------------------------------------------------------------------
void did_auth_module::process_auth_result(
    const std::string& session_id, const auth_result_response_t& result) {
  auto session = m_session_mgr->get_session(session_id);
  if (!session) {
    return;
  }

  if (result.result == AuthResult::SUCCESS ||
      result.result == AuthResult::MUTUAL_SUCCESS) {
    m_session_mgr->update_state(session_id, AuthState::MUTUAL_AUTH_COMPLETE);

    // Store the auth token from responder (if provided)
    // We might also generate our own token
    if (!result.auth_token.empty()) {
      // Use the token provided by the responder
      session->auth_token        = result.auth_token;
      session->token_expires_at = result.expires_at;
    }
  } else {
    m_session_mgr->update_state(session_id, AuthState::AUTH_FAILED);
  }
}

//------------------------------------------------------------------------------
// Responder (Server) interface
//------------------------------------------------------------------------------

std::pair<auth_challenge_response_t, AuthResult>
did_auth_module::handle_auth_init(const auth_init_request_t& request) {
  auth_challenge_response_t response;
  
  Logger::amf_app().info("[BCF Auth] ========== MODULE: HANDLE_AUTH_INIT ==========");
  Logger::amf_app().info("[BCF Auth] --- Request Parameters (Full) ---");
  Logger::amf_app().info("[BCF Auth]   request.did: %s", request.did.c_str());
  Logger::amf_app().info("[BCF Auth]   request.challenge (full): %s", request.nonce.c_str());
  Logger::amf_app().info("[BCF Auth]   request.nf_type: %s", request.nf_type.c_str());
  Logger::amf_app().info("[BCF Auth]   request.nf_instance_id: %s", request.nf_instance_id.c_str());
  Logger::amf_app().info("[BCF Auth]   request.session_id: %s", request.session_id.c_str());
  Logger::amf_app().info("[BCF Auth]   request.timestamp: %s", request.timestamp.c_str());

  if (!is_initialized()) {
    Logger::amf_app().error("[BCF Auth] Module not initialized");
    return {response, AuthResult::FAILURE_INTERNAL_ERROR};
  }

  // Use the session_id provided by Initiator
  // The Initiator generates the canonical session_id for the entire auth flow
  std::string session_id = request.session_id;
  if (session_id.empty()) {
    // If Initiator didn't provide session_id, generate one (backward compatibility)
    session_id = m_session_mgr->create_session(
        m_local_did, m_local_nf_type, m_local_nf_instance_id, false);
    Logger::amf_app().info("[BCF Auth] Generated new session_id: %s", session_id.c_str());
  } else {
    // Check if session already exists (duplicate request)
    if (m_session_mgr->session_exists(session_id)) {
      Logger::amf_app().error("[BCF Auth] Session already exists: %s", session_id.c_str());
      return {response, AuthResult::FAILURE_SESSION_EXISTS};
    }
    // Create session with Initiator's session_id
    // We need to create the session entry with the provided session_id
    m_session_mgr->create_session_with_id(
        session_id, m_local_did, m_local_nf_type, m_local_nf_instance_id, false);
    Logger::amf_app().info("[BCF Auth] Using initiator's session_id: %s", session_id.c_str());
  }

  // Validate initiator's challenge
  nonce_t initiator_nonce = nonce_t::from_hex(request.nonce);
  AuthResult nonce_result = m_nonce_mgr->validate_nonce(initiator_nonce);
  if (nonce_result != AuthResult::SUCCESS) {
    Logger::amf_app().error("[BCF Auth] Challenge validation failed");
    m_session_mgr->update_state(session_id, AuthState::AUTH_FAILED);
    return {response, nonce_result};
  }

  // Get initiator's public key from BCF
  std::string initiator_public_key = get_public_key_for_did(request.did);
  if (initiator_public_key.empty()) {
    Logger::amf_app().error("[BCF Auth] Failed to get public key for DID: %s", request.did.c_str());
    m_session_mgr->update_state(session_id, AuthState::AUTH_FAILED);
    return {response, AuthResult::FAILURE_KEY_NOT_FOUND};
  }
  Logger::amf_app().info("[BCF Auth] Initiator public_key (full): %s", initiator_public_key.c_str());

  // Store initiator info
  m_session_mgr->set_remote_info(
      session_id, request.did, request.nf_type, request.nf_instance_id,
      initiator_public_key);
  m_session_mgr->set_remote_nonce(session_id, initiator_nonce);

  // Generate our challenge
  nonce_t our_nonce = m_nonce_mgr->generate_nonce();
  m_session_mgr->set_local_nonce(session_id, our_nonce);
  Logger::amf_app().info("[BCF Auth] Generated our challenge (full): %s", our_nonce.to_hex().c_str());

  // Sign the initiator's challenge to prove our identity
  Logger::amf_app().info("[BCF Auth] Signing initiator's challenge...");
  std::string our_signature = sign_challenge(request.nonce);
  if (our_signature.empty()) {
    Logger::amf_app().error("[BCF Auth] Failed to sign challenge");
    m_session_mgr->update_state(session_id, AuthState::AUTH_FAILED);
    return {response, AuthResult::FAILURE_INTERNAL_ERROR};
  }
  Logger::amf_app().info("[BCF Auth] Generated signature (full): %s", our_signature.c_str());

  // Mark initiator challenge as used
  m_nonce_mgr->mark_used(request.nonce);

  // Update state
  m_session_mgr->update_state(session_id, AuthState::CHALLENGE_SENT);

  // Build response - echo back the same session_id
  response.did            = m_local_did;
  response.nf_type        = m_local_nf_type;
  response.nf_instance_id = m_local_nf_instance_id;
  response.nonce          = our_nonce.to_hex();
  response.signature      = our_signature;
  response.session_id     = session_id;  // Use Initiator's session_id
  response.timestamp      = std::to_string(nonce_t::current_timestamp_ms());

  Logger::amf_app().info("[BCF Auth] --- Response Parameters (Full) ---");
  Logger::amf_app().info("[BCF Auth]   response.did: %s", response.did.c_str());
  Logger::amf_app().info("[BCF Auth]   response.nf_type: %s", response.nf_type.c_str());
  Logger::amf_app().info("[BCF Auth]   response.nf_instance_id: %s", response.nf_instance_id.c_str());
  Logger::amf_app().info("[BCF Auth]   response.challenge (full): %s", response.nonce.c_str());
  Logger::amf_app().info("[BCF Auth]   response.signature (full): %s", response.signature.c_str());
  Logger::amf_app().info("[BCF Auth]   response.session_id: %s", response.session_id.c_str());
  Logger::amf_app().info("[BCF Auth]   response.timestamp: %s", response.timestamp.c_str());
  Logger::amf_app().info("[BCF Auth] ========== MODULE: HANDLE_AUTH_INIT COMPLETE ==========");

  return {response, AuthResult::SUCCESS};
}

//------------------------------------------------------------------------------
auth_result_response_t did_auth_module::handle_auth_complete(
    const auth_complete_request_t& request) {
  auth_result_response_t result;
  result.session_id = request.session_id;
  
  Logger::amf_app().info("[BCF Auth] ========== MODULE: HANDLE_AUTH_COMPLETE ==========");
  Logger::amf_app().info("[BCF Auth] --- Request Parameters (Full) ---");
  Logger::amf_app().info("[BCF Auth]   request.session_id: %s", request.session_id.c_str());
  Logger::amf_app().info("[BCF Auth]   request.signature (full): %s", request.signature.c_str());

  // Get session
  auto session = m_session_mgr->get_session(request.session_id);
  if (!session) {
    Logger::amf_app().error("[BCF Auth] Session not found: %s", request.session_id.c_str());
    result.result  = AuthResult::FAILURE_SESSION_NOT_FOUND;
    result.message = "Session not found";
    return result;
  }

  // Get our challenge that the initiator should have signed
  std::string our_nonce_hex = session->local_nonce.to_hex();
  Logger::amf_app().info("[BCF Auth] --- Session Info (Full) ---");
  Logger::amf_app().info("[BCF Auth]   local_challenge (full): %s", our_nonce_hex.c_str());
  Logger::amf_app().info("[BCF Auth]   remote_did: %s", session->remote_did.c_str());
  Logger::amf_app().info("[BCF Auth]   remote_public_key (full): %s", session->remote_public_key.c_str());

  // Verify initiator's signature
  Logger::amf_app().info("[BCF Auth] Verifying initiator's signature...");
  if (!verify_challenge_signature(
          our_nonce_hex, request.signature, session->remote_public_key)) {
    m_session_mgr->update_state(request.session_id, AuthState::AUTH_FAILED);
    result.result  = AuthResult::FAILURE_SIGNATURE_INVALID;
    result.message = "Signature verification failed";
    Logger::amf_app().error("[BCF Auth] ========== SIGNATURE VERIFICATION FAILED ==========");
    return result;
  }
  Logger::amf_app().info("[BCF Auth] Signature verification SUCCESS");

  // Mutual authentication complete!
  m_session_mgr->update_state(request.session_id, AuthState::MUTUAL_AUTH_COMPLETE);

  // Generate auth token
  std::string token = m_session_mgr->generate_auth_token(request.session_id);
  Logger::amf_app().info("[BCF Auth] Generated auth_token (full): %s", token.c_str());

  // Get updated session for token expiry
  session = m_session_mgr->get_session(request.session_id);

  result.result     = AuthResult::MUTUAL_SUCCESS;
  result.message    = "Mutual authentication completed successfully";
  result.auth_token = token;
  result.expires_at = session ? session->token_expires_at : 0;
  result.peer_did   = session ? session->remote_did : "";
  
  // Calculate expires_in (seconds from now)
  if (session && session->token_expires_at > 0) {
    uint64_t now_ms = nonce_t::current_timestamp_ms();
    if (session->token_expires_at > now_ms) {
      result.expires_in = static_cast<int>((session->token_expires_at - now_ms) / 1000);
    } else {
      result.expires_in = 0;
    }
  } else {
    result.expires_in = 0;
  }

  Logger::amf_app().info("[BCF Auth] --- Response Parameters (Full) ---");
  Logger::amf_app().info("[BCF Auth]   result: MUTUAL_SUCCESS");
  Logger::amf_app().info("[BCF Auth]   message: %s", result.message.c_str());
  Logger::amf_app().info("[BCF Auth]   auth_token (full): %s", result.auth_token.c_str());
  Logger::amf_app().info("[BCF Auth]   expires_at: %lu", result.expires_at);
  Logger::amf_app().info("[BCF Auth]   expires_in: %d", result.expires_in);
  Logger::amf_app().info("[BCF Auth]   peer_did: %s", result.peer_did.c_str());
  Logger::amf_app().info("[BCF Auth] ========== MODULE: HANDLE_AUTH_COMPLETE SUCCESS ==========");

  return result;
}

//------------------------------------------------------------------------------
// Authentication status queries
//------------------------------------------------------------------------------

bool did_auth_module::is_session_authenticated(
    const std::string& session_id) const {
  auto session = m_session_mgr->get_session(session_id);
  if (!session) {
    return false;
  }

  if (session->state != AuthState::MUTUAL_AUTH_COMPLETE) {
    return false;
  }

  // Check token validity
  uint64_t current_time = nonce_t::current_timestamp_ms();
  return current_time <= session->token_expires_at;
}

//------------------------------------------------------------------------------
std::string did_auth_module::get_auth_token(
    const std::string& session_id) const {
  auto session = m_session_mgr->get_session(session_id);
  if (!session) {
    return "";
  }

  if (session->state != AuthState::MUTUAL_AUTH_COMPLETE) {
    return "";
  }

  // Check token validity
  uint64_t current_time = nonce_t::current_timestamp_ms();
  if (current_time > session->token_expires_at) {
    return "";
  }

  return session->auth_token;
}

//------------------------------------------------------------------------------
AuthResult did_auth_module::verify_auth_token(
    const std::string& token, const std::string& remote_did) const {
  std::string session_id;

  if (!m_session_mgr->validate_auth_token(token, session_id)) {
    return AuthResult::FAILURE_TIMEOUT;  // Token expired or invalid
  }

  if (!remote_did.empty()) {
    auto session = m_session_mgr->get_session(session_id);
    if (!session || session->remote_did != remote_did) {
      return AuthResult::FAILURE_INVALID_DID;
    }
  }

  return AuthResult::SUCCESS;
}

//------------------------------------------------------------------------------
std::string did_auth_module::find_authenticated_session(
    const std::string& remote_did) const {
  return m_session_mgr->find_authenticated_session(remote_did);
}

//------------------------------------------------------------------------------
bool did_auth_module::needs_authentication(const std::string& remote_did) const {
  std::string session_id = find_authenticated_session(remote_did);
  return session_id.empty();
}

//------------------------------------------------------------------------------
std::shared_ptr<const auth_session_t> did_auth_module::get_session_info(
    const std::string& session_id) const {
  return m_session_mgr->get_session(session_id);
}

//------------------------------------------------------------------------------
// Maintenance operations
//------------------------------------------------------------------------------

void did_auth_module::cleanup() {
  if (m_session_mgr) {
    m_session_mgr->cleanup_expired();
  }
  if (m_nonce_mgr) {
    m_nonce_mgr->cleanup_expired();
  }
}

//------------------------------------------------------------------------------
void did_auth_module::close_session(const std::string& session_id) {
  if (m_session_mgr) {
    m_session_mgr->remove_session(session_id);
  }
}

//------------------------------------------------------------------------------
bool did_auth_module::migrate_session(
    const std::string& old_session_id, const std::string& new_session_id) {
  if (!m_session_mgr) {
    return false;
  }
  return m_session_mgr->migrate_session(old_session_id, new_session_id);
}

//------------------------------------------------------------------------------
did_auth_module::statistics_t did_auth_module::get_statistics() const {
  statistics_t stats = {};

  if (m_session_mgr) {
    stats.active_sessions = m_session_mgr->active_session_count();
    // Count authenticated sessions (would need iteration - simplified here)
    stats.authenticated_sessions = 0;
    stats.pending_sessions       = stats.active_sessions;
  }

  if (m_nonce_mgr) {
    stats.used_nonces = m_nonce_mgr->used_nonce_count();
  }

  // Note: cached public keys count would need to be exposed from bcf_client
  stats.cached_public_keys = 0;

  return stats;
}

//------------------------------------------------------------------------------
void did_auth_module::preload_public_key(
    const std::string& did, const std::string& public_key) {
  // Store in local cache
  std::unique_lock<std::shared_mutex> lock(m_cache_mutex);
  m_public_key_cache[did] = public_key;
}

// =============================================================================
// BCF 单向认证实现（新版）
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

  // 将签名模块传递给 BCF Auth Client
  if (m_crypto) {
    m_bcf_auth_client->set_crypto(m_crypto.get());
  }

  Logger::amf_app().info(
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

void did_auth_module::set_bcf_notification_uri(const std::string& uri) {
  if (!m_bcf_auth_client) {
    m_bcf_auth_client = std::make_unique<BcfAuthClient>();
  }

  std::string normalized_uri = uri;
  if (!normalized_uri.empty() &&
      normalized_uri.rfind("http://", 0) != 0 &&
      normalized_uri.rfind("https://", 0) != 0) {
    normalized_uri = "http://" + normalized_uri;
  }

  m_bcf_auth_client->set_notification_uri(normalized_uri);
}

void did_auth_module::set_bcf_notification_transport(
    const std::string& transport) {
  if (!m_bcf_auth_client) {
    m_bcf_auth_client = std::make_unique<BcfAuthClient>();
  }

  m_bcf_auth_client->set_notification_transport(transport);
}

//------------------------------------------------------------------------------
BcfAuthResult did_auth_module::authenticate_via_bcf(
    std::string& auth_token) {
  if (!is_initialized()) {
    Logger::amf_app().error("[BCF Auth] Module not initialized");
    return BcfAuthResult::FAILURE_INTERNAL_ERROR;
  }

  if (!m_bcf_auth_client) {
    Logger::amf_app().error(
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
    Logger::amf_app().error("[BCF Auth] Module not initialized");
    return BcfAuthResult::FAILURE_INTERNAL_ERROR;
  }

  if (!m_bcf_auth_client) {
    Logger::amf_app().error(
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

    // Try to read private key from file
    std::ifstream key_file(m_private_key_path);
    if (!key_file.is_open()) {
      Logger::amf_app().warn(
          "Private key file not found: %s, BCF auth will use placeholder key",
          m_private_key_path.c_str());
      // Use a placeholder key for testing - in production this should fail
      // Generate a deterministic key from DID for testing purposes
      private_key_hex = "0000000000000000000000000000000000000000000000000000000000000001";
    } else {
      std::getline(key_file, private_key_hex);
      key_file.close();

      // Trim whitespace
      private_key_hex.erase(0, private_key_hex.find_first_not_of(" \t\n\r"));
      private_key_hex.erase(private_key_hex.find_last_not_of(" \t\n\r") + 1);

      // Check if it looks like hex (64 characters for 32-byte key)
      if (private_key_hex.length() != 64) {
        Logger::amf_app().error(
            "Invalid private key format in %s, expected 64 hex characters, got %zu",
            m_private_key_path.c_str(), private_key_hex.length());
        return false;
      }

      Logger::amf_app().debug("Read private key from file: %s", m_private_key_path.c_str());
    }

    // Create module instance with NF type and instance ID from constructor
    Logger::amf_app().debug(
        "[Identity] Creating BCF auth module with nf_type=%s, nf_instance_id=%s",
        m_nf_type.c_str(), m_nf_instance_id.c_str());
        
    m_module = std::make_unique<did_auth_module>(
        m_local_did,
        m_nf_type,
        m_nf_instance_id,
        private_key_hex);

    m_initialized = m_module && m_module->is_initialized();

    if (!m_initialized) {
      Logger::amf_app().error("[Identity] BCF auth module initialization returned false");
    }

    return m_initialized;

  } catch (const std::exception& e) {
    Logger::amf_app().error("BCF auth initialize exception: %s", e.what());
    m_initialized = false;
    return false;
  }
}

//------------------------------------------------------------------------------
void DIDAuth::set_public_key_query_callback(public_key_query_callback_t callback) {
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
bool DIDAuth::generate_challenge(
    const auth_request_t& request,
    auth_challenge_t& challenge,
    std::string& session_id) {
  if (!m_initialized || !m_module) {
    return false;
  }

  try {
    // Convert request types - map all fields
    auth_init_request_t init_request;
    init_request.did            = request.initiator_did;
    init_request.nonce          = request.nonce;
    init_request.nf_type        = request.nf_type;
    init_request.nf_instance_id = request.nf_instance_id;
    init_request.session_id     = request.session_id;
    init_request.timestamp      = std::to_string(request.timestamp);

    auto [challenge_response, result] = m_module->handle_auth_init(init_request);

    if (result != AuthResult::SUCCESS) {
      return false;
    }

    // Copy to output
    session_id                    = challenge_response.session_id;
    challenge.responder_did       = challenge_response.did;
    challenge.challenge_nonce     = challenge_response.nonce;
    try {
      challenge.challenge_timestamp = std::stoull(challenge_response.timestamp);
    } catch (...) {
      challenge.challenge_timestamp = 0;
    }
    challenge.responder_signature = challenge_response.signature;

    // Track peer DID
    {
      std::lock_guard<std::mutex> lock(m_peer_map_mutex);
      m_peer_did_to_session[request.initiator_did] = session_id;
    }

    return true;

  } catch (const std::exception& e) {
    return false;
  }
}

//------------------------------------------------------------------------------
bool DIDAuth::process_auth_response(
    const auth_response_t& response,
    auth_result_t& result) {
  if (!m_initialized || !m_module) {
    result.error_message = "BCF auth module not initialized";
    return false;
  }

  try {
    // Convert request types
    auth_complete_request_t complete_request;
    complete_request.session_id = response.session_id;
    complete_request.signature  = response.initiator_signature;

    auto result_response = m_module->handle_auth_complete(complete_request);

    result.peer_did   = result_response.peer_did;
    result.auth_token = result_response.auth_token;
    result.expires_in = result_response.expires_in;

    if (result_response.result == AuthResult::MUTUAL_SUCCESS) {
      return true;
    } else {
      result.error_message = result_response.message;
      return false;
    }

  } catch (const std::exception& e) {
    result.error_message = e.what();
    return false;
  }
}

//------------------------------------------------------------------------------
bool DIDAuth::get_session(
    const std::string& session_id,
    auth_session_t& session) {
  if (!m_initialized || !m_module) {
    return false;
  }

  auto session_info = m_module->get_session_info(session_id);
  if (!session_info) {
    return false;
  }

  session = *session_info;
  return true;
}

//------------------------------------------------------------------------------
void DIDAuth::set_http_request_callback(http_request_callback_t callback) {
  m_http_callback = std::move(callback);
  Logger::amf_app().debug("HTTP request callback set for BCF auth initiator mode");
}

//------------------------------------------------------------------------------
bool DIDAuth::init_auth_as_initiator(
    const std::string& remote_endpoint,
    std::string& auth_token) {
  if (!m_initialized || !m_module) {
    Logger::amf_app().error("[BCF Auth] Module not initialized");
    return false;
  }

  if (!m_http_callback) {
    Logger::amf_app().error(
        "[BCF Auth] HTTP callback not set - call set_http_request_callback first");
    return false;
  }

  // Note: "Initiating BCF Auth" log is printed by caller (amf_app::initiate_did_auth)
  // to avoid duplicate logs

  try {
    // Step 1: Create init request
    auto [init_request, session_id] =
        m_module->create_auth_init_request(remote_endpoint);

    if (session_id.empty()) {
      Logger::amf_app().error("[BCF Auth] Failed to create auth init request");
      return false;
    }

    // Validate nf_instance_id is not empty
    if (init_request.nf_instance_id.empty()) {
      Logger::amf_app().warn(
          "[BCF Auth] initiator_nf_instance_id is empty, authentication may fail");
    }

    // Step 2: Build init request with v2 protocol field names
    std::string init_uri = remote_endpoint + "/nf_auth/v1/mutual_auth/init";
    uint64_t timestamp_ms = nonce_t::current_timestamp_ms();
    
    nlohmann::json init_body;
    init_body["initiator_did"]            = init_request.did;
    init_body["initiator_nf_type"]        = init_request.nf_type;
    init_body["initiator_nf_instance_id"] = init_request.nf_instance_id;
    init_body["initiator_nonce"]          = init_request.nonce;
    init_body["session_id"]               = init_request.session_id;
    init_body["timestamp_ms"]             = timestamp_ms;

    std::string init_response_body;
    uint32_t init_response_code = 0;

    if (!m_http_callback(
            init_uri, "POST", init_body.dump(), init_response_body,
            init_response_code)) {
      Logger::amf_app().error("[BCF Auth] Failed to send init request to %s", init_uri.c_str());
      m_module->close_session(session_id);
      return false;
    }

    Logger::amf_app().debug(
        "[BCF Auth] Init response: code=%d, body=%s",
        init_response_code, init_response_body.c_str());

    if (init_response_code != 200) {
      Logger::amf_app().error(
          "[BCF Auth] Init request failed with HTTP %d", init_response_code);
      m_module->close_session(session_id);
      return false;
    }

    // Step 3: Parse init response (v2 protocol field names)
    nlohmann::json resp_json = nlohmann::json::parse(init_response_body);
    
    // Support both v2 and legacy field names for backward compatibility
    std::string responder_did = resp_json.value("responder_did", "");
    if (responder_did.empty()) {
      responder_did = resp_json.value("did", "");  // Legacy fallback
    }
    std::string responder_nonce = resp_json.value("responder_nonce", "");
    if (responder_nonce.empty()) {
      responder_nonce = resp_json.value("nonce", "");  // Legacy fallback
    }
    std::string responder_signature = resp_json.value("responder_signature", "");
    if (responder_signature.empty()) {
      responder_signature = resp_json.value("signature", "");  // Legacy fallback
    }
    std::string resp_session_id = resp_json.value("session_id", "");
    uint64_t resp_timestamp_ms = resp_json.value("timestamp_ms", 0ULL);
    if (resp_timestamp_ms == 0) {
      // Legacy: timestamp as string
      std::string ts_str = resp_json.value("timestamp", "");
      if (!ts_str.empty()) {
        try { resp_timestamp_ms = std::stoull(ts_str); } catch (...) {}
      }
    }

    // ====== PreCheck Validation for Init Response ======
    Logger::amf_app().info("[PreCheck] === Validating /mutual_auth/init Response ===");
    
    // 1. Session ID consistency check
    bool session_valid = (!resp_session_id.empty() && resp_session_id == session_id);
    Logger::amf_app().info(
        "[PreCheck] Session ID consistency check: %s (sent=%s, recv=%s)",
        session_valid ? "PASS" : "FAIL",
        session_id.c_str(), resp_session_id.c_str());
    if (!session_valid) {
      m_module->close_session(session_id);
      return false;
    }

    // 2. Responder DID format check
    bool did_valid = (responder_did.find("did:oai5gc:") == 0 && responder_did.length() > 20);
    Logger::amf_app().info(
        "[PreCheck] Responder DID format check: %s (did=%s)",
        did_valid ? "PASS" : "FAIL", short_did(responder_did).c_str());
    if (!did_valid) {
      Logger::amf_app().error("[PreCheck] Invalid responder_did format");
      m_module->close_session(session_id);
      return false;
    }

    // 3. Responder Challenge format check (40 bytes = 80 hex chars)
    bool nonce_valid = (responder_nonce.length() == 80 &&
        responder_nonce.find_first_not_of("0123456789abcdefABCDEF") == std::string::npos);
    Logger::amf_app().info(
        "[PreCheck] Responder Challenge format check: %s (len=%zu, expected=80)",
        nonce_valid ? "PASS" : "FAIL", responder_nonce.length());
    if (!nonce_valid) {
      Logger::amf_app().error("[PreCheck] Invalid responder challenge format");
      m_module->close_session(session_id);
      return false;
    }

    // 4. Responder Signature format check (DER encoded, typically 70-72 bytes = 140-144 hex)
    bool sig_valid = (!responder_signature.empty() &&
        responder_signature.length() >= 128 &&
        responder_signature.length() <= 160);
    Logger::amf_app().info(
        "[PreCheck] Responder Signature format check: %s (len=%zu, expected=128-160)",
        sig_valid ? "PASS" : "FAIL", responder_signature.length());
    if (!sig_valid) {
      Logger::amf_app().error("[PreCheck] Invalid responder_signature format");
      m_module->close_session(session_id);
      return false;
    }

    // 5. Timestamp freshness check
    bool timestamp_valid = true;
    if (resp_timestamp_ms > 0) {
      uint64_t now_ms = nonce_t::current_timestamp_ms();
      constexpr uint64_t max_age_ms = 5 * 60 * 1000;      // 5 minutes
      constexpr uint64_t max_future_ms = 60 * 1000;       // 1 minute
      int64_t diff_ms = static_cast<int64_t>(now_ms) - static_cast<int64_t>(resp_timestamp_ms);
      
      if (resp_timestamp_ms > now_ms + max_future_ms) {
        timestamp_valid = false;
      } else if (now_ms > resp_timestamp_ms + max_age_ms) {
        timestamp_valid = false;
      }
      Logger::amf_app().info(
          "[PreCheck] Timestamp freshness check: %s (diff=%ldms, max_age=300000ms)",
          timestamp_valid ? "PASS" : "FAIL", diff_ms);
      if (!timestamp_valid) {
        Logger::amf_app().error("[PreCheck] Response timestamp out of range");
        m_module->close_session(session_id);
        return false;
      }
    } else {
      Logger::amf_app().info("[PreCheck] Timestamp freshness check: SKIP (no timestamp)");
    }

    Logger::amf_app().info("[PreCheck] === All Init Response Checks PASSED ===");
    // ====== End PreCheck Validation ======

    Logger::amf_app().info(
        "[BCF Auth] Received init response from responder=%s",
        short_did(responder_did).c_str());
    Logger::amf_app().debug(
        "[BCF Auth] responder_challenge=%s, responder_signature=%s",
        truncate_for_log(responder_nonce, 32).c_str(),
        truncate_for_log(responder_signature, 32).c_str());

    // Step 4: Process challenge (verify responder_signature, sign responder challenge)
    // Build legacy challenge struct for module compatibility
    auth_challenge_response_t challenge;
    challenge.session_id = resp_session_id;
    challenge.did = responder_did;
    challenge.nonce = responder_nonce;
    challenge.signature = responder_signature;
    challenge.timestamp = std::to_string(resp_timestamp_ms);

    auto [complete_request, result] =
        m_module->process_auth_challenge(session_id, challenge);

    if (result != AuthResult::SUCCESS) {
      Logger::amf_app().error(
          "[BCF Auth] Failed to verify responder_signature: %s",
          auth_result_to_string(result).c_str());
      m_module->close_session(session_id);
      return false;
    }

    // Step 5: Send complete request with v2 field names
    std::string complete_uri =
        remote_endpoint + "/nf_auth/v1/mutual_auth/complete";
    uint64_t complete_timestamp_ms = nonce_t::current_timestamp_ms();
    
    nlohmann::json complete_body;
    complete_body["session_id"]          = complete_request.session_id;
    complete_body["initiator_did"]       = m_local_did;      // AMF's DID (initiator)
    complete_body["responder_did"]       = responder_did;    // AUSF's DID (responder)
    complete_body["initiator_signature"] = complete_request.signature;
    complete_body["timestamp_ms"]        = complete_timestamp_ms;

    std::string complete_response_body;
    uint32_t complete_response_code = 0;

    if (!m_http_callback(
            complete_uri, "POST", complete_body.dump(), complete_response_body,
            complete_response_code)) {
      Logger::amf_app().error("[BCF Auth] Failed to send complete request");
      m_module->close_session(session_id);
      return false;
    }

    Logger::amf_app().debug(
        "[BCF Auth] Complete response: code=%d, body=%s",
        complete_response_code, complete_response_body.c_str());

    if (complete_response_code != 200) {
      Logger::amf_app().error(
          "[BCF Auth] Complete request failed with HTTP %d", complete_response_code);
      m_module->close_session(session_id);
      return false;
    }

    // Step 6: Parse complete response (v2 protocol field names)
    nlohmann::json result_json = nlohmann::json::parse(complete_response_body);
    
    // Extract v2 fields with legacy fallback
    bool auth_success = result_json.value("success", false);
    auth_token = result_json.value("auth_token", "");
    std::string result_session_id = result_json.value("session_id", "");
    std::string result_responder_did = result_json.value("responder_did", "");
    if (result_responder_did.empty()) {
      result_responder_did = result_json.value("peer_did", "");  // Legacy
    }
    int expires_in = result_json.value("expires_in", 3600);
    uint64_t result_timestamp_ms = result_json.value("timestamp_ms", 0ULL);

    // ====== PreCheck Validation for Complete Response ======
    Logger::amf_app().info("[PreCheck] === Validating /mutual_auth/complete Response ===");
    
    // 1. Success field check
    Logger::amf_app().info(
        "[PreCheck] Success field check: %s",
        auth_success ? "PASS" : "FAIL");
    if (!auth_success) {
      std::string error_msg = result_json.value("error_message", 
          result_json.value("message", "Unknown error"));
      Logger::amf_app().error("[PreCheck] Auth failed: %s", error_msg.c_str());
      m_module->close_session(session_id);
      return false;
    }

    // 2. Session ID consistency check (must match the one we sent)
    bool session_consistent = (!result_session_id.empty() && result_session_id == session_id);
    Logger::amf_app().info(
        "[PreCheck] Session ID consistency check: %s (sent=%s, recv=%s)",
        session_consistent ? "PASS" : "FAIL",
        session_id.c_str(), result_session_id.c_str());
    if (!session_consistent) {
      Logger::amf_app().error("[PreCheck] Session ID mismatch in complete response");
      m_module->close_session(session_id);
      return false;
    }

    // 3. Responder DID consistency check (must match the one from init response)
    bool did_consistent = (result_responder_did.empty() || result_responder_did == responder_did);
    Logger::amf_app().info(
        "[PreCheck] Responder DID consistency check: %s (init=%s, complete=%s)",
        did_consistent ? "PASS" : "FAIL",
        short_did(responder_did).c_str(), 
        result_responder_did.empty() ? "(empty)" : short_did(result_responder_did).c_str());
    if (!did_consistent) {
      Logger::amf_app().error("[PreCheck] Responder DID mismatch - possible tampering!");
      m_module->close_session(session_id);
      return false;
    }

    // 4. Auth Token format check (SHA256 hash = 64 hex chars typically)
    bool token_valid = (!auth_token.empty() && 
        auth_token.length() >= 32 && 
        auth_token.length() <= 128 &&
        auth_token.find_first_not_of("0123456789abcdefABCDEF") == std::string::npos);
    Logger::amf_app().info(
        "[PreCheck] Auth Token format check: %s (len=%zu, expected=32-128 hex)",
        token_valid ? "PASS" : "FAIL", auth_token.length());
    if (!token_valid) {
      Logger::amf_app().error("[PreCheck] Invalid auth_token format");
      m_module->close_session(session_id);
      return false;
    }

    // 5. Expires_in sanity check
    bool expires_valid = (expires_in > 0 && expires_in <= 86400);  // max 24 hours
    Logger::amf_app().info(
        "[PreCheck] Expires_in check: %s (value=%d, expected=1-86400)",
        expires_valid ? "PASS" : "FAIL", expires_in);
    if (!expires_valid) {
      Logger::amf_app().warn("[PreCheck] Invalid expires_in, using default 3600");
      expires_in = 3600;
    }

    // 6. Timestamp freshness check (if present)
    if (result_timestamp_ms > 0) {
      uint64_t now_ms = nonce_t::current_timestamp_ms();
      int64_t diff_ms = static_cast<int64_t>(now_ms) - static_cast<int64_t>(result_timestamp_ms);
      bool timestamp_valid = (std::abs(diff_ms) <= 60000);  // 60 seconds
      Logger::amf_app().info(
          "[PreCheck] Timestamp freshness check: %s (diff=%ldms, max=60000ms)",
          timestamp_valid ? "PASS" : "FAIL", diff_ms);
      if (!timestamp_valid) {
        Logger::amf_app().error("[PreCheck] Complete response timestamp out of range");
        m_module->close_session(session_id);
        return false;
      }
    } else {
      Logger::amf_app().info("[PreCheck] Timestamp freshness check: SKIP (no timestamp)");
    }

    Logger::amf_app().info("[PreCheck] === All Complete Response Checks PASSED ===");
    // ====== End PreCheck Validation ======

    // Step 7: Update local session state
    auth_result_response_t auth_result;
    auth_result.session_id = session_id;
    auth_result.result     = AuthResult::MUTUAL_SUCCESS;
    auth_result.auth_token = auth_token;
    auth_result.peer_did   = responder_did;  // Use DID from init response (verified)
    auth_result.expires_in = expires_in;
    
    uint64_t now_ms = nonce_t::current_timestamp_ms();
    auth_result.expires_at = now_ms + (static_cast<uint64_t>(expires_in) * 1000);
    
    m_module->process_auth_result(session_id, auth_result);

    // Track peer DID to session mapping
    {
      std::lock_guard<std::mutex> lock(m_peer_map_mutex);
      m_peer_did_to_session[responder_did] = session_id;
    }

    Logger::amf_app().info(
        "[BCF Auth] Mutual auth SUCCESS: responder=%s, auth_token=%s, expires_in=%d",
        short_did(responder_did).c_str(),
        truncate_for_log(auth_token, 32).c_str(),
        expires_in);

    return true;

  } catch (const nlohmann::json::exception& e) {
    Logger::amf_app().error("JSON parse error in DID auth: %s", e.what());
    return false;
  } catch (const std::exception& e) {
    Logger::amf_app().error("DID auth exception: %s", e.what());
    return false;
  }
}

//------------------------------------------------------------------------------
bool DIDAuth::is_peer_authenticated(const std::string& peer_did) {
  if (!m_initialized || !m_module) {
    return false;
  }

  std::string session_id = m_module->find_authenticated_session(peer_did);
  return !session_id.empty();
}

//------------------------------------------------------------------------------
std::string DIDAuth::get_peer_auth_token(const std::string& peer_did) {
  if (!m_initialized || !m_module) {
    return "";
  }

  std::string session_id = m_module->find_authenticated_session(peer_did);
  if (session_id.empty()) {
    return "";
  }

  return m_module->get_auth_token(session_id);
}

//------------------------------------------------------------------------------
void DIDAuth::cleanup_expired_sessions() {
  if (m_initialized && m_module) {
    m_module->cleanup();
  }

  // 同时清理 BCF auth token 缓存
  if (m_module && m_module->get_bcf_auth_client()) {
    m_module->get_bcf_auth_client()->cleanup_expired_tokens();
  }
}

// =============================================================================
// DIDAuth - BCF 单向认证接口实现（新版）
// =============================================================================

//------------------------------------------------------------------------------
void DIDAuth::configure_bcf_auth(
    const std::string& bcf_uri,
    const std::string& api_version) {
  if (!m_initialized || !m_module) {
    Logger::amf_app().error("[BCF Auth] Cannot configure BCF auth: module not initialized");
    return;
  }

  // 配置底层模块
  m_module->configure_bcf_auth(bcf_uri, api_version);

  // 复用现有 HTTP 回调给 BCF auth client
  if (m_http_callback && m_module->get_bcf_auth_client()) {
    m_module->get_bcf_auth_client()->set_http_callback(
        [this](const std::string& uri, const std::string& method,
               const std::string& body, std::string& response_body,
               uint32_t& response_code) -> bool {
          return m_http_callback(uri, method, body, response_body, response_code);
        });
  }

  Logger::amf_app().info(
      "[BCF Auth] BCF authentication configured: bcf_uri=%s",
      bcf_uri.c_str());
}

//------------------------------------------------------------------------------
bool DIDAuth::authenticate_to_bcf(std::string& auth_token) {
  if (!m_initialized || !m_module) {
    Logger::amf_app().error("[BCF Auth] Module not initialized");
    return false;
  }

  BcfAuthResult result = m_module->authenticate_via_bcf(auth_token);

  if (result != BcfAuthResult::SUCCESS) {
    Logger::amf_app().error(
        "[BCF Auth] Authentication failed: %s",
        bcf_auth_result_to_string(result).c_str());
    return false;
  }

  return true;
}

//------------------------------------------------------------------------------
bool DIDAuth::ensure_bcf_auth(std::string& auth_token) {
  if (!m_initialized || !m_module) {
    Logger::amf_app().error("[BCF Auth] Module not initialized");
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

}  // namespace oai::amf::did_auth
