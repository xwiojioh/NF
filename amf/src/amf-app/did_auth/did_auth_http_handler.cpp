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

#include "did_auth_http_handler.hpp"

#include <curl/curl.h>
#include <nlohmann/json.hpp>

#include <chrono>
#include <future>
#include <thread>

#include "logger.hpp"

namespace oai::amf::did_auth {

//------------------------------------------------------------------------------
// CURL callback
//------------------------------------------------------------------------------
static size_t curl_write_callback(
    void* contents, size_t size, size_t nmemb, std::string* response) {
  size_t total_size = size * nmemb;
  response->append(static_cast<char*>(contents), total_size);
  return total_size;
}

//==============================================================================
// did_auth_http_handler Implementation
//==============================================================================

did_auth_http_handler::did_auth_http_handler(
    std::shared_ptr<did_auth_module> auth_module)
    : m_auth_module(auth_module) {}

//------------------------------------------------------------------------------
did_auth_http_handler::~did_auth_http_handler() {}

//------------------------------------------------------------------------------
http_response_t did_auth_http_handler::make_error_response(
    int status_code, const std::string& error_code,
    const std::string& message) {
  nlohmann::json error = {
      {"error", error_code},
      {"message", message},
  };

  return {status_code, "application/json", error.dump()};
}

//------------------------------------------------------------------------------
http_response_t did_auth_http_handler::make_success_response(
    const std::string& body) {
  return {200, "application/json", body};
}

//------------------------------------------------------------------------------
http_response_t did_auth_http_handler::handle_auth_init(
    const std::string& request_body) {
  if (!m_auth_module || !m_auth_module->is_initialized()) {
    return make_error_response(
        503, "SERVICE_UNAVAILABLE", "BCF authentication module not available");
  }

  try {
    nlohmann::json j = nlohmann::json::parse(request_body);
    auth_init_request_t request = auth_init_request_t::from_json(j);

    // Handle the authentication init
    auto [challenge, result] = m_auth_module->handle_auth_init(request);

    if (result != AuthResult::SUCCESS) {
      std::string error_code;
      std::string message;
      int status_code = 400;

      switch (result) {
        case AuthResult::FAILURE_KEY_NOT_FOUND:
          error_code  = "KEY_NOT_FOUND";
          message     = "Public key for DID not found on BCF";
          status_code = 404;
          break;
        case AuthResult::FAILURE_NONCE_EXPIRED:
          error_code = "NONCE_EXPIRED";
          message    = "Nonce has expired";
          break;
        case AuthResult::FAILURE_NONCE_REUSED:
          error_code = "NONCE_REUSED";
          message    = "Nonce has been used (possible replay attack)";
          break;
        case AuthResult::FAILURE_BCF_UNAVAILABLE:
          error_code  = "BCF_UNAVAILABLE";
          message     = "Cannot connect to BCF";
          status_code = 503;
          break;
        default:
          error_code  = "INTERNAL_ERROR";
          message     = "Internal authentication error";
          status_code = 500;
          break;
      }

      return make_error_response(status_code, error_code, message);
    }

    return make_success_response(challenge.to_json().dump());

  } catch (const nlohmann::json::exception& e) {
    return make_error_response(
        400, "INVALID_REQUEST", "Invalid JSON: " + std::string(e.what()));
  } catch (const std::exception& e) {
    return make_error_response(
        500, "INTERNAL_ERROR", "Internal error: " + std::string(e.what()));
  }
}

//------------------------------------------------------------------------------
http_response_t did_auth_http_handler::handle_bcf_notification(
    const std::string& request_body) {
  if (!m_auth_module || !m_auth_module->is_initialized()) {
    return make_error_response(
        503, "SERVICE_UNAVAILABLE", "Auth module not available");
  }

  try {
    bool ok = m_auth_module->handle_bcf_notification(request_body);
    if (!ok) {
      return make_error_response(400, "INVALID_NOTIFICATION", "Failed to process notification");
    }
    // Per spec: on successful processing of notification, return 204 No Content
    return {204, "application/json", ""};
  } catch (const std::exception& e) {
    return make_error_response(500, "INTERNAL_ERROR", e.what());
  }
}

//------------------------------------------------------------------------------
http_response_t did_auth_http_handler::handle_auth_complete(
    const std::string& request_body) {
  if (!m_auth_module || !m_auth_module->is_initialized()) {
    return make_error_response(
        503, "SERVICE_UNAVAILABLE", "BCF authentication module not available");
  }

  try {
    nlohmann::json j = nlohmann::json::parse(request_body);
    auth_complete_request_t request = auth_complete_request_t::from_json(j);

    // Handle the authentication complete
    auth_result_response_t result = m_auth_module->handle_auth_complete(request);

    if (result.result != AuthResult::SUCCESS &&
        result.result != AuthResult::MUTUAL_SUCCESS) {
      std::string error_code;
      int status_code = 400;

      switch (result.result) {
        case AuthResult::FAILURE_SESSION_NOT_FOUND:
          error_code  = "SESSION_NOT_FOUND";
          status_code = 404;
          break;
        case AuthResult::FAILURE_SIGNATURE_INVALID:
          error_code  = "SIGNATURE_INVALID";
          status_code = 401;
          break;
        default:
          error_code  = "AUTH_FAILED";
          status_code = 401;
          break;
      }

      return make_error_response(status_code, error_code, result.message);
    }

    return make_success_response(result.to_json().dump());

  } catch (const nlohmann::json::exception& e) {
    return make_error_response(
        400, "INVALID_REQUEST", "Invalid JSON: " + std::string(e.what()));
  } catch (const std::exception& e) {
    return make_error_response(
        500, "INTERNAL_ERROR", "Internal error: " + std::string(e.what()));
  }
}

//------------------------------------------------------------------------------
// V2 API with PreCheck Integration
//------------------------------------------------------------------------------

http_response_t did_auth_http_handler::handle_auth_init_v2(
    const std::string& request_body) {
  Logger::amf_app().info("[PreCheck] === /mutual_auth/init REQUEST ===");
  
  if (!m_auth_module || !m_auth_module->is_initialized()) {
    Logger::amf_app().error("[PreCheck] BCF authentication module not available");
    return make_error_response(
        503, "SERVICE_UNAVAILABLE", "BCF authentication module not available");
  }

  try {
    // Step 1: Parse JSON
    nlohmann::json j;
    try {
      j = nlohmann::json::parse(request_body);
    } catch (const nlohmann::json::exception& e) {
      Logger::amf_app().error("[PreCheck] Invalid JSON: %s", e.what());
      return make_error_response(
          400, "INVALID_REQUEST", "Invalid JSON: " + std::string(e.what()));
    }
    
    // Step 2: Parse v2 request
    auth_init_request_v2_t request = auth_init_request_v2_t::from_json(j);
    
    Logger::amf_app().info(
        "[PreCheck] Received init request: session_id=%s, initiator_did=%s",
        request.session_id.c_str(),
        short_did(request.initiator_did).c_str());
    
    // Step 3: PreCheck validation
    // 函数签名: (initiator_did, initiator_nf_type, initiator_nonce, session_id, timestamp_ms)
    auto precheck_result = m_prechecker.precheck_auth_init_request(
        request.initiator_did,
        request.initiator_nf_type,
        request.initiator_nonce,
        request.session_id,
        request.timestamp_ms);
    
    if (!precheck_result.success) {
      Logger::amf_app().error(
          "[PreCheck] FAILED: error=%s, detail=%s",
          precheck_error_to_string(precheck_result.error).c_str(),
          precheck_result.detail.c_str());
      
      return make_error_response(
          precheck_result.http_code(),
          precheck_result.error_code,
          precheck_result.detail);
    }
    
    Logger::amf_app().info("[PreCheck] All checks passed, proceeding to auth logic");
    
    // Step 4: Convert v2 request to v1 for existing auth module
    auth_init_request_t v1_request;
    v1_request.did             = request.initiator_did;
    v1_request.nf_type         = request.initiator_nf_type;
    v1_request.nf_instance_id  = request.initiator_nf_instance_id;
    v1_request.nonce           = request.initiator_nonce;
    v1_request.session_id      = request.session_id;
    v1_request.timestamp       = std::to_string(request.timestamp_ms);
    
    // Step 5: Handle authentication init
    auto [challenge, result] = m_auth_module->handle_auth_init(v1_request);

    if (result != AuthResult::SUCCESS) {
      std::string error_code;
      std::string message;
      int status_code = 400;

      switch (result) {
        case AuthResult::FAILURE_KEY_NOT_FOUND:
          error_code  = "KEY_NOT_FOUND";
          message     = "Public key for DID not found on BCF";
          status_code = 404;
          break;
        case AuthResult::FAILURE_NONCE_EXPIRED:
          error_code = "NONCE_EXPIRED";
          message    = "Nonce has expired";
          break;
        case AuthResult::FAILURE_NONCE_REUSED:
          error_code = "NONCE_REUSED";
          message    = "Nonce has been used (possible replay attack)";
          break;
        case AuthResult::FAILURE_BCF_UNAVAILABLE:
          error_code  = "BCF_UNAVAILABLE";
          message     = "Cannot connect to BCF";
          status_code = 503;
          break;
        default:
          error_code  = "INTERNAL_ERROR";
          message     = "Internal authentication error";
          status_code = 500;
          break;
      }

      Logger::amf_app().error(
          "[PreCheck] Auth logic failed: code=%s, msg=%s",
          error_code.c_str(), message.c_str());
      return make_error_response(status_code, error_code, message);
    }

    // Step 6: Convert v1 response to v2 format
    auth_init_response_v2_t v2_response;
    v2_response.responder_did          = challenge.did;
    v2_response.responder_nf_type      = challenge.nf_type;
    v2_response.responder_nf_instance_id = challenge.nf_instance_id;
    v2_response.responder_nonce        = challenge.nonce;
    v2_response.responder_signature    = challenge.signature;
    v2_response.session_id             = challenge.session_id;
    v2_response.timestamp_ms           = std::stoull(challenge.timestamp);
    
    Logger::amf_app().info(
        "[PreCheck] === /mutual_auth/init RESPONSE SUCCESS === session_id=%s",
        v2_response.session_id.c_str());

    return make_success_response(v2_response.to_json().dump());

  } catch (const std::exception& e) {
    Logger::amf_app().error("[PreCheck] Exception: %s", e.what());
    return make_error_response(
        500, "INTERNAL_ERROR", "Internal error: " + std::string(e.what()));
  }
}

//------------------------------------------------------------------------------
http_response_t did_auth_http_handler::handle_auth_complete_v2(
    const std::string& request_body) {
  Logger::amf_app().info("[PreCheck] === /mutual_auth/complete REQUEST ===");
  
  if (!m_auth_module || !m_auth_module->is_initialized()) {
    Logger::amf_app().error("[PreCheck] BCF authentication module not available");
    return make_error_response(
        503, "SERVICE_UNAVAILABLE", "BCF authentication module not available");
  }

  try {
    // Step 1: Parse JSON
    nlohmann::json j;
    try {
      j = nlohmann::json::parse(request_body);
    } catch (const nlohmann::json::exception& e) {
      Logger::amf_app().error("[PreCheck] Invalid JSON: %s", e.what());
      return make_error_response(
          400, "INVALID_REQUEST", "Invalid JSON: " + std::string(e.what()));
    }
    
    // Step 2: Parse v2 request
    auth_complete_request_v2_t request = auth_complete_request_v2_t::from_json(j);
    
    Logger::amf_app().info(
        "[PreCheck] Received complete request: session_id=%s",
        request.session_id.c_str());
    
    // Step 3: PreCheck validation for complete request
    // 需要从 session 获取 initiator_did 和 responder_did
    std::string expected_initiator_did;
    std::string expected_responder_did;
    
    auto session = m_auth_module->get_session_info(request.session_id);
    if (session) {
      expected_initiator_did = session->remote_did;   // 对方是 initiator
      expected_responder_did = session->local_did;    // 我们是 responder
    }
    
    // 函数签名: (session_id, initiator_signature, timestamp_ms, expected_initiator_did, expected_responder_did)
    auto precheck_result = m_prechecker.precheck_auth_complete_request(
        request.session_id,
        request.initiator_signature,
        request.timestamp_ms,
        expected_initiator_did,
        expected_responder_did);
    
    if (!precheck_result.success) {
      Logger::amf_app().error(
          "[PreCheck] FAILED: error=%s, detail=%s",
          precheck_error_to_string(precheck_result.error).c_str(),
          precheck_result.detail.c_str());
      
      return make_error_response(
          precheck_result.http_code(),
          precheck_result.error_code,
          precheck_result.detail);
    }
    
    Logger::amf_app().info("[PreCheck] All checks passed, proceeding to auth logic");
    
    // Step 4: Convert v2 request to v1 for existing auth module
    auth_complete_request_t v1_request;
    v1_request.session_id = request.session_id;
    v1_request.signature  = request.initiator_signature;
    v1_request.timestamp  = std::to_string(request.timestamp_ms);

    // Step 5: Handle authentication complete
    auth_result_response_t auth_result = m_auth_module->handle_auth_complete(v1_request);

    if (auth_result.result != AuthResult::SUCCESS &&
        auth_result.result != AuthResult::MUTUAL_SUCCESS) {
      std::string error_code;
      int status_code = 400;

      switch (auth_result.result) {
        case AuthResult::FAILURE_SESSION_NOT_FOUND:
          error_code  = "SESSION_NOT_FOUND";
          status_code = 404;
          break;
        case AuthResult::FAILURE_SIGNATURE_INVALID:
          error_code  = "SIGNATURE_INVALID";
          status_code = 401;
          break;
        default:
          error_code  = "AUTH_FAILED";
          status_code = 401;
          break;
      }

      Logger::amf_app().error(
          "[PreCheck] Auth logic failed: code=%s, msg=%s",
          error_code.c_str(), auth_result.message.c_str());
      return make_error_response(status_code, error_code, auth_result.message);
    }

    // Step 6: Convert to v2 response format
    auth_complete_response_v2_t v2_response;
    v2_response.success       = true;
    v2_response.auth_token    = auth_result.auth_token;
    v2_response.expires_in    = auth_result.expires_in;
    v2_response.initiator_did = session ? session->remote_did : "";
    v2_response.responder_did = session ? session->local_did : "";
    v2_response.session_id    = request.session_id;
    v2_response.timestamp_ms  = std::chrono::duration_cast<std::chrono::milliseconds>(
                                    std::chrono::system_clock::now().time_since_epoch())
                                    .count();
    
    Logger::amf_app().info(
        "[PreCheck] === /mutual_auth/complete RESPONSE SUCCESS === session_id=%s",
        v2_response.session_id.c_str());

    return make_success_response(v2_response.to_json().dump());

  } catch (const std::exception& e) {
    Logger::amf_app().error("[PreCheck] Exception: %s", e.what());
    return make_error_response(
        500, "INTERNAL_ERROR", "Internal error: " + std::string(e.what()));
  }
}

//------------------------------------------------------------------------------
http_response_t did_auth_http_handler::handle_get_session_status(
    const std::string& session_id) {
  if (!m_auth_module || !m_auth_module->is_initialized()) {
    return make_error_response(
        503, "SERVICE_UNAVAILABLE", "BCF authentication module not available");
  }

  auto session = m_auth_module->get_session_info(session_id);
  if (!session) {
    return make_error_response(404, "SESSION_NOT_FOUND", "Session not found");
  }

  nlohmann::json response = {
      {"sessionId", session->session_id},
      {"state", static_cast<int>(session->state)},
      {"localDid", session->local_did},
      {"remoteDid", session->remote_did},
      {"isInitiator", session->is_initiator},
      {"authenticated",
       session->state == AuthState::MUTUAL_AUTH_COMPLETE},
  };

  if (session->state == AuthState::MUTUAL_AUTH_COMPLETE &&
      !session->auth_token.empty()) {
    response["hasAuthToken"] = true;
    response["tokenExpiresAt"] = session->token_expires_at;
  }

  return make_success_response(response.dump());
}

//------------------------------------------------------------------------------
AuthResult did_auth_http_handler::validate_auth_header(
    const std::string& auth_token, const std::string& did) {
  if (!m_auth_module || !m_auth_module->is_initialized()) {
    return AuthResult::FAILURE_INTERNAL_ERROR;
  }

  return m_auth_module->verify_auth_token(auth_token, did);
}

//------------------------------------------------------------------------------
AuthResult did_auth_http_handler::validate_bcf_token(
    const std::string& bcf_token,
    const std::string& expected_target_nf_type,
    const std::string& bcf_public_key) {
  if (!m_auth_module || !m_auth_module->is_initialized()) {
    Logger::amf_app().error("[BCF Token] Auth module not initialized");
    return AuthResult::FAILURE_INTERNAL_ERROR;
  }

  if (bcf_token.empty()) {
    Logger::amf_app().warn("[BCF Token] Empty BCF token received");
    return AuthResult::FAILURE_TOKEN_INVALID;
  }

  try {
    // Parse BCF token (expected format: JSON with BCF signature)
    // Token structure from BCF:
    // {
    //   "token": "<jwt-or-opaque-token>",
    //   "requester_did": "did:oai5gc:...",
    //   "target_nf_type": "AMF",
    //   "issued_at": 1234567890,
    //   "expires_at": 1234568790,
    //   "bcf_signature": "<hex-signature>"
    // }
    nlohmann::json token_json;
    try {
      token_json = nlohmann::json::parse(bcf_token);
    } catch (const nlohmann::json::exception&) {
      // Token might be opaque/JWT format, fall back to basic validation
      Logger::amf_app().debug(
          "[BCF Token] Token is not JSON, using legacy validation");
      return m_auth_module->verify_auth_token(bcf_token, "");
    }

    // Check expiry
    if (token_json.contains("expires_at")) {
      uint64_t expires_at = token_json["expires_at"].get<uint64_t>();
      uint64_t now = std::chrono::duration_cast<std::chrono::seconds>(
                         std::chrono::system_clock::now().time_since_epoch())
                         .count();
      if (now > expires_at) {
        Logger::amf_app().warn(
            "[BCF Token] Token expired at %lu, current time %lu",
            expires_at, now);
        return AuthResult::FAILURE_TOKEN_EXPIRED;
      }
    }

    // Check target NF type if specified
    if (!expected_target_nf_type.empty() &&
        token_json.contains("target_nf_type")) {
      std::string token_target =
          token_json["target_nf_type"].get<std::string>();
      if (token_target != expected_target_nf_type) {
        Logger::amf_app().warn(
            "[BCF Token] Token target NF type mismatch: expected=%s, got=%s",
            expected_target_nf_type.c_str(), token_target.c_str());
        return AuthResult::FAILURE_TOKEN_INVALID;
      }
    }

    // Verify BCF signature if BCF public key is available
    if (!bcf_public_key.empty() && token_json.contains("bcf_signature")) {
      // TODO: Verify BCF signature using bcf_public_key
      // This would validate that the token was indeed issued by BCF
      Logger::amf_app().debug(
          "[BCF Token] BCF signature verification - to be implemented with BCF public key");
    }

    Logger::amf_app().info(
        "[BCF Token] Token validation successful, requester_did=%s",
        token_json.value("requester_did", "(unknown)").c_str());

    return AuthResult::SUCCESS;

  } catch (const std::exception& e) {
    Logger::amf_app().error(
        "[BCF Token] Exception during token validation: %s", e.what());
    return AuthResult::FAILURE_INTERNAL_ERROR;
  }
}

//==============================================================================
// did_auth_http_client Implementation
//==============================================================================

did_auth_http_client::did_auth_http_client(
    std::shared_ptr<did_auth_module> auth_module, uint64_t timeout_sec)
    : m_auth_module(auth_module), m_timeout_sec(timeout_sec) {}

//------------------------------------------------------------------------------
did_auth_http_client::~did_auth_http_client() {}

//------------------------------------------------------------------------------
int did_auth_http_client::send_post_request(
    const std::string& url, const std::string& body,
    std::string& response_body) {
  CURL* curl = curl_easy_init();
  if (!curl) {
    return -1;
  }

  response_body.clear();

  curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
  curl_easy_setopt(curl, CURLOPT_POST, 1L);
  curl_easy_setopt(curl, CURLOPT_POSTFIELDS, body.c_str());
  curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, body.size());
  curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, curl_write_callback);
  curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response_body);
  curl_easy_setopt(curl, CURLOPT_TIMEOUT, static_cast<long>(m_timeout_sec));
  curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, 5L);

  struct curl_slist* headers = nullptr;
  headers = curl_slist_append(headers, "Content-Type: application/json");
  headers = curl_slist_append(headers, "Accept: application/json");
  curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);

  CURLcode res = curl_easy_perform(curl);

  long http_code = 0;
  if (res == CURLE_OK) {
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);
  }

  curl_slist_free_all(headers);
  curl_easy_cleanup(curl);

  return (res == CURLE_OK) ? static_cast<int>(http_code) : -1;
}

//------------------------------------------------------------------------------
void did_auth_http_client::initiate_mutual_auth_async(
    const std::string& target_endpoint, auth_complete_callback_t callback) {
  // Run authentication in a separate thread
  std::thread([this, target_endpoint, callback]() {
    std::string session_id;
    std::string auth_token;

    AuthResult result =
        initiate_mutual_auth(target_endpoint, session_id, auth_token);

    bool success = (result == AuthResult::SUCCESS ||
                    result == AuthResult::MUTUAL_SUCCESS);

    std::string error_message;
    if (!success) {
      error_message = auth_result_to_string(result);
    }

    callback(success, session_id, auth_token, error_message);
  }).detach();
}

//------------------------------------------------------------------------------
AuthResult did_auth_http_client::initiate_mutual_auth(
    const std::string& target_endpoint, std::string& session_id,
    std::string& auth_token) {
  if (!m_auth_module || !m_auth_module->is_initialized()) {
    return AuthResult::FAILURE_INTERNAL_ERROR;
  }

  // Step 1: Create authentication init request
  auto [init_request, sid] =
      m_auth_module->create_auth_init_request(target_endpoint);
  session_id = sid;

  if (session_id.empty()) {
    return AuthResult::FAILURE_INTERNAL_ERROR;
  }

  // Step 2: Send init request to target
  std::string init_url = target_endpoint + "/nf_auth/v1/mutual_auth/init";
  std::string response_body;

  int http_code =
      send_post_request(init_url, init_request.to_json().dump(), response_body);

  if (http_code != 200) {
    m_auth_module->close_session(session_id);
    if (http_code < 0) {
      return AuthResult::FAILURE_BCF_UNAVAILABLE;  // Network error
    }
    return AuthResult::FAILURE_INTERNAL_ERROR;
  }

  // Step 3: Parse challenge response
  auth_challenge_response_t challenge;
  try {
    nlohmann::json j = nlohmann::json::parse(response_body);
    challenge        = auth_challenge_response_t::from_json(j);
  } catch (const std::exception& e) {
    m_auth_module->close_session(session_id);
    return AuthResult::FAILURE_INTERNAL_ERROR;
  }

  // Step 4: Process challenge and create complete request
  auto [complete_request, process_result] =
      m_auth_module->process_auth_challenge(session_id, challenge);

  if (process_result != AuthResult::SUCCESS) {
    return process_result;
  }

  // Step 5: Send complete request
  std::string complete_url =
      target_endpoint + "/nf_auth/v1/mutual_auth/complete";
  response_body.clear();

  http_code = send_post_request(
      complete_url, complete_request.to_json().dump(), response_body);

  if (http_code != 200) {
    m_auth_module->close_session(session_id);
    return AuthResult::FAILURE_INTERNAL_ERROR;
  }

  // Step 6: Parse final result
  auth_result_response_t final_result;
  try {
    nlohmann::json j = nlohmann::json::parse(response_body);
    final_result     = auth_result_response_t::from_json(j);
  } catch (const std::exception& e) {
    m_auth_module->close_session(session_id);
    return AuthResult::FAILURE_INTERNAL_ERROR;
  }

  // Step 7: Process final result
  m_auth_module->process_auth_result(session_id, final_result);

  if (final_result.result == AuthResult::SUCCESS ||
      final_result.result == AuthResult::MUTUAL_SUCCESS) {
    auth_token = final_result.auth_token;
    return AuthResult::MUTUAL_SUCCESS;
  }

  return final_result.result;
}

//------------------------------------------------------------------------------
AuthResult did_auth_http_client::ensure_authenticated(
    const std::string& target_endpoint, const std::string& target_did,
    std::string& auth_token) {
  if (!m_auth_module || !m_auth_module->is_initialized()) {
    return AuthResult::FAILURE_INTERNAL_ERROR;
  }

  // Check if we already have an authenticated session
  std::string existing_session =
      m_auth_module->find_authenticated_session(target_did);

  if (!existing_session.empty()) {
    auth_token = m_auth_module->get_auth_token(existing_session);
    if (!auth_token.empty()) {
      return AuthResult::SUCCESS;  // Already authenticated
    }
  }

  // Need to authenticate
  std::string session_id;
  return initiate_mutual_auth(target_endpoint, session_id, auth_token);
}

}  // namespace oai::amf::did_auth
