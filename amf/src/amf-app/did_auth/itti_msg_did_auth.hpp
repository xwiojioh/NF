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

#ifndef _ITTI_MSG_DID_AUTH_H_
#define _ITTI_MSG_DID_AUTH_H_

#include "itti_msg.hpp"
#include "did_auth/did_auth_types.hpp"

#include <functional>
#include <string>

// Forward declaration to avoid circular includes
namespace oai::amf::did_auth {
enum class AuthResult;
}

/**
 * @brief ITTI Message Types for DID Authentication
 *
 * These should be added to the itti_msg_type_t enum in itti_msg.hpp:
 *
 *   // DID Authentication messages
 *   DID_AUTH_INITIATE,
 *   DID_AUTH_INIT_RECEIVED,
 *   DID_AUTH_CHALLENGE_RECEIVED,
 *   DID_AUTH_COMPLETE_RECEIVED,
 *   DID_AUTH_RESULT,
 */

namespace amf_application {

/**
 * @brief Request to initiate DID mutual authentication with a remote NF
 *
 * Sent from AMF_APP to AMF_SBI when AMF needs to authenticate
 * before communicating with another NF.
 */
class itti_did_auth_initiate : public itti_msg {
 public:
  itti_did_auth_initiate(const task_id_t origin, const task_id_t destination)
      : itti_msg(ITTI_MSG_TYPE_NONE, origin, destination) {}

  itti_did_auth_initiate(const itti_did_auth_initiate& i)
      : itti_msg(i),
        remote_endpoint(i.remote_endpoint),
        remote_did(i.remote_did),
        correlation_id(i.correlation_id) {}

  const char* get_msg_name() const { return "DID_AUTH_INITIATE"; }

  // Target NF's HTTP endpoint (e.g., "http://smf:8080")
  std::string remote_endpoint;

  // Target NF's DID (optional, for session lookup)
  std::string remote_did;

  // Correlation ID for tracking the original request
  std::string correlation_id;
};

/**
 * @brief Notification of authentication result
 *
 * Sent from AMF_SBI to AMF_APP when authentication completes
 * (either success or failure).
 */
class itti_did_auth_result : public itti_msg {
 public:
  itti_did_auth_result(const task_id_t origin, const task_id_t destination)
      : itti_msg(ITTI_MSG_TYPE_NONE, origin, destination),
        success(false) {}

  itti_did_auth_result(const itti_did_auth_result& i)
      : itti_msg(i),
        session_id(i.session_id),
        remote_did(i.remote_did),
        remote_endpoint(i.remote_endpoint),
        auth_token(i.auth_token),
        correlation_id(i.correlation_id),
        success(i.success),
        error_message(i.error_message) {}

  const char* get_msg_name() const { return "DID_AUTH_RESULT"; }

  // Authentication session ID
  std::string session_id;

  // Remote NF's DID
  std::string remote_did;

  // Remote NF's endpoint
  std::string remote_endpoint;

  // Authentication token (valid only if success=true)
  std::string auth_token;

  // Correlation ID from the original request
  std::string correlation_id;

  // Whether authentication succeeded
  bool success;

  // Error message (if success=false)
  std::string error_message;
};

/**
 * @brief Request to handle incoming authentication init request
 *
 * Sent from HTTP server to AMF_APP when receiving
 * POST /nf_auth/v1/mutual_auth/init
 */
class itti_did_auth_init_request : public itti_msg {
 public:
  itti_did_auth_init_request(const task_id_t origin, const task_id_t destination)
      : itti_msg(ITTI_MSG_TYPE_NONE, origin, destination),
        http_version(1) {}

  itti_did_auth_init_request(const itti_did_auth_init_request& i)
      : itti_msg(i),
        request_body(i.request_body),
        source_address(i.source_address),
        http_version(i.http_version),
        promise_id(i.promise_id) {}

  const char* get_msg_name() const { return "DID_AUTH_INIT_REQUEST"; }

  // JSON request body
  std::string request_body;

  // Source IP address
  std::string source_address;

  // HTTP version (1 or 2)
  int http_version;

  // Promise ID for async response
  uint32_t promise_id;
};

/**
 * @brief Response to authentication init request
 *
 * Sent from AMF_APP to HTTP server with the challenge response
 */
class itti_did_auth_init_response : public itti_msg {
 public:
  itti_did_auth_init_response(
      const task_id_t origin, const task_id_t destination)
      : itti_msg(ITTI_MSG_TYPE_NONE, origin, destination),
        http_code(200) {}

  itti_did_auth_init_response(const itti_did_auth_init_response& i)
      : itti_msg(i),
        response_body(i.response_body),
        http_code(i.http_code),
        promise_id(i.promise_id) {}

  const char* get_msg_name() const { return "DID_AUTH_INIT_RESPONSE"; }

  // JSON response body
  std::string response_body;

  // HTTP response code
  int http_code;

  // Promise ID to match with request
  uint32_t promise_id;
};

/**
 * @brief Request to handle incoming authentication complete request
 *
 * Sent from HTTP server to AMF_APP when receiving
 * POST /nf_auth/v1/mutual_auth/complete
 */
class itti_did_auth_complete_request : public itti_msg {
 public:
  itti_did_auth_complete_request(
      const task_id_t origin, const task_id_t destination)
      : itti_msg(ITTI_MSG_TYPE_NONE, origin, destination),
        http_version(1) {}

  itti_did_auth_complete_request(const itti_did_auth_complete_request& i)
      : itti_msg(i),
        request_body(i.request_body),
        source_address(i.source_address),
        http_version(i.http_version),
        promise_id(i.promise_id) {}

  const char* get_msg_name() const { return "DID_AUTH_COMPLETE_REQUEST"; }

  // JSON request body
  std::string request_body;

  // Source IP address
  std::string source_address;

  // HTTP version (1 or 2)
  int http_version;

  // Promise ID for async response
  uint32_t promise_id;
};

/**
 * @brief Response to authentication complete request
 *
 * Sent from AMF_APP to HTTP server with the final result
 */
class itti_did_auth_complete_response : public itti_msg {
 public:
  itti_did_auth_complete_response(
      const task_id_t origin, const task_id_t destination)
      : itti_msg(ITTI_MSG_TYPE_NONE, origin, destination),
        http_code(200) {}

  itti_did_auth_complete_response(const itti_did_auth_complete_response& i)
      : itti_msg(i),
        response_body(i.response_body),
        http_code(i.http_code),
        promise_id(i.promise_id) {}

  const char* get_msg_name() const { return "DID_AUTH_COMPLETE_RESPONSE"; }

  // JSON response body
  std::string response_body;

  // HTTP response code
  int http_code;

  // Promise ID to match with request
  uint32_t promise_id;
};

/**
 * @brief Periodic cleanup request for expired sessions and nonces
 *
 * Sent from timer task to AMF_APP periodically
 */
class itti_did_auth_cleanup : public itti_msg {
 public:
  itti_did_auth_cleanup(const task_id_t origin, const task_id_t destination)
      : itti_msg(ITTI_MSG_TYPE_NONE, origin, destination) {}

  itti_did_auth_cleanup(const itti_did_auth_cleanup& i) : itti_msg(i) {}

  const char* get_msg_name() const { return "DID_AUTH_CLEANUP"; }
};

}  // namespace amf_application

#endif  // _ITTI_MSG_DID_AUTH_H_
