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

/*
 * DIDAuthApi.h
 *
 * DID-based Mutual Authentication API for NF-to-NF communication
 */

#ifndef DID_AUTH_API_H_
#define DID_AUTH_API_H_

#include <pistache/http.h>
#include <pistache/http_headers.h>
#include <pistache/optional.h>
#include <pistache/router.h>

#include <string>
#include <memory>

namespace oai {
namespace amf {
namespace api {

/**
 * @brief DID Authentication API base class
 *
 * Provides HTTP endpoints for DID-based mutual authentication:
 * - POST /nf_auth/v1/mutual_auth/init    - Initiate authentication
 * - POST /nf_auth/v1/mutual_auth/complete - Complete authentication
 * - GET  /nf_auth/v1/status/{sessionId}   - Check auth status
 */
class DIDAuthApi {
 public:
  DIDAuthApi(std::shared_ptr<Pistache::Rest::Router> rtr);
  virtual ~DIDAuthApi() {}

  void init();

  // Base path for DID auth API
  static const std::string base;

 private:
  void setupRoutes();

  // Route handlers
  void auth_init_handler(
      const Pistache::Rest::Request& request,
      Pistache::Http::ResponseWriter response);

  void auth_complete_handler(
      const Pistache::Rest::Request& request,
      Pistache::Http::ResponseWriter response);

  void auth_status_handler(
      const Pistache::Rest::Request& request,
      Pistache::Http::ResponseWriter response);

  void bcf_notification_handler(
      const Pistache::Rest::Request& request,
      Pistache::Http::ResponseWriter response);

  void did_auth_default_handler(
      const Pistache::Rest::Request& request,
      Pistache::Http::ResponseWriter response);

  std::shared_ptr<Pistache::Rest::Router> router;

  // Virtual methods to be implemented by DIDAuthApiImpl
  /**
   * @brief Handle authentication init request from peer NF
   * @param request_body JSON body containing initiator_did, nonce, timestamp
   * @param source_address Source IP address
   * @param response HTTP response writer
   */
  virtual void handle_auth_init(
      const std::string& request_body,
      const std::string& source_address,
      Pistache::Http::ResponseWriter& response) = 0;

  /**
   * @brief Handle authentication complete request from peer NF
   * @param request_body JSON body containing session_id, initiator_signature, nonce
   * @param source_address Source IP address
   * @param response HTTP response writer
   */
  virtual void handle_auth_complete(
      const std::string& request_body,
      const std::string& source_address,
      Pistache::Http::ResponseWriter& response) = 0;

  /**
   * @brief Check authentication session status
   * @param session_id Authentication session ID
   * @param response HTTP response writer
   */
  virtual void handle_auth_status(
      const std::string& session_id,
      Pistache::Http::ResponseWriter& response) = 0;

  /**
   * @brief Handle BCF callback notification
   * @param request_body Notification JSON body
   * @param source_address Source IP address
   * @param response HTTP response writer
   */
  virtual void handle_bcf_notification(
      const std::string& request_body,
      const std::string& source_address,
      Pistache::Http::ResponseWriter& response) = 0;
};

}  // namespace api
}  // namespace amf
}  // namespace oai

#endif /* DID_AUTH_API_H_ */
