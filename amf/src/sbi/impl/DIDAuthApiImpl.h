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
 * DIDAuthApiImpl.h
 *
 * DID Authentication API Implementation
 */

#ifndef DID_AUTH_API_IMPL_H_
#define DID_AUTH_API_IMPL_H_

#include <pistache/endpoint.h>
#include <pistache/http.h>
#include <pistache/router.h>
#include <memory>

#include "DIDAuthApi.h"
#include "amf_app.hpp"

namespace oai {
namespace amf {
namespace api {

/**
 * @brief Implementation of DID Authentication API
 *
 * Handles DID-based mutual authentication requests by delegating
 * to the amf_app's DID auth module.
 */
class DIDAuthApiImpl : public DIDAuthApi {
 public:
  /**
   * @brief Constructor
   * @param rtr Pistache router
   * @param amf_app_inst Pointer to AMF application instance
   */
  DIDAuthApiImpl(
      std::shared_ptr<Pistache::Rest::Router> rtr,
      amf_application::amf_app* amf_app_inst);

  ~DIDAuthApiImpl() override;

  /**
   * @brief Handle authentication init request from peer NF
   *
   * Expected JSON body:
   * {
   *   "initiator_did": "did:oai5gc:...",
   *   "nonce": "hex_encoded_random_bytes",
   *   "timestamp": 1234567890,
   *   "nf_type": "SMF"
   * }
   *
   * Response:
   * {
   *   "session_id": "uuid",
   *   "responder_did": "did:oai5gc:...",
   *   "challenge_nonce": "hex_encoded_random_bytes",
   *   "challenge_timestamp": 1234567890,
   *   "responder_signature": "hex_signature_of_initiator_nonce"
   * }
   */
  void handle_auth_init(
      const std::string& request_body,
      const std::string& source_address,
      Pistache::Http::ResponseWriter& response) override;

  /**
   * @brief Handle authentication complete request from peer NF
   *
   * Expected JSON body:
   * {
   *   "session_id": "uuid",
   *   "initiator_signature": "hex_signature_of_challenge_nonce"
   * }
   *
   * Response:
   * {
   *   "success": true,
   *   "auth_token": "session_token",
   *   "expires_in": 3600
   * }
   */
  void handle_auth_complete(
      const std::string& request_body,
      const std::string& source_address,
      Pistache::Http::ResponseWriter& response) override;

  /**
   * @brief Check authentication session status
   *
   * Response:
   * {
   *   "session_id": "uuid",
   *   "state": "AUTHENTICATED",
   *   "peer_did": "did:oai5gc:...",
   *   "authenticated": true
   * }
   */
  void handle_auth_status(
      const std::string& session_id,
      Pistache::Http::ResponseWriter& response) override;

  void handle_bcf_notification(
      const std::string& request_body,
      const std::string& source_address,
      Pistache::Http::ResponseWriter& response) override;

 private:
  amf_application::amf_app* m_amf_app;
};

}  // namespace api
}  // namespace amf
}  // namespace oai

#endif /* DID_AUTH_API_IMPL_H_ */
