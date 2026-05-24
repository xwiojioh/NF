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

#include "DIDAuthApiImpl.h"
#include "logger.hpp"

#include <nlohmann/json.hpp>

namespace oai {
namespace amf {
namespace api {

DIDAuthApiImpl::DIDAuthApiImpl(
    std::shared_ptr<Pistache::Rest::Router> rtr,
    amf_application::amf_app* amf_app_inst)
    : DIDAuthApi(rtr), m_amf_app(amf_app_inst) {}

DIDAuthApiImpl::~DIDAuthApiImpl() {}

// ===========================================================================
// NOTE: All mutual auth handlers are DEPRECATED.
// They now return HTTP 410 (Gone) — BCF single-direction auth replaces
// the old NF-NF mutual authentication.
// ===========================================================================

void DIDAuthApiImpl::handle_auth_init(
    const std::string& request_body,
    const std::string& source_address,
    Pistache::Http::ResponseWriter& response) {
  Logger::amf_server().warn(
      "[BCF Auth] Mutual auth init endpoint is DEPRECATED (Pistache)");
  nlohmann::json error_json;
  error_json["error"]   = "deprecated";
  error_json["message"] = "NF-NF mutual authentication is deprecated. "
                          "Use BCF single-direction auth (POST /nbcf_auth/v1/auth/init).";
  response.send(
      static_cast<Pistache::Http::Code>(410),
      error_json.dump(),
      MIME(Application, Json));
}

void DIDAuthApiImpl::handle_auth_complete(
    const std::string& request_body,
    const std::string& source_address,
    Pistache::Http::ResponseWriter& response) {
  Logger::amf_server().warn(
      "[BCF Auth] Mutual auth complete endpoint is DEPRECATED (Pistache)");
  nlohmann::json error_json;
  error_json["error"]   = "deprecated";
  error_json["message"] = "NF-NF mutual authentication is deprecated. "
                          "Use BCF single-direction auth (POST /nbcf_auth/v1/auth/verify).";
  response.send(
      static_cast<Pistache::Http::Code>(410),
      error_json.dump(),
      MIME(Application, Json));
}

void DIDAuthApiImpl::handle_auth_status(
    const std::string& session_id,
    Pistache::Http::ResponseWriter& response) {
  Logger::amf_server().warn(
      "[BCF Auth] Mutual auth status endpoint is DEPRECATED (Pistache)");
  nlohmann::json error_json;
  error_json["error"]   = "deprecated";
  error_json["message"] = "Mutual auth session status is deprecated.";
  response.send(
      static_cast<Pistache::Http::Code>(410),
      error_json.dump(),
      MIME(Application, Json));
}

void DIDAuthApiImpl::handle_bcf_notification(
    const std::string& request_body,
    const std::string& source_address,
    Pistache::Http::ResponseWriter& response) {
  if (!m_amf_app) {
    Logger::amf_server().warn(
        "BCF callback via HTTP/1 rejected because AMF app is unavailable "
        "source=%s",
        source_address.c_str());
    nlohmann::json error_json;
    error_json["error"]   = "service_unavailable";
    error_json["message"] = "AMF application is not available";
    response.send(
        Pistache::Http::Code::Service_Unavailable,
        error_json.dump(),
        MIME(Application, Json));
    return;
  }

  try {
    if (m_amf_app->handle_bcf_notification(request_body)) {
      response.send(Pistache::Http::Code::No_Content);
      return;
    }

    Logger::amf_server().warn(
        "BCF callback via HTTP/1 failed validation source=%s bytes=%zu",
        source_address.c_str(), request_body.size());
    nlohmann::json error_json;
    error_json["error"]   = "invalid_notification";
    error_json["message"] = "Failed to process BCF notification";
    response.send(
        Pistache::Http::Code::Bad_Request,
        error_json.dump(),
        MIME(Application, Json));
  } catch (const std::exception& e) {
    Logger::amf_server().warn(
        "BCF callback via HTTP/1 raised exception source=%s error=%s",
        source_address.c_str(), e.what());
    nlohmann::json error_json;
    error_json["error"]   = "internal_error";
    error_json["message"] = e.what();
    response.send(
        Pistache::Http::Code::Internal_Server_Error,
        error_json.dump(),
        MIME(Application, Json));
  }
}

}  // namespace api
}  // namespace amf
}  // namespace oai
