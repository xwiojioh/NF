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

#include "DIDAuthApi.h"
#include "amf_config.hpp"
#include "logger.hpp"

#include <nlohmann/json.hpp>

extern std::unique_ptr<oai::config::amf_config> amf_cfg;

namespace oai {
namespace amf {
namespace api {

// Base path for DID authentication API
const std::string DIDAuthApi::base = "/nf_auth/v1";

DIDAuthApi::DIDAuthApi(std::shared_ptr<Pistache::Rest::Router> rtr) {
  router = rtr;
}

void DIDAuthApi::init() {
  setupRoutes();
}

void DIDAuthApi::setupRoutes() {
  using namespace Pistache::Rest;
  const std::string api_version = amf_cfg && amf_cfg->sbi.api_version.has_value()
                                      ? amf_cfg->sbi.api_version.value()
                                      : "v1";
  const std::string bcf_callback_path =
      "/namf-callback/" + api_version + "/nbcf_management/" + api_version +
      "/notifications";

  // POST /nf_auth/v1/mutual_auth/init
  Routes::Post(
      *router, base + "/mutual_auth/init",
      Routes::bind(&DIDAuthApi::auth_init_handler, this));

  // POST /nf_auth/v1/mutual_auth/complete
  Routes::Post(
      *router, base + "/mutual_auth/complete",
      Routes::bind(&DIDAuthApi::auth_complete_handler, this));

  // GET /nf_auth/v1/status/:sessionId
  Routes::Get(
      *router, base + "/status/:sessionId",
      Routes::bind(&DIDAuthApi::auth_status_handler, this));

  Routes::Post(
      *router, bcf_callback_path,
      Routes::bind(&DIDAuthApi::bcf_notification_handler, this));

  Logger::amf_server().info(
      "DID Auth API routes configured, BCF callback route=%s",
      bcf_callback_path.c_str());
}

void DIDAuthApi::auth_init_handler(
    const Pistache::Rest::Request& request,
    Pistache::Http::ResponseWriter response) {
  Logger::amf_server().debug("Received DID Auth Init request");

  // Get source address
  std::string source_address;
  auto address = request.address();
  source_address = address.host();

  // Get request body
  std::string request_body = request.body();

  if (request_body.empty()) {
    Logger::amf_server().warn("DID Auth Init: Empty request body");
    nlohmann::json error_json;
    error_json["error"]   = "bad_request";
    error_json["message"] = "Request body is empty";
    response.send(
        Pistache::Http::Code::Bad_Request,
        error_json.dump(),
        MIME(Application, Json));
    return;
  }

  // Delegate to implementation
  handle_auth_init(request_body, source_address, response);
}

void DIDAuthApi::auth_complete_handler(
    const Pistache::Rest::Request& request,
    Pistache::Http::ResponseWriter response) {
  Logger::amf_server().debug("Received DID Auth Complete request");

  // Get source address
  std::string source_address;
  auto address = request.address();
  source_address = address.host();

  // Get request body
  std::string request_body = request.body();

  if (request_body.empty()) {
    Logger::amf_server().warn("DID Auth Complete: Empty request body");
    nlohmann::json error_json;
    error_json["error"]   = "bad_request";
    error_json["message"] = "Request body is empty";
    response.send(
        Pistache::Http::Code::Bad_Request,
        error_json.dump(),
        MIME(Application, Json));
    return;
  }

  // Delegate to implementation
  handle_auth_complete(request_body, source_address, response);
}

void DIDAuthApi::auth_status_handler(
    const Pistache::Rest::Request& request,
    Pistache::Http::ResponseWriter response) {
  Logger::amf_server().debug("Received DID Auth Status request");

  // Get session ID from path parameter
  auto session_id = request.param(":sessionId").as<std::string>();

  if (session_id.empty()) {
    Logger::amf_server().warn("DID Auth Status: Empty session ID");
    nlohmann::json error_json;
    error_json["error"]   = "bad_request";
    error_json["message"] = "Session ID is required";
    response.send(
        Pistache::Http::Code::Bad_Request,
        error_json.dump(),
        MIME(Application, Json));
    return;
  }

  // Delegate to implementation
  handle_auth_status(session_id, response);
}

void DIDAuthApi::bcf_notification_handler(
    const Pistache::Rest::Request& request,
    Pistache::Http::ResponseWriter response) {
  auto address = request.address();
  const std::string source_address = address.host();
  const std::string request_body   = request.body();

  Logger::amf_server().info(
      "Received BCF notification via HTTP/1 source=%s path=%s bytes=%zu",
      source_address.c_str(), request.resource().c_str(), request_body.size());

  if (request_body.empty()) {
    Logger::amf_server().warn(
        "BCF callback via HTTP/1 has empty request body source=%s path=%s",
        source_address.c_str(), request.resource().c_str());
    nlohmann::json error_json;
    error_json["error"]   = "bad_request";
    error_json["message"] = "Request body is empty";
    response.send(
        Pistache::Http::Code::Bad_Request,
        error_json.dump(),
        MIME(Application, Json));
    return;
  }

  handle_bcf_notification(request_body, source_address, response);
}

void DIDAuthApi::did_auth_default_handler(
    const Pistache::Rest::Request& request,
    Pistache::Http::ResponseWriter response) {
  Logger::amf_server().warn(
      "DID Auth: Unhandled request - %s %s",
      Pistache::Http::methodString(request.method()),
      request.resource().c_str());

  response.send(Pistache::Http::Code::Not_Found, "Not found");
}

}  // namespace api
}  // namespace amf
}  // namespace oai
