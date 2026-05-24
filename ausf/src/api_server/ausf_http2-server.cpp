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

#include <algorithm>
#include <boost/algorithm/string.hpp>
#include <boost/thread.hpp>
#include <boost/thread/future.hpp>
#include <nlohmann/json.hpp>
#include <regex>
#include <string>

#include "3gpp_29.500.h"
#include "ausf-http2-server.h"
#include "ausf_config.hpp"
#include "ausf_sbi_helper.hpp"
#include "ausf_token_auth.hpp"
#include "logger.hpp"
#include "security_audit.hpp"
#include "string.hpp"

using namespace nghttp2::asio_http2;
using namespace nghttp2::asio_http2::server;
using namespace oai::model::ausf;
using namespace oai::config;
using namespace oai::ausf::api;

extern ausf_config ausf_cfg;

namespace {

unsigned int to_http2_status_code(Pistache::Http::Code code) {
  switch (code) {
    case Pistache::Http::Code::Bad_Request:
      return static_cast<unsigned int>(
          oai::common::sbi::http_status_code::BAD_REQUEST);
    case Pistache::Http::Code::Forbidden:
      return static_cast<unsigned int>(
          oai::common::sbi::http_status_code::FORBIDDEN);
    case Pistache::Http::Code::Service_Unavailable:
      return static_cast<unsigned int>(
          oai::common::sbi::http_status_code::SERVICE_UNAVAILABLE);
    case Pistache::Http::Code::Unauthorized:
    default:
      return static_cast<unsigned int>(
          oai::common::sbi::http_status_code::UNAUTHORIZED);
  }
}

std::string audit_header_value(
    const header_map& request_headers, const std::string& name) {
  for (const auto& entry : request_headers) {
    if (boost::iequals(entry.first, name)) {
      return entry.second.value;
    }
  }
  return {};
}

oai::common::audit::audit_request_context build_audit_context(
    const header_map& request_headers) {
  return {
      audit_header_value(request_headers, "x-session-id"),
      audit_header_value(request_headers, "x-interaction-id"),
      audit_header_value(request_headers, "x-subject-did"),
      audit_header_value(request_headers, "x-peer-did"),
      audit_header_value(request_headers, "x-subject-nf-type"),
      audit_header_value(request_headers, "x-peer-nf-type"),
  };
}

}  // namespace

//------------------------------------------------------------------------------
void ausf_http2_server::start() {
  boost::system::error_code ec;

  Logger::ausf_server().info("HTTP2 server being started");

  // Default API
  server.handle(
      ausf_sbi_helper::UEAuthenticationServiceBase +
          ausf_sbi_helper::AusfAuthPathUeAuthentications,
      [&](const request& request, const response& response) {
        // Capture headers before on_data (request may become invalid after)
        const header_map& request_headers = request.header();
        request.on_data([&, request_headers](const uint8_t* data, std::size_t len) {
          std::string msg((char*) data, len);
          try {
            std::vector<std::string> split_result;
            boost::split(
                split_result, request.uri().path, boost::is_any_of("/"));
            if (request.method().compare("POST") == 0 && len > 0) {
              AuthenticationInfo authenticationInfo;
              const auto request_payload = nlohmann::json::parse(msg.c_str());
              request_payload.get_to(authenticationInfo);
              this->ue_authentications_post_handler(
                  authenticationInfo, request_payload, request_headers,
                  response);
            }
          } catch (std::exception& e) {
            Logger::ausf_server().warn(
                "Invalid request (error: %s)!", e.what());
            response.write_head(
                oai::common::sbi::http_status_code::BAD_REQUEST);
            response.end();
            return;
          }
        });
      });

  server.handle(
      ausf_sbi_helper::UEAuthenticationServiceBase +
          ausf_sbi_helper::AusfAuthPathUeAuthentications + "/",
      [&](const request& request, const response& response) {
        request.on_data([&](const uint8_t* data, std::size_t len) {
          std::string msg((char*) data, len);
          try {
            std::vector<std::string> split_result;
            boost::split(
                split_result, request.uri().path, boost::is_any_of("/"));
            if (request.method().compare("POST") == 0 && len > 0) {
              if (split_result[split_result.size() - 1].compare(
                      "eap-session") == 0) {
                EapSession eapSession;
                std::string authCtxId =
                    split_result[split_result.size() - 2].c_str();
                nlohmann::json::parse(msg.c_str()).get_to(eapSession);
                this->eap_auth_method_handler(authCtxId, eapSession, response);
              }
              if (split_result[split_result.size() - 1].compare("deregister") ==
                  0) {
                DeregistrationInfo deregistrationInfo;
                nlohmann::json::parse(msg.c_str()).get_to(deregistrationInfo);
                this->ue_authentications_deregister_post_handler(
                    deregistrationInfo, response);
              }
            }
            if (request.method().compare("PUT") == 0 && len > 0) {
              ConfirmationData confirmationData;
              std::string authCtxId =
                  split_result[split_result.size() - 2].c_str();
              nlohmann::json::parse(msg.c_str()).get_to(confirmationData);
              this->ue_authentications_auth_ctx_id5g_aka_confirmation_put_handler(
                  authCtxId, confirmationData, response);
            }
          } catch (std::exception& e) {
            Logger::ausf_server().warn(
                "Invalid request (error: %s)!", e.what());
            response.write_head(
                oai::common::sbi::http_status_code::BAD_REQUEST);
            response.end();
            return;
          }
        });
      });

  server.handle(
      ausf_sbi_helper::UEAuthenticationServiceBase + NAUSF_RG_AUTH,
      [&](const request& request, const response& response) {
        request.on_data([&](const uint8_t* data, std::size_t len) {
          std::string msg((char*) data, len);
          try {
            std::vector<std::string> split_result;
            boost::split(
                split_result, request.uri().path, boost::is_any_of("/"));
            if (request.method().compare("POST") == 0 && len > 0) {
              RgAuthenticationInfo rgAuthenticationInfo;
              std::string authCtxId =
                  split_result[split_result.size() - 2].c_str();
              nlohmann::json::parse(msg.c_str()).get_to(rgAuthenticationInfo);
              this->rg_authentications_post_handler(
                  rgAuthenticationInfo, response);
            }
          } catch (std::exception& e) {
            Logger::ausf_server().warn(
                "Invalid request (error: %s)!", e.what());
            response.write_head(
                oai::common::sbi::http_status_code::BAD_REQUEST);
            response.end();
            return;
          }
        });
      });

  running_server = true;
  if (server.listen_and_serve(ec, m_address, std::to_string(m_port))) {
    Logger::ausf_server().debug("HTTP Server status: %s", ec.message());
  }
  running_server = false;
  Logger::ausf_server().info("HTTP2 server fully stopped");
}

//------------------------------------------------------------------------
void ausf_http2_server::stop() {
  server.stop();
  while (running_server) {
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
  }
  Logger::ausf_server().info("HTTP2 server should be fully stopped");
  std::this_thread::sleep_for(std::chrono::milliseconds(50));
}

//------------------------------------------------------------------------
void ausf_http2_server::eap_auth_method_handler(
    const std::string& authCtxId, const EapSession& eapSession,
    const response& response) {
  Logger::ausf_server().info("eap_auth_method");
  header_map h;
  response.write_head(oai::common::sbi::http_status_code::NOT_IMPLEMENTED, h);
  response.end("eap_auth_method API has not been implemented yet!");
}

//------------------------------------------------------------------------
void ausf_http2_server::rg_authentications_post_handler(
    const RgAuthenticationInfo& rgAuthenticationInfo,
    const response& response) {
  Logger::ausf_server().info("rg_authentications_post");
  header_map h;
  response.write_head(oai::common::sbi::http_status_code::NOT_IMPLEMENTED, h);
  response.end("rg_authentications_post API has not been implemented yet!");
}

//------------------------------------------------------------------------
void ausf_http2_server::ue_authentications_deregister_post_handler(
    const DeregistrationInfo& deregistrationInfo, const response& response) {
  Logger::ausf_server().info("ue_authentications_deregister_post");
  header_map h;
  response.write_head(oai::common::sbi::http_status_code::NOT_IMPLEMENTED, h);
  response.end(
      "ue_authentications_deregister_post API has not been implemented yet!");
}

//------------------------------------------------------------------------
void ausf_http2_server::
    ue_authentications_auth_ctx_id5g_aka_confirmation_put_handler(
        const std::string& authCtxId, const ConfirmationData& confirmationData,
        const response& response) {
  Logger::ausf_server().info("Received 5g_aka_confirmation Request");

  Logger::ausf_server().info(
      "5gaka confirmation received with authctxID %s", authCtxId.c_str());

  nlohmann::json json_data  = {};
  Pistache::Http::Code code = {};
  header_map h;

  m_ausf_app->handle_ue_authentications_confirmation(
      authCtxId, confirmationData, json_data, code);

  // ausf --> seaf
  Logger::ausf_server().debug(
      "5g-aka-confirmation response:\n %s", json_data.dump().c_str());

  Logger::ausf_server().info(
      "Send 5g-aka-confirmation response to SEAF (Code %d)", (int) code);
  if (code == Pistache::Http::Code::Ok)
    response.write_head(oai::common::sbi::http_status_code::OK, h);
  else
    response.write_head(oai::common::sbi::http_status_code::FORBIDDEN, h);
  response.end(json_data.dump().c_str());
}

//------------------------------------------------------------------------
void ausf_http2_server::ue_authentications_post_handler(
    const AuthenticationInfo& authenticationInfo,
    const nlohmann::json& request_payload,
    const header_map& request_headers,
    const response& response) {
  Logger::ausf_server().info("Received ue_authentications_post Request");

  std::string reponse_from_udm    = {};
  std::string location            = {};
  UEAuthenticationCtx ue_auth_ctx = {};
  nlohmann::json UEAuthCtx_json   = {};
  Pistache::Http::Code code       = {};
  header_map h;

  // =========================================================================
  // BCF Access Token Verification
  // When BCF auth is enabled, verify the requesting AMF access token before
  // entering the UE authentication flow.
  // =========================================================================
  if (ausf_cfg.register_bcf) {
    oai::ausf::auth::token_validation_result_t token_result = {};
    if (!oai::ausf::auth::authorize_ue_authentication_request(
            request_payload, request_headers, token_result)) {
      h.insert(std::make_pair("content-type", header_value{"application/json"}));
      response.write_head(to_http2_status_code(token_result.http_status), h);
      response.end(token_result.error_body.dump().c_str());
      return;
    }
  }
  // =========================================================================

  oai::common::audit::set_thread_audit_context(
      build_audit_context(request_headers));
  m_ausf_app->handle_ue_authentications(
      authenticationInfo, UEAuthCtx_json, location, code, 2);
  oai::common::audit::clear_thread_audit_context();

  Logger::ausf_server().debug(
      "Auth response:\n %s", UEAuthCtx_json.dump().c_str());

  Logger::ausf_server().info(
      "Send Auth response to SEAF (Code %d)", (int) code);
  if (code == Pistache::Http::Code::Created)
    response.write_head(oai::common::sbi::http_status_code::CREATED, h);
  else
    response.write_head(oai::common::sbi::http_status_code::NOT_FOUND, h);
  response.end(UEAuthCtx_json.dump().c_str());
}
