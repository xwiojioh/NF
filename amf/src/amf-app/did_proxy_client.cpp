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

#include "did_proxy_client.hpp"
#include "logger.hpp"
#include "http_client.hpp"

namespace amf_application {

extern std::shared_ptr<oai::http::http_client> http_client_inst;

//------------------------------------------------------------------------------
did_proxy_client::did_proxy_client(
    const std::string& proxy_host, unsigned int proxy_port)
    : m_proxy_host(proxy_host), m_proxy_port(proxy_port) {
  Logger::amf_app().info(
      "DID Proxy Client initialized (host: %s, port: %d)",
      m_proxy_host.c_str(), m_proxy_port);
}

//------------------------------------------------------------------------------
did_proxy_client::~did_proxy_client() {
  Logger::amf_app().debug("DID Proxy Client destroyed");
}

//------------------------------------------------------------------------------
std::string did_proxy_client::get_base_uri() const {
  return "http://" + m_proxy_host + ":" + std::to_string(m_proxy_port);
}

//------------------------------------------------------------------------------
bool did_proxy_client::send_get_request(
    const std::string& path, nlohmann::json& response) {
  std::string uri = get_base_uri() + path;
  Logger::amf_app().debug("DID Proxy GET request: %s", uri.c_str());

  try {
    oai::http::request req;
    req.uri = uri;
    req.headers["Accept"] = "application/json";

    auto resp = http_client_inst->send_http_request(
        oai::common::sbi::method_e::GET, req);

    if (resp.status_code == 200) {
      response = resp.get_json();
      return true;
    } else {
      Logger::amf_app().warn(
          "DID Proxy GET request failed with status: %d", resp.status_code);
      return false;
    }
  } catch (const std::exception& e) {
    Logger::amf_app().error("DID Proxy GET request exception: %s", e.what());
    return false;
  }
}

//------------------------------------------------------------------------------
bool did_proxy_client::send_post_request(
    const std::string& path, nlohmann::json& response) {
  std::string uri = get_base_uri() + path;
  Logger::amf_app().debug("DID Proxy POST request: %s", uri.c_str());

  try {
    oai::http::request req;
    req.uri = uri;
    req.headers["Accept"] = "application/json";
    req.headers["Content-Type"] = "application/json";

    auto resp = http_client_inst->send_http_request(
        oai::common::sbi::method_e::POST, req);

    if (resp.status_code == 200 || resp.status_code == 201) {
      response = resp.get_json();
      return true;
    } else {
      Logger::amf_app().warn(
          "DID Proxy POST request failed with status: %d", resp.status_code);
      return false;
    }
  } catch (const std::exception& e) {
    Logger::amf_app().error("DID Proxy POST request exception: %s", e.what());
    return false;
  }
}

//------------------------------------------------------------------------------
bool did_proxy_client::get_extended_profile(extended_nf_profile_t& profile) {
  Logger::amf_app().debug("Getting extended NF profile from DID Proxy");

  nlohmann::json response;
  if (!send_get_request("/did-proxy/v1/profile", response)) {
    return false;
  }

  try {
    if (response.contains("did")) {
      profile.did = response["did"].get<std::string>();
    }
    if (response.contains("didDocument")) {
      profile.did_document = response["didDocument"];
    }
    // Store the full response as NF profile
    profile.nf_profile = response;
    return true;
  } catch (const std::exception& e) {
    Logger::amf_app().error("Failed to parse extended profile: %s", e.what());
    return false;
  }
}

//------------------------------------------------------------------------------
bool did_proxy_client::get_did(std::string& did) {
  Logger::amf_app().debug("Getting DID from DID Proxy");

  nlohmann::json response;
  if (!send_get_request("/did-proxy/v1/did", response)) {
    return false;
  }

  try {
    if (response.contains("did")) {
      did = response["did"].get<std::string>();
      Logger::amf_app().info("Retrieved DID: %s", did.c_str());
      return true;
    }
    return false;
  } catch (const std::exception& e) {
    Logger::amf_app().error("Failed to parse DID response: %s", e.what());
    return false;
  }
}

//------------------------------------------------------------------------------
bool did_proxy_client::get_did_document(nlohmann::json& did_document) {
  Logger::amf_app().debug("Getting DID Document from DID Proxy");

  if (!send_get_request("/did_proxy/v1/did_document", did_document)) {
    return false;
  }

  Logger::amf_app().info("Retrieved DID Document successfully");
  return true;
}

//------------------------------------------------------------------------------
bool did_proxy_client::trigger_bcf_registration() {
  Logger::amf_app().info("Triggering BCF registration through DID Proxy");

  nlohmann::json response;
  if (!send_post_request("/did-proxy/v1/register", response)) {
    Logger::amf_app().error("Failed to trigger BCF registration");
    return false;
  }

  if (response.contains("status") && 
      response["status"].get<std::string>() == "registered") {
    Logger::amf_app().info("BCF registration successful");
    return true;
  }

  return false;
}

//------------------------------------------------------------------------------
bool did_proxy_client::trigger_bcf_deregistration() {
  Logger::amf_app().info("Triggering BCF deregistration through DID Proxy");

  nlohmann::json response;
  if (!send_post_request("/did-proxy/v1/deregister", response)) {
    Logger::amf_app().error("Failed to trigger BCF deregistration");
    return false;
  }

  if (response.contains("status") && 
      response["status"].get<std::string>() == "deregistered") {
    Logger::amf_app().info("BCF deregistration successful");
    return true;
  }

  return false;
}

//------------------------------------------------------------------------------
bool did_proxy_client::get_status(nlohmann::json& status) {
  Logger::amf_app().debug("Getting status from DID Proxy");
  return send_get_request("/did-proxy/v1/status", status);
}

//------------------------------------------------------------------------------
bool did_proxy_client::is_available() {
  Logger::amf_app().debug("Checking DID Proxy availability");

  nlohmann::json response;
  if (!send_get_request("/health", response)) {
    return false;
  }

  return response.contains("status") && 
         response["status"].get<std::string>() == "healthy";
}

}  // namespace amf_application
