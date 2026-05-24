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

#ifndef _DID_PROXY_CLIENT_H_
#define _DID_PROXY_CLIENT_H_

#include <string>
#include <nlohmann/json.hpp>

namespace amf_application {

/**
 * @brief Extended NF Profile containing DID information
 * This extends the standard 3GPP NF Profile with DID capabilities
 */
struct extended_nf_profile_t {
  nlohmann::json nf_profile;                 // Standard NF Profile as JSON
  std::string did;                           // DID identifier
  nlohmann::json did_document;               // DID Document
  
  /**
   * @brief Convert to JSON for BCF registration
   */
  nlohmann::json to_json() const {
    nlohmann::json j = nf_profile;
    j["did"] = did;
    j["didDocument"] = did_document;
    return j;
  }
};

/**
 * @brief Client interface for DID Proxy service
 * This allows AMF to interact with the DID Proxy for DID-related operations
 */
class did_proxy_client {
 public:
  /**
   * @brief Constructor
   * @param proxy_host DID Proxy host
   * @param proxy_port DID Proxy port
   */
  did_proxy_client(const std::string& proxy_host, unsigned int proxy_port);
  
  /**
   * @brief Destructor
   */
  ~did_proxy_client();

  /**
   * @brief Get extended NF profile from DID Proxy
   * @param profile Output extended profile
   * @return true if successful
   */
  bool get_extended_profile(extended_nf_profile_t& profile);

  /**
   * @brief Get DID for the current NF
   * @param did Output DID string
   * @return true if successful
   */
  bool get_did(std::string& did);

  /**
   * @brief Get DID Document for the current NF
   * @param did_document Output DID Document
   * @return true if successful
   */
  bool get_did_document(nlohmann::json& did_document);

  /**
   * @brief Trigger BCF registration through DID Proxy
   * @return true if successful
   */
  bool trigger_bcf_registration();

  /**
   * @brief Trigger BCF deregistration through DID Proxy
   * @return true if successful
   */
  bool trigger_bcf_deregistration();

  /**
   * @brief Get registration status
   * @param status Output status information
   * @return true if successful
   */
  bool get_status(nlohmann::json& status);

  /**
   * @brief Check if DID Proxy is available
   * @return true if proxy is healthy
   */
  bool is_available();

 private:
  std::string m_proxy_host;
  unsigned int m_proxy_port;
  
  /**
   * @brief Get base URI for DID Proxy API
   */
  std::string get_base_uri() const;
  
  /**
   * @brief Send HTTP GET request to DID Proxy
   */
  bool send_get_request(const std::string& path, nlohmann::json& response);
  
  /**
   * @brief Send HTTP POST request to DID Proxy
   */
  bool send_post_request(const std::string& path, nlohmann::json& response);
};

}  // namespace amf_application

#endif  // _DID_PROXY_CLIENT_H_
