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

#ifndef _AMF_BCF_HELPER_H_
#define _AMF_BCF_HELPER_H_

#include <string>
#include <fmt/format.h>
#include "sbi_helper.hpp"
#include "config_types.hpp"

namespace oai::amf::api {

/**
 * @brief Helper class for BCF-related URI construction and operations
 * Following the same pattern as sbi_helper for NRF operations
 */
class amf_bcf_helper {
 public:
  // BCF API path constants (similar to NrfNfmBase pattern)
  static inline const std::string BcfNfmBase = "/nbcf_nfm/";
  static inline const std::string BcfNfmPathNfInstances = "/nf_instances";
  static inline const std::string BcfNfmPathNfInstancesNfInstanceId =
      "/nf_instances/{}";

  /**
   * @brief Get BCF NFM API root
   * Similar to get_nrf_nfm_api_root pattern
   * 
   * @param bcf_addr BCF address configuration (nf_addr_t)
   * @param api_root Output API root string
   */
  static void get_bcf_nfm_api_root(
      const oai::config::nf_addr_t& bcf_addr,
      std::string& api_root) {
    api_root = bcf_addr.uri_root + BcfNfmBase + bcf_addr.api_version;
  }

  /**
   * @brief Get BCF NF instance registration URI
   * Similar to get_nrf_nf_instance_uri pattern
   * 
   * @param bcf_addr BCF address configuration
   * @param nf_instance_id NF instance ID
   * @param uri Output URI string
   */
  static void get_bcf_nf_instance_uri(
      const oai::config::nf_addr_t& bcf_addr,
      const std::string& nf_instance_id,
      std::string& uri) {
    std::string bcf_api_root = {};
    get_bcf_nfm_api_root(bcf_addr, bcf_api_root);
    std::string path_nf_instance_id = {};
    oai::common::sbi::sbi_helper::get_fmt_format_form(
        BcfNfmPathNfInstancesNfInstanceId, path_nf_instance_id);
    uri = bcf_api_root + fmt::format(path_nf_instance_id, nf_instance_id);
  }

  /**
   * @brief Get BCF NF instance registration URI (overload returning string)
   * 
   * @param bcf_addr BCF address configuration
   * @param nf_instance_id NF instance ID
   * @return URI string
   */
  static std::string get_bcf_nf_instance_uri(
      const oai::config::nf_addr_t& bcf_addr,
      const std::string& nf_instance_id) {
    std::string uri;
    get_bcf_nf_instance_uri(bcf_addr, nf_instance_id, uri);
    return uri;
  }

  /**
   * @brief Get BCF base URI for NF management
   * 
   * @param bcf_addr BCF address configuration
   * @return Base URI string
   */
  static std::string get_bcf_nfm_base_uri(
      const oai::config::nf_addr_t& bcf_addr) {
    std::string api_root;
    get_bcf_nfm_api_root(bcf_addr, api_root);
    return api_root;
  }

  /**
   * @brief Get BCF DID registration URI
   * 
   * @param bcf_addr BCF address configuration
   * @param did The DID to register
   * @return DID registration URI
   */
  static std::string get_bcf_did_registration_uri(
      const oai::config::nf_addr_t& bcf_addr,
      const std::string& did) {
    std::string api_root;
    get_bcf_nfm_api_root(bcf_addr, api_root);
    return api_root + "/did_documents/" + did;
  }

  /**
   * @brief Get BCF heartbeat URI (same as NF instance URI for PATCH)
   * 
   * @param bcf_addr BCF address configuration  
   * @param nf_instance_id NF instance ID
   * @return Heartbeat URI
   */
  static std::string get_bcf_heartbeat_uri(
      const oai::config::nf_addr_t& bcf_addr,
      const std::string& nf_instance_id) {
    return get_bcf_nf_instance_uri(bcf_addr, nf_instance_id);
  }
};

}  // namespace oai::amf::api

#endif  // _AMF_BCF_HELPER_H_
