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

#ifndef FILE_AUSF_BCF_HELPER_HPP_SEEN
#define FILE_AUSF_BCF_HELPER_HPP_SEEN

#include <string>

#include "sbi_helper.hpp"

namespace oai::ausf::api {

class ausf_bcf_helper {
 public:
  // BCF Management API Base Path
  static inline const std::string BcfManagementBase = "/nbcf_management/";

  /*
   * Get BCF NF Instance URI for registration
   * @param [const nf_addr_t&] bcf_addr: BCF address
   * @param [const std::string&] nf_instance_id: NF Instance ID
   * @param [std::string&] uri: Output URI
   */
  static void get_bcf_nf_instance_uri(
      const oai::common::sbi::nf_addr_t& bcf_addr,
      const std::string& nf_instance_id, std::string& uri) {
    uri = bcf_addr.uri_root + BcfManagementBase + bcf_addr.api_version +
          "/nf_instances/" + nf_instance_id;
  }
};

}  // namespace oai::ausf::api

#endif /* FILE_AUSF_BCF_HELPER_HPP_SEEN */
