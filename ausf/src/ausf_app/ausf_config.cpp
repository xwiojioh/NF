/*
 * Licensed to the OpenAirInterface (OAI) Software Alliance under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The OpenAirInterface Software Alliance licenses this file to You under
 * the OAI Public License, Version 1.1  (the "License"); you may not use this
 *file except in compliance with the License. You may obtain a copy of the
 *License at
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

#include "ausf_config.hpp"

#include <arpa/inet.h>

#include "ausf.h"
#include "ausf_sbi_helper.hpp"
#include "common_defs.h"
#include "config.hpp"
#include "if.hpp"
#include "logger.hpp"
#include "string.hpp"

using namespace oai::ausf::api;

namespace oai::config {

//------------------------------------------------------------------------------
ausf_config::ausf_config() : sbi(), ausf_name(), pid_dir(), instance() {
  udm_addr.ipv4_addr.s_addr = INADDR_ANY;
  udm_addr.port             = 8080;  // HTTP/2 by default
  udm_addr.api_version      = "v1";
  nrf_addr.ipv4_addr.s_addr = INADDR_ANY;
  nrf_addr.port             = 8080;  // HTTP/2 by default
  nrf_addr.api_version      = "v1";
  http_version              = 2;  // HTTP/2 by default
  log_level                 = spdlog::level::debug;
  register_nrf              = false;
  register_bcf              = false;  // BCF registration disabled by default
  extended_profile_path     = AUSF_DEFAULT_EXTENDED_PROFILE_PATH;
  key_store_path            = AUSF_DEFAULT_KEY_STORE_PATH;
  bcf_addr.ipv4_addr.s_addr = INADDR_ANY;
  bcf_addr.port             = 8080;
  bcf_addr.api_version      = "v1";
  plmn_list                 = {};
  http_request_timeout =
      oai::config::NF_CONFIG_HTTP_REQUEST_TIMEOUT_DEFAULT_VALUE;
}

//------------------------------------------------------------------------------
ausf_config::~ausf_config() {}

//------------------------------------------------------------------------------
void ausf_config::display() const {
  Logger::config().info("==== OPENAIRINTERFACE AUSF ====");
  Logger::config().info(
      "====================== AUSF Configuration =====================");
  Logger::config().info("Configuration AUSF:");
  Logger::config().info("- Instance ................: %d", instance);
  Logger::config().info("- PID dir .................: %s", pid_dir.c_str());
  Logger::config().info("- AUSF NAME................: %s", ausf_name.c_str());
  Logger::config().info("- PLMN Support: ");
  for (size_t i = 0; i < plmn_list.size(); i++) {
    Logger::config().info(
        "    MCC, MNC ..............: %s, %s", plmn_list[i].mcc.c_str(),
        plmn_list[i].mnc.c_str());
    Logger::config().info("    TAC ...................: %d", plmn_list[i].tac);
    Logger::config().info("    Slice Support .........:");
    for (size_t j = 0; j < plmn_list[i].slice_list.size(); j++) {
      if (plmn_list[i].slice_list[j].get_sd_int() != SD_NO_VALUE) {
        Logger::config().info(
            "        SST, SD ...........: %d, %s",
            plmn_list[i].slice_list[j].sst, plmn_list[i].slice_list[j].sd.c_str());
      } else {
        Logger::config().info(
            "        SST ...............: %d", plmn_list[i].slice_list[j].sst);
      }
    }
  }

  Logger::config().info("- SBI Networking:");
  Logger::config().info("    Iface .................: %s", sbi.if_name.c_str());
  Logger::config().info(
      "    IP Addr ...............: %s", inet_ntoa(sbi.addr4));
  Logger::config().info("    Port ..................: %d", sbi.port);

  Logger::config().info("- UDM:");
  Logger::config().info(
      "    URI root ...............: %s", udm_addr.uri_root.c_str());
  Logger::config().info(
      "    API version ...........: %s", udm_addr.api_version.c_str());

  if (register_nrf) {
    Logger::config().info("- NRF:");
    Logger::config().info(
        "    URI root ...............: %s", nrf_addr.uri_root.c_str());
    Logger::config().info(
        "    API version ...........: %s", nrf_addr.api_version.c_str());
  }

  if (register_bcf) {
    Logger::config().info("- BCF (Blockchain Function):");
    Logger::config().info(
        "    URI root ...............: %s", bcf_addr.uri_root.c_str());
    Logger::config().info(
        "    API version ...........: %s", bcf_addr.api_version.c_str());
    Logger::config().info(
        "    Extended Profile Path ..: %s", extended_profile_path.c_str());
    Logger::config().info(
        "    Key Store Path .........: %s", key_store_path.c_str());
  }

  Logger::config().info("- Supported Features:");
  Logger::config().info(
      "    NRF Registration ......: %s",
      register_nrf ? "Yes" : "No");
  Logger::config().info(
      "    BCF Registration ......: %s",
      register_bcf ? "Yes" : "No");
  Logger::config().info("    HTTP version...........: %d", http_version);
  Logger::config().info(
      "- Log Level ...............: %s",
      spdlog::level::to_string_view(log_level).data());
}

//---------------------------------------------------------------------------------------------
std::string ausf_config::get_udm_ueau_api_root() const {
  return (
      udm_addr.uri_root + ausf_sbi_helper::UdmUeAuBase + udm_addr.api_version);
}

//---------------------------------------------------------------------------------------------
std::string ausf_config::get_udm_ueau_generate_auth_data_uri(
    const std::string& supi) const {
  std::string fmr_format_str = {};
  ausf_sbi_helper::get_fmt_format_form(
      ausf_sbi_helper::UdmUeAuPathGenerateAuthData, fmr_format_str);
  return (
      udm_addr.uri_root + ausf_sbi_helper::UdmUeAuBase + udm_addr.api_version +
      fmt::format(fmr_format_str, supi));
}

//---------------------------------------------------------------------------------------------
std::string ausf_config::get_udm_ueau_confirm_auth_uri(
    const std::string& supi) const {
  std::string fmr_format_str = {};
  ausf_sbi_helper::get_fmt_format_form(
      ausf_sbi_helper::UdmUeAuPathConfirmAuth, fmr_format_str);
  return (
      udm_addr.uri_root + ausf_sbi_helper::UdmUeAuBase + udm_addr.api_version +
      fmt::format(fmr_format_str, supi));
}

//------------------------------------------------------------------------------
std::vector<plmn_item_t> ausf_config::get_plmn_list() const {
  return plmn_list;
}
}  // namespace oai::config
