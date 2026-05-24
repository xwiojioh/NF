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

#include "ausf_config_yaml.hpp"

#include <boost/algorithm/string.hpp>
#include <fmt/format.h>

#include "Snssai.h"
#include "conversions.hpp"
#include "logger.hpp"

namespace oai::config {

//------------------------------------------------------------------------------
s_nssai::s_nssai(uint8_t sst) {
  m_sst = int_config_value(AUSF_CONFIG_SST, sst);
  m_sst.set_validation_interval(SST_MIN_VALUE, SST_MAX_VALUE);
  m_sd = string_config_value(
      AUSF_CONFIG_SD, oai::model::common::SD_DEFAULT_VALUE);
  m_sd.set_validation_regex(SD_REGEX);
  m_set = true;
}

//------------------------------------------------------------------------------
s_nssai::s_nssai(uint8_t sst, const std::string& sd) {
  m_sst = int_config_value(AUSF_CONFIG_SST, sst);
  m_sst.set_validation_interval(SST_MIN_VALUE, SST_MAX_VALUE);
  m_sd = string_config_value(AUSF_CONFIG_SD, sd);
  m_sd.set_validation_regex(SD_REGEX);
  m_set = true;
}

//------------------------------------------------------------------------------
void s_nssai::from_yaml(const YAML::Node& node) {
  if (node[AUSF_CONFIG_SST]) {
    m_sst.from_yaml(node[AUSF_CONFIG_SST]);
  }
  if (node[AUSF_CONFIG_SD]) {
    m_sd.from_yaml(node[AUSF_CONFIG_SD]);
  }
}

//------------------------------------------------------------------------------
std::string s_nssai::to_string(const std::string& indent) const {
  std::string out;
  unsigned int inner_width = get_inner_width(indent.length());

  out.append(indent).append(fmt::format(
      BASE_FORMATTER, INNER_LIST_ELEM, AUSF_CONFIG_SST_LABEL, inner_width,
      m_sst.get_value()));

  if (m_sd.is_set()) {
    out.append(indent).append(fmt::format(
        BASE_FORMATTER, EMPTY_LIST_ELEM, AUSF_CONFIG_SD_LABEL, inner_width,
        get_sd()));
  }

  return out;
}

//------------------------------------------------------------------------------
int s_nssai::get_sst() const {
  return m_sst.get_value();
}

//------------------------------------------------------------------------------
bool s_nssai::get_sd(std::string& sd) const {
  if (m_sd.is_set()) {
    std::string tmp = m_sd.get_value();
    sd              = (tmp.size() == 8) ? tmp.substr(2) : tmp;
  }
  return m_sd.is_set();
}

//------------------------------------------------------------------------------
std::string s_nssai::get_sd() const {
  if (m_sd.is_set()) {
    std::string tmp = m_sd.get_value();
    return (tmp.size() == 8) ? tmp.substr(2) : tmp;
  }
  return {};
}

//------------------------------------------------------------------------------
void s_nssai::validate() {
  if (!m_set) return;
  m_sst.validate();
  m_sd.validate();
}

//------------------------------------------------------------------------------
plmn_support_item::plmn_support_item() {
  m_mcc = string_config_value(AUSF_CONFIG_MCC, AUSF_CONFIG_TEST_PLMN_MCC);
  m_mcc.set_validation_regex(MCC_REGEX);
  m_mnc = string_config_value(AUSF_CONFIG_MNC, AUSF_CONFIG_TEST_PLMN_MNC);
  m_mnc.set_validation_regex(MNC_REGEX);
  m_tac = int_config_value(AUSF_CONFIG_TAC, AUSF_CONFIG_TAC_DEFAULT_VALUE);
  m_tac.set_validation_interval(TAC_MIN_VALUE, TAC_MAX_VALUE);
  m_set = true;
}

//------------------------------------------------------------------------------
plmn_support_item::plmn_support_item(
    const std::string& mcc, const std::string& mnc) {
  m_mcc = string_config_value(AUSF_CONFIG_MCC, mcc);
  m_mcc.set_validation_regex(MCC_REGEX);
  m_mnc = string_config_value(AUSF_CONFIG_MNC, mnc);
  m_mnc.set_validation_regex(MNC_REGEX);
  m_tac = int_config_value(AUSF_CONFIG_TAC, AUSF_CONFIG_TAC_DEFAULT_VALUE);
  m_tac.set_validation_interval(TAC_MIN_VALUE, TAC_MAX_VALUE);
  m_set = true;
}

//------------------------------------------------------------------------------
void plmn_support_item::from_yaml(const YAML::Node& node) {
  m_nssai.clear();

  if (node[AUSF_CONFIG_MCC]) {
    m_mcc.from_yaml(node[AUSF_CONFIG_MCC]);
  }
  if (node[AUSF_CONFIG_MNC]) {
    m_mnc.from_yaml(node[AUSF_CONFIG_MNC]);
  }
  if (node[AUSF_CONFIG_TAC]) {
    m_tac.from_yaml(node[AUSF_CONFIG_TAC]);
  }

  if (!node[AUSF_CONFIG_NSSAI] || !node[AUSF_CONFIG_NSSAI].IsSequence()) {
    Logger::ausf_app().warn("Could not parse %s", AUSF_CONFIG_NSSAI_LABEL);
  } else {
    for (int i = 0; i < node[AUSF_CONFIG_NSSAI].size(); i++) {
      s_nssai snssai(AUSF_CONFIG_DEFAULT_SST);
      snssai.from_yaml(node[AUSF_CONFIG_NSSAI][i]);
      m_nssai.push_back(snssai);
    }
  }
}

//------------------------------------------------------------------------------
std::string plmn_support_item::to_string(const std::string& indent) const {
  std::string out;
  std::string inner_indent = indent + indent;
  unsigned int inner_width = get_inner_width(indent.length());

  out.append(indent).append(fmt::format(
      BASE_FORMATTER, INNER_LIST_ELEM, AUSF_CONFIG_MCC_LABEL, inner_width,
      m_mcc.get_value()));
  out.append(indent).append(fmt::format(
      BASE_FORMATTER, EMPTY_LIST_ELEM, AUSF_CONFIG_MNC_LABEL, inner_width,
      m_mnc.get_value()));
  out.append(indent).append(fmt::format(
      BASE_FORMATTER, EMPTY_LIST_ELEM, AUSF_CONFIG_TAC_LABEL, inner_width,
      m_tac.get_value()));
  out.append(inner_indent)
      .append(fmt::format("{} {}\n", OUTER_LIST_ELEM, AUSF_CONFIG_NSSAI_LABEL));

  for (const auto& i : m_nssai) {
    out.append(i.to_string(inner_indent + indent));
  }
  return out;
}

//------------------------------------------------------------------------------
std::string plmn_support_item::get_mcc() const {
  return m_mcc.get_value();
}

//------------------------------------------------------------------------------
std::string plmn_support_item::get_mnc() const {
  return m_mnc.get_value();
}

//------------------------------------------------------------------------------
int plmn_support_item::get_tac() const {
  return m_tac.get_value();
}

//------------------------------------------------------------------------------
std::vector<s_nssai> plmn_support_item::get_nssai() const {
  return m_nssai;
}

//------------------------------------------------------------------------------
void plmn_support_item::validate() {
  if (!m_set) return;
  m_mcc.validate();
  m_mnc.validate();
  m_tac.validate();
  for (auto& n : m_nssai) {
    n.validate();
  }
}

//------------------------------------------------------------------------------
ausf::ausf(
    const std::string& name, const std::string& host, const sbi_interface& sbi)
    : nf(name, host, sbi) {
  m_instance_id =
      int_config_value(AUSF_CONFIG_INSTANCE_ID, AUSF_CONFIG_INSTANCE_ID_DEFAULT_VALUE);
  m_pid_directory = string_config_value(
      AUSF_CONFIG_PID_DIRECTORY, AUSF_CONFIG_PID_DIRECTORY_DEFAULT_VALUE);
  m_ausf_name =
      string_config_value(AUSF_CONFIG_AUSF_NAME, AUSF_CONFIG_AUSF_NAME_DEFAULT_VALUE);
}

void ausf::from_yaml(const YAML::Node& node) {
  nf::from_yaml(node);
  m_plmn_support_list.clear();

  // Load AUSF specified parameter
  for (const auto& elem : node) {
    auto key = elem.first.as<std::string>();

    if (key == AUSF_CONFIG_INSTANCE_ID) {
      m_instance_id.from_yaml(elem.second);
    }

    if (key == AUSF_CONFIG_PID_DIRECTORY) {
      m_pid_directory.from_yaml(elem.second);
    }

    if (key == AUSF_CONFIG_AUSF_NAME) {
      m_ausf_name.from_yaml(elem.second);
    }

    if (key == AUSF_CONFIG_PLMN_SUPPORT_LIST) {
      if (!elem.second.IsSequence()) {
        Logger::ausf_app().warn("Could not parse %s", key);
      } else {
        for (int i = 0; i < elem.second.size(); i++) {
          plmn_support_item plmn_item(
              AUSF_CONFIG_TEST_PLMN_MCC, AUSF_CONFIG_TEST_PLMN_MNC);
          plmn_item.from_yaml(elem.second[i]);
          m_plmn_support_list.push_back(plmn_item);
        }
      }
    }
  }
}

//------------------------------------------------------------------------------
void ausf::validate() {
  nf::validate();
  m_instance_id.validate();
  for (auto& p : m_plmn_support_list) {
    p.validate();
  }
}

//------------------------------------------------------------------------------
std::string ausf::to_string(const std::string& indent) const {
  std::string out;
  std::string inner_indent = indent + indent;
  unsigned int inner_width = get_inner_width(inner_indent.length());

  out.append(nf::to_string(indent));

  out.append(inner_indent)
      .append(fmt::format(
          BASE_FORMATTER, OUTER_LIST_ELEM, AUSF_CONFIG_INSTANCE_ID_LABEL,
          inner_width, m_instance_id.get_value()));

  out.append(inner_indent)
      .append(fmt::format(
          BASE_FORMATTER, OUTER_LIST_ELEM, AUSF_CONFIG_PID_DIRECTORY_LABEL,
          inner_width, m_pid_directory.get_value()));

  out.append(inner_indent)
      .append(fmt::format(
          BASE_FORMATTER, OUTER_LIST_ELEM, AUSF_CONFIG_AUSF_NAME_LABEL,
          inner_width, m_ausf_name.get_value()));

  out.append(inner_indent)
      .append(fmt::format(
          "{} {}\n", OUTER_LIST_ELEM, AUSF_CONFIG_PLMN_SUPPORT_LIST_LABEL));
  for (const auto& i : m_plmn_support_list) {
    out.append(i.to_string(inner_indent + indent));
  }

  return out;
}

//------------------------------------------------------------------------------
const uint32_t ausf::get_instance_id() const {
  return m_instance_id.get_value();
}
//------------------------------------------------------------------------------
const std::string ausf::get_pid_directory() const {
  return m_pid_directory.get_value();
}
//------------------------------------------------------------------------------
const std::string ausf::get_ausf_name() const {
  return m_ausf_name.get_value();
}

//------------------------------------------------------------------------------
std::vector<plmn_support_item> ausf::get_plmn_list() const {
  return m_plmn_support_list;
}

//------------------------------------------------------------------------------
ausf_config_yaml::ausf_config_yaml(
    const std::string& config_path, bool log_stdout, bool log_rot_file)
    : oai::config::config(
          config_path, oai::config::AUSF_CONFIG_NAME, log_stdout,
          log_rot_file),
      m_ausf_config_path(config_path) {
  m_used_sbi_values = {
      oai::config::AUSF_CONFIG_NAME, oai::config::UDM_CONFIG_NAME,
      oai::config::NRF_CONFIG_NAME, AUSF_BCF_CONFIG_NAME};
  m_used_config_values = {
      oai::config::LOG_LEVEL_CONFIG_NAME, oai::config::REGISTER_NF_CONFIG_NAME,
      NF_CONFIG_HTTP_NAME, oai::config::NF_LIST_CONFIG_NAME,
      oai::config::NF_CONFIG_TLS_NAME,
      oai::config::NF_CONFIG_HTTP_REQUEST_TIMEOUT,
      oai::config::AUSF_CONFIG_NAME, AUSF_CONFIG_REGISTER_BCF,
      AUSF_CONFIG_EXTENDED_PROFILE_PATH, AUSF_CONFIG_KEY_STORE_PATH};

  // TODO with NF_Type and switch
  // TODO: Still we need to add default NFs even we don't use this in all_in_one
  // use case
  auto m_ausf = std::make_shared<ausf>(
      "AUSF", "oai-ausf", sbi_interface("SBI", "oai-ausf1", 80, "v1", "eth0"));
  add_nf("ausf", m_ausf);

  auto m_udm = std::make_shared<nf>(
      "UDM", "oai-udm", sbi_interface("SBI", "oai-udm", 80, "v1", "eth0"));
  add_nf("udm", m_udm);

  auto m_nrf = std::make_shared<nf>(
      "NRF", "oai-nrf", sbi_interface("SBI", "oai-nrf", 80, "v1", "eth0"));
  add_nf("nrf", m_nrf);

  // Add BCF NF definition
  auto m_bcf = std::make_shared<nf>(
      "BCF", "oai-bcf", sbi_interface("SBI", "oai-bcf", 8080, "v1", "eth0"));
  add_nf("bcf", m_bcf);

  update_used_nfs();
}

//------------------------------------------------------------------------------
ausf_config_yaml::~ausf_config_yaml() {}

//------------------------------------------------------------------------------
std::string ausf_config_yaml::to_string() const {
  std::string out = config::to_string();
  std::string indent = fmt::format("{:<{}}", "", INDENT_WIDTH);
  
  // Add BCF-specific configuration display (similar to AMF style)
  out.append("BCF Configuration:\n");
  out.append(indent)
      .append(fmt::format(
          "{:<3}{:<25}: {}\n", "-", AUSF_CONFIG_REGISTER_BCF_LABEL,
          m_register_bcf ? "Yes" : "No"));
  
  if (m_register_bcf) {
    out.append(indent)
        .append(fmt::format(
            "{:<3}{:<25}: {}\n", "-", AUSF_CONFIG_EXTENDED_PROFILE_PATH_LABEL,
            m_extended_profile_path));
    out.append(indent)
        .append(fmt::format(
            "{:<3}{:<25}: {}\n", "-", AUSF_CONFIG_KEY_STORE_PATH_LABEL,
            m_key_store_path));
  }
  
  return out;
}

//------------------------------------------------------------------------------
void ausf_config_yaml::display() const {
  config::display();
}

//------------------------------------------------------------------------------
bool ausf_config_yaml::init() {
  // Call base class init first
  if (!config::init()) {
    return false;
  }

  try {
    read_legacy_ausf_config(m_ausf_config_path);
  } catch (const std::exception& e) {
    Logger::ausf_app().warn("Failed to read legacy AUSF config: %s", e.what());
  }

  // Read BCF-specific config
  try {
    read_bcf_config(m_ausf_config_path);
  } catch (const std::exception& e) {
    Logger::ausf_app().warn("Failed to read BCF config: %s", e.what());
  }
  
  // Log BCF configuration during init (similar to AMF style)
  // This ensures the log appears at the same position as AMF's config log
  if (m_register_bcf && get_nf(AUSF_BCF_CONFIG_NAME)) {
    std::string bcf_uri = get_nf(AUSF_BCF_CONFIG_NAME)->get_url();
    Logger::ausf_app().info(
        "BCF registration enabled, URI root: %s", bcf_uri.c_str());
    Logger::ausf_app().info(
        "Extended profile path: %s", m_extended_profile_path.c_str());
    Logger::ausf_app().info(
        "Key store path: %s", m_key_store_path.c_str());
  } else if (m_register_bcf) {
    Logger::ausf_app().warn(
        "BCF enabled but BCF not configured in nfs section");
  }
  
  return true;
}

//------------------------------------------------------------------------------
void ausf_config_yaml::read_legacy_ausf_config(const std::string& config_path) {
  YAML::Node node = YAML::LoadFile(config_path);

  YAML::Node legacy_ausf_node;
  bool has_legacy_ausf_config = false;

  if (node[AUSF_CONFIG_INSTANCE_ID]) {
    legacy_ausf_node[AUSF_CONFIG_INSTANCE_ID] = node[AUSF_CONFIG_INSTANCE_ID];
    has_legacy_ausf_config = true;
  }
  if (node[AUSF_CONFIG_PID_DIRECTORY]) {
    legacy_ausf_node[AUSF_CONFIG_PID_DIRECTORY] = node[AUSF_CONFIG_PID_DIRECTORY];
    has_legacy_ausf_config = true;
  }
  if (node[AUSF_CONFIG_AUSF_NAME]) {
    legacy_ausf_node[AUSF_CONFIG_AUSF_NAME] = node[AUSF_CONFIG_AUSF_NAME];
    has_legacy_ausf_config = true;
  }
  if (node[AUSF_CONFIG_PLMN_SUPPORT_LIST]) {
    legacy_ausf_node[AUSF_CONFIG_PLMN_SUPPORT_LIST] =
        node[AUSF_CONFIG_PLMN_SUPPORT_LIST];
    has_legacy_ausf_config = true;
  }

  if (!has_legacy_ausf_config) {
    return;
  }

  auto ausf_local = std::dynamic_pointer_cast<ausf>(get_local());
  if (!ausf_local) {
    Logger::ausf_app().warn("Could not access local AUSF config for legacy fields");
    return;
  }

  Logger::ausf_app().warn(
      "Detected legacy top-level AUSF config fields; please move them under the 'ausf' section");

  ausf_local->from_yaml(legacy_ausf_node);
  ausf_local->validate();
}

//------------------------------------------------------------------------------
void ausf_config_yaml::read_bcf_config(const std::string& config_path) {
  try {
    YAML::Node node = YAML::LoadFile(config_path);
    for (const auto& elem : node) {
      auto key = elem.first.as<std::string>();

      if (key == AUSF_CONFIG_REGISTER_BCF) {
        if (elem.second["general"]) {
          std::string value = elem.second["general"].as<std::string>();
          m_register_bcf = (value == "yes" || value == "true" || 
                           value == "Yes" || value == "True");
        }
      }

      if (key == AUSF_CONFIG_EXTENDED_PROFILE_PATH) {
        m_extended_profile_path = elem.second.as<std::string>();
      }
      if (key == AUSF_CONFIG_KEY_STORE_PATH) {
        m_key_store_path = elem.second.as<std::string>();
      }
    }
  } catch (const std::exception& e) {
    Logger::ausf_app().warn("Error reading BCF config: %s", e.what());
  }
}

void ausf_config_yaml::pre_process() {
  // Process configuration information to display only the appropriate
  // information
  // TODO
}

//------------------------------------------------------------------------------
void ausf_config_yaml::to_ausf_config(oai::config::ausf_config& cfg) {
  std::shared_ptr<ausf> ausf_local =
      std::static_pointer_cast<ausf>(get_local());
  cfg.instance             = ausf_local->get_instance_id();
  cfg.pid_dir              = ausf_local->get_pid_directory();
  cfg.ausf_name            = ausf_local->get_ausf_name();
  cfg.log_level            = spdlog::level::from_str(log_level());
  cfg.register_nrf         = register_nrf();
  cfg.register_bcf         = register_bcf();
  cfg.extended_profile_path = get_extended_profile_path();
  cfg.key_store_path       = get_key_store_path();
  cfg.http_request_timeout = get_http_request_timeout();
  cfg.plmn_list.clear();

  cfg.http_version    = get_http_version();
  cfg.sbi.api_version = local().get_sbi().get_api_version();
  cfg.sbi.port        = local().get_sbi().get_port();
  cfg.sbi.addr4       = local().get_sbi().get_addr4();
  cfg.sbi.if_name     = local().get_sbi().get_if_name();

  if (get_nf(oai::config::NRF_CONFIG_NAME)) {
    cfg.nrf_addr.api_version = get_nf("nrf")->get_sbi().get_api_version();
    cfg.nrf_addr.uri_root    = get_nf(oai::config::NRF_CONFIG_NAME)->get_url();
  }

  if (get_nf(oai::config::UDM_CONFIG_NAME)) {
    cfg.udm_addr.api_version = get_nf("udm")->get_sbi().get_api_version();
    cfg.udm_addr.uri_root    = get_nf(oai::config::UDM_CONFIG_NAME)->get_url();
  }

  for (const auto& i : ausf_local->get_plmn_list()) {
    plmn_item_t item = {};
    item.mcc         = i.get_mcc();
    item.mnc         = i.get_mnc();
    item.tac         = i.get_tac();
    for (const auto& s : i.get_nssai()) {
      snssai_t slice = {};
      slice.sst      = s.get_sst();
      slice.sd       = s.get_sd();
      item.slice_list.push_back(slice);
    }
    cfg.plmn_list.push_back(item);
  }

  // BCF configuration
  if (get_nf(AUSF_BCF_CONFIG_NAME)) {
    cfg.bcf_addr.api_version = get_nf(AUSF_BCF_CONFIG_NAME)->get_sbi().get_api_version();
    cfg.bcf_addr.uri_root    = get_nf(AUSF_BCF_CONFIG_NAME)->get_url();
  }
}

//------------------------------------------------------------------------------
bool ausf_config_yaml::register_bcf() const {
  return m_register_bcf;
}

//------------------------------------------------------------------------------
std::string ausf_config_yaml::get_extended_profile_path() const {
  return m_extended_profile_path;
}

//------------------------------------------------------------------------------
std::string ausf_config_yaml::get_key_store_path() const {
  return m_key_store_path;
}
}  // namespace oai::config
