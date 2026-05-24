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

#pragma once

#include "../common-src/3gpp/3gpp_23.003.h"
#include "config.hpp"
#include "ausf_config.hpp"

constexpr auto AUSF_CONFIG_INSTANCE_ID         = "instance_id";
constexpr auto AUSF_CONFIG_INSTANCE_ID_LABEL   = "Instance ID";
constexpr auto AUSF_CONFIG_PID_DIRECTORY       = "pid_directory";
constexpr auto AUSF_CONFIG_PID_DIRECTORY_LABEL = "PID Directory";
constexpr auto AUSF_CONFIG_AUSF_NAME           = "ausf_name";
constexpr auto AUSF_CONFIG_AUSF_NAME_LABEL     = "AUSF Name";
constexpr auto AUSF_CONFIG_PLMN_SUPPORT_LIST       = "plmn_support_list";
constexpr auto AUSF_CONFIG_PLMN_SUPPORT_LIST_LABEL = "PLMN Support List";
constexpr auto AUSF_CONFIG_MCC                     = "mcc";
constexpr auto AUSF_CONFIG_MCC_LABEL               = "MCC";
constexpr auto AUSF_CONFIG_MNC                     = "mnc";
constexpr auto AUSF_CONFIG_MNC_LABEL               = "MNC";
constexpr auto AUSF_CONFIG_TAC                     = "tac";
constexpr auto AUSF_CONFIG_TAC_LABEL               = "TAC";
constexpr auto AUSF_CONFIG_NSSAI                   = "nssai";
constexpr auto AUSF_CONFIG_NSSAI_LABEL             = "NSSAI";
constexpr auto AUSF_CONFIG_SST                     = "sst";
constexpr auto AUSF_CONFIG_SST_LABEL               = "SST";
constexpr auto AUSF_CONFIG_SD                      = "sd";
constexpr auto AUSF_CONFIG_SD_LABEL                = "SD";

constexpr auto AUSF_CONFIG_OPTION_YES_STR = "Yes";
constexpr auto AUSF_CONFIG_OPTION_NO_STR  = "No";

constexpr auto AUSF_CONFIG_INSTANCE_ID_DEFAULT_VALUE   = 1;
constexpr auto AUSF_CONFIG_PID_DIRECTORY_DEFAULT_VALUE = "/var/run";
constexpr auto AUSF_CONFIG_AUSF_NAME_DEFAULT_VALUE     = "oai-ausf";
constexpr auto AUSF_CONFIG_TEST_PLMN_MCC = "001";
constexpr auto AUSF_CONFIG_TEST_PLMN_MNC = "01";
constexpr auto AUSF_CONFIG_DEFAULT_SST   = 1;
constexpr auto AUSF_CONFIG_TAC_DEFAULT_VALUE = 1;

constexpr auto MCC_REGEX = "^[0-9]{3}$";
constexpr auto MNC_REGEX = "^[0-9]{2,3}$";
constexpr auto SD_REGEX  = "(^[A-Fa-f0-9]{6}$)|(^0(x|X)[A-Fa-f0-9]{6}$)";

constexpr uint8_t SST_MIN_VALUE  = 0;
constexpr uint8_t SST_MAX_VALUE  = 255;
constexpr uint32_t TAC_MIN_VALUE = 0;
constexpr uint32_t TAC_MAX_VALUE = 16777215;

namespace oai::config {

class s_nssai : public config_type {
 private:
  int_config_value m_sst{};
  string_config_value m_sd{};

 public:
  explicit s_nssai(uint8_t sst);
  explicit s_nssai(uint8_t sst, const std::string& sd);

  void from_yaml(const YAML::Node& node) override;
  void validate() override;

  [[nodiscard]] std::string to_string(const std::string& indent) const override;
  [[nodiscard]] bool get_sd(std::string& sd) const;
  [[nodiscard]] std::string get_sd() const;
  [[nodiscard]] int get_sst() const;
};

class plmn_support_item : public config_type {
 private:
  string_config_value m_mcc{};
  string_config_value m_mnc{};
  int_config_value m_tac{};
  std::vector<s_nssai> m_nssai;

 public:
  explicit plmn_support_item();
  explicit plmn_support_item(const std::string& mcc, const std::string& mnc);

  void from_yaml(const YAML::Node& node) override;
  void validate() override;

  [[nodiscard]] std::string to_string(const std::string& indent) const override;
  [[nodiscard]] std::string get_mcc() const;
  [[nodiscard]] std::string get_mnc() const;
  [[nodiscard]] int get_tac() const;
  [[nodiscard]] std::vector<s_nssai> get_nssai() const;
};

class ausf : public nf {
 private:
  int_config_value m_instance_id;
  string_config_value m_pid_directory;
  string_config_value m_ausf_name;
  std::vector<plmn_support_item> m_plmn_support_list;

 public:
  explicit ausf(
      const std::string& name, const std::string& host,
      const sbi_interface& sbi);

  void from_yaml(const YAML::Node& node) override;
  void validate() override;

  [[nodiscard]] std::string to_string(const std::string& indent) const override;
  [[nodiscard]] const uint32_t get_instance_id() const;
  [[nodiscard]] const std::string get_pid_directory() const;
  [[nodiscard]] const std::string get_ausf_name() const;
  std::vector<plmn_support_item> get_plmn_list() const;
};

class ausf_config_yaml : public config {
 public:
  explicit ausf_config_yaml(
      const std::string& config_path, bool log_stdout, bool log_rot_file);
  virtual ~ausf_config_yaml();

  bool init() override;
  std::string to_string() const override;
  void display() const override;
  void to_ausf_config(oai::config::ausf_config& cfg);
  void pre_process();

  /*
   * Check if BCF registration is enabled
   * @return true if BCF registration is enabled, false otherwise
   */
  bool register_bcf() const;

  /*
   * Get extended NF Profile path
   * @return Path to extended NF Profile file
   */
  std::string get_extended_profile_path() const;
  std::string get_key_store_path() const;

 private:
  void read_legacy_ausf_config(const std::string& config_path);
  void read_bcf_config(const std::string& config_path);

  std::string m_ausf_config_path;
  bool m_register_bcf{false};
  std::string m_extended_profile_path{AUSF_DEFAULT_EXTENDED_PROFILE_PATH};
  std::string m_key_store_path{AUSF_DEFAULT_KEY_STORE_PATH};
};
}  // namespace oai::config
