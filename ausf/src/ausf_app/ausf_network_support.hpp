#ifndef FILE_AUSF_NETWORK_SUPPORT_HPP_SEEN
#define FILE_AUSF_NETWORK_SUPPORT_HPP_SEEN

#include <algorithm>
#include <string>
#include <vector>

#include <nlohmann/json.hpp>

#include "ausf.h"

namespace oai {
namespace ausf {
namespace app {
namespace network_support {

inline bool has_sd(const snssai_t& snssai) {
  return !snssai.sd.empty() &&
         snssai.sd != oai::model::common::SD_DEFAULT_VALUE &&
         snssai.get_sd_int() != SD_NO_VALUE;
}

inline nlohmann::json snssai_to_json(const snssai_t& snssai) {
  nlohmann::json json_data = {{"sst", snssai.sst}};
  if (has_sd(snssai)) {
    json_data["sd"] = snssai.sd;
  }
  return json_data;
}

inline std::vector<snssai_t> collect_unique_snssais(
    const std::vector<plmn_item_t>& plmn_list) {
  std::vector<snssai_t> snssais = {};

  for (const auto& plmn : plmn_list) {
    for (const auto& slice : plmn.slice_list) {
      const auto same_snssai = [&slice](const snssai_t& existing) {
        return (existing.sst == slice.sst) && (existing.sd == slice.sd);
      };
      if (std::find_if(snssais.begin(), snssais.end(), same_snssai) ==
          snssais.end()) {
        snssais.push_back(slice);
      }
    }
  }

  return snssais;
}

inline void append_nf_profile_network_support(
    nlohmann::json& json_data, const std::vector<plmn_item_t>& plmn_list) {
  if (plmn_list.empty()) {
    return;
  }

  json_data["plmnList"]           = nlohmann::json::array();
  json_data["sNssais"]            = nlohmann::json::array();
  json_data["perPlmnSnssaiList"]  = nlohmann::json::array();

  for (const auto& plmn : plmn_list) {
    json_data["plmnList"].push_back(
        {{"mcc", plmn.mcc}, {"mnc", plmn.mnc}});

    nlohmann::json per_plmn_item = {
        {"plmnId", {{"mcc", plmn.mcc}, {"mnc", plmn.mnc}}},
        {"sNssaiList", nlohmann::json::array()}};

    for (const auto& slice : plmn.slice_list) {
      per_plmn_item["sNssaiList"].push_back(snssai_to_json(slice));
    }

    json_data["perPlmnSnssaiList"].push_back(per_plmn_item);
  }

  for (const auto& slice : collect_unique_snssais(plmn_list)) {
    json_data["sNssais"].push_back(snssai_to_json(slice));
  }
}

inline nlohmann::json build_auth_plmn_list(
    const std::vector<plmn_item_t>& plmn_list) {
  nlohmann::json json_data = nlohmann::json::array();

  for (const auto& plmn : plmn_list) {
    json_data.push_back(
        {{"mcc", plmn.mcc}, {"mnc", plmn.mnc}, {"tac", plmn.tac}});
  }

  return json_data;
}

inline nlohmann::json build_auth_snssais(
    const std::vector<plmn_item_t>& plmn_list) {
  nlohmann::json json_data = nlohmann::json::array();

  for (const auto& slice : collect_unique_snssais(plmn_list)) {
    json_data.push_back(snssai_to_json(slice));
  }

  return json_data;
}

}  // namespace network_support
}  // namespace app
}  // namespace ausf
}  // namespace oai

#endif
