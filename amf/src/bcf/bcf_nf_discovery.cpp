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

#include "bcf_nf_discovery.hpp"

#include <algorithm>
#include <chrono>
#include <random>
#include <sstream>

#include "bcf_client.hpp"
#include "logger.hpp"

namespace oai::common::bcf {

//==============================================================================
// NF 类型转换工具函数实现
//==============================================================================

std::string nf_type_to_string(NfType type) {
  switch (type) {
    case NfType::NF_TYPE_AMF:
      return "AMF";
    case NfType::NF_TYPE_SMF:
      return "SMF";
    case NfType::NF_TYPE_AUSF:
      return "AUSF";
    case NfType::NF_TYPE_UDM:
      return "UDM";
    case NfType::NF_TYPE_UDR:
      return "UDR";
    case NfType::NF_TYPE_PCF:
      return "PCF";
    case NfType::NF_TYPE_NSSF:
      return "NSSF";
    case NfType::NF_TYPE_NEF:
      return "NEF";
    case NfType::NF_TYPE_AF:
      return "AF";
    case NfType::NF_TYPE_NWDAF:
      return "NWDAF";
    case NfType::NF_TYPE_BSF:
      return "BSF";
    case NfType::NF_TYPE_CHF:
      return "CHF";
    case NfType::NF_TYPE_SMSF:
      return "SMSF";
    case NfType::NF_TYPE_LMF:
      return "LMF";
    case NfType::NF_TYPE_GMLC:
      return "GMLC";
    case NfType::NF_TYPE_5G_EIR:
      return "5G_EIR";
    case NfType::NF_TYPE_SEPP:
      return "SEPP";
    case NfType::NF_TYPE_UPF:
      return "UPF";
    case NfType::NF_TYPE_N3IWF:
      return "N3IWF";
    case NfType::NF_TYPE_BCF:
      return "BCF";
    default:
      return "UNKNOWN";
  }
}

NfType string_to_nf_type(const std::string& str) {
  if (str == "AMF") return NfType::NF_TYPE_AMF;
  if (str == "SMF") return NfType::NF_TYPE_SMF;
  if (str == "AUSF") return NfType::NF_TYPE_AUSF;
  if (str == "UDM") return NfType::NF_TYPE_UDM;
  if (str == "UDR") return NfType::NF_TYPE_UDR;
  if (str == "PCF") return NfType::NF_TYPE_PCF;
  if (str == "NSSF") return NfType::NF_TYPE_NSSF;
  if (str == "NEF") return NfType::NF_TYPE_NEF;
  if (str == "AF") return NfType::NF_TYPE_AF;
  if (str == "NWDAF") return NfType::NF_TYPE_NWDAF;
  if (str == "BSF") return NfType::NF_TYPE_BSF;
  if (str == "CHF") return NfType::NF_TYPE_CHF;
  if (str == "SMSF") return NfType::NF_TYPE_SMSF;
  if (str == "LMF") return NfType::NF_TYPE_LMF;
  if (str == "GMLC") return NfType::NF_TYPE_GMLC;
  if (str == "5G_EIR") return NfType::NF_TYPE_5G_EIR;
  if (str == "SEPP") return NfType::NF_TYPE_SEPP;
  if (str == "UPF") return NfType::NF_TYPE_UPF;
  if (str == "N3IWF") return NfType::NF_TYPE_N3IWF;
  if (str == "BCF") return NfType::NF_TYPE_BCF;
  return NfType::NF_TYPE_UNKNOWN;
}

std::string nf_status_to_string(NfStatus status) {
  switch (status) {
    case NfStatus::NF_STATUS_REGISTERED:
      return "REGISTERED";
    case NfStatus::NF_STATUS_SUSPENDED:
      return "SUSPENDED";
    case NfStatus::NF_STATUS_UNDISCOVERABLE:
      return "UNDISCOVERABLE";
    default:
      return "UNKNOWN";
  }
}

NfStatus string_to_nf_status(const std::string& str) {
  if (str == "REGISTERED") return NfStatus::NF_STATUS_REGISTERED;
  if (str == "SUSPENDED") return NfStatus::NF_STATUS_SUSPENDED;
  if (str == "UNDISCOVERABLE") return NfStatus::NF_STATUS_UNDISCOVERABLE;
  return NfStatus::NF_STATUS_UNKNOWN;
}

//==============================================================================
// NfProfile 实现
//==============================================================================

nlohmann::json NfProfile::to_json() const {
  nlohmann::json j;
  j["nfInstanceId"] = nf_instance_id;
  j["nfType"]       = nf_type_to_string(nf_type);
  j["nfStatus"]     = nf_status_to_string(nf_status);

  if (!did.empty()) j["did"] = did;
  if (!public_key.empty()) j["publicKey"] = public_key;

  if (!plmn_list.empty()) {
    nlohmann::json plmns = nlohmann::json::array();
    for (const auto& p : plmn_list) {
      plmns.push_back(p.to_json());
    }
    j["plmnList"] = plmns;
  }

  if (!snssai_list.empty()) {
    nlohmann::json snssais = nlohmann::json::array();
    for (const auto& s : snssai_list) {
      snssais.push_back(s.to_json());
    }
    j["sNssais"] = snssais;
  }

  if (!per_plmn_snssai_list.empty()) {
    nlohmann::json per_plmn_snssais = nlohmann::json::array();
    for (const auto& item : per_plmn_snssai_list) {
      per_plmn_snssais.push_back(item.to_json());
    }
    j["perPlmnSnssaiList"] = per_plmn_snssais;
  }

  if (!nsi_list.empty()) j["nsiList"] = nsi_list;
  if (!fqdn.empty()) j["fqdn"] = fqdn;
  if (!ipv4_addresses.empty()) j["ipv4Addresses"] = ipv4_addresses;
  if (!ipv6_addresses.empty()) j["ipv6Addresses"] = ipv6_addresses;

  if (!nf_services.empty()) {
    nlohmann::json services = nlohmann::json::array();
    for (const auto& svc : nf_services) {
      services.push_back(svc.to_json());
    }
    j["nfServices"] = services;
  }

  if (priority > 0) j["priority"] = priority;
  if (capacity > 0) j["capacity"] = capacity;
  if (load > 0) j["load"] = load;
  if (!locality.empty()) j["locality"] = locality;

  return j;
}

NfProfile NfProfile::from_json(const nlohmann::json& j) {
  NfProfile p;
  const nlohmann::json* profile = &j;
  if (j.contains("nfProfile") && j["nfProfile"].is_object()) {
    profile = &j["nfProfile"];
    if (j.contains("did")) p.did = j["did"].get<std::string>();
    if (j.contains("publicKey")) p.public_key = j["publicKey"].get<std::string>();
  }

  if (profile->contains("nfInstanceId"))
    p.nf_instance_id = (*profile)["nfInstanceId"].get<std::string>();
  if (profile->contains("nfType"))
    p.nf_type = string_to_nf_type((*profile)["nfType"].get<std::string>());
  if (profile->contains("nfStatus"))
    p.nf_status = string_to_nf_status((*profile)["nfStatus"].get<std::string>());

  if (profile->contains("did")) p.did = (*profile)["did"].get<std::string>();
  if (profile->contains("publicKey")) p.public_key = (*profile)["publicKey"].get<std::string>();

  if (profile->contains("plmnList")) {
    for (const auto& plmn : (*profile)["plmnList"]) {
      p.plmn_list.push_back(PlmnId::from_json(plmn));
    }
  }

  if (profile->contains("sNssais")) {
    for (const auto& snssai : (*profile)["sNssais"]) {
      p.snssai_list.push_back(Snssai::from_json(snssai));
    }
  }

  if (profile->contains("perPlmnSnssaiList")) {
    for (const auto& item : (*profile)["perPlmnSnssaiList"]) {
      p.per_plmn_snssai_list.push_back(PerPlmnSnssaiItem::from_json(item));
    }
  }

  if (profile->contains("nsiList"))
    p.nsi_list = (*profile)["nsiList"].get<std::vector<std::string>>();
  if (profile->contains("fqdn")) p.fqdn = (*profile)["fqdn"].get<std::string>();
  if (profile->contains("ipv4Addresses"))
    p.ipv4_addresses = (*profile)["ipv4Addresses"].get<std::vector<std::string>>();
  if (profile->contains("ipv6Addresses"))
    p.ipv6_addresses = (*profile)["ipv6Addresses"].get<std::vector<std::string>>();

  if (profile->contains("nfServices")) {
    for (const auto& svc : (*profile)["nfServices"]) {
      p.nf_services.push_back(NfService::from_json(svc));
    }
  }

  if (profile->contains("priority")) p.priority = (*profile)["priority"].get<int32_t>();
  if (profile->contains("capacity")) p.capacity = (*profile)["capacity"].get<int32_t>();
  if (profile->contains("load")) p.load = (*profile)["load"].get<int32_t>();
  if (profile->contains("locality")) p.locality = (*profile)["locality"].get<std::string>();

  return p;
}

//==============================================================================
// NfDiscoveryCriteria 实现
//==============================================================================

std::string NfDiscoveryCriteria::to_query_params() const {
  std::ostringstream oss;
  oss << "target_nf_type=" << nf_type_to_string(target_nf_type);
  oss << "&requester_nf_type=" << nf_type_to_string(requester_nf_type);

  if (!requester_nf_instance_id.empty()) {
    oss << "&requester_nf_instance_id=" << requester_nf_instance_id;
  }

  if (service_name.has_value()) {
    oss << "&service_names=" << service_name.value();
  }

  if (target_nf_instance_id.has_value()) {
    oss << "&target_nf_instance_id=" << target_nf_instance_id.value();
  }

  if (target_plmn.has_value()) {
    oss << "&target_plmn_list=" << target_plmn->mcc << "-" << target_plmn->mnc;
  }

  if (target_snssai.has_value()) {
    oss << "&snssais=" << static_cast<int>(target_snssai->sst);
    if (!target_snssai->sd.empty()) {
      oss << "-" << target_snssai->sd;
    }
  }

  if (target_locality.has_value()) {
    oss << "&preferred_locality=" << target_locality.value();
  }

  if (max_results > 0) {
    oss << "&limit=" << max_results;
  }

  return oss.str();
}

nlohmann::json NfDiscoveryCriteria::to_json() const {
  nlohmann::json j;
  j["targetNfType"]    = nf_type_to_string(target_nf_type);
  j["requesterNfType"] = nf_type_to_string(requester_nf_type);
  if (!requester_nf_instance_id.empty())
    j["requesterNfInstanceId"] = requester_nf_instance_id;
  if (service_name.has_value()) j["serviceName"] = service_name.value();
  if (target_nf_instance_id.has_value())
    j["targetNfInstanceId"] = target_nf_instance_id.value();
  if (target_plmn.has_value()) j["targetPlmn"] = target_plmn->to_json();
  if (target_snssai.has_value()) j["targetSnssai"] = target_snssai->to_json();
  if (target_locality.has_value()) j["targetLocality"] = target_locality.value();
  if (max_results > 0) j["maxResults"] = max_results;
  return j;
}

//==============================================================================
// NfDiscoveryResponse 实现
//==============================================================================

NfDiscoveryResponse NfDiscoveryResponse::from_json(const nlohmann::json& j) {
  NfDiscoveryResponse resp;

  // 检查是否是错误响应
  if (j.contains("status") && j["status"].get<std::string>() != "success") {
    resp.success = false;
    if (j.contains("message")) resp.error_message = j["message"].get<std::string>();
    if (j.contains("error")) resp.error_code = j["error"].get<std::string>();
    return resp;
  }

  resp.success = true;

  // 解析 NF 列表 - 支持多种响应格式
  if (j.contains("nfInstances")) {
    for (const auto& nf : j["nfInstances"]) {
      resp.nf_profiles.push_back(NfProfile::from_json(nf));
    }
  } else if (j.is_array()) {
    for (const auto& nf : j) {
      resp.nf_profiles.push_back(NfProfile::from_json(nf));
    }
  }

  if (j.contains("validityPeriod"))
    resp.validity_period = j["validityPeriod"].get<uint64_t>();

  return resp;
}

//==============================================================================
// BcfNfDiscoveryClient 实现
//==============================================================================

BcfNfDiscoveryClient::BcfNfDiscoveryClient()
    : m_bcf_api_version("v1"),
      m_local_nf_type(NfType::NF_TYPE_UNKNOWN),
      m_selection_strategy(NfSelectionStrategy::PRIORITY_BASED),
      m_http_version(2),
      m_cache_enabled(true),
      m_cache_ttl_seconds(300) {}

void BcfNfDiscoveryClient::set_bcf_uri(const std::string& uri) {
  m_bcf_uri = uri;
  // 移除尾部斜杠
  while (!m_bcf_uri.empty() && m_bcf_uri.back() == '/') {
    m_bcf_uri.pop_back();
  }
}

void BcfNfDiscoveryClient::set_bcf_api_version(const std::string& version) {
  m_bcf_api_version = version;
}

void BcfNfDiscoveryClient::set_local_nf_info(
    NfType nf_type, const std::string& nf_instance_id,
    const std::string& locality) {
  m_local_nf_type        = nf_type;
  m_local_nf_instance_id = nf_instance_id;
  m_local_locality       = locality;
}

void BcfNfDiscoveryClient::set_selection_strategy(NfSelectionStrategy strategy) {
  m_selection_strategy = strategy;
}

void BcfNfDiscoveryClient::set_http_version(int version) {
  m_http_version = version;
}

void BcfNfDiscoveryClient::enable_cache(bool enable, uint32_t ttl_seconds) {
  m_cache_enabled     = enable;
  m_cache_ttl_seconds = ttl_seconds;
}

//------------------------------------------------------------------------------
// NF 发现方法
//------------------------------------------------------------------------------

NfDiscoveryResponse BcfNfDiscoveryClient::discover_nf(
    NfType target_nf_type, const std::string& service_name) {
  NfDiscoveryCriteria criteria;
  criteria.target_nf_type        = target_nf_type;
  criteria.requester_nf_type     = m_local_nf_type;
  criteria.requester_nf_instance_id = m_local_nf_instance_id;
  if (!service_name.empty()) {
    criteria.service_name = service_name;
  }
  if (!m_local_locality.empty()) {
    criteria.target_locality = m_local_locality;
  }
  return discover_nf(criteria);
}

NfDiscoveryResponse BcfNfDiscoveryClient::discover_nf(
    const NfDiscoveryCriteria& criteria) {
  NfDiscoveryResponse response;

  // 检查缓存
  if (m_cache_enabled) {
    auto cached = get_from_cache(criteria.target_nf_type);
    if (cached.has_value()) {
      response.success     = true;
      response.nf_profiles = cached.value();
      return response;
    }
  }

  // 检查 BCF URI
  if (m_bcf_uri.empty()) {
    response.success       = false;
    response.error_message = "BCF URI not configured";
    return response;
  }

  // 构建请求 URI
  std::string path = build_discovery_uri(criteria);

  // 发送请求
  nlohmann::json json_response;
  uint32_t http_code = 0;

  bool success = send_bcf_request(path, "GET", "", json_response, http_code);

  if (!success) {
    response.success       = false;
    response.error_message = "Failed to send request to BCF";
    return response;
  }

  if (http_code != 200) {
    response.success       = false;
    response.error_message = "BCF returned HTTP " + std::to_string(http_code);
    if (json_response.contains("message")) {
      response.error_message += ": " + json_response["message"].get<std::string>();
    }
    return response;
  }

  // 解析响应
  response = NfDiscoveryResponse::from_json(json_response);

  // 更新缓存
  if (response.success && m_cache_enabled) {
    update_cache(
        criteria.target_nf_type, response.nf_profiles, response.validity_period);
  }

  return response;
}

std::optional<NfProfile> BcfNfDiscoveryClient::discover_and_select_nf(
    NfType target_nf_type, const std::string& service_name) {
  auto response = discover_nf(target_nf_type, service_name);

  if (!response.success || response.nf_profiles.empty()) {
    return std::nullopt;
  }

  return select_nf(response.nf_profiles);
}

std::optional<NfProfile> BcfNfDiscoveryClient::select_nf(
    const std::vector<NfProfile>& nf_list,
    std::optional<NfSelectionStrategy> strategy) {
  if (nf_list.empty()) {
    return std::nullopt;
  }

  // 过滤掉非 REGISTERED 状态的 NF
  std::vector<NfProfile> active_nfs;
  for (const auto& nf : nf_list) {
    if (nf.nf_status == NfStatus::NF_STATUS_REGISTERED) {
      active_nfs.push_back(nf);
    }
  }

  if (active_nfs.empty()) {
    // 如果没有 REGISTERED 的，尝试使用原始列表
    active_nfs = nf_list;
  }

  NfSelectionStrategy actual_strategy =
      strategy.value_or(m_selection_strategy);

  switch (actual_strategy) {
    case NfSelectionStrategy::PRIORITY_BASED:
      return select_by_priority(active_nfs);
    case NfSelectionStrategy::LOAD_BASED:
      return select_by_load(active_nfs);
    case NfSelectionStrategy::CAPACITY_BASED:
      return select_by_capacity(active_nfs);
    case NfSelectionStrategy::ROUND_ROBIN:
      return select_round_robin(active_nfs);
    case NfSelectionStrategy::RANDOM:
      return select_random(active_nfs);
    case NfSelectionStrategy::LOCALITY_BASED:
      return select_by_locality(active_nfs);
    case NfSelectionStrategy::WEIGHTED_RANDOM:
      return select_weighted_random(active_nfs);
    default:
      return select_by_priority(active_nfs);
  }
}

//------------------------------------------------------------------------------
// 公钥查询方法
//------------------------------------------------------------------------------

PublicKeyResponse BcfNfDiscoveryClient::query_public_key(const std::string& did) {
  PublicKeyResponse response;

  if (m_bcf_uri.empty()) {
    response.error_message = "BCF URI not configured";
    return response;
  }

  // 构建查询路径
  std::string path = "/nbcf_nfm/" + m_bcf_api_version + "/did/" + did + "/publickey";

  nlohmann::json json_response;
  uint32_t http_code = 0;

  bool success = send_bcf_request(path, "GET", "", json_response, http_code);

  if (!success || http_code != 200) {
    response.found         = false;
    response.error_message = "Failed to query public key from BCF";
    return response;
  }

  response.found = true;
  response.did   = did;

  if (json_response.contains("publicKey"))
    response.public_key = json_response["publicKey"].get<std::string>();
  if (json_response.contains("nfType"))
    response.nf_type = string_to_nf_type(json_response["nfType"].get<std::string>());
  if (json_response.contains("nfInstanceId"))
    response.nf_instance_id = json_response["nfInstanceId"].get<std::string>();

  return response;
}

PublicKeyResponse BcfNfDiscoveryClient::query_public_key_by_nf_id(
    const std::string& nf_instance_id) {
  PublicKeyResponse response;

  if (m_bcf_uri.empty()) {
    response.error_message = "BCF URI not configured";
    return response;
  }

  // 构建查询路径
  std::string path =
      "/nbcf_nfm/" + m_bcf_api_version + "/nf_instances/" + nf_instance_id;

  nlohmann::json json_response;
  uint32_t http_code = 0;

  bool success = send_bcf_request(path, "GET", "", json_response, http_code);

  if (!success || http_code != 200) {
    response.found         = false;
    response.error_message = "Failed to query NF profile from BCF";
    return response;
  }

  response.found          = true;
  response.nf_instance_id = nf_instance_id;

  if (json_response.contains("did"))
    response.did = json_response["did"].get<std::string>();
  if (json_response.contains("publicKey"))
    response.public_key = json_response["publicKey"].get<std::string>();
  if (json_response.contains("nfType"))
    response.nf_type = string_to_nf_type(json_response["nfType"].get<std::string>());

  return response;
}

//------------------------------------------------------------------------------
// 便捷方法
//------------------------------------------------------------------------------

std::optional<NfProfile> BcfNfDiscoveryClient::discover_ausf() {
  return discover_and_select_nf(NfType::NF_TYPE_AUSF, "nausf-auth");
}

std::optional<NfProfile> BcfNfDiscoveryClient::discover_udm() {
  return discover_and_select_nf(NfType::NF_TYPE_UDM, "nudm-ueau");
}

std::optional<NfProfile> BcfNfDiscoveryClient::discover_smf(
    const std::optional<Snssai>& snssai) {
  NfDiscoveryCriteria criteria;
  criteria.target_nf_type        = NfType::NF_TYPE_SMF;
  criteria.requester_nf_type     = m_local_nf_type;
  criteria.requester_nf_instance_id = m_local_nf_instance_id;
  criteria.service_name          = "nsmf-pdusession";
  if (snssai.has_value()) {
    criteria.target_snssai = snssai;
  }

  auto response = discover_nf(criteria);
  if (!response.success || response.nf_profiles.empty()) {
    return std::nullopt;
  }
  return select_nf(response.nf_profiles);
}

std::optional<NfProfile> BcfNfDiscoveryClient::discover_pcf() {
  return discover_and_select_nf(NfType::NF_TYPE_PCF, "npcf-am-policy-control");
}

std::optional<NfProfile> BcfNfDiscoveryClient::discover_amf() {
  return discover_and_select_nf(NfType::NF_TYPE_AMF, "namf-comm");
}

//------------------------------------------------------------------------------
// 缓存管理
//------------------------------------------------------------------------------

void BcfNfDiscoveryClient::clear_cache() {
  std::lock_guard<std::mutex> lock(m_cache_mutex);
  m_cache.clear();
}

void BcfNfDiscoveryClient::clear_cache(NfType nf_type) {
  std::lock_guard<std::mutex> lock(m_cache_mutex);
  m_cache.erase(nf_type);
}

nlohmann::json BcfNfDiscoveryClient::get_cache_stats() const {
  std::lock_guard<std::mutex> lock(m_cache_mutex);

  nlohmann::json stats;
  stats["enabled"]     = m_cache_enabled;
  stats["ttl_seconds"] = m_cache_ttl_seconds;
  stats["entries"]     = nlohmann::json::array();

  auto now = std::chrono::steady_clock::now();
  for (const auto& [type, entry] : m_cache) {
    nlohmann::json entry_json;
    entry_json["nf_type"]   = nf_type_to_string(type);
    entry_json["count"]     = entry.profiles.size();
    auto remaining =
        std::chrono::duration_cast<std::chrono::seconds>(entry.expire_time - now)
            .count();
    entry_json["ttl_remaining"] = remaining > 0 ? remaining : 0;
    stats["entries"].push_back(entry_json);
  }

  return stats;
}

//------------------------------------------------------------------------------
// 内部方法
//------------------------------------------------------------------------------

bool BcfNfDiscoveryClient::send_bcf_request(
    const std::string& path, const std::string& method, const std::string& body,
    nlohmann::json& response, uint32_t& http_code) {
  try {
    std::string full_uri = m_bcf_uri + path;

    // 标准化日志格式 - NF Discovery
    Logger::amf_app().info("BCF Discovery URI: %s", full_uri.c_str());
    Logger::amf_app().info("Send HTTP message to %s", full_uri.c_str());
    Logger::amf_app().info("HTTP message Body: %s", body.empty() ? "{}" : body.c_str());

    // 使用 BCF HTTP 客户端
    BcfHttpClient client;
    client.set_base_uri(m_bcf_uri);
    client.set_http_version(m_http_version);
    client.set_timeout(5000);  // 5 秒超时

    HttpResponse http_response;

    if (method == "GET") {
      http_response = client.get(path);
    } else if (method == "POST") {
      http_response = client.post(path, body);
    } else if (method == "PUT") {
      http_response = client.put(path, body);
    } else if (method == "DELETE") {
      http_response = client.del(path);
    } else {
      return false;
    }

    http_code = http_response.status_code;

    if (!http_response.body.empty()) {
      try {
        response = nlohmann::json::parse(http_response.body);
      } catch (const std::exception& e) {
        // JSON 解析失败，但请求可能成功
        response = nlohmann::json();
      }
    }

    return http_response.success ||
           (http_code >= 200 && http_code < 300);
  } catch (const std::exception& e) {
    return false;
  }
}

std::string BcfNfDiscoveryClient::build_discovery_uri(
    const NfDiscoveryCriteria& criteria) const {
  std::string path =
      "/nbcf_discovery/" + m_bcf_api_version + "/nf_instances?target-nf-type=" +
      nf_type_to_string(criteria.target_nf_type);
  return path;
}

std::optional<std::vector<NfProfile>> BcfNfDiscoveryClient::get_from_cache(
    NfType target_nf_type) const {
  std::lock_guard<std::mutex> lock(m_cache_mutex);

  auto it = m_cache.find(target_nf_type);
  if (it == m_cache.end()) {
    return std::nullopt;
  }

  // 检查是否过期
  auto now = std::chrono::steady_clock::now();
  if (now > it->second.expire_time) {
    return std::nullopt;
  }

  return it->second.profiles;
}

void BcfNfDiscoveryClient::update_cache(
    NfType target_nf_type, const std::vector<NfProfile>& profiles,
    uint64_t validity_period) {
  std::lock_guard<std::mutex> lock(m_cache_mutex);

  CacheEntry entry;
  entry.profiles = profiles;

  // 使用配置的 TTL 或响应中的有效期，取较小值
  uint64_t ttl = std::min(
      static_cast<uint64_t>(m_cache_ttl_seconds),
      validity_period > 0 ? validity_period : m_cache_ttl_seconds);

  entry.expire_time =
      std::chrono::steady_clock::now() + std::chrono::seconds(ttl);

  m_cache[target_nf_type] = entry;
}

//------------------------------------------------------------------------------
// NF 选择算法实现
//------------------------------------------------------------------------------

std::optional<NfProfile> BcfNfDiscoveryClient::select_by_priority(
    const std::vector<NfProfile>& nf_list) const {
  if (nf_list.empty()) return std::nullopt;

  auto it = std::min_element(
      nf_list.begin(), nf_list.end(),
      [](const NfProfile& a, const NfProfile& b) {
        return a.priority < b.priority;
      });

  return *it;
}

std::optional<NfProfile> BcfNfDiscoveryClient::select_by_load(
    const std::vector<NfProfile>& nf_list) const {
  if (nf_list.empty()) return std::nullopt;

  auto it = std::min_element(
      nf_list.begin(), nf_list.end(),
      [](const NfProfile& a, const NfProfile& b) { return a.load < b.load; });

  return *it;
}

std::optional<NfProfile> BcfNfDiscoveryClient::select_by_capacity(
    const std::vector<NfProfile>& nf_list) const {
  if (nf_list.empty()) return std::nullopt;

  auto it = std::max_element(
      nf_list.begin(), nf_list.end(),
      [](const NfProfile& a, const NfProfile& b) {
        return a.capacity < b.capacity;
      });

  return *it;
}

std::optional<NfProfile> BcfNfDiscoveryClient::select_random(
    const std::vector<NfProfile>& nf_list) const {
  if (nf_list.empty()) return std::nullopt;

  static std::random_device rd;
  static std::mt19937 gen(rd());
  std::uniform_int_distribution<size_t> dis(0, nf_list.size() - 1);

  return nf_list[dis(gen)];
}

std::optional<NfProfile> BcfNfDiscoveryClient::select_round_robin(
    const std::vector<NfProfile>& nf_list) {
  if (nf_list.empty()) return std::nullopt;

  std::lock_guard<std::mutex> lock(m_rr_mutex);

  // 使用第一个 NF 的类型作为键
  NfType key = nf_list[0].nf_type;

  size_t& index = m_round_robin_indices[key];
  index         = index % nf_list.size();

  auto result = nf_list[index];
  index++;

  return result;
}

std::optional<NfProfile> BcfNfDiscoveryClient::select_by_locality(
    const std::vector<NfProfile>& nf_list) const {
  if (nf_list.empty()) return std::nullopt;

  // 优先选择同一 locality 的 NF
  if (!m_local_locality.empty()) {
    std::vector<NfProfile> same_locality;
    for (const auto& nf : nf_list) {
      if (nf.locality == m_local_locality) {
        same_locality.push_back(nf);
      }
    }

    if (!same_locality.empty()) {
      // 在同一 locality 中按优先级选择
      return select_by_priority(same_locality);
    }
  }

  // 没有同一 locality 的，按优先级选择
  return select_by_priority(nf_list);
}

std::optional<NfProfile> BcfNfDiscoveryClient::select_weighted_random(
    const std::vector<NfProfile>& nf_list) const {
  if (nf_list.empty()) return std::nullopt;

  // 计算权重：weight = capacity * (100 - load)
  std::vector<double> weights;
  double total_weight = 0.0;

  for (const auto& nf : nf_list) {
    double weight = static_cast<double>(nf.capacity) *
                    (100.0 - static_cast<double>(nf.load));
    weights.push_back(weight);
    total_weight += weight;
  }

  if (total_weight <= 0) {
    return select_random(nf_list);
  }

  static std::random_device rd;
  static std::mt19937 gen(rd());
  std::uniform_real_distribution<double> dis(0.0, total_weight);

  double rand_val = dis(gen);
  double cumulative = 0.0;

  for (size_t i = 0; i < nf_list.size(); ++i) {
    cumulative += weights[i];
    if (rand_val <= cumulative) {
      return nf_list[i];
    }
  }

  return nf_list.back();
}

//==============================================================================
// 全局单例
//==============================================================================

BcfNfDiscoveryClient& get_bcf_nf_discovery_client() {
  static BcfNfDiscoveryClient instance;
  return instance;
}

}  // namespace oai::common::bcf
