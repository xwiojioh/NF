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

/**
 * @file bcf_nf_discovery.hpp
 * @brief BCF NF Discovery - 通用 NF 发现框架
 *
 * 本模块提供基于 BCF (Blockchain Control Function) 的 NF 发现能力，
 * 可被任何 5G 核心网网元 (AMF, AUSF, SMF, UDM 等) 使用。
 *
 * BCF 替代了传统的 NRF，提供：
 * - NF 注册与注销
 * - NF 发现与查询
 * - DID 公钥查询
 * - 可信审计
 */

#ifndef _BCF_NF_DISCOVERY_HPP_
#define _BCF_NF_DISCOVERY_HPP_

#include <functional>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <vector>

#include <nlohmann/json.hpp>

namespace oai::common::bcf {

//==============================================================================
// 基础数据结构定义
//==============================================================================

/**
 * @brief NF 类型枚举
 */
enum class NfType {
  NF_TYPE_UNKNOWN = 0,
  NF_TYPE_AMF,
  NF_TYPE_SMF,
  NF_TYPE_AUSF,
  NF_TYPE_UDM,
  NF_TYPE_UDR,
  NF_TYPE_PCF,
  NF_TYPE_NSSF,
  NF_TYPE_NEF,
  NF_TYPE_AF,
  NF_TYPE_NWDAF,
  NF_TYPE_BSF,
  NF_TYPE_CHF,
  NF_TYPE_SMSF,
  NF_TYPE_LMF,
  NF_TYPE_GMLC,
  NF_TYPE_5G_EIR,
  NF_TYPE_SEPP,
  NF_TYPE_UPF,
  NF_TYPE_N3IWF,
  NF_TYPE_BCF  // Blockchain Control Function
};

/**
 * @brief NF 状态枚举
 */
enum class NfStatus {
  NF_STATUS_UNKNOWN = 0,
  NF_STATUS_REGISTERED,
  NF_STATUS_SUSPENDED,
  NF_STATUS_UNDISCOVERABLE
};

/**
 * @brief PLMN ID 结构
 */
struct PlmnId {
  std::string mcc;  // Mobile Country Code (3 位)
  std::string mnc;  // Mobile Network Code (2-3 位)

  bool operator==(const PlmnId& other) const {
    return mcc == other.mcc && mnc == other.mnc;
  }

  nlohmann::json to_json() const {
    return {{"mcc", mcc}, {"mnc", mnc}};
  }

  static PlmnId from_json(const nlohmann::json& j) {
    PlmnId p;
    if (j.contains("mcc")) p.mcc = j["mcc"].get<std::string>();
    if (j.contains("mnc")) p.mnc = j["mnc"].get<std::string>();
    return p;
  }
};

/**
 * @brief S-NSSAI 结构 (Single Network Slice Selection Assistance Information)
 */
struct Snssai {
  uint8_t sst;      // Slice/Service Type (1-255)
  std::string sd;   // Slice Differentiator (可选, 6 位十六进制)

  bool operator==(const Snssai& other) const {
    return sst == other.sst && sd == other.sd;
  }

  nlohmann::json to_json() const {
    nlohmann::json j = {{"sst", sst}};
    if (!sd.empty()) j["sd"] = sd;
    return j;
  }

  static Snssai from_json(const nlohmann::json& j) {
    Snssai s;
    if (j.contains("sst")) s.sst = j["sst"].get<uint8_t>();
    if (j.contains("sd")) s.sd = j["sd"].get<std::string>();
    return s;
  }
};

/**
 * @brief Per-PLMN S-NSSAI 结构
 */
struct PerPlmnSnssaiItem {
  PlmnId plmn_id;
  std::vector<Snssai> snssai_list;

  nlohmann::json to_json() const {
    nlohmann::json j;
    j["plmnId"] = plmn_id.to_json();

    nlohmann::json snssais = nlohmann::json::array();
    for (const auto& snssai : snssai_list) {
      snssais.push_back(snssai.to_json());
    }
    j["sNssaiList"] = snssais;
    return j;
  }

  static PerPlmnSnssaiItem from_json(const nlohmann::json& j) {
    PerPlmnSnssaiItem item;
    if (j.contains("plmnId")) {
      item.plmn_id = PlmnId::from_json(j["plmnId"]);
    }

    if (j.contains("sNssaiList")) {
      for (const auto& snssai : j["sNssaiList"]) {
        item.snssai_list.push_back(Snssai::from_json(snssai));
      }
    } else if (j.contains("snssaiList")) {
      for (const auto& snssai : j["snssaiList"]) {
        item.snssai_list.push_back(Snssai::from_json(snssai));
      }
    }
    return item;
  }
};

/**
 * @brief IP 端点结构
 */
struct IpEndpoint {
  std::string ipv4_address;
  std::string ipv6_address;
  uint16_t port;
  std::string transport;  // "TCP" or "UDP"

  nlohmann::json to_json() const {
    nlohmann::json j;
    if (!ipv4_address.empty()) j["ipv4Address"] = ipv4_address;
    if (!ipv6_address.empty()) j["ipv6Address"] = ipv6_address;
    if (port > 0) j["port"] = port;
    if (!transport.empty()) j["transport"] = transport;
    return j;
  }

  static IpEndpoint from_json(const nlohmann::json& j) {
    IpEndpoint ep;
    if (j.contains("ipv4Address"))
      ep.ipv4_address = j["ipv4Address"].get<std::string>();
    if (j.contains("ipv6Address"))
      ep.ipv6_address = j["ipv6Address"].get<std::string>();
    if (j.contains("port")) ep.port = j["port"].get<uint16_t>();
    if (j.contains("transport"))
      ep.transport = j["transport"].get<std::string>();
    return ep;
  }
};

/**
 * @brief NF 服务信息
 */
struct NfService {
  std::string service_instance_id;
  std::string service_name;
  std::vector<std::string> versions;
  std::string scheme;  // "http" or "https"
  std::string fqdn;
  std::vector<IpEndpoint> ip_endpoints;
  std::string api_prefix;
  uint16_t priority;
  uint16_t capacity;
  uint8_t load;

  nlohmann::json to_json() const {
    nlohmann::json j;
    j["serviceInstanceId"] = service_instance_id;
    j["serviceName"]       = service_name;
    j["versions"]          = versions;
    j["scheme"]            = scheme;
    if (!fqdn.empty()) j["fqdn"] = fqdn;
    if (!api_prefix.empty()) j["apiPrefix"] = api_prefix;
    if (priority > 0) j["priority"] = priority;
    if (capacity > 0) j["capacity"] = capacity;
    if (load > 0) j["load"] = load;

    if (!ip_endpoints.empty()) {
      nlohmann::json eps = nlohmann::json::array();
      for (const auto& ep : ip_endpoints) {
        eps.push_back(ep.to_json());
      }
      j["ipEndPoints"] = eps;
    }
    return j;
  }

  static NfService from_json(const nlohmann::json& j) {
    NfService svc;
    if (j.contains("serviceInstanceId"))
      svc.service_instance_id = j["serviceInstanceId"].get<std::string>();
    if (j.contains("serviceName"))
      svc.service_name = j["serviceName"].get<std::string>();
    
    // Handle versions - can be array of strings or array of objects
    if (j.contains("versions")) {
      const auto& versions = j["versions"];
      if (versions.is_array() && !versions.empty()) {
        if (versions[0].is_string()) {
          // Array of strings: ["v1", "v2"]
          svc.versions = versions.get<std::vector<std::string>>();
        } else if (versions[0].is_object()) {
          // Array of objects: [{"apiVersionInUri": "v1", ...}]
          for (const auto& v : versions) {
            if (v.contains("apiVersionInUri")) {
              svc.versions.push_back(v["apiVersionInUri"].get<std::string>());
            } else if (v.contains("apiVersionInURI")) {
              svc.versions.push_back(v["apiVersionInURI"].get<std::string>());
            }
          }
        }
      }
    }
    
    if (j.contains("scheme")) svc.scheme = j["scheme"].get<std::string>();
    if (j.contains("fqdn")) svc.fqdn = j["fqdn"].get<std::string>();
    if (j.contains("apiPrefix"))
      svc.api_prefix = j["apiPrefix"].get<std::string>();
    if (j.contains("priority")) svc.priority = j["priority"].get<uint16_t>();
    if (j.contains("capacity")) svc.capacity = j["capacity"].get<uint16_t>();
    if (j.contains("load")) svc.load = j["load"].get<uint8_t>();
    if (j.contains("ipEndPoints")) {
      for (const auto& ep : j["ipEndPoints"]) {
        svc.ip_endpoints.push_back(IpEndpoint::from_json(ep));
      }
    }
    return svc;
  }

  /**
   * @brief 获取服务的基础 URI（不包含 apiPrefix）
   * 用于 DID 认证等需要基础 URI 的场景
   */
  std::string get_base_uri() const {
    std::string base_uri;
    if (!fqdn.empty()) {
      base_uri = scheme + "://" + fqdn;
    } else if (!ip_endpoints.empty()) {
      const auto& ep = ip_endpoints[0];
      if (!ep.ipv4_address.empty()) {
        base_uri =
            scheme + "://" + ep.ipv4_address + ":" + std::to_string(ep.port);
      } else if (!ep.ipv6_address.empty()) {
        base_uri =
            scheme + "://[" + ep.ipv6_address + "]:" + std::to_string(ep.port);
      }
    }
    return base_uri;
  }

  /**
   * @brief 获取服务 URI（包含 apiPrefix）
   */
  std::string get_uri() const {
    return get_base_uri() + api_prefix;
  }
};

//==============================================================================
// NF Profile 结构
//==============================================================================

/**
 * @brief NF Profile 结构 (BCF 返回的 NF 信息)
 *
 * 基于 3GPP TS 29.510 NFProfile 定义，扩展 DID 相关字段
 */
struct NfProfile {
  // ===== 必选字段 =====
  std::string nf_instance_id;  // NF 实例 ID (UUID)
  NfType nf_type;              // NF 类型
  NfStatus nf_status;          // NF 状态

  // ===== DID 相关 (BCF 扩展) =====
  std::string did;         // 去中心化身份标识
  std::string public_key;  // 公钥 (PEM 或十六进制)

  // ===== 网络标识 =====
  std::vector<PlmnId> plmn_list;    // 支持的 PLMN 列表
  std::vector<Snssai> snssai_list;  // 支持的网络切片列表
  std::vector<PerPlmnSnssaiItem>
      per_plmn_snssai_list;          // 按 PLMN 划分的切片能力
  std::vector<std::string> nsi_list;  // Network Slice Instance 列表

  // ===== 访问地址 =====
  std::string fqdn;  // 完全限定域名
  std::vector<std::string> ipv4_addresses;
  std::vector<std::string> ipv6_addresses;
  std::vector<NfService> nf_services;  // NF 服务列表

  // ===== 负载和容量 =====
  int32_t priority;  // 优先级 (0-65535, 越小越优先)
  int32_t capacity;  // 容量 (0-65535)
  int32_t load;      // 当前负载百分比 (0-100)

  // ===== 位置信息 =====
  std::string locality;  // 地理位置标识

  // ===== SBI 信息 =====
  std::string sbi_api_version;  // API 版本

  /**
   * @brief 默认构造函数
   */
  NfProfile()
      : nf_type(NfType::NF_TYPE_UNKNOWN),
        nf_status(NfStatus::NF_STATUS_UNKNOWN),
        priority(0),
        capacity(100),
        load(0) {}

  /**
   * @brief 获取 NF 的基础 URI
   * @param use_https 是否使用 HTTPS
   * @param default_port 默认端口
   * @return NF 的访问 URI
   */
  std::string get_uri(bool use_https = true, uint16_t default_port = 8080) const {
    std::string scheme = use_https ? "https" : "http";
    if (!fqdn.empty()) {
      return scheme + "://" + fqdn;
    }
    if (!ipv4_addresses.empty()) {
      return scheme + "://" + ipv4_addresses[0] + ":" +
             std::to_string(default_port);
    }
    if (!ipv6_addresses.empty()) {
      return scheme + "://[" + ipv6_addresses[0] +
             "]:" + std::to_string(default_port);
    }
    return "";
  }

  /**
   * @brief 获取指定服务的 URI
   * @param service_name 服务名称
   * @return 服务 URI（包含 apiPrefix）
   */
  std::string get_service_uri(const std::string& service_name) const {
    for (const auto& svc : nf_services) {
      if (svc.service_name == service_name) {
        return svc.get_uri();
      }
    }
    return get_uri();  // 回退到默认 URI
  }

  /**
   * @brief 获取指定服务的基础 URI（不包含 apiPrefix）
   * @param service_name 服务名称
   * @return 服务基础 URI，用于 DID 认证等场景
   */
  std::string get_service_base_uri(const std::string& service_name) const {
    for (const auto& svc : nf_services) {
      if (svc.service_name == service_name) {
        return svc.get_base_uri();
      }
    }
    return get_uri();  // 回退到默认 URI
  }

  /**
   * @brief 序列化为 JSON
   */
  nlohmann::json to_json() const;

  /**
   * @brief 从 JSON 反序列化
   */
  static NfProfile from_json(const nlohmann::json& j);
};

//==============================================================================
// NF 发现查询条件
//==============================================================================

/**
 * @brief NF 发现查询条件
 *
 * 向 BCF 发送的查询条件，用于筛选符合要求的目标 NF
 */
struct NfDiscoveryCriteria {
  // ===== 必选条件 =====
  NfType target_nf_type;     // 目标 NF 类型
  NfType requester_nf_type;  // 请求方 NF 类型
  std::string requester_nf_instance_id;  // 请求方 NF Instance ID

  // ===== 可选筛选条件 =====
  std::optional<PlmnId> target_plmn;        // 目标 PLMN
  std::optional<Snssai> target_snssai;      // 目标网络切片
  std::optional<std::string> target_nsi;    // 目标 NSI
  std::optional<std::string> target_locality;  // 目标地理位置
  std::optional<std::string> service_name;  // 所需服务名称
  std::optional<std::string> target_nf_instance_id;  // 特定 NF Instance ID

  // ===== 容量和负载要求 =====
  std::optional<int32_t> min_capacity;  // 最小容量要求
  std::optional<int32_t> max_load;      // 最大负载要求 (百分比)

  // ===== 结果限制 =====
  uint32_t max_results = 10;  // 最大返回数量

  /**
   * @brief 构建 BCF 查询 URL 参数
   */
  std::string to_query_params() const;

  /**
   * @brief 序列化为 JSON
   */
  nlohmann::json to_json() const;
};

//==============================================================================
// NF 发现响应
//==============================================================================

/**
 * @brief NF 发现响应
 */
struct NfDiscoveryResponse {
  bool success;
  std::vector<NfProfile> nf_profiles;  // 符合条件的 NF 列表
  std::string error_message;
  std::string error_code;
  uint64_t validity_period;  // 结果有效期 (秒)

  NfDiscoveryResponse() : success(false), validity_period(3600) {}

  /**
   * @brief 从 JSON 反序列化
   */
  static NfDiscoveryResponse from_json(const nlohmann::json& j);
};

//==============================================================================
// 公钥查询响应
//==============================================================================

/**
 * @brief 公钥查询响应
 */
struct PublicKeyResponse {
  bool found;
  std::string did;
  std::string public_key;
  NfType nf_type;
  std::string nf_instance_id;
  std::string error_message;

  PublicKeyResponse() : found(false), nf_type(NfType::NF_TYPE_UNKNOWN) {}
};

//==============================================================================
// NF 选择策略
//==============================================================================

/**
 * @brief NF 选择策略
 */
enum class NfSelectionStrategy {
  PRIORITY_BASED,   // 基于优先级（priority 值越小越优先）
  LOAD_BASED,       // 基于负载（load 值越小越优先）
  CAPACITY_BASED,   // 基于容量（capacity 值越大越优先）
  ROUND_ROBIN,      // 轮询
  RANDOM,           // 随机选择
  LOCALITY_BASED,   // 基于地理位置（优先选择同一 locality）
  WEIGHTED_RANDOM   // 加权随机（基于 capacity 和 load）
};

//==============================================================================
// NF 类型转换工具函数
//==============================================================================

/**
 * @brief NF 类型转字符串
 */
std::string nf_type_to_string(NfType type);

/**
 * @brief 字符串转 NF 类型
 */
NfType string_to_nf_type(const std::string& str);

/**
 * @brief NF 状态转字符串
 */
std::string nf_status_to_string(NfStatus status);

/**
 * @brief 字符串转 NF 状态
 */
NfStatus string_to_nf_status(const std::string& str);

//==============================================================================
// BCF NF Discovery Client
//==============================================================================

/**
 * @brief BCF NF Discovery Client
 *
 * 通用的 BCF NF 发现客户端，可被任何 NF 使用
 *
 * 使用示例:
 * @code
 * // 初始化
 * BcfNfDiscoveryClient client;
 * client.set_bcf_uri("https://bcf.example.com");
 * client.set_local_nf_info(NfType::NF_TYPE_AMF, "amf-instance-id", "locality1");
 *
 * // 发现 AUSF
 * auto result = client.discover_nf(NfType::NF_TYPE_AUSF);
 * if (result.success && !result.nf_profiles.empty()) {
 *   auto selected = client.select_nf(result.nf_profiles);
 *   if (selected) {
 *     std::string ausf_uri = selected->get_uri();
 *   }
 * }
 *
 * // 查询公钥
 * auto pk_result = client.query_public_key("did:example:ausf-123");
 * if (pk_result.found) {
 *   std::string public_key = pk_result.public_key;
 * }
 * @endcode
 */
class BcfNfDiscoveryClient {
 public:
  BcfNfDiscoveryClient();
  ~BcfNfDiscoveryClient() = default;

  // 禁止拷贝
  BcfNfDiscoveryClient(const BcfNfDiscoveryClient&)            = delete;
  BcfNfDiscoveryClient& operator=(const BcfNfDiscoveryClient&) = delete;

  //============================================================================
  // 配置方法
  //============================================================================

  /**
   * @brief 设置 BCF URI
   * @param uri BCF 的基础 URI (如 "https://bcf.example.com:8080")
   */
  void set_bcf_uri(const std::string& uri);

  /**
   * @brief 设置 BCF NFM API 版本
   * @param version API 版本 (如 "v1")
   */
  void set_bcf_api_version(const std::string& version);

  /**
   * @brief 设置本地 NF 信息
   * @param nf_type 本地 NF 类型
   * @param nf_instance_id 本地 NF Instance ID
   * @param locality 地理位置标识
   */
  void set_local_nf_info(
      NfType nf_type, const std::string& nf_instance_id,
      const std::string& locality = "");

  /**
   * @brief 设置默认 NF 选择策略
   * @param strategy 选择策略
   */
  void set_selection_strategy(NfSelectionStrategy strategy);

  /**
   * @brief 设置 HTTP 版本
   * @param version HTTP 版本 (1 或 2)
   */
  void set_http_version(int version);

  /**
   * @brief 启用/禁用缓存
   * @param enable 是否启用
   * @param ttl_seconds 缓存 TTL (秒)
   */
  void enable_cache(bool enable, uint32_t ttl_seconds = 300);

  //============================================================================
  // NF 发现方法
  //============================================================================

  /**
   * @brief 发现指定类型的 NF
   * @param target_nf_type 目标 NF 类型
   * @param service_name 可选的服务名称筛选
   * @return 发现响应
   */
  NfDiscoveryResponse discover_nf(
      NfType target_nf_type,
      const std::string& service_name = "");

  /**
   * @brief 使用自定义条件发现 NF
   * @param criteria 查询条件
   * @return 发现响应
   */
  NfDiscoveryResponse discover_nf(const NfDiscoveryCriteria& criteria);

  /**
   * @brief 发现 NF 并选择一个最优实例
   * @param target_nf_type 目标 NF 类型
   * @param service_name 可选的服务名称筛选
   * @return 选中的 NF Profile，失败返回 nullopt
   */
  std::optional<NfProfile> discover_and_select_nf(
      NfType target_nf_type,
      const std::string& service_name = "");

  /**
   * @brief 从 NF 列表中选择一个最优实例
   * @param nf_list NF 列表
   * @param strategy 选择策略 (默认使用配置的策略)
   * @return 选中的 NF Profile，列表为空返回 nullopt
   */
  std::optional<NfProfile> select_nf(
      const std::vector<NfProfile>& nf_list,
      std::optional<NfSelectionStrategy> strategy = std::nullopt);

  //============================================================================
  // 公钥查询方法
  //============================================================================

  /**
   * @brief 查询 DID 的公钥
   * @param did DID 标识符
   * @return 公钥查询响应
   */
  PublicKeyResponse query_public_key(const std::string& did);

  /**
   * @brief 查询 NF Instance 的公钥
   * @param nf_instance_id NF Instance ID
   * @return 公钥查询响应
   */
  PublicKeyResponse query_public_key_by_nf_id(const std::string& nf_instance_id);

  //============================================================================
  // 便捷方法 - 常用 NF 类型
  //============================================================================

  /**
   * @brief 发现并选择 AUSF
   * @return 选中的 AUSF Profile
   */
  std::optional<NfProfile> discover_ausf();

  /**
   * @brief 发现并选择 UDM
   * @return 选中的 UDM Profile
   */
  std::optional<NfProfile> discover_udm();

  /**
   * @brief 发现并选择 SMF
   * @param snssai 可选的网络切片筛选
   * @return 选中的 SMF Profile
   */
  std::optional<NfProfile> discover_smf(
      const std::optional<Snssai>& snssai = std::nullopt);

  /**
   * @brief 发现并选择 PCF
   * @return 选中的 PCF Profile
   */
  std::optional<NfProfile> discover_pcf();

  /**
   * @brief 发现并选择 AMF
   * @return 选中的 AMF Profile
   */
  std::optional<NfProfile> discover_amf();

  //============================================================================
  // 缓存管理
  //============================================================================

  /**
   * @brief 清除所有缓存
   */
  void clear_cache();

  /**
   * @brief 清除指定 NF 类型的缓存
   * @param nf_type NF 类型
   */
  void clear_cache(NfType nf_type);

  /**
   * @brief 获取缓存统计信息
   * @return JSON 格式的统计信息
   */
  nlohmann::json get_cache_stats() const;

 private:
  //============================================================================
  // 内部方法
  //============================================================================

  /**
   * @brief 发送 HTTP 请求到 BCF
   */
  bool send_bcf_request(
      const std::string& path, const std::string& method,
      const std::string& body, nlohmann::json& response, uint32_t& http_code);

  /**
   * @brief 构建 BCF NF Discovery URI
   */
  std::string build_discovery_uri(const NfDiscoveryCriteria& criteria) const;

  /**
   * @brief 从缓存获取 NF 列表
   */
  std::optional<std::vector<NfProfile>> get_from_cache(
      NfType target_nf_type) const;

  /**
   * @brief 更新缓存
   */
  void update_cache(
      NfType target_nf_type, const std::vector<NfProfile>& profiles,
      uint64_t validity_period);

  /**
   * @brief NF 选择算法实现
   */
  std::optional<NfProfile> select_by_priority(
      const std::vector<NfProfile>& nf_list) const;
  std::optional<NfProfile> select_by_load(
      const std::vector<NfProfile>& nf_list) const;
  std::optional<NfProfile> select_by_capacity(
      const std::vector<NfProfile>& nf_list) const;
  std::optional<NfProfile> select_random(
      const std::vector<NfProfile>& nf_list) const;
  std::optional<NfProfile> select_round_robin(
      const std::vector<NfProfile>& nf_list);
  std::optional<NfProfile> select_by_locality(
      const std::vector<NfProfile>& nf_list) const;
  std::optional<NfProfile> select_weighted_random(
      const std::vector<NfProfile>& nf_list) const;

  //============================================================================
  // 成员变量
  //============================================================================

  std::string m_bcf_uri;
  std::string m_bcf_api_version;
  NfType m_local_nf_type;
  std::string m_local_nf_instance_id;
  std::string m_local_locality;
  NfSelectionStrategy m_selection_strategy;
  int m_http_version;

  // 缓存
  bool m_cache_enabled;
  uint32_t m_cache_ttl_seconds;

  struct CacheEntry {
    std::vector<NfProfile> profiles;
    std::chrono::steady_clock::time_point expire_time;
  };
  mutable std::map<NfType, CacheEntry> m_cache;
  mutable std::mutex m_cache_mutex;

  // 轮询索引
  mutable std::map<NfType, size_t> m_round_robin_indices;
  mutable std::mutex m_rr_mutex;
};

//==============================================================================
// 全局单例访问 (可选)
//==============================================================================

/**
 * @brief 获取全局 BCF NF Discovery Client 单例
 *
 * 注意：单例需要在使用前初始化配置
 */
BcfNfDiscoveryClient& get_bcf_nf_discovery_client();

}  // namespace oai::common::bcf

#endif  // _BCF_NF_DISCOVERY_HPP_
