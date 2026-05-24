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

#ifndef _HARDWARE_ID_HPP_
#define _HARDWARE_ID_HPP_

#include <string>
#include <vector>

namespace oai::amf::did_auth {

/**
 * @brief 硬件ID管理模块
 * 
 * 硬件ID的生成和存储现在由 did-proxy (Go) 负责。
 * C++ 端仅负责读取和验证。
 * 
 * 工作流程：
 * 1. 运行 did-proxy 生成 extended_profile.json（包含 hardwareId 字段）
 * 2. AMF/AUSF 启动时从 extended_profile.json 读取 hardwareId
 * 3. 本类仅用于验证硬件绑定是否有效
 */
class hardware_id_manager {
 public:
  // 默认存储路径
  static constexpr const char* DEFAULT_STORAGE_PATH = "/usr/local/etc/oai/nf_hardware_id";
  
  /**
   * @brief 获取硬件ID（仅读取，不再生成）
   * 
   * @deprecated 硬件ID应从 extended_profile.json 读取（由 did-proxy 生成）。
   *             此函数仅用于向后兼容。
   * 
   * @param storage_path 存储路径
   * @return 硬件ID的十六进制字符串，失败返回空字符串
   */
  [[deprecated("Use hardware ID from extended_profile.json instead")]]
  static std::string get_or_generate_hardware_id(
      const std::string& storage_path = DEFAULT_STORAGE_PATH);

  /**
   * @brief 验证当前硬件ID是否与存储的匹配
   * 
   * @param storage_path 存储路径
   * @return true 如果匹配，false 如果不匹配或文件不存在
   */
  static bool verify_hardware_id(
      const std::string& storage_path = DEFAULT_STORAGE_PATH);

  /**
   * @brief 从NF Profile和hardware_id生成DID
   * 
   * DID = did:oai5gc:<hash(nf_type + nf_instance_id + hardware_id + public_key)>
   * 
   * @param nf_type NF类型 (AMF, AUSF, etc.)
   * @param nf_instance_id NF实例ID
   * @param hardware_id 硬件ID
   * @param public_key_hex 公钥的十六进制字符串
   * @return 生成的DID字符串
   */
  static std::string generate_did_with_hardware_binding(
      const std::string& nf_type,
      const std::string& nf_instance_id,
      const std::string& hardware_id,
      const std::string& public_key_hex);

  /**
   * @brief 验证DID是否与给定的硬件ID绑定
   * 
   * @param did 要验证的DID
   * @param nf_type NF类型
   * @param nf_instance_id NF实例ID
   * @param public_key_hex 公钥
   * @param hardware_id 硬件ID（从 extended_profile.json 读取）
   * @return true 如果DID与硬件ID绑定匹配
   */
  static bool verify_did_hardware_binding(
      const std::string& did,
      const std::string& nf_type,
      const std::string& nf_instance_id,
      const std::string& public_key_hex,
      const std::string& hardware_id);

 private:
  /**
   * @brief 收集硬件特征信息
   * @return 包含硬件特征的字符串
   */
  static std::string collect_hardware_fingerprint();

  /**
   * @brief 获取CPU序列号/ID
   * @return CPU ID字符串
   */
  static std::string get_cpu_id();

  /**
   * @brief 获取主板序列号
   * @return 主板序列号字符串
   */
  static std::string get_motherboard_serial();

  /**
   * @brief 获取第一个网卡MAC地址
   * @return MAC地址字符串
   */
  static std::string get_primary_mac_address();

  /**
   * @brief 获取机器ID (Linux /etc/machine-id)
   * @return 机器ID字符串
   */
  static std::string get_machine_id();

  /**
   * @brief 加密存储硬件ID
   * 
   * @deprecated 此功能现在由 did-proxy (Go) 负责。
   *             请运行: ./did-proxy -config /usr/local/etc/oai/amf.conf
   * 
   * @param hardware_id 要存储的硬件ID
   * @param storage_path 存储路径
   * @return 始终返回 false
   */
  [[deprecated("Use did-proxy to generate and store hardware ID")]]
  static bool encrypt_and_store(
      const std::string& hardware_id,
      const std::string& storage_path);

  /**
   * @brief 从存储文件解密读取硬件ID
   * 
   * @param storage_path 存储路径
   * @return 解密后的硬件ID，失败返回空字符串
   */
  static std::string decrypt_and_load(const std::string& storage_path);

  /**
   * @brief 计算硬件指纹的哈希
   * @param fingerprint 硬件指纹字符串
   * @return SHA256哈希的十六进制字符串
   */
  static std::string hash_fingerprint(const std::string& fingerprint);

  /**
   * @brief 派生加密密钥
   * @param fingerprint 硬件指纹
   * @return 32字节密钥
   */
  static std::vector<uint8_t> derive_encryption_key(const std::string& fingerprint);
};

}  // namespace oai::amf::did_auth

#endif  // _HARDWARE_ID_HPP_
