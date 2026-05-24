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

#ifndef _SIGNATURE_UTILS_HPP_
#define _SIGNATURE_UTILS_HPP_

#include <string>
#include <vector>

namespace oai::amf::did_auth {

/**
 * @brief 统一签名工具类
 * 
 * 提供标准化的签名/验签流程，确保AMF和AUSF使用相同的：
 * - Payload构造逻辑
 * - Hash规则（SHA256）
 * - ECDSA签名参数（secp256k1）
 * - DID公钥解析格式
 * 
 * 所有签名操作都有详细日志输出，便于调试
 */
class signature_utils {
 public:
  /**
   * @brief 签名版本号，用于保证兼容性
   */
  static constexpr const char* SIGNATURE_VERSION = "OAI5GC_SIG_v1";

  /**
   * @brief 构造签名payload
   * 
   * 格式: VERSION|CHALLENGE_HEX|TIMESTAMP
   * 这确保了payload的唯一性和可验证性
   * 
   * @param challenge_hex challenge的十六进制字符串
   * @param timestamp_ms 时间戳（毫秒）
   * @return 构造的payload字符串
   */
  static std::string build_signature_payload(
      const std::string& nonce_hex,
      uint64_t timestamp_ms = 0);

  /**
   * @brief 从DID中提取公钥
   * 
   * 支持两种DID格式:
   * 1. did:oai5gc:<public_key_hex> - 传统格式
   * 2. did:oai5gc:<binding_hash>:<public_key_hex> - 硬件绑定格式
   * 
   * @param did DID字符串
   * @return 公钥的十六进制字符串，提取失败返回空字符串
   */
  static std::string extract_public_key_from_did(const std::string& did);

  /**
   * @brief 标准化公钥格式
   * 
   * 确保公钥为标准的未压缩格式（65字节，04前缀）
   * 或压缩格式（33字节，02/03前缀）
   * 
   * @param public_key_hex 输入的公钥十六进制字符串
   * @return 标准化后的公钥，失败返回空字符串
   */
  static std::string normalize_public_key(const std::string& public_key_hex);

  /**
   * @brief 使用私钥签名challenge（带详细日志）
   * 
   * 签名流程:
   * 1. 构造payload = build_signature_payload(challenge_hex, timestamp)
   * 2. 计算hash = SHA256(payload)
   * 3. 签名 = ECDSA_sign(hash, private_key)
   * 4. 返回DER编码的签名hex
   * 
   * @param challenge_hex challenge的十六进制字符串
   * @param private_key_bytes 私钥字节数组
   * @param timestamp_ms 时间戳（可选，用于payload）
   * @return 签名的十六进制字符串，失败返回空字符串
   */
  static std::string sign_challenge_with_logging(
      const std::string& challenge_hex,
      const std::vector<uint8_t>& private_key_bytes,
      uint64_t timestamp_ms = 0);

  /**
   * @brief 验证challenge签名（带详细日志）
   * 
   * 验证流程:
   * 1. 构造payload = build_signature_payload(challenge_hex, timestamp)
   * 2. 计算expected_hash = SHA256(payload)
   * 3. 解析公钥（支持压缩/未压缩格式）
   * 4. 解析DER签名
   * 5. 验证 = ECDSA_verify(expected_hash, signature, public_key)
   * 
   * @param challenge_hex challenge的十六进制字符串
   * @param signature_hex 签名的十六进制字符串（DER编码）
   * @param public_key_hex 公钥的十六进制字符串
   * @param timestamp_ms 时间戳（必须与签名时使用的相同）
   * @return true 如果验证通过
   */
  static bool verify_challenge_with_logging(
      const std::string& challenge_hex,
      const std::string& signature_hex,
      const std::string& public_key_hex,
      uint64_t timestamp_ms = 0);

  /**
   * @brief 计算SHA256哈希
   * 
   * @param data 输入数据
   * @return 32字节哈希值
   */
  static std::vector<uint8_t> sha256(const std::vector<uint8_t>& data);
  static std::vector<uint8_t> sha256(const std::string& data);

  /**
   * @brief 十六进制编解码
   */
  static std::string to_hex(const std::vector<uint8_t>& data);
  static std::vector<uint8_t> from_hex(const std::string& hex);

  /**
   * @brief 日志辅助 - 打印字节数组（截断显示）
   */
  static std::string bytes_to_debug_string(
      const std::vector<uint8_t>& data, size_t max_len = 32);

 private:
  /**
   * @brief ECDSA签名（内部使用）
   */
  static std::string ecdsa_sign(
      const std::vector<uint8_t>& hash,
      const std::vector<uint8_t>& private_key);

  /**
   * @brief ECDSA验签（内部使用）
   */
  static bool ecdsa_verify(
      const std::vector<uint8_t>& hash,
      const std::vector<uint8_t>& signature,
      const std::vector<uint8_t>& public_key);

  /**
   * @brief 将压缩公钥转换为未压缩格式
   */
  static std::vector<uint8_t> decompress_public_key(
      const std::vector<uint8_t>& compressed_key);
};

}  // namespace oai::amf::did_auth

#endif  // _SIGNATURE_UTILS_HPP_
