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

#ifndef _DID_CRYPTO_H_
#define _DID_CRYPTO_H_

#include <cstdint>
#include <string>
#include <vector>

namespace oai::amf::did_auth {

/**
 * @brief secp256k1 密码学操作类
 *
 * 提供基于 secp256k1 椭圆曲线的：
 * - ECDSA 签名
 * - ECDSA 验签
 * - SHA256 哈希
 * - 随机数生成
 *
 * 使用 OpenSSL 实现
 */
class did_crypto {
 public:
  /**
   * @brief 构造函数
   * @param private_key_hex 私钥（Hex 编码，64 字符 = 32 字节）
   */
  explicit did_crypto(const std::string& private_key_hex);

  /**
   * @brief 默认构造函数（仅用于静态方法）
   */
  did_crypto();

  ~did_crypto();

  /**
   * @brief 检查是否已初始化私钥
   */
  bool has_private_key() const { return !m_private_key.empty(); }

  /**
   * @brief 获取私钥字节（用于统一签名工具）
   */
  const std::vector<uint8_t>& get_private_key_bytes() const { return m_private_key; }

  /**
   * @brief 获取公钥（压缩格式 Hex）
   */
  std::string get_public_key_hex() const { return m_public_key_hex; }

  /**
   * @brief 对数据进行签名
   * @param data 待签名数据
   * @return 签名结果（Hex 编码）
   */
  std::string sign(const std::vector<uint8_t>& data) const;

  /**
   * @brief 对数据进行签名（字符串版本）
   * @param data 待签名字符串
   * @return 签名结果（Hex 编码）
   */
  std::string sign(const std::string& data) const;

  /**
   * @brief 对 Hex 编码的数据进行签名
   * @param hex_data Hex 编码的待签名数据
   * @return 签名结果（Hex 编码）
   */
  std::string sign_hex(const std::string& hex_data) const;

  /**
   * @brief 验证签名
   * @param data 原始数据
   * @param signature_hex 签名（Hex 编码）
   * @param public_key_hex 公钥（Hex 编码，压缩格式 66 字符）
   * @return true 如果签名有效
   */
  static bool verify(
      const std::vector<uint8_t>& data, const std::string& signature_hex,
      const std::string& public_key_hex);

  /**
   * @brief 验证签名（字符串版本）
   */
  static bool verify(
      const std::string& data, const std::string& signature_hex,
      const std::string& public_key_hex);

  /**
   * @brief 验证 Hex 编码数据的签名
   */
  static bool verify_hex(
      const std::string& hex_data, const std::string& signature_hex,
      const std::string& public_key_hex);

  /**
   * @brief 计算 SHA256 哈希
   * @param data 输入数据
   * @return 32 字节哈希结果
   */
  static std::vector<uint8_t> sha256(const std::vector<uint8_t>& data);

  /**
   * @brief 计算 SHA256 哈希（字符串版本）
   */
  static std::vector<uint8_t> sha256(const std::string& data);

  /**
   * @brief 计算 SHA256 哈希并返回 Hex 字符串
   */
  static std::string sha256_hex(const std::string& data);

  /**
   * @brief 生成安全随机数
   * @param length 随机数长度（字节）
   * @return 随机字节数组
   */
  static std::vector<uint8_t> generate_random(size_t length);

  /**
   * @brief 从私钥导出公钥
   * @param private_key_hex 私钥（Hex 编码）
   * @return 压缩格式公钥（Hex 编码，66 字符）
   */
  static std::string derive_public_key(const std::string& private_key_hex);

  /**
   * @brief 生成新的密钥对
   * @param private_key_hex 输出：私钥（Hex 编码）
   * @param public_key_hex 输出：公钥（Hex 编码，压缩格式）
   * @return true 如果成功
   */
  static bool generate_key_pair(
      std::string& private_key_hex, std::string& public_key_hex);

  /**
   * @brief Hex 编码
   */
  static std::string to_hex(const std::vector<uint8_t>& data);

  /**
   * @brief Hex 解码
   */
  static std::vector<uint8_t> from_hex(const std::string& hex);

  /**
   * @brief 验证私钥格式是否有效
   */
  static bool is_valid_private_key(const std::string& private_key_hex);

  /**
   * @brief 验证公钥格式是否有效
   */
  static bool is_valid_public_key(const std::string& public_key_hex);

 private:
  std::vector<uint8_t> m_private_key;
  std::string m_public_key_hex;

  /**
   * @brief 内部签名实现
   */
  std::string sign_hash(const std::vector<uint8_t>& hash) const;

  /**
   * @brief 内部验签实现
   */
  static bool verify_hash(
      const std::vector<uint8_t>& hash, const std::string& signature_hex,
      const std::string& public_key_hex);
};

}  // namespace oai::amf::did_auth

#endif  // _DID_CRYPTO_H_
