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
 * @file bcf_client.hpp
 * @brief BCF HTTP Client - BCF 通信的 HTTP 客户端封装
 *
 * 提供与 BCF 通信的 HTTP 客户端功能，支持 HTTP/1.1 和 HTTP/2
 */

#ifndef _BCF_CLIENT_HPP_
#define _BCF_CLIENT_HPP_

#include <functional>
#include <memory>
#include <string>

#include <nlohmann/json.hpp>

namespace oai::common::bcf {

/**
 * @brief HTTP 方法枚举
 */
enum class HttpMethod { GET, POST, PUT, PATCH, DELETE };

/**
 * @brief HTTP 响应结构
 */
struct HttpResponse {
  uint32_t status_code;
  std::string body;
  nlohmann::json json_body;
  bool success;
  std::string error_message;

  HttpResponse() : status_code(0), success(false) {}

  /**
   * @brief 检查响应是否成功 (2xx)
   */
  bool is_success() const {
    return status_code >= 200 && status_code < 300;
  }

  /**
   * @brief 解析 JSON body
   */
  bool parse_json() {
    if (body.empty()) return false;
    try {
      json_body = nlohmann::json::parse(body);
      return true;
    } catch (...) {
      return false;
    }
  }
};

/**
 * @brief BCF HTTP Client
 *
 * 封装与 BCF 的 HTTP 通信，支持 HTTP/1.1 和 HTTP/2
 */
class BcfHttpClient {
 public:
  BcfHttpClient();
  ~BcfHttpClient() = default;

  /**
   * @brief 设置 BCF 基础 URI
   * @param uri BCF 基础 URI (如 "https://bcf.example.com:8080")
   */
  void set_base_uri(const std::string& uri);

  /**
   * @brief 设置 HTTP 版本
   * @param version HTTP 版本 (1 或 2)
   */
  void set_http_version(int version);

  /**
   * @brief 设置请求超时时间
   * @param timeout_ms 超时时间 (毫秒)
   */
  void set_timeout(uint32_t timeout_ms);

  /**
   * @brief 发送 GET 请求
   * @param path 请求路径 (相对于基础 URI)
   * @return HTTP 响应
   */
  HttpResponse get(const std::string& path);

  /**
   * @brief 发送 POST 请求
   * @param path 请求路径
   * @param body 请求体
   * @return HTTP 响应
   */
  HttpResponse post(const std::string& path, const std::string& body);

  /**
   * @brief 发送 POST 请求 (JSON)
   * @param path 请求路径
   * @param json_body JSON 请求体
   * @return HTTP 响应
   */
  HttpResponse post(const std::string& path, const nlohmann::json& json_body);

  /**
   * @brief 发送 PUT 请求
   * @param path 请求路径
   * @param body 请求体
   * @return HTTP 响应
   */
  HttpResponse put(const std::string& path, const std::string& body);

  /**
   * @brief 发送 PUT 请求 (JSON)
   * @param path 请求路径
   * @param json_body JSON 请求体
   * @return HTTP 响应
   */
  HttpResponse put(const std::string& path, const nlohmann::json& json_body);

  /**
   * @brief 发送 DELETE 请求
   * @param path 请求路径
   * @return HTTP 响应
   */
  HttpResponse del(const std::string& path);

  /**
   * @brief 发送通用 HTTP 请求
   * @param method HTTP 方法
   * @param path 请求路径
   * @param body 请求体 (可选)
   * @return HTTP 响应
   */
  HttpResponse send_request(
      HttpMethod method, const std::string& path,
      const std::string& body = "");

 private:
  std::string m_base_uri;
  int m_http_version;
  uint32_t m_timeout_ms;

  /**
   * @brief 内部发送请求实现
   */
  HttpResponse do_send(
      const std::string& method, const std::string& full_uri,
      const std::string& body);
};

/**
 * @brief 获取 HTTP 方法字符串
 */
inline std::string http_method_to_string(HttpMethod method) {
  switch (method) {
    case HttpMethod::GET:
      return "GET";
    case HttpMethod::POST:
      return "POST";
    case HttpMethod::PUT:
      return "PUT";
    case HttpMethod::PATCH:
      return "PATCH";
    case HttpMethod::DELETE:
      return "DELETE";
    default:
      return "GET";
  }
}

}  // namespace oai::common::bcf

#endif  // _BCF_CLIENT_HPP_
