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

#include "bcf_client.hpp"

#include <curl/curl.h>

#include <cstring>

#include "logger.hpp"

namespace oai::common::bcf {

//------------------------------------------------------------------------------
// CURL 回调函数
//------------------------------------------------------------------------------

static size_t write_callback(
    void* contents, size_t size, size_t nmemb, void* userp) {
  size_t total_size = size * nmemb;
  std::string* str  = static_cast<std::string*>(userp);
  str->append(static_cast<char*>(contents), total_size);
  return total_size;
}

//------------------------------------------------------------------------------
// BcfHttpClient 实现
//------------------------------------------------------------------------------

BcfHttpClient::BcfHttpClient()
    : m_http_version(2), m_timeout_ms(5000) {}

void BcfHttpClient::set_base_uri(const std::string& uri) {
  m_base_uri = uri;
  // 移除尾部斜杠
  while (!m_base_uri.empty() && m_base_uri.back() == '/') {
    m_base_uri.pop_back();
  }
}

void BcfHttpClient::set_http_version(int version) {
  m_http_version = version;
}

void BcfHttpClient::set_timeout(uint32_t timeout_ms) {
  m_timeout_ms = timeout_ms;
}

HttpResponse BcfHttpClient::get(const std::string& path) {
  return send_request(HttpMethod::GET, path);
}

HttpResponse BcfHttpClient::post(
    const std::string& path, const std::string& body) {
  return send_request(HttpMethod::POST, path, body);
}

HttpResponse BcfHttpClient::post(
    const std::string& path, const nlohmann::json& json_body) {
  return post(path, json_body.dump());
}

HttpResponse BcfHttpClient::put(
    const std::string& path, const std::string& body) {
  return send_request(HttpMethod::PUT, path, body);
}

HttpResponse BcfHttpClient::put(
    const std::string& path, const nlohmann::json& json_body) {
  return put(path, json_body.dump());
}

HttpResponse BcfHttpClient::del(const std::string& path) {
  return send_request(HttpMethod::DELETE, path);
}

HttpResponse BcfHttpClient::send_request(
    HttpMethod method, const std::string& path, const std::string& body) {
  std::string full_uri = m_base_uri + path;
  return do_send(http_method_to_string(method), full_uri, body);
}

HttpResponse BcfHttpClient::do_send(
    const std::string& method, const std::string& full_uri,
    const std::string& body) {
  HttpResponse response;

  CURL* curl = curl_easy_init();
  if (!curl) {
    response.error_message = "Failed to initialize CURL";
    return response;
  }

  std::string response_body;

  // 设置 URL
  curl_easy_setopt(curl, CURLOPT_URL, full_uri.c_str());

  // 设置 HTTP 版本
  if (m_http_version == 2) {
    curl_easy_setopt(curl, CURLOPT_HTTP_VERSION, CURL_HTTP_VERSION_2_0);
  } else {
    curl_easy_setopt(curl, CURLOPT_HTTP_VERSION, CURL_HTTP_VERSION_1_1);
  }

  // 设置超时
  curl_easy_setopt(curl, CURLOPT_TIMEOUT_MS, m_timeout_ms);
  curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT_MS, m_timeout_ms / 2);

  // 设置回调
  curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
  curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response_body);

  // 设置 HTTP 方法
  if (method == "GET") {
    curl_easy_setopt(curl, CURLOPT_HTTPGET, 1L);
  } else if (method == "POST") {
    curl_easy_setopt(curl, CURLOPT_POST, 1L);
  } else if (method == "PUT") {
    curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, "PUT");
  } else if (method == "DELETE") {
    curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, "DELETE");
  } else if (method == "PATCH") {
    curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, "PATCH");
  }

  // 设置请求体
  if (!body.empty()) {
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, body.c_str());
    curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, body.size());
  }

  // 设置请求头
  struct curl_slist* headers = nullptr;
  headers = curl_slist_append(headers, "Content-Type: application/json");
  headers = curl_slist_append(headers, "Accept: application/json");
  curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);

  // 忽略 SSL 证书验证 (开发环境)
  curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
  curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);

  // 执行请求
  CURLcode res = curl_easy_perform(curl);

  if (res == CURLE_OK) {
    long http_code = 0;
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);

    response.status_code = static_cast<uint32_t>(http_code);
    response.body        = response_body;
    response.success     = response.is_success();
    response.parse_json();
  } else {
    response.error_message = curl_easy_strerror(res);
  }

  // 清理
  curl_slist_free_all(headers);
  curl_easy_cleanup(curl);

  return response;
}

}  // namespace oai::common::bcf
