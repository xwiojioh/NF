#include "bcf_token_verifier.hpp"

#include <algorithm>
#include <array>
#include <cctype>
#include <ctime>
#include <sstream>
#include <string>
#include <vector>

#include <curl/curl.h>
#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/obj_mac.h>
#include <openssl/sha.h>

#include "ausf_config.hpp"
#include "logger.hpp"

extern oai::config::ausf_config ausf_cfg;

namespace oai::ausf::did_auth {

namespace {

constexpr std::time_t kJwksCacheTtlSeconds = 300;
constexpr const char* kTrustedIssuer       = "BCF";

size_t curl_write_callback(void* contents, size_t size, size_t nmemb, void* userp) {
  const auto total_size = size * nmemb;
  auto* buffer          = reinterpret_cast<std::string*>(userp);
  buffer->append(reinterpret_cast<char*>(contents), total_size);
  return total_size;
}

std::string trim_trailing_slash(std::string value) {
  while (!value.empty() && value.back() == '/') {
    value.pop_back();
  }
  return value;
}

std::string get_bcf_api_version() {
  return ausf_cfg.bcf_addr.api_version.empty() ? "v1" : ausf_cfg.bcf_addr.api_version;
}

std::string build_bcf_auth_url(const std::string& suffix) {
  return trim_trailing_slash(ausf_cfg.bcf_addr.uri_root) + "/nbcf_auth/" +
         get_bcf_api_version() + suffix;
}

bool send_bcf_http_request(
    const std::string& url, const std::string& method,
    const std::string& body, long& http_code, std::string& response_body) {
  CURL* curl = curl_easy_init();
  if (!curl) {
    return false;
  }

  struct curl_slist* headers = nullptr;
  curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
  curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, curl_write_callback);
  curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response_body);
  curl_easy_setopt(curl, CURLOPT_TIMEOUT_MS, ausf_cfg.http_request_timeout);

  if (method == "POST") {
    headers = curl_slist_append(headers, "Content-Type: application/json");
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_POST, 1L);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, body.c_str());
    curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, body.size());
  }

  const auto rc = curl_easy_perform(curl);
  if (rc != CURLE_OK) {
    Logger::ausf_server().warn(
        "[AUSF][Auth] BCF HTTP request failed: %s",
        curl_easy_strerror(rc));
    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);
    return false;
  }

  curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);
  curl_slist_free_all(headers);
  curl_easy_cleanup(curl);
  return true;
}

std::string base64url_to_base64(std::string value) {
  std::replace(value.begin(), value.end(), '-', '+');
  std::replace(value.begin(), value.end(), '_', '/');
  while (value.size() % 4 != 0) {
    value.push_back('=');
  }
  return value;
}

bool base64url_decode(const std::string& input, std::string& output) {
  static const std::array<int, 256> kDecodeTable = [] {
    std::array<int, 256> table{};
    table.fill(-1);
    for (int c = 'A'; c <= 'Z'; ++c) table[c] = c - 'A';
    for (int c = 'a'; c <= 'z'; ++c) table[c] = c - 'a' + 26;
    for (int c = '0'; c <= '9'; ++c) table[c] = c - '0' + 52;
    table[static_cast<unsigned char>('+')] = 62;
    table[static_cast<unsigned char>('/')] = 63;
    table[static_cast<unsigned char>('=')] = 0;
    return table;
  }();

  const auto normalized = base64url_to_base64(input);
  output.clear();
  output.reserve((normalized.size() * 3) / 4);

  for (size_t i = 0; i < normalized.size(); i += 4) {
    if (i + 4 > normalized.size()) {
      return false;
    }

    const unsigned char c0 = normalized[i];
    const unsigned char c1 = normalized[i + 1];
    const unsigned char c2 = normalized[i + 2];
    const unsigned char c3 = normalized[i + 3];
    if (kDecodeTable[c0] < 0 || kDecodeTable[c1] < 0 ||
        (c2 != '=' && kDecodeTable[c2] < 0) ||
        (c3 != '=' && kDecodeTable[c3] < 0)) {
      return false;
    }

    const unsigned int triple =
        (static_cast<unsigned int>(kDecodeTable[c0]) << 18) |
        (static_cast<unsigned int>(kDecodeTable[c1]) << 12) |
        (static_cast<unsigned int>(kDecodeTable[c2]) << 6) |
        static_cast<unsigned int>(kDecodeTable[c3]);

    output.push_back(static_cast<char>((triple >> 16) & 0xFF));
    if (c2 != '=') {
      output.push_back(static_cast<char>((triple >> 8) & 0xFF));
    }
    if (c3 != '=') {
      output.push_back(static_cast<char>(triple & 0xFF));
    }
  }

  return true;
}

bool decode_jwt(
    const std::string& token, nlohmann::json& header, nlohmann::json& payload,
    std::string& signature_raw, std::string& signing_input) {
  const auto first_dot = token.find('.');
  if (first_dot == std::string::npos) {
    return false;
  }
  const auto second_dot = token.find('.', first_dot + 1);
  if (second_dot == std::string::npos) {
    return false;
  }

  const auto header_part = token.substr(0, first_dot);
  const auto payload_part =
      token.substr(first_dot + 1, second_dot - first_dot - 1);
  const auto signature_part = token.substr(second_dot + 1);

  std::string header_json;
  std::string payload_json;
  if (!base64url_decode(header_part, header_json) ||
      !base64url_decode(payload_part, payload_json) ||
      !base64url_decode(signature_part, signature_raw)) {
    return false;
  }

  try {
    header = nlohmann::json::parse(header_json);
    payload = nlohmann::json::parse(payload_json);
  } catch (...) {
    return false;
  }

  signing_input = header_part + "." + payload_part;
  return true;
}

std::vector<std::string> json_to_string_vector(const nlohmann::json& value) {
  std::vector<std::string> items;
  if (value.is_array()) {
    for (const auto& entry : value) {
      if (entry.is_string()) {
        items.push_back(entry.get<std::string>());
      }
    }
  } else if (value.is_string()) {
    const auto raw_value = value.get<std::string>();
    std::stringstream stream(raw_value);
    std::string token = {};
    while (stream >> token) {
      items.push_back(token);
    }
    if (items.empty() && !raw_value.empty()) {
      items.push_back(raw_value);
    }
  }
  return items;
}

bool contains_string(
    const std::vector<std::string>& values, const std::string& expected) {
  return std::find(values.begin(), values.end(), expected) != values.end();
}

std::string to_upper_copy(std::string value) {
  std::transform(
      value.begin(), value.end(), value.begin(),
      [](unsigned char c) { return std::toupper(c); });
  return value;
}

}  // namespace

bool BcfTokenVerifier::verify_request_token(
    const std::string& token, const std::string& expected_audience,
    const std::string& required_scope, const std::string& bound_nf_instance_id,
    const std::string& bound_nf_type, token_verification_result_t& result) {
  result = {};

  nlohmann::json header  = {};
  nlohmann::json claims  = {};
  std::string signature  = {};
  std::string signing_in = {};
  if (!decode_jwt(token, header, claims, signature, signing_in)) {
    result.error_message = "invalid_jwt";
    return false;
  }

  result.header = header;
  result.claims = claims;

  const auto alg = header.value("alg", "");
  if (alg == "ES256K") {
    Logger::ausf_server().info("[AUSF][Auth] Verifying ES256K token");
    const auto kid = header.value("kid", "");
    jwk_entry_t jwk;
    if (kid.empty() || !get_jwk_for_kid(kid, jwk)) {
      result.error_message = "jwks_key_not_found";
      return false;
    }
    if (!verify_es256k_signature(signing_in, signature, jwk)) {
      result.error_message = "invalid_signature";
      return false;
    }
    Logger::ausf_server().info("[AUSF][Auth] Signature valid");
  } else if (alg == "HS256") {
    Logger::ausf_server().warn(
        "[AUSF][Auth] Falling back to BCF token/validate for HS256 token");
    if (!validate_hs256_via_bcf(token, result)) {
      return false;
    }
    claims        = result.claims;
    result.header = header;
  } else {
    result.error_message = "unsupported_alg";
    return false;
  }

  if (!validate_claims(
          claims, expected_audience, required_scope, bound_nf_instance_id,
          bound_nf_type, result.error_message)) {
    return false;
  }

  result.success = true;
  result.claims  = claims;
  Logger::ausf_server().info("[AUSF][Auth] Claims validated");
  return true;
}

bool BcfTokenVerifier::get_jwk_for_kid(const std::string& kid, jwk_entry_t& jwk) {
  {
    std::lock_guard<std::mutex> lock(m_mutex);
    const auto now = std::time(nullptr);
    const auto it  = m_jwk_cache.find(kid);
    if (it != m_jwk_cache.end() && (now - m_last_refresh) < kJwksCacheTtlSeconds) {
      jwk = it->second;
      return true;
    }
  }

  if (!refresh_jwks()) {
    return false;
  }

  std::lock_guard<std::mutex> lock(m_mutex);
  const auto it = m_jwk_cache.find(kid);
  if (it == m_jwk_cache.end()) {
    return false;
  }
  jwk = it->second;
  return true;
}

bool BcfTokenVerifier::refresh_jwks() {
  const auto url = build_bcf_auth_url("/jwks");
  long http_code = 0;
  std::string response_body;
  if (!send_bcf_http_request(url, "GET", "", http_code, response_body) ||
      http_code != 200) {
    Logger::ausf_server().warn(
        "[AUSF][Auth] Failed to fetch JWKS from BCF: HTTP %ld", http_code);
    return false;
  }

  try {
    const auto jwks_json = nlohmann::json::parse(response_body);
    std::map<std::string, jwk_entry_t> new_cache;
    const auto now = std::time(nullptr);
    if (jwks_json.contains("keys") && jwks_json["keys"].is_array()) {
      for (const auto& key : jwks_json["keys"]) {
        const auto kid = key.value("kid", "");
        if (kid.empty() || key.value("kty", "") != "EC" ||
            key.value("crv", "") != "secp256k1") {
          continue;
        }
        new_cache[kid] = {
            kid,
            key.value("x", ""),
            key.value("y", ""),
            now,
        };
      }
    }

    std::lock_guard<std::mutex> lock(m_mutex);
    m_jwk_cache    = std::move(new_cache);
    m_last_refresh = now;
    return !m_jwk_cache.empty();
  } catch (const std::exception& e) {
    Logger::ausf_server().warn(
        "[AUSF][Auth] Failed to parse JWKS response: %s", e.what());
    return false;
  }
}

bool BcfTokenVerifier::validate_hs256_via_bcf(
    const std::string& token, token_verification_result_t& result) {
  const auto url = build_bcf_auth_url("/token/validate");
  const auto body =
      nlohmann::json({{"access_token", token}}).dump();
  long http_code = 0;
  std::string response_body;
  if (!send_bcf_http_request(url, "POST", body, http_code, response_body) ||
      http_code != 200) {
    result.error_message = "hs256_validate_failed";
    return false;
  }

  try {
    const auto json = nlohmann::json::parse(response_body);
    if (!json.value("valid", false)) {
      result.error_message = "hs256_invalid";
      return false;
    }
    result.claims = json.value("token_claims", nlohmann::json::object());
    return true;
  } catch (const std::exception& e) {
    result.error_message = std::string("hs256_parse_error:") + e.what();
    return false;
  }
}

bool BcfTokenVerifier::validate_claims(
    const nlohmann::json& claims, const std::string& expected_audience,
    const std::string& required_scope, const std::string& bound_nf_instance_id,
    const std::string& bound_nf_type, std::string& error_message) const {
  const auto now = static_cast<long long>(std::time(nullptr));
  if (claims.value("iss", "") != kTrustedIssuer) {
    error_message = "invalid_issuer";
    return false;
  }

  const auto aud = claims.contains("aud")
                       ? json_to_string_vector(claims.at("aud"))
                       : std::vector<std::string>{};
  if (!contains_string(aud, expected_audience)) {
    error_message = "aud_mismatch";
    return false;
  }

  const auto scope = claims.contains("scope")
                         ? json_to_string_vector(claims.at("scope"))
                         : std::vector<std::string>{};
  if (!contains_string(scope, required_scope)) {
    error_message = "scope_missing";
    return false;
  }

  const auto exp = claims.value("exp", 0LL);
  if (exp <= now) {
    error_message = "token_expired";
    return false;
  }

  const auto nbf = claims.value("nbf", 0LL);
  if (nbf > now) {
    error_message = "token_not_yet_valid";
    return false;
  }

  std::string token_nf_instance_id = claims.value("sub", "");
  if (token_nf_instance_id.empty()) {
    token_nf_instance_id = claims.value("nf_instance_id", "");
  }
  if (token_nf_instance_id.empty()) {
    token_nf_instance_id = claims.value("nfInstanceId", "");
  }
  if (token_nf_instance_id != bound_nf_instance_id) {
    error_message = "sub_binding_mismatch";
    return false;
  }

  std::string token_nf_type = claims.value("nf_type", "");
  if (token_nf_type.empty()) {
    token_nf_type = claims.value("nfType", "");
  }
  if (!bound_nf_type.empty() &&
      to_upper_copy(token_nf_type) != to_upper_copy(bound_nf_type)) {
    error_message = "nf_type_binding_mismatch";
    return false;
  }

  return true;
}

bool BcfTokenVerifier::verify_es256k_signature(
    const std::string& signing_input, const std::string& signature_raw,
    const jwk_entry_t& jwk) const {
  std::string x_bytes;
  std::string y_bytes;
  if (!base64url_decode(jwk.x, x_bytes) ||
      !base64url_decode(jwk.y, y_bytes) || signature_raw.size() != 64 ||
      x_bytes.empty() || y_bytes.empty()) {
    return false;
  }

  unsigned char digest[SHA256_DIGEST_LENGTH];
  SHA256(
      reinterpret_cast<const unsigned char*>(signing_input.data()),
      signing_input.size(), digest);

  bool verified = false;
  EC_KEY* ec_key = nullptr;
  EC_POINT* point = nullptr;
  BIGNUM* x = nullptr;
  BIGNUM* y = nullptr;
  BIGNUM* r = nullptr;
  BIGNUM* s = nullptr;
  ECDSA_SIG* signature = nullptr;

  ec_key = EC_KEY_new_by_curve_name(NID_secp256k1);
  if (!ec_key) goto cleanup;

  point = EC_POINT_new(EC_KEY_get0_group(ec_key));
  if (!point) goto cleanup;

  x = BN_bin2bn(
      reinterpret_cast<const unsigned char*>(x_bytes.data()), x_bytes.size(),
      nullptr);
  y = BN_bin2bn(
      reinterpret_cast<const unsigned char*>(y_bytes.data()), y_bytes.size(),
      nullptr);
  if (!x || !y) goto cleanup;

  if (EC_POINT_set_affine_coordinates_GFp(
          EC_KEY_get0_group(ec_key), point, x, y, nullptr) != 1) {
    goto cleanup;
  }

  if (EC_KEY_set_public_key(ec_key, point) != 1) goto cleanup;

  signature = ECDSA_SIG_new();
  if (!signature) goto cleanup;

  r = BN_bin2bn(
      reinterpret_cast<const unsigned char*>(signature_raw.data()), 32, nullptr);
  s = BN_bin2bn(
      reinterpret_cast<const unsigned char*>(signature_raw.data()) + 32, 32,
      nullptr);
  if (!r || !s) goto cleanup;

  if (ECDSA_SIG_set0(signature, r, s) != 1) goto cleanup;
  r = nullptr;
  s = nullptr;

  verified = (ECDSA_do_verify(digest, SHA256_DIGEST_LENGTH, signature, ec_key) ==
              1);

cleanup:
  BN_free(r);
  BN_free(s);
  ECDSA_SIG_free(signature);
  EC_POINT_free(point);
  BN_free(x);
  BN_free(y);
  EC_KEY_free(ec_key);
  return verified;
}

}  // namespace oai::ausf::did_auth
