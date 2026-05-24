#ifndef FILE_AUSF_TOKEN_AUTH_SEEN
#define FILE_AUSF_TOKEN_AUTH_SEEN

#if AUSF_ENABLE_HTTP2
#include <nghttp2/asio_http2_server.h>
#endif
#include <pistache/router.h>

#include <nlohmann/json.hpp>

namespace oai::ausf::auth {

enum class token_error_cause_t {
  NONE = 0,
  MISSING_TOKEN,
  MALFORMED_TOKEN,
  INVALID_SIGNATURE,
  EXPIRED_TOKEN,
  INVALID_AUDIENCE,
  INSUFFICIENT_SCOPE,
  INVALID_ISSUER,
  INVALID_BINDING,
  INVALID_AMF_PROFILE,
  VALIDATOR_UNAVAILABLE,
};

struct token_validation_result_t {
  bool success                               = false;
  Pistache::Http::Code http_status           = Pistache::Http::Code::Unauthorized;
  token_error_cause_t cause                  = token_error_cause_t::NONE;
  std::string detail                         = {};
  nlohmann::json claims                      = nlohmann::json::object();
  nlohmann::json error_body                  = nlohmann::json::object();
};

#if AUSF_ENABLE_HTTP2
std::string get_authorization_header(
    const nghttp2::asio_http2::header_map& request_headers);
#endif
std::string get_authorization_header(
    const Pistache::Rest::Request& request);

bool extract_bearer_token_from_header(
    const std::string& authorization_header, std::string& bearer_token,
    token_validation_result_t& result);

bool verify_access_token(
    const std::string& token, const nlohmann::json& request_payload,
    token_validation_result_t& result);

bool validate_token_claims_for_ausf(
    const nlohmann::json& claims, const nlohmann::json& request_payload,
    token_validation_result_t& result);

nlohmann::json build_token_error_response(
    Pistache::Http::Code status, const std::string& detail);

#if AUSF_ENABLE_HTTP2
bool authorize_ue_authentication_request(
    const nlohmann::json& request_payload,
    const nghttp2::asio_http2::header_map& request_headers,
    token_validation_result_t& result);
#endif

bool authorize_ue_authentication_request(
    const nlohmann::json& request_payload,
    const Pistache::Rest::Request& request, token_validation_result_t& result);

}  // namespace oai::ausf::auth

#endif
