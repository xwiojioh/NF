#include "ausf_token_auth.hpp"

#include <algorithm>
#include <cctype>
#include <cstring>
#include <set>
#include <sstream>
#include <string>
#include <vector>

#include <boost/algorithm/string/predicate.hpp>

#include "did_auth/bcf_token_verifier.hpp"
#include "logger.hpp"

namespace oai::ausf::auth {

namespace {

using oai::ausf::did_auth::BcfTokenVerifier;
using oai::ausf::did_auth::token_verification_result_t;

BcfTokenVerifier& get_bcf_token_verifier() {
  static BcfTokenVerifier verifier;
  return verifier;
}

std::string trim_copy(const std::string& value) {
  const auto begin = value.find_first_not_of(" \t\r\n");
  if (begin == std::string::npos) {
    return {};
  }
  const auto end = value.find_last_not_of(" \t\r\n");
  return value.substr(begin, end - begin + 1);
}

std::string json_string_value(
    const nlohmann::json& json_data, const std::string& key) {
  if (json_data.contains(key) && json_data[key].is_string()) {
    return json_data[key].get<std::string>();
  }
  return {};
}

std::string get_expected_nf_instance_id(const nlohmann::json& amf_profile) {
  auto value = json_string_value(amf_profile, "nfInstanceId");
  if (value.empty()) {
    value = json_string_value(amf_profile, "nf_instance_id");
  }
  return value;
}

std::string get_expected_nf_type(const nlohmann::json& amf_profile) {
  auto value = json_string_value(amf_profile, "nfType");
  if (value.empty()) {
    value = json_string_value(amf_profile, "nf_type");
  }
  return value;
}

std::string normalize_plmn_entry(const nlohmann::json& plmn_json) {
  if (plmn_json.is_string()) {
    return trim_copy(plmn_json.get<std::string>());
  }

  if (!plmn_json.is_object()) {
    return {};
  }

  const auto& normalized =
      plmn_json.contains("plmnId") && plmn_json["plmnId"].is_object()
          ? plmn_json["plmnId"]
          : plmn_json;

  const auto mcc = json_string_value(normalized, "mcc");
  const auto mnc = json_string_value(normalized, "mnc");
  if (mcc.empty() || mnc.empty()) {
    return {};
  }

  return mcc + "-" + mnc;
}

std::set<std::string> collect_plmns(const nlohmann::json& value) {
  std::set<std::string> plmns = {};

  if (value.is_array()) {
    for (const auto& entry : value) {
      const auto normalized = normalize_plmn_entry(entry);
      if (!normalized.empty()) {
        plmns.insert(normalized);
      }
    }
    return plmns;
  }

  const auto normalized = normalize_plmn_entry(value);
  if (!normalized.empty()) {
    plmns.insert(normalized);
  }
  return plmns;
}

std::set<std::string> collect_claim_plmns(const nlohmann::json& claims) {
  if (claims.contains("plmnList")) {
    return collect_plmns(claims["plmnList"]);
  }
  if (claims.contains("plmn_list")) {
    return collect_plmns(claims["plmn_list"]);
  }
  if (claims.contains("plmn")) {
    return collect_plmns(claims["plmn"]);
  }
  return {};
}

std::set<std::string> collect_profile_plmns(const nlohmann::json& amf_profile) {
  if (amf_profile.contains("plmnList")) {
    return collect_plmns(amf_profile["plmnList"]);
  }
  if (amf_profile.contains("plmn_list")) {
    return collect_plmns(amf_profile["plmn_list"]);
  }
  return {};
}

const nlohmann::json* get_request_amf_profile(
    const nlohmann::json& request_payload) {
  if (!request_payload.is_object()) {
    return nullptr;
  }

  const auto amf_profile_it = request_payload.find("amfProfile");
  if (amf_profile_it == request_payload.end() || !amf_profile_it->is_object()) {
    return nullptr;
  }

  return &(*amf_profile_it);
}

bool map_verifier_error(
    const token_verification_result_t& verify_result,
    token_validation_result_t& result) {
  const auto& error = verify_result.error_message;

  if (error == "invalid_jwt") {
    Logger::ausf_server().warn(
        "[AUSF][Token Check] token parse fail: malformed JWT");
    result.http_status = Pistache::Http::Code::Unauthorized;
    result.cause       = token_error_cause_t::MALFORMED_TOKEN;
    result.detail      = "Malformed Bearer token";
  } else if (
      error == "invalid_signature" || error == "jwks_key_not_found" ||
      error == "hs256_invalid" || error == "hs256_validate_failed") {
    Logger::ausf_server().warn(
        "[AUSF][Token Check] signature invalid");
    result.http_status = Pistache::Http::Code::Unauthorized;
    result.cause       = token_error_cause_t::INVALID_SIGNATURE;
    result.detail      = "Invalid token signature";
  } else if (error == "token_expired") {
    Logger::ausf_server().warn(
        "[AUSF][Token Check] token expired");
    result.http_status = Pistache::Http::Code::Unauthorized;
    result.cause       = token_error_cause_t::EXPIRED_TOKEN;
    result.detail      = "Access token expired";
  } else if (error == "aud_mismatch") {
    Logger::ausf_server().warn(
        "[AUSF][Token Check] aud invalid");
    result.http_status = Pistache::Http::Code::Forbidden;
    result.cause       = token_error_cause_t::INVALID_AUDIENCE;
    result.detail      = "Invalid audience for AUSF access";
  } else if (error == "scope_missing") {
    Logger::ausf_server().warn(
        "[AUSF][Token Check] scope invalid");
    result.http_status = Pistache::Http::Code::Forbidden;
    result.cause       = token_error_cause_t::INSUFFICIENT_SCOPE;
    result.detail      = "Insufficient scope for AUSF access";
  } else if (error == "invalid_issuer") {
    Logger::ausf_server().warn(
        "[AUSF][Token Check] issuer invalid");
    result.http_status = Pistache::Http::Code::Unauthorized;
    result.cause       = token_error_cause_t::INVALID_ISSUER;
    result.detail      = "Invalid token issuer";
  } else if (
      error == "sub_binding_mismatch" ||
      error == "nf_type_binding_mismatch") {
    Logger::ausf_server().warn(
        "[AUSF][Token Check] token claims do not match AMF profile");
    result.http_status = Pistache::Http::Code::Forbidden;
    result.cause       = token_error_cause_t::INVALID_BINDING;
    result.detail      = "Token claims do not match AMF profile";
  } else if (error == "token_not_yet_valid") {
    Logger::ausf_server().warn(
        "[AUSF][Token Check] token not yet valid");
    result.http_status = Pistache::Http::Code::Unauthorized;
    result.cause       = token_error_cause_t::MALFORMED_TOKEN;
    result.detail      = "Access token not yet valid";
  } else if (error == "unsupported_alg") {
    Logger::ausf_server().warn(
        "[AUSF][Token Check] token parse fail: unsupported algorithm");
    result.http_status = Pistache::Http::Code::Unauthorized;
    result.cause       = token_error_cause_t::MALFORMED_TOKEN;
    result.detail      = "Malformed Bearer token";
  } else {
    Logger::ausf_server().warn(
        "[AUSF][Token Check] verification failed: %s", error.c_str());
    result.http_status = Pistache::Http::Code::Unauthorized;
    result.cause       = token_error_cause_t::INVALID_SIGNATURE;
    result.detail      = "Access token verification failed";
  }

  result.error_body = build_token_error_response(result.http_status, result.detail);
  return false;
}

bool authorize_with_header_value(
    const nlohmann::json& request_payload,
    const std::string& authorization_header, token_validation_result_t& result) {
  std::string bearer_token = {};
  if (!extract_bearer_token_from_header(
          authorization_header, bearer_token, result)) {
    return false;
  }

  if (!verify_access_token(bearer_token, request_payload, result)) {
    return false;
  }

  Logger::ausf_server().info(
      "[AUSF][Token Check] Token verification passed, continue UE authentication");
  return true;
}

}  // namespace

#if AUSF_ENABLE_HTTP2
std::string get_authorization_header(
    const nghttp2::asio_http2::header_map& request_headers) {
  for (const auto& entry : request_headers) {
    if (boost::iequals(entry.first, "authorization")) {
      return entry.second.value;
    }
  }
  return {};
}
#endif

std::string get_authorization_header(const Pistache::Rest::Request& request) {
  for (const auto& entry : request.headers().rawList()) {
    if (boost::iequals(entry.first, "authorization")) {
      return entry.second.value();
    }
  }
  return {};
}

bool extract_bearer_token_from_header(
    const std::string& authorization_header, std::string& bearer_token,
    token_validation_result_t& result) {
  result = {};

  if (authorization_header.empty()) {
    Logger::ausf_server().warn(
        "[AUSF][Token Check] Authorization header missing");
    result.http_status = Pistache::Http::Code::Unauthorized;
    result.cause       = token_error_cause_t::MISSING_TOKEN;
    result.detail      = "Missing Bearer token";
    result.error_body  = build_token_error_response(result.http_status, result.detail);
    return false;
  }

  Logger::ausf_server().info(
      "[AUSF][Token Check] Authorization header received");

  constexpr const char* bearer_prefix = "Bearer ";
  if (authorization_header.size() <= std::strlen(bearer_prefix) ||
      !boost::istarts_with(authorization_header, bearer_prefix)) {
    Logger::ausf_server().warn(
        "[AUSF][Token Check] Authorization header is not Bearer format");
    result.http_status = Pistache::Http::Code::Unauthorized;
    result.cause       = token_error_cause_t::MALFORMED_TOKEN;
    result.detail      = "Malformed Bearer token";
    result.error_body  = build_token_error_response(result.http_status, result.detail);
    return false;
  }

  bearer_token =
      trim_copy(authorization_header.substr(std::strlen(bearer_prefix)));
  if (bearer_token.empty()) {
    Logger::ausf_server().warn(
        "[AUSF][Token Check] Empty Bearer token received");
    result.http_status = Pistache::Http::Code::Unauthorized;
    result.cause       = token_error_cause_t::MALFORMED_TOKEN;
    result.detail      = "Malformed Bearer token";
    result.error_body  = build_token_error_response(result.http_status, result.detail);
    return false;
  }

  Logger::ausf_server().info(
      "[AUSF][Token Check] Bearer token extracted successfully");
  return true;
}

bool verify_access_token(
    const std::string& token, const nlohmann::json& request_payload,
    token_validation_result_t& result) {
  const auto* amf_profile = get_request_amf_profile(request_payload);
  if (!amf_profile) {
    Logger::ausf_server().warn(
        "[AUSF][Token Check] Request amfProfile missing or invalid");
    result.http_status = Pistache::Http::Code::Bad_Request;
    result.cause       = token_error_cause_t::INVALID_AMF_PROFILE;
    result.detail      = "Missing or invalid amfProfile in authentication request";
    result.error_body  = build_token_error_response(result.http_status, result.detail);
    return false;
  }

  const auto nf_instance_id = get_expected_nf_instance_id(*amf_profile);
  const auto nf_type        = get_expected_nf_type(*amf_profile);

  if (nf_instance_id.empty() || nf_type.empty()) {
    Logger::ausf_server().warn(
        "[AUSF][Token Check] Request amfProfile missing nfInstanceId or nfType");
    result.http_status = Pistache::Http::Code::Bad_Request;
    result.cause       = token_error_cause_t::INVALID_AMF_PROFILE;
    result.detail =
        "amfProfile must include nfInstanceId and nfType";
    result.error_body = build_token_error_response(result.http_status, result.detail);
    return false;
  }

  Logger::ausf_server().info(
      "[AUSF][Token Check] Verifying token signature and claims");

  token_verification_result_t verify_result = {};
  const auto verified = get_bcf_token_verifier().verify_request_token(
      token, "AUSF", "nausf-auth:ue-authentications", nf_instance_id,
      nf_type, verify_result);

  result.claims = verify_result.claims;

  if (!verified) {
    if (verify_result.error_message != "invalid_jwt") {
      Logger::ausf_server().info(
          "[AUSF][Token Check] token parse success");
    }
    return map_verifier_error(verify_result, result);
  }

  Logger::ausf_server().info("[AUSF][Token Check] token parse success");
  Logger::ausf_server().info("[AUSF][Token Check] signature valid");

  return validate_token_claims_for_ausf(
      verify_result.claims, request_payload, result);
}

bool validate_token_claims_for_ausf(
    const nlohmann::json& claims, const nlohmann::json& request_payload,
    token_validation_result_t& result) {
  const auto* amf_profile = get_request_amf_profile(request_payload);
  if (!amf_profile) {
    result.http_status = Pistache::Http::Code::Bad_Request;
    result.cause       = token_error_cause_t::INVALID_AMF_PROFILE;
    result.detail      = "Missing or invalid amfProfile in authentication request";
    result.error_body  = build_token_error_response(result.http_status, result.detail);
    return false;
  }

  const auto profile_plmns = collect_profile_plmns(*amf_profile);
  const auto claim_plmns   = collect_claim_plmns(claims);

  if (!claim_plmns.empty()) {
    if (profile_plmns.empty()) {
      Logger::ausf_server().warn(
          "[AUSF][Token Check] token PLMN claim present but request profile has no PLMN");
      result.http_status = Pistache::Http::Code::Forbidden;
      result.cause       = token_error_cause_t::INVALID_BINDING;
      result.detail      = "Token claims do not match AMF profile";
      result.error_body  = build_token_error_response(result.http_status, result.detail);
      return false;
    }

    for (const auto& claim_plmn : claim_plmns) {
      if (!profile_plmns.count(claim_plmn)) {
        Logger::ausf_server().warn(
            "[AUSF][Token Check] PLMN claim mismatch: %s",
            claim_plmn.c_str());
        result.http_status = Pistache::Http::Code::Forbidden;
        result.cause       = token_error_cause_t::INVALID_BINDING;
        result.detail      = "Token claims do not match AMF profile";
        result.error_body  = build_token_error_response(result.http_status, result.detail);
        return false;
      }
    }
  }

  result.success    = true;
  result.http_status = Pistache::Http::Code::Ok;
  result.cause      = token_error_cause_t::NONE;
  result.detail     = {};
  result.error_body = nlohmann::json::object();
  return true;
}

nlohmann::json build_token_error_response(
    Pistache::Http::Code status, const std::string& detail) {
  const auto status_code = static_cast<int>(status);
  const auto title =
      status == Pistache::Http::Code::Forbidden ? "Forbidden" :
      status == Pistache::Http::Code::Bad_Request ? "Bad Request" :
      status == Pistache::Http::Code::Service_Unavailable ? "Service Unavailable" :
      "Unauthorized";

  return {
      {"title", title},
      {"status", status_code},
      {"detail", detail},
  };
}

#if AUSF_ENABLE_HTTP2
bool authorize_ue_authentication_request(
    const nlohmann::json& request_payload,
    const nghttp2::asio_http2::header_map& request_headers,
    token_validation_result_t& result) {
  return authorize_with_header_value(
      request_payload, get_authorization_header(request_headers), result);
}
#endif

bool authorize_ue_authentication_request(
    const nlohmann::json& request_payload,
    const Pistache::Rest::Request& request, token_validation_result_t& result) {
  return authorize_with_header_value(
      request_payload, get_authorization_header(request), result);
}

}  // namespace oai::ausf::auth
