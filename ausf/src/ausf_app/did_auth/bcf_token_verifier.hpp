#ifndef _AUSF_BCF_TOKEN_VERIFIER_HPP_
#define _AUSF_BCF_TOKEN_VERIFIER_HPP_

#include <ctime>
#include <map>
#include <mutex>
#include <string>

#include <nlohmann/json.hpp>

namespace oai::ausf::did_auth {

struct token_verification_result_t {
  bool success = false;
  std::string error_message;
  nlohmann::json header = {};
  nlohmann::json claims = {};
};

class BcfTokenVerifier {
 public:
  BcfTokenVerifier() = default;
  ~BcfTokenVerifier() = default;

  bool verify_request_token(
      const std::string& token, const std::string& expected_audience,
      const std::string& required_scope,
      const std::string& bound_nf_instance_id,
      const std::string& bound_nf_type,
      token_verification_result_t& result);

 private:
  struct jwk_entry_t {
    std::string kid;
    std::string x;
    std::string y;
    std::time_t fetched_at = 0;
  };

  bool get_jwk_for_kid(const std::string& kid, jwk_entry_t& jwk);
  bool refresh_jwks();
  bool validate_hs256_via_bcf(
      const std::string& token, token_verification_result_t& result);
  bool validate_claims(
      const nlohmann::json& claims, const std::string& expected_audience,
      const std::string& required_scope,
      const std::string& bound_nf_instance_id,
      const std::string& bound_nf_type, std::string& error_message) const;
  bool verify_es256k_signature(
      const std::string& signing_input, const std::string& signature_raw,
      const jwk_entry_t& jwk) const;

  std::map<std::string, jwk_entry_t> m_jwk_cache;
  std::time_t m_last_refresh = 0;
  mutable std::mutex m_mutex;
};

}  // namespace oai::ausf::did_auth

#endif  // _AUSF_BCF_TOKEN_VERIFIER_HPP_
