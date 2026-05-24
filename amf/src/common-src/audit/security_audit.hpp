#pragma once

#include <cstdint>
#include <functional>
#include <mutex>
#include <string>
#include <vector>

#include <nlohmann/json.hpp>

namespace oai::common::audit {

struct audit_request_context {
  std::string session_id;
  std::string interaction_id;
  std::string subject_did;
  std::string peer_did;
  std::string subject_nf_type;
  std::string peer_nf_type;

  bool empty() const;
};

void set_thread_audit_context(const audit_request_context& context);
audit_request_context get_thread_audit_context();
void clear_thread_audit_context();

struct security_audit_summary {
  std::string session_id;
  std::string interaction_id;
  std::string local_DID;
  std::string peer_DID;
  std::string local_type;
  std::string peer_type;
  std::string hash;
  std::string prev_summary_hash;
  std::uint64_t event_count = 0;
  std::uint64_t summary_seq = 0;
  std::string stage;
  std::string summary_type;
  std::vector<std::string> related_tx_hashes;
  std::uint64_t timestamp = 0;
  std::string token_fingerprint;

  nlohmann::json to_session_digest_json() const;
};

class security_audit {
 public:
  using summary_submit_callback = std::function<bool(
      const security_audit_summary& summary, std::string& response_body,
      std::uint32_t& response_code)>;
  using token_fingerprint_callback = std::function<std::string()>;

  security_audit(
      std::string component, std::string local_type,
      std::string nf_instance_id, std::string audit_file_path = "");

  void set_identity(
      const std::string& local_did, const std::string& local_type,
      const std::string& nf_instance_id);
  void set_summary_submit_callback(summary_submit_callback callback);
  void set_token_fingerprint_callback(token_fingerprint_callback callback);

  const std::string& session_id() const;
  const std::string& local_did() const;
  const std::string& local_type() const;

  std::string make_interaction_id() const;

  bool record_event(
      const std::string& event_type, const std::string& phase,
      const std::string& result, const std::string& interaction_id = "",
      const std::string& peer_did = "", const std::string& peer_type = "",
      const nlohmann::json& metadata = nlohmann::json::object(),
      const std::string& token_fingerprint = "");

  bool checkpoint(
      const std::string& stage, const std::string& interaction_id = "",
      const std::string& peer_did = "", const std::string& peer_type = "",
      const std::string& summary_type = "checkpoint",
      const std::vector<std::string>& related_tx_hashes = {});

  bool finalize_all(const std::string& stage = "final");

  static std::string fingerprint_token(const std::string& token);

 private:
  static std::uint64_t now_ms();
  static std::string sha256_hex(const std::string& input);
  static std::string short_did(const std::string& did);
  static std::string sanitize_interaction_part(const std::string& value);
  static std::string canonical_dump(const nlohmann::json& value);

  std::string next_token_fingerprint() const;
  void rebuild_session_id_locked();

  mutable std::mutex m_mutex;
  std::string m_component;
  std::string m_local_type;
  std::string m_nf_instance_id;
  std::string m_local_did;
  std::string m_session_id;
  std::string m_audit_file_path;
  std::string m_rolling_hash;
  std::string m_prev_summary_hash;
  std::uint64_t m_event_seq = 0;
  std::uint64_t m_summary_seq = 0;
  std::string m_last_interaction_id;
  std::string m_last_peer_did;
  std::string m_last_peer_type;
  summary_submit_callback m_submit_callback;
  token_fingerprint_callback m_token_fingerprint_callback;
};

}  // namespace oai::common::audit
