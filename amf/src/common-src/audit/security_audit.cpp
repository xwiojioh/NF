#include "security_audit.hpp"

#include <openssl/sha.h>

#include <algorithm>
#include <chrono>
#include <cctype>
#include <fstream>
#include <iomanip>
#include <random>
#include <sstream>
#include <utility>

namespace oai::common::audit {
namespace {

thread_local audit_request_context thread_audit_context;

std::string to_upper_copy(std::string value) {
  std::transform(value.begin(), value.end(), value.begin(), [](unsigned char c) {
    return static_cast<char>(std::toupper(c));
  });
  return value;
}

}  // namespace

bool audit_request_context::empty() const {
  return session_id.empty() && interaction_id.empty() && subject_did.empty() &&
         peer_did.empty() && subject_nf_type.empty() && peer_nf_type.empty();
}

void set_thread_audit_context(const audit_request_context& context) {
  thread_audit_context = context;
}

audit_request_context get_thread_audit_context() {
  return thread_audit_context;
}

void clear_thread_audit_context() {
  thread_audit_context = {};
}

nlohmann::json security_audit_summary::to_session_digest_json() const {
  nlohmann::json body = {
      {"session_id", session_id},
      {"interaction_id", interaction_id},
      {"subject_did", local_DID},
      {"peer_did", peer_DID},
      {"subject_nf_type", local_type},
      {"peer_nf_type", peer_type},
      {"digest_hash", hash},
      {"prev_digest_hash", prev_summary_hash},
      {"event_count", event_count},
      {"summary_seq", summary_seq},
      {"stage", stage},
      {"summary_type", summary_type},
      {"related_tx_hashes", related_tx_hashes},
      {"timestamp", timestamp},
      {"token_fingerprint", token_fingerprint},
  };
  return body;
}

security_audit::security_audit(
    std::string component, std::string local_type, std::string nf_instance_id,
    std::string audit_file_path)
    : m_component(std::move(component)),
      m_local_type(to_upper_copy(std::move(local_type))),
      m_nf_instance_id(std::move(nf_instance_id)),
      m_audit_file_path(std::move(audit_file_path)),
      m_rolling_hash(sha256_hex("")) {
  if (m_audit_file_path.empty()) {
    m_audit_file_path = "/tmp/oai-" + m_component + "-audit-events.jsonl";
    std::transform(
        m_audit_file_path.begin(), m_audit_file_path.end(),
        m_audit_file_path.begin(), [](unsigned char c) {
          return static_cast<char>(std::tolower(c));
        });
  }
  rebuild_session_id_locked();
}

void security_audit::set_identity(
    const std::string& local_did, const std::string& local_type,
    const std::string& nf_instance_id) {
  std::lock_guard<std::mutex> lock(m_mutex);
  m_local_did       = local_did;
  m_local_type      = to_upper_copy(local_type);
  m_nf_instance_id  = nf_instance_id;
  rebuild_session_id_locked();
}

void security_audit::set_summary_submit_callback(
    summary_submit_callback callback) {
  std::lock_guard<std::mutex> lock(m_mutex);
  m_submit_callback = std::move(callback);
}

void security_audit::set_token_fingerprint_callback(
    token_fingerprint_callback callback) {
  std::lock_guard<std::mutex> lock(m_mutex);
  m_token_fingerprint_callback = std::move(callback);
}

const std::string& security_audit::session_id() const {
  return m_session_id;
}

const std::string& security_audit::local_did() const {
  return m_local_did;
}

const std::string& security_audit::local_type() const {
  return m_local_type;
}

std::string security_audit::make_interaction_id() const {
  std::string did_part;
  {
    std::lock_guard<std::mutex> lock(m_mutex);
    did_part = short_did(m_local_did.empty() ? m_nf_instance_id : m_local_did);
  }
  if (did_part.empty()) {
    did_part = "nf";
  }

  std::random_device rd;
  std::uniform_int_distribution<unsigned int> dist(0, 0xffffffffU);
  std::ostringstream random_hex;
  random_hex << std::hex << std::setw(8) << std::setfill('0') << dist(rd);

  return "interaction:" + sanitize_interaction_part(did_part) + ":" +
         std::to_string(now_ms()) + ":" + random_hex.str();
}

bool security_audit::record_event(
    const std::string& event_type, const std::string& phase,
    const std::string& result, const std::string& interaction_id,
    const std::string& peer_did, const std::string& peer_type,
    const nlohmann::json& metadata, const std::string& token_fingerprint) {
  std::lock_guard<std::mutex> lock(m_mutex);

  const std::uint64_t event_seq = ++m_event_seq;
  const std::uint64_t ts        = now_ms();
  const std::string normalized_peer_type = to_upper_copy(peer_type);
  const std::string effective_token_fingerprint =
      token_fingerprint.empty() ? next_token_fingerprint() : token_fingerprint;

  if (!interaction_id.empty()) {
    m_last_interaction_id = interaction_id;
  }
  if (!peer_did.empty()) {
    m_last_peer_did = peer_did;
  }
  if (!normalized_peer_type.empty()) {
    m_last_peer_type = normalized_peer_type;
  }

  nlohmann::json canonical = {
      {"event_seq", event_seq},
      {"session_id", m_session_id},
      {"interaction_id", interaction_id},
      {"timestamp", ts},
      {"event_type", event_type},
      {"phase", phase},
      {"result", result},
      {"local_DID", m_local_did},
      {"peer_DID", peer_did},
      {"local_type", m_local_type},
      {"peer_type", normalized_peer_type},
      {"request_scope_id", interaction_id},
      {"token_fingerprint", effective_token_fingerprint},
      {"metadata", metadata.is_null() ? nlohmann::json::object() : metadata},
  };

  const std::string canonical_json = canonical_dump(canonical);
  m_rolling_hash                   = sha256_hex(m_rolling_hash + canonical_json);

  nlohmann::json log_line = canonical;
  log_line["canonical_json"] = canonical_json;
  log_line["rolling_hash"]   = m_rolling_hash;

  std::ofstream output(m_audit_file_path, std::ios::app);
  if (!output.is_open()) {
    return false;
  }
  output << log_line.dump() << '\n';
  return true;
}

bool security_audit::checkpoint(
    const std::string& stage, const std::string& interaction_id,
    const std::string& peer_did, const std::string& peer_type,
    const std::string& summary_type,
    const std::vector<std::string>& related_tx_hashes) {
  security_audit_summary summary;
  summary_submit_callback callback;

  {
    std::lock_guard<std::mutex> lock(m_mutex);
    const std::string effective_interaction_id =
        interaction_id.empty() ? m_last_interaction_id : interaction_id;
    const std::string effective_peer_did =
        peer_did.empty() ? m_last_peer_did : peer_did;
    const std::string effective_peer_type =
        peer_type.empty() ? m_last_peer_type : to_upper_copy(peer_type);

    summary.session_id        = m_session_id;
    summary.interaction_id    = effective_interaction_id;
    summary.local_DID         = m_local_did;
    summary.peer_DID          = effective_peer_did;
    summary.local_type        = m_local_type;
    summary.peer_type         = effective_peer_type;
    summary.prev_summary_hash = m_prev_summary_hash;
    summary.event_count       = m_event_seq;
    summary.summary_seq       = ++m_summary_seq;
    summary.stage             = stage;
    summary.summary_type      = summary_type.empty() ? "checkpoint" : summary_type;
    summary.related_tx_hashes = related_tx_hashes;
    summary.timestamp         = now_ms();
    summary.token_fingerprint = next_token_fingerprint();

    nlohmann::json metadata = {
        {"session_id", summary.session_id},
        {"interaction_id", summary.interaction_id},
        {"subject_did", summary.local_DID},
        {"peer_did", summary.peer_DID},
        {"subject_nf_type", summary.local_type},
        {"peer_nf_type", summary.peer_type},
        {"prev_digest_hash", summary.prev_summary_hash},
        {"event_count", summary.event_count},
        {"summary_seq", summary.summary_seq},
        {"stage", summary.stage},
        {"summary_type", summary.summary_type},
        {"rolling_hash", m_rolling_hash},
        {"token_fingerprint", summary.token_fingerprint},
        {"related_tx_hashes", summary.related_tx_hashes},
      };
    summary.hash        = sha256_hex(m_rolling_hash + canonical_dump(metadata));
    m_prev_summary_hash = summary.hash;
    callback            = m_submit_callback;
  }

  if (!callback) {
    return false;
  }

  std::string response_body;
  std::uint32_t response_code = 0;
  return callback(summary, response_body, response_code);
}

bool security_audit::finalize_all(const std::string& stage) {
  return checkpoint(stage, "", "", "", "final");
}

std::string security_audit::fingerprint_token(const std::string& token) {
  if (token.empty()) {
    return "";
  }
  return sha256_hex(token).substr(0, 16);
}

std::uint64_t security_audit::now_ms() {
  using namespace std::chrono;
  return static_cast<std::uint64_t>(
      duration_cast<milliseconds>(system_clock::now().time_since_epoch()).count());
}

std::string security_audit::sha256_hex(const std::string& input) {
  unsigned char hash[SHA256_DIGEST_LENGTH];
  SHA256(
      reinterpret_cast<const unsigned char*>(input.data()), input.size(), hash);

  std::ostringstream oss;
  for (unsigned char byte : hash) {
    oss << std::hex << std::setw(2) << std::setfill('0')
        << static_cast<int>(byte);
  }
  return oss.str();
}

std::string security_audit::short_did(const std::string& did) {
  if (did.empty()) {
    return "";
  }
  const auto pos = did.find_last_of(':');
  std::string tail = (pos == std::string::npos) ? did : did.substr(pos + 1);
  tail             = sanitize_interaction_part(tail);
  if (tail.size() > 12) {
    return tail.substr(tail.size() - 12);
  }
  return tail;
}

std::string security_audit::sanitize_interaction_part(
    const std::string& value) {
  std::string result;
  result.reserve(value.size());
  for (unsigned char c : value) {
    if (std::isalnum(c)) {
      result.push_back(static_cast<char>(std::tolower(c)));
    }
  }
  return result;
}

std::string security_audit::canonical_dump(const nlohmann::json& value) {
  return value.dump();
}

std::string security_audit::next_token_fingerprint() const {
  if (!m_token_fingerprint_callback) {
    return "";
  }
  return m_token_fingerprint_callback();
}

void security_audit::rebuild_session_id_locked() {
  const std::string anchor = m_nf_instance_id.empty() ? "unknown" : m_nf_instance_id;
  m_session_id = "lifecycle:" + m_local_type + ":" + anchor;
}

}  // namespace oai::common::audit
