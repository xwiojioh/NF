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

#include "did_session_manager.hpp"
#include "did_crypto.hpp"

#include <algorithm>
#include <iomanip>
#include <random>
#include <sstream>

namespace oai::amf::did_auth {

//------------------------------------------------------------------------------
did_session_manager::did_session_manager(
    uint64_t session_timeout_sec, uint64_t token_validity_sec)
    : m_session_timeout_sec(session_timeout_sec),
      m_token_validity_sec(token_validity_sec) {}

//------------------------------------------------------------------------------
did_session_manager::~did_session_manager() {}

//------------------------------------------------------------------------------
std::string did_session_manager::generate_session_id() {
  // Generate UUID v4 style session ID
  std::vector<uint8_t> random_bytes = did_crypto::generate_random(16);

  // Set version (4) and variant bits according to RFC 4122
  random_bytes[6] = (random_bytes[6] & 0x0F) | 0x40;  // Version 4
  random_bytes[8] = (random_bytes[8] & 0x3F) | 0x80;  // Variant 1

  // Format as UUID string
  std::stringstream ss;
  ss << std::hex;
  for (size_t i = 0; i < 16; ++i) {
    if (i == 4 || i == 6 || i == 8 || i == 10) {
      ss << "-";
    }
    ss << std::setw(2) << std::setfill('0') << (int) random_bytes[i];
  }

  return "auth-" + ss.str();
}

//------------------------------------------------------------------------------
std::string did_session_manager::generate_secure_token() {
  // Generate 32 bytes of random data for the token
  std::vector<uint8_t> random_bytes = did_crypto::generate_random(32);
  return did_crypto::to_hex(random_bytes);
}

//------------------------------------------------------------------------------
std::string did_session_manager::create_session(
    const std::string& local_did, const std::string& local_nf_type,
    const std::string& local_nf_instance_id, bool is_initiator) {
  std::unique_lock<std::shared_mutex> lock(m_mutex);

  auto session                 = std::make_shared<auth_session_t>();
  session->session_id          = generate_session_id();
  session->local_did           = local_did;
  session->local_nf_type       = local_nf_type;
  session->local_nf_instance_id = local_nf_instance_id;
  session->is_initiator        = is_initiator;
  session->state               = AuthState::AUTH_PENDING;
  session->created_time        = std::chrono::steady_clock::now();
  session->last_activity       = session->created_time;
  session->created_at          = static_cast<uint64_t>(
      std::chrono::duration_cast<std::chrono::seconds>(
          std::chrono::system_clock::now().time_since_epoch())
          .count());

  m_sessions[session->session_id] = session;

  return session->session_id;
}

//------------------------------------------------------------------------------
bool did_session_manager::create_session_with_id(
    const std::string& session_id, const std::string& local_did,
    const std::string& local_nf_type, const std::string& local_nf_instance_id,
    bool is_initiator) {
  std::unique_lock<std::shared_mutex> lock(m_mutex);

  // Check if session_id already exists
  if (m_sessions.find(session_id) != m_sessions.end()) {
    return false;
  }

  auto session                  = std::make_shared<auth_session_t>();
  session->session_id           = session_id;  // Use provided session_id
  session->local_did            = local_did;
  session->local_nf_type        = local_nf_type;
  session->local_nf_instance_id = local_nf_instance_id;
  session->is_initiator         = is_initiator;
  session->state                = AuthState::AUTH_PENDING;
  session->created_time         = std::chrono::steady_clock::now();
  session->last_activity        = session->created_time;
  session->created_at           = static_cast<uint64_t>(
      std::chrono::duration_cast<std::chrono::seconds>(
          std::chrono::system_clock::now().time_since_epoch())
          .count());

  m_sessions[session_id] = session;

  return true;
}

//------------------------------------------------------------------------------
std::shared_ptr<auth_session_t> did_session_manager::get_session(
    const std::string& session_id) {
  std::shared_lock<std::shared_mutex> lock(m_mutex);

  auto it = m_sessions.find(session_id);
  if (it != m_sessions.end()) {
    return it->second;
  }
  return nullptr;
}

//------------------------------------------------------------------------------
std::shared_ptr<const auth_session_t> did_session_manager::get_session(
    const std::string& session_id) const {
  std::shared_lock<std::shared_mutex> lock(m_mutex);

  auto it = m_sessions.find(session_id);
  if (it != m_sessions.end()) {
    return it->second;
  }
  return nullptr;
}

//------------------------------------------------------------------------------
bool did_session_manager::update_state(
    const std::string& session_id, AuthState new_state) {
  std::unique_lock<std::shared_mutex> lock(m_mutex);

  auto it = m_sessions.find(session_id);
  if (it == m_sessions.end()) {
    return false;
  }

  it->second->state         = new_state;
  it->second->last_activity = std::chrono::steady_clock::now();

  return true;
}

//------------------------------------------------------------------------------
bool did_session_manager::set_remote_info(
    const std::string& session_id, const std::string& remote_did,
    const std::string& remote_nf_type, const std::string& remote_nf_instance_id,
    const std::string& remote_public_key) {
  std::unique_lock<std::shared_mutex> lock(m_mutex);

  auto it = m_sessions.find(session_id);
  if (it == m_sessions.end()) {
    return false;
  }

  it->second->remote_did           = remote_did;
  it->second->remote_nf_type       = remote_nf_type;
  it->second->remote_nf_instance_id = remote_nf_instance_id;
  it->second->remote_public_key    = remote_public_key;
  it->second->last_activity        = std::chrono::steady_clock::now();

  return true;
}

//------------------------------------------------------------------------------
bool did_session_manager::set_remote_endpoint(
    const std::string& session_id, const std::string& endpoint) {
  std::unique_lock<std::shared_mutex> lock(m_mutex);

  auto it = m_sessions.find(session_id);
  if (it == m_sessions.end()) {
    return false;
  }

  it->second->remote_endpoint = endpoint;
  it->second->last_activity   = std::chrono::steady_clock::now();

  return true;
}

//------------------------------------------------------------------------------
bool did_session_manager::set_local_nonce(
    const std::string& session_id, const nonce_t& nonce) {
  std::unique_lock<std::shared_mutex> lock(m_mutex);

  auto it = m_sessions.find(session_id);
  if (it == m_sessions.end()) {
    return false;
  }

  it->second->local_nonce   = nonce;
  it->second->last_activity = std::chrono::steady_clock::now();

  return true;
}

//------------------------------------------------------------------------------
bool did_session_manager::set_remote_nonce(
    const std::string& session_id, const nonce_t& nonce) {
  std::unique_lock<std::shared_mutex> lock(m_mutex);

  auto it = m_sessions.find(session_id);
  if (it == m_sessions.end()) {
    return false;
  }

  it->second->remote_nonce  = nonce;
  it->second->last_activity = std::chrono::steady_clock::now();

  return true;
}

//------------------------------------------------------------------------------
std::string did_session_manager::generate_auth_token(
    const std::string& session_id) {
  std::unique_lock<std::shared_mutex> lock(m_mutex);

  auto it = m_sessions.find(session_id);
  if (it == m_sessions.end()) {
    return "";
  }

  // Generate new token
  std::string token                    = generate_secure_token();
  it->second->auth_token               = token;
  it->second->token_expires_at         = nonce_t::current_timestamp_ms() +
                                 (m_token_validity_sec * 1000);
  it->second->last_activity = std::chrono::steady_clock::now();

  // Map token to session
  m_token_to_session[token] = session_id;

  return token;
}

//------------------------------------------------------------------------------
bool did_session_manager::validate_auth_token(
    const std::string& token, std::string& session_id) const {
  std::shared_lock<std::shared_mutex> lock(m_mutex);

  auto token_it = m_token_to_session.find(token);
  if (token_it == m_token_to_session.end()) {
    return false;
  }

  session_id     = token_it->second;
  auto session_it = m_sessions.find(session_id);
  if (session_it == m_sessions.end()) {
    return false;
  }

  // Check if token is expired
  uint64_t current_time = nonce_t::current_timestamp_ms();
  if (current_time > session_it->second->token_expires_at) {
    return false;
  }

  // Check if session is authenticated
  if (session_it->second->state != AuthState::MUTUAL_AUTH_COMPLETE) {
    return false;
  }

  return true;
}

//------------------------------------------------------------------------------
void did_session_manager::remove_session(const std::string& session_id) {
  std::unique_lock<std::shared_mutex> lock(m_mutex);

  auto it = m_sessions.find(session_id);
  if (it != m_sessions.end()) {
    // Remove associated token
    if (!it->second->auth_token.empty()) {
      m_token_to_session.erase(it->second->auth_token);
    }
    m_sessions.erase(it);
  }
}

//------------------------------------------------------------------------------
size_t did_session_manager::cleanup_expired() {
  std::unique_lock<std::shared_mutex> lock(m_mutex);

  auto now              = std::chrono::steady_clock::now();
  size_t cleaned_count  = 0;

  auto it = m_sessions.begin();
  while (it != m_sessions.end()) {
    auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(
                       now - it->second->last_activity)
                       .count();

    bool should_remove = false;

    // Remove if session timed out and not completed
    if (it->second->state != AuthState::MUTUAL_AUTH_COMPLETE &&
        static_cast<uint64_t>(elapsed) > m_session_timeout_sec) {
      should_remove = true;
    }

    // Remove if token expired for completed sessions
    if (it->second->state == AuthState::MUTUAL_AUTH_COMPLETE) {
      uint64_t current_time = nonce_t::current_timestamp_ms();
      if (current_time > it->second->token_expires_at) {
        should_remove = true;
      }
    }

    if (should_remove) {
      // Remove associated token
      if (!it->second->auth_token.empty()) {
        m_token_to_session.erase(it->second->auth_token);
      }
      it = m_sessions.erase(it);
      ++cleaned_count;
    } else {
      ++it;
    }
  }

  return cleaned_count;
}

//------------------------------------------------------------------------------
size_t did_session_manager::active_session_count() const {
  std::shared_lock<std::shared_mutex> lock(m_mutex);
  return m_sessions.size();
}

//------------------------------------------------------------------------------
bool did_session_manager::session_exists(const std::string& session_id) const {
  std::shared_lock<std::shared_mutex> lock(m_mutex);
  return m_sessions.find(session_id) != m_sessions.end();
}

//------------------------------------------------------------------------------
std::string did_session_manager::find_authenticated_session(
    const std::string& remote_did) const {
  std::shared_lock<std::shared_mutex> lock(m_mutex);

  for (const auto& pair : m_sessions) {
    if (pair.second->remote_did == remote_did &&
        pair.second->state == AuthState::MUTUAL_AUTH_COMPLETE) {
      // Check token validity
      uint64_t current_time = nonce_t::current_timestamp_ms();
      if (current_time <= pair.second->token_expires_at) {
        return pair.first;
      }
    }
  }

  return "";
}

//------------------------------------------------------------------------------
void did_session_manager::touch_session(const std::string& session_id) {
  std::unique_lock<std::shared_mutex> lock(m_mutex);

  auto it = m_sessions.find(session_id);
  if (it != m_sessions.end()) {
    it->second->last_activity = std::chrono::steady_clock::now();
  }
}

//------------------------------------------------------------------------------
bool did_session_manager::migrate_session(
    const std::string& old_session_id, const std::string& new_session_id) {
  std::unique_lock<std::shared_mutex> lock(m_mutex);

  // Check if old session exists
  auto old_it = m_sessions.find(old_session_id);
  if (old_it == m_sessions.end()) {
    return false;
  }

  // Check if new session_id is already in use
  if (m_sessions.find(new_session_id) != m_sessions.end()) {
    // New session_id already exists - this shouldn't happen in normal flow
    return false;
  }

  // Get the session data
  auto session = old_it->second;

  // Update the session's internal session_id to the new one
  session->session_id = new_session_id;

  // Update last activity time
  session->last_activity = std::chrono::steady_clock::now();

  // Insert with new key and remove old key
  m_sessions[new_session_id] = session;
  m_sessions.erase(old_it);

  return true;
}

}  // namespace oai::amf::did_auth
