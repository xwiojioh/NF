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

#include "did_nonce_manager.hpp"
#include "did_crypto.hpp"

namespace oai::amf::did_auth {

//------------------------------------------------------------------------------
did_nonce_manager::did_nonce_manager(uint64_t nonce_validity_sec)
    : m_nonce_validity_sec(nonce_validity_sec) {}

//------------------------------------------------------------------------------
did_nonce_manager::~did_nonce_manager() {}

//------------------------------------------------------------------------------
nonce_t did_nonce_manager::generate_nonce() {
  nonce_t nonce;

  // Generate 32 bytes of random data
  nonce.random_bytes = did_crypto::generate_random(32);

  // Set current timestamp
  nonce.timestamp_ms = nonce_t::current_timestamp_ms();

  return nonce;
}

//------------------------------------------------------------------------------
AuthResult did_nonce_manager::validate_nonce(const nonce_t& nonce) {
  // Check if nonce is expired
  if (nonce.is_expired(m_nonce_validity_sec * 1000)) {
    return AuthResult::FAILURE_NONCE_EXPIRED;
  }

  // Check if nonce has been used (replay attack detection)
  std::string nonce_hex = nonce.to_hex();
  if (is_used(nonce_hex)) {
    return AuthResult::FAILURE_NONCE_REUSED;
  }

  return AuthResult::SUCCESS;
}

//------------------------------------------------------------------------------
AuthResult did_nonce_manager::validate_nonce_hex(const std::string& nonce_hex) {
  nonce_t nonce = nonce_t::from_hex(nonce_hex);
  return validate_nonce(nonce);
}

//------------------------------------------------------------------------------
void did_nonce_manager::mark_used(const std::string& nonce_hex) {
  std::unique_lock<std::shared_mutex> lock(m_mutex);

  uint64_t current_time = nonce_t::current_timestamp_ms();
  m_used_nonces[nonce_hex] = current_time;
}

//------------------------------------------------------------------------------
bool did_nonce_manager::is_used(const std::string& nonce_hex) const {
  std::shared_lock<std::shared_mutex> lock(m_mutex);

  return m_used_nonces.find(nonce_hex) != m_used_nonces.end();
}

//------------------------------------------------------------------------------
size_t did_nonce_manager::cleanup_expired() {
  std::unique_lock<std::shared_mutex> lock(m_mutex);

  uint64_t current_time  = nonce_t::current_timestamp_ms();
  uint64_t validity_ms   = m_nonce_validity_sec * 1000;
  size_t cleaned_count   = 0;

  // Remove expired nonces
  auto it = m_used_nonces.begin();
  while (it != m_used_nonces.end()) {
    if ((current_time > it->second) &&
        ((current_time - it->second) > validity_ms)) {
      it = m_used_nonces.erase(it);
      ++cleaned_count;
    } else {
      ++it;
    }
  }

  return cleaned_count;
}

//------------------------------------------------------------------------------
size_t did_nonce_manager::used_nonce_count() const {
  std::shared_lock<std::shared_mutex> lock(m_mutex);
  return m_used_nonces.size();
}

}  // namespace oai::amf::did_auth
