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

#include "bcf_interface.hpp"

#include <chrono>

namespace oai::amf::did_auth {

//------------------------------------------------------------------------------
// Helper: current timestamp in milliseconds
//------------------------------------------------------------------------------
static uint64_t current_time_ms() {
  return std::chrono::duration_cast<std::chrono::milliseconds>(
             std::chrono::system_clock::now().time_since_epoch())
      .count();
}

//------------------------------------------------------------------------------
bool bcf_auth_session_t::is_token_valid() const {
  if (state != BcfAuthState::AUTH_SUCCESS || auth_token.empty()) {
    return false;
  }
  return current_time_ms() < token_expires_at_ms;
}

//------------------------------------------------------------------------------
bool bcf_auth_session_t::is_challenge_expired() const {
  if (challenge.empty() || challenge_expires_ms == 0) {
    return true;
  }
  return current_time_ms() > challenge_expires_ms;
}

//------------------------------------------------------------------------------
bool bcf_token_cache_entry_t::is_valid(uint64_t safety_margin_ms) const {
  if (auth_token.empty() || expires_at_ms == 0) {
    return false;
  }
  return current_time_ms() + safety_margin_ms < expires_at_ms;
}

}  // namespace oai::amf::did_auth
