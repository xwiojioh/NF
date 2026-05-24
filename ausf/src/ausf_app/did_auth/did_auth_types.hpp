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

#ifndef _AUSF_DID_AUTH_TYPES_H_
#define _AUSF_DID_AUTH_TYPES_H_

#include <chrono>
#include <cstdint>
#include <string>

namespace oai::ausf::did_auth {

// =============================================================================
// DID Auth Logging Utilities
// =============================================================================

/**
 * @brief Extract short DID for logging (first 12 chars of hash)
 */
inline std::string short_did(const std::string& full_did) {
  if (full_did.length() <= 24) return full_did;
  
  const std::string prefix = "did:oai5gc:";
  if (full_did.substr(0, prefix.length()) == prefix) {
    std::string hash_part = full_did.substr(prefix.length());
    if (hash_part.length() > 12) {
      return prefix + hash_part.substr(0, 12) + "...";
    }
  }
  return full_did.substr(0, 24) + "...";
}

/**
 * @brief Truncate string for logging with ellipsis
 */
inline std::string truncate_for_log(const std::string& s, size_t max_len = 32) {
  if (s.length() <= max_len) return s;
  return s.substr(0, max_len) + "...";
}

/**
 * @brief Get current time in milliseconds since epoch
 */
inline uint64_t current_timestamp_ms() {
  return std::chrono::duration_cast<std::chrono::milliseconds>(
             std::chrono::system_clock::now().time_since_epoch())
      .count();
}

}  // namespace oai::ausf::did_auth

#endif  // _AUSF_DID_AUTH_TYPES_H_
