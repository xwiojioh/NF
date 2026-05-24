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

#include <algorithm>
#include <chrono>
#include <random>

namespace oai::ausf::did_auth {

//------------------------------------------------------------------------------
// Helper: current timestamp in milliseconds
//------------------------------------------------------------------------------
static uint64_t current_time_ms() {
  return std::chrono::duration_cast<std::chrono::milliseconds>(
             std::chrono::system_clock::now().time_since_epoch())
      .count();
}

// 静态成员初始化
size_t nf_selector::s_round_robin_index = 0;

//------------------------------------------------------------------------------
std::optional<nf_profile_t> nf_selector::select(
    const std::vector<nf_profile_t>& nf_list,
    NfSelectionStrategy strategy,
    const std::string& local_locality) {
  if (nf_list.empty()) {
    return std::nullopt;
  }

  switch (strategy) {
    case NfSelectionStrategy::PRIORITY_BASED:
      return select_by_priority(nf_list);

    case NfSelectionStrategy::LOAD_BASED:
      return select_by_load(nf_list);

    case NfSelectionStrategy::CAPACITY_BASED:
      return select_by_capacity(nf_list);

    case NfSelectionStrategy::ROUND_ROBIN: {
      size_t index = s_round_robin_index % nf_list.size();
      s_round_robin_index++;
      return nf_list[index];
    }

    case NfSelectionStrategy::RANDOM:
      return select_random(nf_list);

    case NfSelectionStrategy::LOCALITY_BASED:
      return select_by_locality(nf_list, local_locality);

    default:
      return select_by_priority(nf_list);
  }
}

//------------------------------------------------------------------------------
std::optional<nf_profile_t> nf_selector::select_by_priority(
    const std::vector<nf_profile_t>& nf_list) {
  if (nf_list.empty()) {
    return std::nullopt;
  }

  // 找到优先级最高的（priority 值最小）
  auto it = std::min_element(
      nf_list.begin(), nf_list.end(),
      [](const nf_profile_t& a, const nf_profile_t& b) {
        return a.priority < b.priority;
      });

  return *it;
}

//------------------------------------------------------------------------------
std::optional<nf_profile_t> nf_selector::select_by_load(
    const std::vector<nf_profile_t>& nf_list) {
  if (nf_list.empty()) {
    return std::nullopt;
  }

  // 找到负载最低的
  auto it = std::min_element(
      nf_list.begin(), nf_list.end(),
      [](const nf_profile_t& a, const nf_profile_t& b) {
        return a.load < b.load;
      });

  return *it;
}

//------------------------------------------------------------------------------
std::optional<nf_profile_t> nf_selector::select_by_capacity(
    const std::vector<nf_profile_t>& nf_list) {
  if (nf_list.empty()) {
    return std::nullopt;
  }

  // 找到容量最大的
  auto it = std::max_element(
      nf_list.begin(), nf_list.end(),
      [](const nf_profile_t& a, const nf_profile_t& b) {
        return a.capacity < b.capacity;
      });

  return *it;
}

//------------------------------------------------------------------------------
std::optional<nf_profile_t> nf_selector::select_random(
    const std::vector<nf_profile_t>& nf_list) {
  if (nf_list.empty()) {
    return std::nullopt;
  }

  std::random_device rd;
  std::mt19937 gen(rd());
  std::uniform_int_distribution<size_t> dist(0, nf_list.size() - 1);

  return nf_list[dist(gen)];
}

//------------------------------------------------------------------------------
std::optional<nf_profile_t> nf_selector::select_by_locality(
    const std::vector<nf_profile_t>& nf_list,
    const std::string& local_locality) {
  if (nf_list.empty()) {
    return std::nullopt;
  }

  // 首先尝试找到同一位置的 NF
  if (!local_locality.empty()) {
    std::vector<nf_profile_t> same_locality;
    for (const auto& nf : nf_list) {
      if (nf.locality == local_locality) {
        same_locality.push_back(nf);
      }
    }

    // 如果找到同一位置的 NF，从中选择优先级最高的
    if (!same_locality.empty()) {
      return select_by_priority(same_locality);
    }
  }

  // 如果没有同一位置的 NF，回退到优先级选择
  return select_by_priority(nf_list);
}

// =============================================================================
// BCF Auth Session / Token Cache Entry Implementations
// =============================================================================

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

}  // namespace oai::ausf::did_auth
