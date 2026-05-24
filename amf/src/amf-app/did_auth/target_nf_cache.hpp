#pragma once

#include <map>
#include <mutex>
#include <shared_mutex>
#include <string>
#include <vector>

#include "bcf_nf_discovery.hpp"

namespace oai::amf::did_auth {

struct target_nf_entry_t {
  std::string nf_type;
  std::string nf_instance_id;
  std::string nf_did;
  std::string nf_uri;
  uint64_t last_seen_ms;
  oai::common::bcf::NfProfile nf_profile;
  bool has_nf_profile = false;
};

class TargetNfCache {
 public:
  TargetNfCache() = default;

  void upsert(const target_nf_entry_t& entry) {
    std::unique_lock lock(mutex_);
    cache_[entry.nf_instance_id] = entry;
  }

  void remove(const std::string& nf_instance_id) {
    std::unique_lock lock(mutex_);
    cache_.erase(nf_instance_id);
  }

  std::vector<target_nf_entry_t> list() const {
    std::shared_lock lock(mutex_);
    std::vector<target_nf_entry_t> out;
    out.reserve(cache_.size());
    for (auto const& kv : cache_) out.push_back(kv.second);
    return out;
  }

  std::vector<target_nf_entry_t> list_by_nf_type(
      const std::string& nf_type) const {
    std::shared_lock lock(mutex_);
    std::vector<target_nf_entry_t> out;
    for (const auto& kv : cache_) {
      if (nf_type.empty() || kv.second.nf_type == nf_type) {
        out.push_back(kv.second);
      }
    }
    return out;
  }

 private:
  mutable std::shared_mutex mutex_;
  std::map<std::string, target_nf_entry_t> cache_;
};

}  // namespace oai::amf::did_auth
