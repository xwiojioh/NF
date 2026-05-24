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

/*
 * latency_probe.hpp — Generic Latency Measurement Toolkit
 *
 * Two-layer design:
 *   Layer 1: LatencyProbe  — cross-function / cross-module trace with stages
 *   Layer 2: ScopedLatencyTimer — RAII scoped timer for local blocks
 *
 * Controlled by compile macro ENABLE_LATENCY_PROBE.
 * When disabled, all LP_* macros expand to nothing (zero overhead).
 *
 * Thread-safe. Header-only. No external dependencies.
 *
 * Usage examples:
 *
 *   // --- Trace probe ---
 *   auto tid = LP_BUILD_ID("AMF", "BCF_REG", nf_instance_id);
 *   LP_START("AMF", "BCF_REG", tid);
 *   LP_MARK(tid, "REG_REQUEST_DISPATCH");
 *   LP_MARK(tid, "HTTP_STATUS_RCVD");
 *   LP_END(tid, "REG_SUCCESS");
 *
 *   // --- Scoped timer ---
 *   void sign_challenge() {
 *       LP_SCOPED("AUSF sign_challenge");
 *       // ... original logic ...
 *   }
 */

#ifndef FILE_LATENCY_PROBE_HPP_SEEN
#define FILE_LATENCY_PROBE_HPP_SEEN

#include <chrono>
#include <cstdio>
#include <mutex>
#include <string>
#include <unordered_map>
#include <vector>

// Use OAI Logger for output (visible in AMF/AUSF log files)
#include "logger_base.hpp"

// ============================================================================
// Macro Interface Layer
// ============================================================================

#ifdef ENABLE_LATENCY_PROBE

// Trace probe macros
#define LP_BUILD_ID(module, flow, key) \
  oai::utils::LatencyProbe::build_trace_id(module, flow, key)

#define LP_START(module, flow, trace_id) \
  oai::utils::LatencyProbe::instance().start_trace(module, flow, trace_id)

#define LP_MARK(trace_id, stage) \
  oai::utils::LatencyProbe::instance().mark(trace_id, stage)

#define LP_END(trace_id, final_stage) \
  oai::utils::LatencyProbe::instance().end_trace(trace_id, final_stage)

#define LP_CANCEL(trace_id) \
  oai::utils::LatencyProbe::instance().cancel_trace(trace_id)

// Scoped timer macro — unique variable name via line number concatenation
#define LP_SCOPED_CONCAT_INNER(a, b) a##b
#define LP_SCOPED_CONCAT(a, b) LP_SCOPED_CONCAT_INNER(a, b)
#define LP_SCOPED(label) \
  oai::utils::ScopedLatencyTimer LP_SCOPED_CONCAT(_slt_, __LINE__)(label)

#else  // ENABLE_LATENCY_PROBE not defined

#define LP_BUILD_ID(module, flow, key) std::string {}
#define LP_START(module, flow, trace_id) \
  do {                                   \
  } while (0)
#define LP_MARK(trace_id, stage) \
  do {                           \
  } while (0)
#define LP_END(trace_id, final_stage) \
  do {                                \
  } while (0)
#define LP_CANCEL(trace_id) \
  do {                      \
  } while (0)
#define LP_SCOPED(label) \
  do {                   \
  } while (0)

#endif  // ENABLE_LATENCY_PROBE

// ============================================================================
// Implementation (only compiled when macro is enabled, but always parseable)
// ============================================================================

namespace oai::utils {

#ifdef ENABLE_LATENCY_PROBE

// --------------------------------------------------------------------------
// Layer 1: LatencyProbe — Cross-function / cross-module trace with stages
// --------------------------------------------------------------------------

class LatencyProbe {
 public:
  using clock_t     = std::chrono::steady_clock;
  using time_point  = clock_t::time_point;

  struct stage_mark {
    std::string stage;
    time_point  ts;
  };

  struct trace_record {
    std::string              module;
    std::string              flow;
    std::string              trace_id;
    time_point               start_ts;
    std::vector<stage_mark>  marks;
    bool                     ended;
  };

  // Singleton access
  static LatencyProbe& instance() {
    static LatencyProbe inst;
    return inst;
  }

  // Build a unified trace_id: "MODULE:FLOW:key"
  static std::string build_trace_id(
      const std::string& module, const std::string& flow,
      const std::string& key) {
    return module + ":" + flow + ":" + key;
  }

  // Start a new trace
  void start_trace(
      const std::string& module, const std::string& flow,
      const std::string& trace_id) {
    std::lock_guard<std::mutex> lock(mtx_);
    trace_record rec;
    rec.module   = module;
    rec.flow     = flow;
    rec.trace_id = trace_id;
    rec.start_ts = clock_t::now();
    rec.ended    = false;
    traces_[trace_id] = std::move(rec);
    oai::logger::logger_common::utils().info(
        "[LATENCY][%s][%s] START trace_id=%s",
        module.c_str(), flow.c_str(), trace_id.c_str());
  }

  // Add a stage mark to an existing trace
  void mark(const std::string& trace_id, const std::string& stage) {
    std::lock_guard<std::mutex> lock(mtx_);
    auto it = traces_.find(trace_id);
    if (it == traces_.end()) return;  // silently ignore if not found
    if (it->second.ended) return;     // already ended
    it->second.marks.push_back({stage, clock_t::now()});
  }

  // End trace: add final stage, print report, remove from map
  void end_trace(
      const std::string& trace_id, const std::string& final_stage) {
    std::lock_guard<std::mutex> lock(mtx_);
    auto it = traces_.find(trace_id);
    if (it == traces_.end()) return;
    if (it->second.ended) return;

    it->second.marks.push_back({final_stage, clock_t::now()});
    it->second.ended = true;
    print_report(it->second);
    traces_.erase(it);
  }

  // Cancel and remove a trace (for error / timeout paths)
  void cancel_trace(const std::string& trace_id) {
    std::lock_guard<std::mutex> lock(mtx_);
    auto it = traces_.find(trace_id);
    if (it != traces_.end()) {
      oai::logger::logger_common::utils().info(
          "[LATENCY][%s][%s] CANCELLED trace_id=%s",
          it->second.module.c_str(), it->second.flow.c_str(),
          trace_id.c_str());
      traces_.erase(it);
    }
  }

 private:
  LatencyProbe() = default;

  void print_report(const trace_record& rec) const {
    auto total_us = std::chrono::duration_cast<std::chrono::microseconds>(
                        rec.marks.back().ts - rec.start_ts)
                        .count();
    double total_ms = static_cast<double>(total_us) / 1000.0;

    // Header line — output via OAI Logger (appears in log file + console)
    oai::logger::logger_common::utils().info(
        "[LATENCY][%s][%s] trace_id=%s  total: %ld us (%.3f ms)",
        rec.module.c_str(), rec.flow.c_str(), rec.trace_id.c_str(),
        total_us, total_ms);

    // Each segment
    time_point prev_ts = rec.start_ts;
    std::string prev_stage = "START";
    long cumulative_us = 0;

    for (const auto& m : rec.marks) {
      long seg_us = std::chrono::duration_cast<std::chrono::microseconds>(
                        m.ts - prev_ts)
                        .count();
      cumulative_us += seg_us;
      double seg_ms = static_cast<double>(seg_us) / 1000.0;
      double cum_ms = static_cast<double>(cumulative_us) / 1000.0;

      oai::logger::logger_common::utils().info(
          "[LATENCY][%s][%s]   %s -> %s: %ld us (%.3f ms), cumulative=%ld us (%.3f ms)",
          rec.module.c_str(), rec.flow.c_str(),
          prev_stage.c_str(), m.stage.c_str(), seg_us, seg_ms,
          cumulative_us, cum_ms);

      prev_ts    = m.ts;
      prev_stage = m.stage;
    }
  }

  std::mutex                                     mtx_;
  std::unordered_map<std::string, trace_record>  traces_;
};

// --------------------------------------------------------------------------
// Layer 2: ScopedLatencyTimer — RAII scoped timer for local code blocks
// --------------------------------------------------------------------------

class ScopedLatencyTimer {
 public:
  explicit ScopedLatencyTimer(const std::string& label)
      : label_(label), start_(std::chrono::steady_clock::now()) {}

  ~ScopedLatencyTimer() {
    auto end = std::chrono::steady_clock::now();
    long us  = std::chrono::duration_cast<std::chrono::microseconds>(
                   end - start_)
                   .count();
    double ms = static_cast<double>(us) / 1000.0;
    oai::logger::logger_common::utils().info(
        "[LATENCY][SCOPED] %s: %ld us (%.3f ms)",
        label_.c_str(), us, ms);
  }

  // Non-copyable, non-movable
  ScopedLatencyTimer(const ScopedLatencyTimer&)            = delete;
  ScopedLatencyTimer& operator=(const ScopedLatencyTimer&) = delete;
  ScopedLatencyTimer(ScopedLatencyTimer&&)                 = delete;
  ScopedLatencyTimer& operator=(ScopedLatencyTimer&&)      = delete;

 private:
  std::string                                    label_;
  std::chrono::steady_clock::time_point          start_;
};

#endif  // ENABLE_LATENCY_PROBE

}  // namespace oai::utils

#endif  // FILE_LATENCY_PROBE_HPP_SEEN
