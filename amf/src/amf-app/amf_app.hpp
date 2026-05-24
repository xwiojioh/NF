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

#ifndef _AMF_APP_H_
#define _AMF_APP_H_

#include <boost/thread.hpp>
#include <boost/thread/future.hpp>
#include <atomic>
#include <condition_variable>
#include <cstdint>
#include <map>
#include <memory>
#include <mutex>
#include <shared_mutex>
#include <unordered_set>

#include "N1MessageClass_anyOf.h"
#include "N2InformationClass_anyOf.h"
#include "NsiInformation.h"
#include "ProblemDetails.h"
#include "UeN1N2InfoSubscriptionCreateData.h"
#include "amf_config.hpp"
#include "amf_msg.hpp"
#include "amf_profile.hpp"
#include "amf_subscription.hpp"
#include "itti.hpp"
#include "itti_msg_amf_app.hpp"
#include "itti_msg_sbi.hpp"
#include "ue_context.hpp"
#include "uint_generator.hpp"
#include "StatusChange.h"
#include "bcf_nf_discovery.hpp"

// Forward declarations for BCF authentication
namespace oai::amf::did_auth {
class DIDAuth;
}

namespace oai::common::audit {
class security_audit;
struct security_audit_summary;
}

using namespace oai::config;
using namespace oai::_3gpp::model;

namespace amf_application {

#define TASK_AMF_APP_PERIODIC_STATISTICS (0)
#define TASK_AMF_MOBILE_REACHABLE_TIMER_EXPIRE (1)
#define TASK_AMF_IMPLICIT_DEREGISTRATION_TIMER_EXPIRE (2)
// NRF timeout handlers removed - BCF has replaced NRF

// =========================================================================
// BCF Lifecycle State Machine
// Enforces strict ordering: INIT → DID_READY → REGISTERING → REGISTERED →
//                           AUTHENTICATING → TOKEN_READY
// =========================================================================
enum class BcfLifecycleState {
  INIT = 0,              // AMF just started, nothing done yet
  DID_READY,             // DID / local keys loaded successfully
  REGISTRATION_IN_PROGRESS,  // BCF registration request sent, waiting response
  BCF_REGISTERED,        // BCF registration response received (success)
  AUTH_IN_PROGRESS,      // BCF auth request sent, waiting for token
  TOKEN_READY,           // BCF auth token obtained and cached
  FAILED                 // Unrecoverable failure
};

// Utility: convert state to string for logging
inline const char* bcf_state_to_string(BcfLifecycleState s) {
  switch (s) {
    case BcfLifecycleState::INIT:                     return "INIT";
    case BcfLifecycleState::DID_READY:                return "DID_READY";
    case BcfLifecycleState::REGISTRATION_IN_PROGRESS: return "REGISTRATION_IN_PROGRESS";
    case BcfLifecycleState::BCF_REGISTERED:           return "BCF_REGISTERED";
    case BcfLifecycleState::AUTH_IN_PROGRESS:          return "AUTH_IN_PROGRESS";
    case BcfLifecycleState::TOKEN_READY:              return "TOKEN_READY";
    case BcfLifecycleState::FAILED:                   return "FAILED";
    default:                                          return "UNKNOWN";
  }
}

enum class amf_shutdown_state_t {
  RUNNING = 0,
  SHUTDOWN_REQUESTED,
  HTTP_SERVER_STOPPED,
  BCF_DEREG_IN_PROGRESS,
  BCF_DEREG_DONE,
  TERMINATE_DISPATCHED,
  STOPPED
};

inline const char* shutdown_state_to_string(amf_shutdown_state_t s) {
  switch (s) {
    case amf_shutdown_state_t::RUNNING:
      return "RUNNING";
    case amf_shutdown_state_t::SHUTDOWN_REQUESTED:
      return "SHUTDOWN_REQUESTED";
    case amf_shutdown_state_t::HTTP_SERVER_STOPPED:
      return "HTTP_SERVER_STOPPED";
    case amf_shutdown_state_t::BCF_DEREG_IN_PROGRESS:
      return "BCF_DEREG_IN_PROGRESS";
    case amf_shutdown_state_t::BCF_DEREG_DONE:
      return "BCF_DEREG_DONE";
    case amf_shutdown_state_t::TERMINATE_DISPATCHED:
      return "TERMINATE_DISPATCHED";
    case amf_shutdown_state_t::STOPPED:
      return "STOPPED";
    default:
      return "UNKNOWN";
  }
}

class amf_app {
 private:
  inline static uint32_t amf_app_ue_ngap_id_generator = 1;
  amf_profile nf_instance_profile;
  std::string amf_instance_id;

  oai::utils::uint_generator<uint32_t> evsub_id_generator;
  std::map<
      std::pair<evsub_id_t, amf_event_type_t>,
      std::shared_ptr<amf_subscription>>
      amf_event_subscriptions;
  mutable std::shared_mutex m_amf_event_subscriptions;

  std::map<uint64_t, std::shared_ptr<ue_context>> amf_ue_ngap_id2ue_ctx;
  mutable std::shared_mutex m_amf_ue_ngap_id2ue_ctx;
  std::map<std::string, std::shared_ptr<ue_context>> ue_ctx_key;
  mutable std::shared_mutex m_ue_ctx_key;

  std::map<std::string, std::shared_ptr<ue_context>> supi2ue_ctx;
  mutable std::shared_mutex m_supi2ue_ctx;

  mutable std::shared_mutex m_curl_handle_responses_sbi;
  std::map<uint32_t, boost::shared_ptr<boost::promise<nlohmann::json>>>
      curl_handle_responses_sbi;

  oai::utils::uint_generator<uint32_t> n1n2sub_id_generator;
  std::map<
      std::pair<std::string, uint32_t>,
      std::shared_ptr<oai::_3gpp::model::UeN1N2InfoSubscriptionCreateData>>
      n1n2_message_subscribe;
  mutable std::shared_mutex m_n1n2_message_subscribe;

  std::map<
      n1n2sub_id_t,
      std::shared_ptr<oai::_3gpp::model::NonUeN2InfoSubscriptionCreateData>>
      non_ue_n2_info_subscribe;
  mutable std::shared_mutex m_non_ue_n2_info_subscribe;

  oai::utils::uint_generator<uint32_t> amf_status_change_sub_id_generator;

  std::map<std::string, std::shared_ptr<oai::_3gpp::model::SubscriptionData>>
      amf_status_change_subscriptions;
  mutable std::shared_mutex m_amf_status_change_subscriptions;

  // BCF Authentication Module
  std::unique_ptr<oai::amf::did_auth::DIDAuth> m_did_auth;
  bool m_did_auth_enabled;
  std::string m_hardware_id;  // Hardware ID from extended profile (generated by did-proxy)
  std::unique_ptr<oai::common::audit::security_audit> m_security_audit;

  // BCF Lifecycle State Machine — protects registration → authentication ordering
  BcfLifecycleState m_bcf_state;
  mutable std::mutex m_bcf_state_mutex;

  // Shutdown state machine
  std::atomic<amf_shutdown_state_t> m_shutdown_state;
  std::atomic<bool> m_shutdown_started;
  std::atomic<bool> m_shutdown_terminate_sent;
  std::atomic<bool> m_http_server_stopped;
  std::atomic<bool> m_bcf_dereg_in_progress;
  std::atomic<bool> m_bcf_dereg_done;
  std::atomic<bool> m_bcf_dereg_success;
  mutable std::mutex m_shutdown_mutex;
  std::condition_variable m_shutdown_cv;
  std::string m_bcf_dereg_uri;
  uint32_t m_bcf_dereg_http_code;

  void set_shutdown_state(const amf_shutdown_state_t state);
  std::string build_bcf_nf_instance_uri() const;
  void dispatch_terminate_to_tasks();

 public:
  explicit amf_app();
  amf_app(amf_app const&) = delete;
  virtual ~amf_app();
  void operator=(amf_app const&) = delete;

  void start();
  /**
   * Unified shutdown entry. During shutdown, BCF deregistration must complete
   * before ITTI termination is dispatched.
   */
  void stop();
  void notify_http_server_stopped();
  void notify_shutdown_complete();
  void trigger_shutdown(uint32_t timeout_ms = 5000);
  bool is_shutdown_in_progress() const;
  amf_shutdown_state_t get_shutdown_state() const;
  bool should_reject_new_async_request(const std::string& action) const;

  /*
   * Generate AMF UE NGAP ID
   * @return generated ID
   */
  uint64_t generate_amf_ue_ngap_id();

  /*
   * Handle ITTI message (NAS Signalling Establishment Request: Registration
   * Request, Service Request )
   * @param [itti_nas_signalling_establishment_request&]: ITTI message
   * @return void
   */
  void handle_itti_message(itti_nas_signalling_establishment_request& itti_msg);

  /*
   * Handle ITTI message (N1N2MessageTransferRequest)
   * @param [itti_n1n2_message_transfer_request&]: ITTI message
   * @return void
   */
  void handle_itti_message(itti_n1n2_message_transfer_request& itti_msg);

  /*
   * Handle ITTI message (NonUeN2MessageTransferRequest)
   * @param [itti_non_ue_n2_message_transfer_request&]: ITTI message
   * @return void
   */
  void handle_itti_message(itti_non_ue_n2_message_transfer_request& itti_msg);

  /*
   * Handle ITTI message (SBI N1 Message Notification)
   * @param [itti_sbi_n1_message_notification&]: ITTI message
   * @return void
   */
  void handle_itti_message(itti_sbi_n1_message_notification& itti_msg);

  /*
   * Handle ITTI message (SBI N1N2 Message Subscribe)
   * @param [itti_sbi_n1n2_subscribe_message&]: ITTI message
   * @return void
   */
  void handle_itti_message(itti_sbi_n1n2_message_subscribe& itti_msg);

  /*
   * Handle ITTI message (SBI N1N2 Message UnSubscribe)
   * @param [itti_sbi_n1n2_unsubscribe_message&]: ITTI message
   * @return void
   */
  void handle_itti_message(itti_sbi_n1n2_message_unsubscribe& itti_msg);

  /*
   * Handle ITTI message (SBI NON UE N2 Info Subscribe)
   * @param [itti_sbi_non_ue_n2_info_subscribe&]: ITTI message
   * @return void
   */
  void handle_itti_message(itti_sbi_non_ue_n2_info_subscribe& itti_msg);

  /*
   * Handle ITTI message (SBI NON UE N2 Info Unsubscribe)
   * @param [itti_sbi_non_ue_n2_info_unsubscribe&]: ITTI message
   * @return void
   */
  void handle_itti_message(itti_sbi_non_ue_n2_info_unsubscribe& itti_msg);

  /*
   * Handle ITTI message (SBI PDU Session Release Notification)
   * @param [itti_sbi_pdu_session_release_notif&]: ITTI message
   * @return void
   */
  void handle_itti_message(itti_sbi_pdu_session_release_notif& itti_msg);

  /*
   * Handle ITTI message (SBI AMF configuration)
   * @param [itti_sbi_amf_configuration&]: ITTI message
   * @return void
   */
  void handle_itti_message(itti_sbi_amf_configuration& itti_msg);

  /*
   * Handle ITTI message (Update AMF configuration)
   * @param [itti_sbi_update_amf_configuration&]: ITTI message
   * @return void
   */
  void handle_itti_message(itti_sbi_update_amf_configuration& itti_msg);

    /**
     * @brief Handle incoming BCF notification JSON (forward to DIDAuth module)
     * @param body_json notification body as JSON string
     * @return true if processed successfully
     */
    bool handle_bcf_notification(const std::string& body_json);

  /*
   * Handle ITTI message (BCF Register NF Instance Response)
   * @param [itti_sbi_bcf_register_nf_instance_response&]: ITTI message
   * @return void
   */
  void handle_itti_message(
      itti_sbi_bcf_register_nf_instance_response& itti_msg);

  /*
   * Handle ITTI message (BCF Update NF Instance Response)
   * @param [itti_sbi_bcf_update_nf_instance_response&]: ITTI message
   * @return void
   */
  void handle_itti_message(itti_sbi_bcf_update_nf_instance_response& itti_msg);

  /*
   * Handle ITTI message (BCF Deregister NF Instance Response)
   * @param [itti_sbi_bcf_deregister_nf_instance_response&]: ITTI message
   * @return void
   */
  void handle_itti_message(
      itti_sbi_bcf_deregister_nf_instance_response& itti_msg);

  /*
   * Handle ITTI message (Register with UDM Response)
   * @param [itti_sbi_register_with_udm_response&]: ITTI message
   * @return void
   */
  void handle_itti_message(itti_sbi_register_with_udm_response& itti_msg);

  /*
   * Handle ITTI message (Retrieve AM Data Response)
   * @param [itti_sbi_retrieve_am_data_response&]: ITTI message
   * @return void
   */
  void handle_itti_message(itti_sbi_retrieve_am_data_response& itti_msg);

  /*
   * Handle ITTI message (retrieve a UE's SMF Selection Subscription Data)
   * @param [itti_sbi_retrieve_smf_selection_subscription_data_response&]: ITTI
   * message
   * @return void
   */
  void handle_itti_message(
      itti_sbi_retrieve_smf_selection_subscription_data_response& itti_msg);

  /*
   * Handle ITTI message (AM Policy Association response)
   * @param [itti_sbi_am_policy_association_response&]: ITTI
   * message
   * @return void
   */
  void handle_itti_message(itti_sbi_am_policy_association_response& itti_msg);

  /*
   * Handle ITTI message (AM Policy Association Termination response)
   * @param [itti_sbi_am_policy_association_termination_response&]: ITTI
   * message
   * @return void
   */
  void handle_itti_message(
      itti_sbi_am_policy_association_termination_response& itti_msg);

  /*
   * Handle ITTI message (AM Policy Association Update response)
   * @param [itti_sbi_am_policy_association_update_response&]: ITTI
   * message
   * @return void
   */
  void handle_itti_message(
      itti_sbi_am_policy_association_update_response& itti_msg);

  /*
   * Handle ITTI message (AM Policy Association Retrieval response)
   * @param [itti_sbi_am_policy_association_retrieval_response&]: ITTI
   * message
   * @return void
   */
  void handle_itti_message(
      itti_sbi_am_policy_association_retrieval_response& itti_msg);

  /*
   * Handle ITTI message (AM Policy Update Notification)
   * @param [itti_sbi_am_policy_update_notification&]: ITTI
   * message
   * @return void
   */
  void handle_itti_message(itti_sbi_am_policy_update_notification& itti_msg);

  /*
   * Handle ITTI message (AM Policy Association Termination Notification)
   * @param [itti_sbi_am_policy_association_termination_notification&]: ITTI
   * message
   * @return void
   */
  void handle_itti_message(
      itti_sbi_am_policy_association_termination_notification& itti_msg);

  /*
   * Handle ITTI message (UE Context In SMF Data Retrieval response)
   * @param [itti_sbi_ue_context_in_smf_data_retrieval_response&]: ITTI
   * message
   * @return void
   */
  void handle_itti_message(
      itti_sbi_ue_context_in_smf_data_retrieval_response& itti_msg);

  /*
   * Handle ITTI message (AMF Status Change Subscribe Request)
   * @param [itti_sbi_amf_status_change_subscribe_request&]: ITTI
   * message
   * @return void
   */
  void handle_itti_message(
      itti_sbi_amf_status_change_subscribe_request& itti_msg);

  /*
   * Handle ITTI message (AMF Status Change Unsubscribe Request)
   * @param [itti_sbi_amf_status_change_unsubscribe_request&]: ITTI
   * message
   * @return void
   */
  void handle_itti_message(
      itti_sbi_amf_status_change_unsubscribe_request& itti_msg);

  /*
   * Handle ITTI message (AMF Status Change Subscribe Modify)
   * @param [itti_sbi_amf_status_change_subscribe_modify&]: ITTI
   * message
   * @return void
   */
  void handle_itti_message(
      itti_sbi_amf_status_change_subscribe_modify& itti_msg);

  /*
   * Handle ITTI message (Provide Domain Selection Info)
   * @param [itti_sbi_provide_domain_selection_info&]: ITTI
   * message
   * @return void
   */
  void handle_itti_message(itti_sbi_provide_domain_selection_info& itti_msg);

  /*
   * Handle ITTI message (Provide Location Info)
   * @param [itti_sbi_provide_location_info&]: ITTI
   * message
   * @return void
   */
  void handle_itti_message(itti_sbi_provide_location_info& itti_msg);

  /*
   * Trigger AMF Registration for 3GPP Access towards UDM
   * @param [std::shared_ptr<ue_context>&] uc: UE context
   * @return void
   */
  void register_3gpp_access(std::shared_ptr<ue_context>& uc) const;

  /*
   * Retrieve a UE's Access and Mobility Subscription Data from UDM
   * @param [std::shared_ptr<ue_context>&] uc: UE context
   * @return void
   */
  void get_access_and_mobility_subscription_data(
      std::shared_ptr<ue_context>& uc) const;

  /*
   * Request to retrieve a SMF Selection Subcription Data from UDM
   * @param [std::shared_ptr<ue_context>&] uc: UE context
   * @return void
   */
  void get_smf_selection_subscription_data(
      std::shared_ptr<ue_context>& uc) const;

  /*
   * Perform PCF discovery to retrieve PCF's info from the corresponding NRF
   * @param [std::shared_ptr<ue_context>&] uc: UE context
   * @return void
   */
  void discover_pcf(std::shared_ptr<ue_context>& uc);

  /*
   * Perform AM Policy Association with the PCF
   * @param [std::shared_ptr<ue_context>&] uc: UE context
   * @return void
   */
  void perform_am_policy_association(std::shared_ptr<ue_context>& uc);

  /*
   * Perform AM Policy Association Termination with the PCF
   * @param [std::shared_ptr<ue_context>&] uc: UE context
   * @return void
   */
  void perform_am_policy_association_termination(
      const std::shared_ptr<ue_context>& uc);

  /*
   * Obtain updated policies for an AM Policy Association Termination with the
   * PCF
   * @param [std::shared_ptr<ue_context>&] uc: UE context
   * @return void
   */
  void perform_am_policy_association_update(
      const std::shared_ptr<ue_context>& uc);

  /*
   * Retrieve policies for an AM Policy Association with the
   * PCF
   * @param [std::shared_ptr<ue_context>&] uc: UE context
   * @return void
   */
  void get_am_policy_association(const std::shared_ptr<ue_context>& uc);

  /*
   * Retrieve UE Context In SMF Data with the UDM
   * @param [std::shared_ptr<ue_context>&] uc: UE context
   * @return void
   */
  void get_ue_context_in_smf_data(const std::shared_ptr<ue_context>& uc);

  /*
   * Get the current AMF's configuration
   * @param [nlohmann::json&]: json_data: Store AMF configuration
   * @return true if success, otherwise return false
   */
  bool read_amf_configuration(nlohmann::json& json_data);

  /*
   * Update AMF configuration
   * @param [nlohmann::json&]: json_data: New AMF configuration
   * @return true if success, otherwise return false
   */
  bool update_amf_configuration(nlohmann::json& json_data);

  /*
   * Get number of registered UEs to this AMF
   * @param [uint32_t&]: num_ues: Store the number of registered UEs
   * @return void
   */
  void get_number_registered_ues(uint32_t& num_ues) const;

  /*
   * Get number of registered UEs to this AMF
   * @param void
   * @return: number of registered UEs
   */
  uint32_t get_number_registered_ues() const;

  /*
   * Get UE context associated with an UE Context Key and verify if this pointer
   * is nullptr
   * @param [const std::string&] ue_context_key: UE Context Key
   * @param [std::shared_ptr<ue_context>&] uc: pointer to UE context if exist
   * @return true if UE Context exist and not null
   */
  bool ran_amf_id_2_ue_context(
      const std::string& ue_context_key, std::shared_ptr<ue_context>& uc) const;

  /*
   * Store an UE context associated with UE Context Key
   * @param [const std::string&] ue_context_key: UE Context Key
   * @param [std::shared_ptr<ue_context>&] uc: pointer to UE context
   * @return void
   */
  void set_ran_amf_id_2_ue_context(
      const std::string& ue_context_key, const std::shared_ptr<ue_context>& uc);

  /*
   * Get UE context associated with a SUPI
   * @param [const std::string&] supi: SUPI
   * @param [std::shared_ptr<ue_context>&] uc: pointer to UE context if exist
   * @return true if UE Context exist and not null
   */
  bool supi_2_ue_context(
      const std::string& supi, std::shared_ptr<ue_context>& uc) const;

  /*
   * Store an UE context associated with a SUPI
   * @param [const std::string&] supi: UE SUPI
   * @param [const std::shared_ptr<ue_context>&] uc: pointer to UE context
   * @return void
   */
  void set_supi_2_ue_context(
      const std::string& supi, const std::shared_ptr<ue_context>& uc);

  /*
   * Find a PDU Session Context associated with a SUPI and a PDU Session ID
   * @param [const std::string&] supi: UE SUPI
   * @param [ const std::uint8_t] pdu_session_id: PDU Session ID
   * @param [const std::shared_ptr<pdu_session_context>&] psc: pointer to the
   * PDU Session Context
   * @return true if found, otherwise false
   */
  bool find_pdu_session_context(
      const std::string& supi, const std::uint8_t pdu_session_id,
      std::shared_ptr<pdu_session_context>& psc);

  /*
   * Get a list of PDU Session Contexts associated with a SUPI
   * @param [const std::string&] supi: UE SUPI
   * @param [std::vector<std::shared_ptr<pdu_session_context>>&] sessions_ctx:
   * vector of contexts
   * @return true if found, otherwise false
   */
  bool get_pdu_sessions_context(
      const std::string& supi,
      std::vector<std::shared_ptr<pdu_session_context>>& sessions_ctx);

  /*
   * Update PDU Session Context status
   * @param [const std::string&] supi: UE SUPI
   * @param [uint8_t] pdu_session_id: PDU Session ID
   * @param [const oai::_3gpp::model::SmContextStatusNotification&]
   * statusNotification: Notification information received from SMF
   * @return true if success, otherwise false
   */
  bool update_pdu_sessions_context(
      const std::string& supi, uint8_t pdu_session_id,
      const oai::_3gpp::model::SmContextStatusNotification& statusNotification);

  /*
   * Generate a random TMSI
   * @param void
   * @return generated value in uint32_t
   */
  uint32_t generate_random_tmsi();

  /*
   * Create a 5G GUTI from PLMN/TMSI
   * @param [const uint32_t] ranid: RAN UE NGAP ID
   * @param [const long] amfid: AMF UE NGAP ID
   * @param [std::string&] MCC: Mobile Country Code
   * @param [std::string&] MNC: Mobile Network Code
   * @param [uint32_t&] tmsi: Generated TMSI
   * @return true if generated successfully, otherwise return false
   */
  bool generate_5g_guti(
      const uint32_t ranid, const long amfid, std::string& mcc,
      std::string& mnc, uint32_t& tmsi);

  /*
   * Generate an Event Exposure Subscription ID
   * @param [void]
   * @return the generated reference
   */
  evsub_id_t generate_ev_subscription_id();

  /*
   * Generate an N1N2MessageSubscribe ID
   * @param [void]
   * @return the generated reference
   */
  n1n2sub_id_t generate_n1n2_message_subscription_id();

  /*
   * Add an N1N2MessageSubscribe subscription to the list
   * @param [const std::string&] ue_ctx_id: UE Context ID
   * @param [const n1n2sub_id_t&] sub_id: Subscription ID
   * @param
   * [std::shared_ptr<oai::_3gpp::model::UeN1N2InfoSubscriptionCreateData>]
   * oai::_3gpp::model::UeN1N2InfoSubscriptionCreateData: a shared pointer
   * stored information of the subscription
   * @return void
   */
  void add_n1n2_message_subscription(
      const std::string& ue_ctx_id, const n1n2sub_id_t& sub_id,
      std::shared_ptr<oai::_3gpp::model::UeN1N2InfoSubscriptionCreateData>&
          subscription);

  /*
   * Remove an N1N2MessageSubscribe subscription from the list
   * @param [const std::string&] ue_ctx_id: UE Context ID
   * @param [const std::string&] sub_id: Subscription ID
   * @return true if the subscription is deleted successfully, otherwise return
   * false
   */
  bool remove_n1n2_message_subscription(
      const std::string& ue_ctx_id, const std::string& sub_id);

  /*
   * Find the subscriptions matched with certain conditions
   * @param [const std::string&] ue_ctx_id: UE Context ID
   * @param
   * [std::optional<oai::_3gpp::model::N1MessageClass_anyOf::eN1MessageClass_anyOf>&]
   * n1_message_class: Type of N1 Message
   * @param
   * [std::optional<oai::_3gpp::model::N2InformationClass_anyOf::eN2InformationClass_anyOf>&]
   * n2_info_class: Type of N2 Message
   * @param [std::map<n1n2sub_id_t,
   * std::shared_ptr<oai::_3gpp::model::UeN1N2InfoSubscriptionCreateData>>&]
   * subscriptions: list of subscriptions matched
   * @return void
   */
  void find_n1n2_info_subscriptions(
      const std::string& ue_ctx_id,
      std::optional<
          oai::_3gpp::model::N1MessageClass_anyOf::eN1MessageClass_anyOf>&
          n1_message_class,
      std::optional<oai::_3gpp::model::N2InformationClass_anyOf::
                        eN2InformationClass_anyOf>& n2_info_class,
      std::map<
          n1n2sub_id_t,
          std::shared_ptr<oai::_3gpp::model::UeN1N2InfoSubscriptionCreateData>>&
          subscriptions);

  /*
   * Add an NonUEN2InfoSubscribe subscription to the list
   * @param [const n1n2sub_id_t&] sub_id: Subscription ID
   * @param
   * [std::shared_ptr<oai::_3gpp::model::NonUeN2InfoSubscriptionCreateData>]
   * subscription_data: a shared pointer stored information of the subscription
   * @return void
   */
  void add_non_ue_n2_info_subscription(
      const n1n2sub_id_t& sub_id,
      std::shared_ptr<oai::_3gpp::model::NonUeN2InfoSubscriptionCreateData>&
          subscription_data);

  /*
   * Remove an NonUEN2InfoSubscribe subscription from the list
   * @param [const std::string&] sub_id: Subscription ID
   * @return true if the subscription is deleted successfully, otherwise return
   * false
   */
  bool remove_non_ue_n2_info_subscription(const std::string& sub_id);

  /*
   * Find the subscriptions matched with certain conditions
   * @param [const std::string&] nf_id: NF Id
   * @param
   * [std::optional<oai::_3gpp::model::N2InformationClass_anyOf::eN2InformationClass_anyOf>&]
   * n2_info_class: Type of N2 Message
   * @param [std::map<n1n2sub_id_t,
   * std::shared_ptr<oai::_3gpp::model::NonUeN2InfoSubscriptionCreateData>>&]
   * subscriptions: list of subscriptions matched
   * @return void
   */
  void find_non_ue_n2_info_subscriptions(
      const std::string& nf_id,
      const oai::_3gpp::model::N2InformationClass_anyOf::
          eN2InformationClass_anyOf& n2_info_class,
      std::map<
          n1n2sub_id_t,
          std::shared_ptr<
              oai::_3gpp::model::NonUeN2InfoSubscriptionCreateData>>&
          subscriptions);

  /*
   * Trigger NF instance registration to BCF with extended profile (DID)
   * Fetches extended profile from DID Proxy and registers to BCF
   * BCF has completely replaced NRF for NF registration and discovery
   * @param [void]
   * @return void
   */
  void register_to_bcf();

  /*
   * Trigger NF instance update to BCF
   * @param [void]
   * @return void
   */
  void update_bcf_registration();

  /*
   * Trigger NF instance deregistration from BCF
   * @param [void]
   * @return true if request dispatch to SBI succeeded
   */
  bool deregister_from_bcf();

  /*
   * Discover AUSF instances from BCF and select the best one
   * @param [std::string&] ausf_uri: Output - Selected AUSF's URI
   * @param [std::string&] ausf_did: Output - Selected AUSF's DID
   * @param [std::string&] ausf_api_version: Output - Selected AUSF's API version
   * @param [const std::vector<oai::common::bcf::Snssai>&] ue_snssais:
   *        UE slice context used for local AUSF selection
   * @return true if discovery and selection successful
   */
  bool discover_ausf_from_bcf(
      std::string& ausf_uri, std::string& ausf_did,
      std::string& ausf_api_version,
      const std::vector<oai::common::bcf::Snssai>& ue_snssais = {});

  /*
   * Query NF instances from BCF by NF type
   * @param [const std::string&] nf_type: Target NF type (e.g., "AUSF", "SMF")
   * @param [std::vector<oai::common::bcf::NfProfile>&] nf_profiles: Output - List of NF profiles
   * @return true if query successful
   */
  bool query_nf_instances_from_bcf(
      const std::string& nf_type,
      std::vector<oai::common::bcf::NfProfile>& nf_profiles);

  /*
   * Read extended NF profile from file (generated by DID Proxy)
   * @return nlohmann::json: The extended profile, empty if read fails
   */
  nlohmann::json read_extended_profile_from_file();

  /*
   * Get hardware ID loaded from extended profile
   * @return std::string: The hardware ID (64 hex chars), or empty if not loaded
   */
  std::string get_hardware_id() const { return m_hardware_id; }

  /*
   * Handle Event Exposure Msg from NF
   * @param [std::shared_ptr<itti_sbi_event_exposure_request>&] Request message
   * @return [evsub_id_t] ID of the created subscription
   */
  evsub_id_t handle_event_exposure_subscription(
      std::shared_ptr<itti_sbi_event_exposure_request> msg);

  /*
   * Handle Unsubscribe Request from an NF
   * @param [const std::string&] subscription_id: Subscription ID
   * @return true if the subscription is unsubscribed successfully, otherwise
   * return false
   */
  bool handle_event_exposure_delete(const std::string& subscription_id);

  /*
   * Handle NF status notification (e.g., when an UPF becomes available)
   * @param [std::shared_ptr<itti_sbi_notification_data>& ] msg: message
   * @param [oai::_3gpp::model::ProblemDetails& ] problem_details
   * @param [uint32_t&] http_code
   * @return true if handle successfully, otherwise return false
   */
  bool handle_nf_status_notification(
      std::shared_ptr<itti_sbi_notification_data>& msg,
      oai::_3gpp::model::ProblemDetails& problem_details, uint32_t& http_code);

  /*
   * Handle a request to determine location from LMF
   * @param void
   * return void
   */
  void handle_determine_location_request();

  /*
   * Generate a random UUID for AMF instance
   * @param [void]
   * @return void
   */
  void generate_uuid();

  /*
   * Add an Event Subscription to the list
   * @param [const evsub_id_t&] sub_id: Subscription ID
   * @param [const amf_event_t&] ev: Event type
   * @param [std::shared_ptr<amf_subscription>] ss: a shared pointer stored
   * information of the subscription
   * @return void
   */
  void add_event_subscription(
      const evsub_id_t& sub_id, const amf_event_type_t& ev,
      std::shared_ptr<amf_subscription> ss);

  /*
   * Remove an Event Subscription from the list
   * @param [const evsub_id_t&] sub_id: Subscription ID
   * @return bool
   */
  bool remove_event_subscription(const evsub_id_t& sub_id);

  /*
   * Get a list of subscription associated with a particular event
   * @param [const amf_event_t] ev: Event type
   * @param [std::vector<std::shared_ptr<amf_subscription>>&] subscriptions:
   * store the list of the subscription associated with this event type
   * @return void
   */
  void get_ee_subscriptions(
      const amf_event_type_t& ev,
      std::vector<std::shared_ptr<amf_subscription>>& subscriptions);

  /*
   * Get a list of subscription associated with a particular event
   * @param [const evsub_id_t&] sub_id: Subscription ID
   * @param [std::vector<std::shared_ptr<amf_subscription>>&] subscriptions:
   * store the list of the subscription associated with this event type
   * @return void
   */
  void get_ee_subscriptions(
      const evsub_id_t& sub_id,
      std::vector<std::shared_ptr<amf_subscription>>& subscriptions);

  /*
   * Get a list of subscription associated with a particular event
   * @param [const amf_event_t] ev: Event type
   * @param [std::string&] supi: SUPI
   * @param [std::vector<std::shared_ptr<amf_subscription>>&] subscriptions:
   * store the list of the subscription associated with this event type
   * @return void
   */
  void get_ee_subscriptions(
      const amf_event_type_t& ev, std::string& supi,
      std::vector<std::shared_ptr<amf_subscription>>& subscriptions);

  /*
   * Generate a AMF profile for this instance
   * @param [void]
   * @return void
   */
  void generate_amf_profile();

  /*
   * Store the promise
   * @param [const uint32_t] pid: promise id
   * @param [const boost::shared_ptr<boost::promise<nlohmann::json>>&] p:
   * promise
   * @return void
   */
  void add_promise(
      const uint32_t pid,
      const boost::shared_ptr<boost::promise<nlohmann::json>>& p);

  /*
   * Remove the promise
   * @param [uint32_t] pid: promise id
   * @return void
   */
  void remove_promise(const uint32_t id);

  /*
   * Generate an unique value for promise id
   * @param void
   * @return generated promise id
   */
  static uint64_t generate_promise_id() {
    return oai::utils::uint_uid_generator<uint64_t>::get_instance().get_uid();
  }

  /*
   * Generate an unique value for promise id and associate this generated id
   * with the promise itself
   * @param [const uint32_t] pid: promise id
   * @param [const boost::shared_ptr<boost::promise<nlohmann::json>>&] p:
   * promise
   * @return void
   */
  void store_promise(
      uint32_t& pid,
      const boost::shared_ptr<boost::promise<nlohmann::json>>& p);

  /*
   * Trigger the response from API server
   * @param [const uint32_t] pid: promise id
   * @param [const nlohmann::json&] json_data: result for the corresponding
   * promise
   * @return void
   */
  void trigger_process_response(
      const uint32_t pid, const nlohmann::json& json_data);

  /*
   * Send request to SBI task to trigger PDU session release to SMF
   * @param [const std::shared_ptr<ue_context>&]uc: UE Context
   * @return void
   */
  void trigger_pdu_session_release(const std::shared_ptr<ue_context>& uc) const;

  /*
   * Send request to SBI task to trigger UP Deactivation of a PDU session
   * towards SMF
   * @param [const std::shared_ptr<ue_context>&]uc: UE Context
   * @return void
   */
  void trigger_pdu_session_up_deactivation(
      const std::shared_ptr<ue_context>& uc) const;

  /*
   * Send request to SBI task to trigger UP Activation of all PDU sessions
   * associated with an UE context towards SMF
   * @param [const std::shared_ptr<ue_context>&]uc: UE Context
   * @return true if activation success, otherwise return false
   */
  bool trigger_pdu_session_up_activation(
      const std::shared_ptr<ue_context>& uc) const;

  /*
   * Send request to SBI task to trigger UP Activation of a PDU session towards
   * SMF
   * @param [uint8_t]pdu_session_id: PDU Session ID
   * @param [const std::shared_ptr<ue_context>&]uc: UE Context
   * @return true if activation success, otherwise return false
   */
  bool trigger_pdu_session_up_activation(
      uint8_t pdu_session_id, const std::shared_ptr<ue_context>& uc) const;

  /*
   * Get the AMF's NF instance
   * @return NF instance in string format
   */
  std::string get_nf_instance() const;

  /*
   * Generate an AMFStatusChangeSubscribe ID
   * @param [void]
   * @return the generated reference
   */
  std::string generate_amf_status_change_sub_id_generator();

  /*
   * Store an AMF Status Change Subcription
   * @param [const std::string&] subscription_id: Subscription ID
   * @param [const std::shared_ptr<oai::_3gpp::model::SubscriptionData>&] sd: a
   * shared pointer stored information of the subscription
   * @return the generated reference
   */
  void add_amf_status_change_subscription(
      const std::string& subscription_id,
      const std::shared_ptr<oai::_3gpp::model::SubscriptionData>& sd);

  /*
   * Remove an AMF Status Change Subcription
   * @param [const std::string&] subscription_id: Subscription ID
   * @return true if success otherwise return false
   */
  bool remove_amf_status_change_subscription(
      const std::string& subscription_id);

  /*
   * Update an AMF Status Change Subcription
   * @param [const std::string&] subscription_id: Subscription ID
   * @param [const std::shared_ptr<oai::_3gpp::model::SubscriptionData>&] sd: a
   * shared pointer stored information of the subscription
   * @return true if success otherwise return false
   */

  bool update_amf_status_change_subscription(
      const std::string& subscription_id,
      const std::shared_ptr<oai::_3gpp::model::SubscriptionData>& sd);

  /*
   * Get a list of AMF Status Change Subscription URIs based on the GUAMI list
   * @param [const std::vector<oai::_3gpp::model::Guami>&] guamis: list of
   * GUAMIs
   * @return a vector of notification URIs
   */

  std::vector<std::string> get_amf_status_change_subscription_uris(
      const std::vector<oai::_3gpp::model::Guami>& guamis);

  /*
   * Perform AMF Status Change Notification to the subscribed NF instances
   * @param [const oai::_3gpp::model::StatusChange&] status_change: status
   * change information
   * @return void
   */
  void perform_amf_status_change_notification(
      const oai::_3gpp::model::StatusChange& status_change);

  //============================================================================
  // DID-based Mutual Authentication Methods
  //============================================================================

  // =========================================================================
  // NOTE: The following mutual auth responder/initiator handlers are DEPRECATED.
  // They are kept as stubs returning HTTP 410 (Gone) for backward compatibility.
  // BCF single-direction auth (NF → BCF → token) replaces all mutual auth.
  // =========================================================================

  /** @deprecated Use BCF single-direction auth instead */
  bool handle_did_auth_init(
      const std::string& initiator_did,
      const std::string& nonce,
      uint64_t timestamp,
      const std::string& nf_type,
      const std::string& source_address,
      nlohmann::json& response_json,
      int& http_code);

  /** @deprecated Use BCF single-direction auth instead */
  bool handle_did_auth_complete(
      const std::string& session_id,
      const std::string& initiator_signature,
      const std::string& initiator_did,
      const std::string& responder_did,
      uint64_t timestamp_ms,
      const std::string& source_address,
      nlohmann::json& response_json,
      int& http_code);

  /** @deprecated Use BCF single-direction auth instead */
  bool handle_did_auth_status(
      const std::string& session_id,
      nlohmann::json& response_json,
      int& http_code);

  /*
   * Check if a peer NF is already authenticated
   * @param [const std::string&] peer_did: Peer's DID
   * @return true if authenticated
   */
  bool is_peer_authenticated(const std::string& peer_did);

  /*
   * Get authentication token for a peer NF
   * @param [const std::string&] peer_did: Peer's DID
   * @return authentication token or empty string if not authenticated
   */
  std::string get_peer_auth_token(const std::string& peer_did);

  /*
   * Initialize BCF authentication module
   * @return true if initialization successful
   */
  bool init_did_auth_module();

  /*
   * Initialize local security audit and BCF session-digest anchoring.
   */
  void init_security_audit_module();

  /*
   * Cleanup expired BCF authentication sessions and challenges
   * @return void
   */
  void cleanup_did_auth_sessions();

  // =========================================================================
  // BCF 单向认证接口（新版 - 替代旧版 NF-A/NF-B 双向认证）
  // =========================================================================

  /*
   * Authenticate to BCF to get a token for accessing a target NF
   *
   * New auth flow: NF → BCF (init) → challenge → NF signs → BCF (verify) → token
   * NF authenticates its own identity to BCF, token represents NF's BCF identity
   *
   * @param [std::string&] auth_token: Output BCF-issued self token
   * @return true if authentication successful
   */
  bool authenticate_to_bcf(std::string& auth_token);

  /*
   * Ensure we have a valid BCF self token
   * Uses cached token if available and valid, otherwise initiates new auth
   *
   * @param [std::string&] auth_token: Output BCF-issued self token
   * @return true if we have a valid token
   */
  bool ensure_bcf_auth(std::string& auth_token);

  /*
   * Check if BCF authentication is enabled
   * @return true if BCF auth module is enabled
   */
  bool is_did_auth_enabled() const { return m_did_auth_enabled; }

  /*
   * Get local DID loaded from the DID auth module.
   */
  std::string get_local_did() const;

  /*
   * Get AMF NF instance ID
   * @return AMF NF instance ID
   */
  std::string get_nf_instance_id() const { return amf_instance_id; }

  oai::common::audit::security_audit* get_security_audit() const {
    return m_security_audit.get();
  }

  bool submit_security_audit_summary(
      const oai::common::audit::security_audit_summary& summary,
      std::string& response_body,
      std::uint32_t& response_code);

  /*
   * Build a compact AMF profile for AMF -> AUSF UE authentication requests.
   * The profile is derived from the locally cached NF profile plus config data.
   */
  nlohmann::json build_amf_profile_for_ausf_request() const;

  /*
   * Get current BCF lifecycle state
   * @return current BcfLifecycleState
   */
  BcfLifecycleState get_bcf_state() const;

  /*
   * Check if AMF is registered with BCF
   * @return true if state >= BCF_REGISTERED
   */
  bool is_bcf_registered() const;

  /*
   * Trigger BCF authentication after successful registration
   * Called from BCF registration response handler.
   * Enforces: only allowed when state == BCF_REGISTERED
   */
  void trigger_bcf_auth_after_registration();
};

}  // namespace amf_application

#endif
