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

#include "amf_app.hpp"

#include <algorithm>
#include <cctype>
#include <chrono>
#include <filesystem>
#include <fstream>
#include <optional>
#include <random>
#include <set>
#include <sstream>
#include <gmp.h>

#include <boost/uuid/random_generator.hpp>
#include <boost/uuid/uuid_io.hpp>

#include "3gpp_29.500.h"
#include "DlNasTransport.hpp"
#include "GlobalRanNodeId.h"
#include "NonUeN2InfoSubscriptionCreatedData.h"
#include "RegistrationContextContainer.h"
#include "UeN1N2InfoSubscriptionCreatedData.h"
#include "amf_config.hpp"
#include "amf_conversions.hpp"
#include "amf_n1.hpp"
#include "amf_n2.hpp"
#include "amf_sbi.hpp"
#include "amf_sbi_helper.hpp"
#include "amf_statistics.hpp"
#include "http_client.hpp"
#include "itti.hpp"
#include "itti_msg_sbi.hpp"
#include "ngap_app.hpp"
#include "output_wrapper.hpp"
#include "utils.hpp"
#include "AccessAndMobilitySubscriptionData.h"
#include "SmfSelectionSubscriptionData.h"
#include "PolicyAssociation.h"
#include "Amf3GppAccessRegistration.h"
#include "Av5gAka.h"
#include "SearchResult.h"
#include "NFProfile.h"
#include "PcfInfo.h"
#include "PolicyUpdate.h"
#include "AmRequestedValueRep.h"
#include "UeContextInSmfData.h"
#include "UeContextInfo.h"
#include "ProvideLocInfo.h"

// BCF Authentication / Identity headers
#include "did_auth/did_auth.hpp"
#include "did_auth/signature_utils.hpp"
#include "did_auth/bcf_interface.hpp"

// BCF NF Discovery framework (common module)
#include "bcf_nf_discovery.hpp"
#include "security_audit.hpp"

// Latency measurement probes (enabled via -DENABLE_LATENCY_PROBE)
#include "latency_probe.hpp"

using namespace std::chrono;
using namespace oai::ngap;
using namespace oai::nas;
using namespace amf_application;
using namespace oai::config;
using namespace oai::amf::api;

extern amf_app* amf_app_inst;
extern itti_mw* itti_inst;
extern std::shared_ptr<oai::http::http_client> http_client_inst;
amf_n2* amf_n2_inst   = nullptr;
amf_n1* amf_n1_inst   = nullptr;
amf_sbi* amf_sbi_inst = nullptr;
extern std::unique_ptr<oai::config::amf_config> amf_cfg;
extern statistics stacs;

void amf_app_task(void*);

//------------------------------------------------------------------------------
amf_app::amf_app()
    : m_amf_ue_ngap_id2ue_ctx(),
      m_ue_ctx_key(),
      m_supi2ue_ctx(),
      m_curl_handle_responses_sbi(),
      m_did_auth(nullptr),
      m_did_auth_enabled(false),
      m_security_audit(nullptr),
      m_bcf_state(BcfLifecycleState::INIT),
      m_shutdown_state(amf_shutdown_state_t::RUNNING),
      m_shutdown_started(false),
      m_shutdown_terminate_sent(false),
      m_http_server_stopped(false),
      m_bcf_dereg_in_progress(false),
      m_bcf_dereg_done(false),
      m_bcf_dereg_success(false),
      m_bcf_dereg_uri(),
      m_bcf_dereg_http_code(0) {
  amf_ue_ngap_id2ue_ctx     = {};
  ue_ctx_key                = {};
  supi2ue_ctx               = {};
  curl_handle_responses_sbi = {};

  Logger::amf_app().startup("Creating AMF application functionality layer");
  if (itti_inst->create_task(TASK_AMF_APP, amf_app_task, nullptr)) {
    Logger::amf_app().error("Cannot create task TASK_AMF_APP");
    throw std::runtime_error("Cannot create task TASK_AMF_APP");
  }

  try {
    amf_n1_inst = new amf_n1();
    amf_n2_inst =
        new amf_n2(std::string(inet_ntoa(amf_cfg->n2.addr4)), amf_cfg->n2.port);
    amf_sbi_inst = new amf_sbi();
  } catch (std::exception& e) {
    Logger::amf_app().error("Cannot create AMF APP: %s", e.what());
    throw;
  }

  // Generate NF Instance ID (UUID)
  generate_uuid();

  // Generate an AMF profile
  generate_amf_profile();

  // Initialize BCF authentication module (if enabled in config)
  // This loads DID/keys but does NOT register or authenticate to BCF yet.
  // The actual flow is: init_did_auth_module() → start() → register_to_bcf()
  //   → registration response handler → trigger_bcf_auth_after_registration()
  init_did_auth_module();
  init_security_audit_module();

  timer_id_t tid = itti_inst->timer_setup(
      amf_cfg->statistics_interval, 0, TASK_AMF_APP,
      TASK_AMF_APP_PERIODIC_STATISTICS);
  Logger::amf_app().startup("Started timer (%d)", tid);
}

//------------------------------------------------------------------------------
amf_app::~amf_app() {
  Logger::amf_app().info("Starting destruction of amf_app object");

  if (amf_n1_inst) {
    Logger::amf_app().info("Deleting N1 object");
    delete amf_n1_inst;
  }
  if (amf_n2_inst) {
    Logger::amf_app().info("Deleting N2 object");
    delete amf_n2_inst;
  }
  if (amf_sbi_inst) {
    Logger::amf_app().info("Deleting SBI object");
    delete amf_sbi_inst;
  }
}

//------------------------------------------------------------------------------
void amf_app_task(void*) {
  const task_id_t task_id = TASK_AMF_APP;
  itti_inst->notify_task_ready(task_id);
  do {
    std::shared_ptr<itti_msg> shared_msg = itti_inst->receive_msg(task_id);
    auto* msg                            = shared_msg.get();
    timer_id_t tid                       = {};
    switch (msg->msg_type) {
      case NAS_SIG_ESTAB_REQ: {
        Logger::amf_app().debug("Received NAS_SIG_ESTAB_REQ");
        itti_nas_signalling_establishment_request* m =
            dynamic_cast<itti_nas_signalling_establishment_request*>(msg);
        amf_app_inst->handle_itti_message(std::ref(*m));
      } break;

      case N1N2_MESSAGE_TRANSFER_REQ: {
        Logger::amf_app().debug("Received N1N2_MESSAGE_TRANSFER_REQ");
        itti_n1n2_message_transfer_request* m =
            dynamic_cast<itti_n1n2_message_transfer_request*>(msg);
        amf_app_inst->handle_itti_message(std::ref(*m));
      } break;

      case NON_UE_N2_MESSAGE_TRANSFER_REQ: {
        Logger::amf_app().debug("Received NON_UE_N2_MESSAGE_TRANSFER_REQ");
        itti_non_ue_n2_message_transfer_request* m =
            dynamic_cast<itti_non_ue_n2_message_transfer_request*>(msg);
        amf_app_inst->handle_itti_message(std::ref(*m));
      } break;

      case SBI_N1_MESSAGE_NOTIFICATION: {
        Logger::amf_app().debug("Received SBI_N1_MESSAGE_NOTIFICATION");
        itti_sbi_n1_message_notification* m =
            dynamic_cast<itti_sbi_n1_message_notification*>(msg);
        amf_app_inst->handle_itti_message(std::ref(*m));
      } break;

      case SBI_N1N2_MESSAGE_SUBSCRIBE: {
        Logger::amf_app().debug("Received SBI_N1N2_MESSAGE_SUBSCRIBE");
        itti_sbi_n1n2_message_subscribe* m =
            dynamic_cast<itti_sbi_n1n2_message_subscribe*>(msg);
        amf_app_inst->handle_itti_message(std::ref(*m));
      } break;

      case SBI_N1N2_MESSAGE_UNSUBSCRIBE: {
        Logger::amf_app().debug("Received SBI_N1N2_MESSAGE_UNSUBSCRIBE");
        itti_sbi_n1n2_message_unsubscribe* m =
            dynamic_cast<itti_sbi_n1n2_message_unsubscribe*>(msg);
        amf_app_inst->handle_itti_message(std::ref(*m));
      } break;

      case SBI_NON_UE_N2_INFO_SUBSCRIBE: {
        Logger::amf_app().debug("Received SBI_NON_UE_N2_INFO_SUBSCRIBE");
        itti_sbi_non_ue_n2_info_subscribe* m =
            dynamic_cast<itti_sbi_non_ue_n2_info_subscribe*>(msg);
        amf_app_inst->handle_itti_message(std::ref(*m));
      } break;

      case SBI_NON_UE_N2_INFO_UNSUBSCRIBE: {
        Logger::amf_app().debug("Received SBI_NON_UE_N2_INFO_UNSUBSCRIBE");
        itti_sbi_non_ue_n2_info_unsubscribe* m =
            dynamic_cast<itti_sbi_non_ue_n2_info_unsubscribe*>(msg);
        amf_app_inst->handle_itti_message(std::ref(*m));
      } break;

      case SBI_PDU_SESSION_RELEASE_NOTIF: {
        Logger::amf_app().debug("Received SBI_PDU_SESSION_RELEASE_NOTIF");
        itti_sbi_pdu_session_release_notif* m =
            dynamic_cast<itti_sbi_pdu_session_release_notif*>(msg);
        amf_app_inst->handle_itti_message(std::ref(*m));
      } break;

      case SBI_AMF_CONFIGURATION: {
        Logger::amf_app().debug("Received SBI_AMF_CONFIGURATION");
        itti_sbi_amf_configuration* m =
            dynamic_cast<itti_sbi_amf_configuration*>(msg);
        amf_app_inst->handle_itti_message(std::ref(*m));
      } break;

      case SBI_UPDATE_AMF_CONFIGURATION: {
        Logger::amf_app().debug("Received SBI_UPDATE_AMF_CONFIGURATION");
        itti_sbi_update_amf_configuration* m =
            dynamic_cast<itti_sbi_update_amf_configuration*>(msg);
        amf_app_inst->handle_itti_message(std::ref(*m));
      } break;

      // BCF (Blockchain Function) Response Messages
      case SBI_BCF_REGISTER_NF_INSTANCE_RESPONSE: {
        Logger::amf_app().debug(
            "Received SBI_BCF_REGISTER_NF_INSTANCE_RESPONSE");
        itti_sbi_bcf_register_nf_instance_response* m =
            dynamic_cast<itti_sbi_bcf_register_nf_instance_response*>(msg);
        amf_app_inst->handle_itti_message(std::ref(*m));
      } break;

      case SBI_BCF_UPDATE_NF_INSTANCE_RESPONSE: {
        Logger::amf_app().debug("Received SBI_BCF_UPDATE_NF_INSTANCE_RESPONSE");
        itti_sbi_bcf_update_nf_instance_response* m =
            dynamic_cast<itti_sbi_bcf_update_nf_instance_response*>(msg);
        amf_app_inst->handle_itti_message(std::ref(*m));
      } break;

      case SBI_BCF_DEREGISTER_NF_INSTANCE_RESPONSE: {
        Logger::amf_app().debug(
            "Received SBI_BCF_DEREGISTER_NF_INSTANCE_RESPONSE");
        itti_sbi_bcf_deregister_nf_instance_response* m =
            dynamic_cast<itti_sbi_bcf_deregister_nf_instance_response*>(msg);
        amf_app_inst->handle_itti_message(std::ref(*m));
      } break;

      case SBI_REGISTER_WITH_UDM_RESPONSE: {
        Logger::amf_app().debug("Received SBI_REGISTER_WITH_UDM_RESPONSE");
        itti_sbi_register_with_udm_response* m =
            dynamic_cast<itti_sbi_register_with_udm_response*>(msg);
        amf_app_inst->handle_itti_message(std::ref(*m));
      } break;

      case SBI_RETRIEVE_AM_DATA_RESPONSE: {
        Logger::amf_app().debug("Received SBI_RETRIEVE_AM_DATA_RESPONSE");
        itti_sbi_retrieve_am_data_response* m =
            dynamic_cast<itti_sbi_retrieve_am_data_response*>(msg);
        amf_app_inst->handle_itti_message(std::ref(*m));
      } break;

      case SBI_RETRIEVE_SMF_SELECTION_SUBSCRIPTION_DATA_RESPONSE: {
        Logger::amf_app().debug(
            "Received SBI_RETRIEVE_SMF_SELECTION_SUBSCRIPTION_DATA_RESPONSE");
        itti_sbi_retrieve_smf_selection_subscription_data_response* m =
            dynamic_cast<
                itti_sbi_retrieve_smf_selection_subscription_data_response*>(
                msg);
        amf_app_inst->handle_itti_message(std::ref(*m));
      } break;

      case SBI_AM_POLICY_ASSOCIATION_RESPONSE: {
        Logger::amf_app().debug("Received SBI_AM_POLICY_ASSOCIATION_RESPONSE");
        itti_sbi_am_policy_association_response* m =
            dynamic_cast<itti_sbi_am_policy_association_response*>(msg);
        amf_app_inst->handle_itti_message(std::ref(*m));
      } break;

      case SBI_AM_POLICY_ASSOCIATION_TERMINATION_RESPONSE: {
        Logger::amf_app().debug(
            "Received SBI_AM_POLICY_ASSOCIATION_TERMINATION_RESPONSE");
        itti_sbi_am_policy_association_termination_response* m =
            dynamic_cast<itti_sbi_am_policy_association_termination_response*>(
                msg);
        amf_app_inst->handle_itti_message(std::ref(*m));
      } break;

      case SBI_AM_POLICY_ASSOCIATION_UPDATE_RESPONSE: {
        Logger::amf_app().debug(
            "Received SBI_AM_POLICY_ASSOCIATION_UPDATE_RESPONSE");
        itti_sbi_am_policy_association_update_response* m =
            dynamic_cast<itti_sbi_am_policy_association_update_response*>(msg);
        amf_app_inst->handle_itti_message(std::ref(*m));
      } break;

      case SBI_AM_POLICY_UPDATE_NOTIFICATION: {
        Logger::amf_app().debug("Received SBI_AM_POLICY_UPDATE_NOTIFICATION");
        itti_sbi_am_policy_update_notification* m =
            dynamic_cast<itti_sbi_am_policy_update_notification*>(msg);
        amf_app_inst->handle_itti_message(std::ref(*m));
      } break;

      case SBI_AM_POLICY_ASSOCIATION_TERMINATION_NOTIFICATION: {
        Logger::amf_app().debug(
            "Received SBI_AM_POLICY_ASSOCIATION_TERMINATION_NOTIFICATION");
        itti_sbi_am_policy_association_termination_notification* m =
            dynamic_cast<
                itti_sbi_am_policy_association_termination_notification*>(msg);
        amf_app_inst->handle_itti_message(std::ref(*m));
      } break;

      case SBI_UE_CONTEXT_IN_SMF_DATA_RETRIEVAL_RESPONSE: {
        Logger::amf_app().debug(
            "Received SBI_UE_CONTEXT_IN_SMF_DATA_RETRIEVAL_RESPONSE");
        itti_sbi_ue_context_in_smf_data_retrieval_response* m =
            dynamic_cast<itti_sbi_ue_context_in_smf_data_retrieval_response*>(
                msg);
        amf_app_inst->handle_itti_message(std::ref(*m));
      } break;

      case SBI_AMF_STATUS_CHANGE_SUBSCRIBE_REQUEST: {
        itti_sbi_amf_status_change_subscribe_request* m =
            dynamic_cast<itti_sbi_amf_status_change_subscribe_request*>(msg);
        Logger::amf_app().debug("Received %s", m->get_msg_name());

        amf_app_inst->handle_itti_message(std::ref(*m));
      } break;

      case SBI_AMF_STATUS_CHANGE_UNSUBSCRIBE_REQUEST: {
        itti_sbi_amf_status_change_unsubscribe_request* m =
            dynamic_cast<itti_sbi_amf_status_change_unsubscribe_request*>(msg);
        Logger::amf_app().debug("Received %s", m->get_msg_name());

        amf_app_inst->handle_itti_message(std::ref(*m));
      } break;

      case SBI_AMF_STATUS_CHANGE_SUBSCRIBE_MODIFY: {
        itti_sbi_amf_status_change_subscribe_modify* m =
            dynamic_cast<itti_sbi_amf_status_change_subscribe_modify*>(msg);
        Logger::amf_app().debug("Received %s", m->get_msg_name());

        amf_app_inst->handle_itti_message(std::ref(*m));
      } break;

      case SBI_PROVIDE_DOMAIN_SELECTION_INFO: {
        itti_sbi_provide_domain_selection_info* m =
            dynamic_cast<itti_sbi_provide_domain_selection_info*>(msg);
        Logger::amf_app().debug("Received %s", m->get_msg_name());

        amf_app_inst->handle_itti_message(std::ref(*m));
      } break;

      case SBI_PROVIDE_LOCATION_INFO: {
        itti_sbi_provide_location_info* m =
            dynamic_cast<itti_sbi_provide_location_info*>(msg);
        Logger::amf_app().debug("Received %s", m->get_msg_name());

        amf_app_inst->handle_itti_message(std::ref(*m));
      } break;

      case TIME_OUT: {
        if (itti_msg_timeout* to = dynamic_cast<itti_msg_timeout*>(msg)) {
          switch (to->arg1_user) {
            case TASK_AMF_APP_PERIODIC_STATISTICS:
              tid = itti_inst->timer_setup(
                  amf_cfg->statistics_interval, 0, TASK_AMF_APP,
                  TASK_AMF_APP_PERIODIC_STATISTICS);
              stacs.display();
              break;
            // NRF timeout handlers removed - BCF has replaced NRF
            default:
              Logger::amf_app().info(
                  "No handler for timer(%d) with arg1_user(%d) ", to->timer_id,
                  to->arg1_user);
          }
        }
      } break;

      case TERMINATE: {
        if (itti_msg_terminate* terminate =
                dynamic_cast<itti_msg_terminate*>(msg)) {
          Logger::amf_app().info("Received terminate message");
          itti_inst->mark_task_ended(task_id);
          return;
        }
      } break;
      default:
        Logger::amf_app().info("No handler for msg type %d", msg->msg_type);
    }
  } while (true);
}

//------------------------------------------------------------------------------
void amf_app::start() {
  if (amf_app_inst) {
    // Register to BCF for DID-based identity (NRF has been replaced by BCF)
    if (amf_cfg->register_bcf) {
      // State transition: INIT/DID_READY → REGISTRATION_IN_PROGRESS
      {
        std::lock_guard<std::mutex> lock(m_bcf_state_mutex);
        m_bcf_state = BcfLifecycleState::REGISTRATION_IN_PROGRESS;
      }
      Logger::amf_app().info(
          "[AMF][BCF-REG] State → REGISTRATION_IN_PROGRESS, "
          "sending registration request to BCF");
      register_to_bcf();
    }
  }
}

//------------------------------------------------------------------------------
void amf_app::stop() {
  if (m_security_audit) {
    m_security_audit->record_event(
        "NF_DEREGISTER", "deregister_requested", "started", "", "BCF",
        "BCF");
    m_security_audit->finalize_all("amf_shutdown");
  }
  trigger_shutdown();
}

//------------------------------------------------------------------------------
void amf_app::set_shutdown_state(const amf_shutdown_state_t state) {
  const auto old_state = m_shutdown_state.exchange(state);
  if (old_state != state) {
    Logger::amf_app().debug(
        "[AMF][Shutdown] State %s -> %s",
        shutdown_state_to_string(old_state), shutdown_state_to_string(state));
  }
}

//------------------------------------------------------------------------------
std::string amf_app::build_bcf_nf_instance_uri() const {
  std::string bcf_uri         = {};
  std::string bcf_api_version = "v1";
  if (!amf_cfg->bcf_addr.api_version.empty()) {
    bcf_api_version = amf_cfg->bcf_addr.api_version;
  }

  if (!amf_cfg->bcf_addr.uri_root.empty()) {
    bcf_uri = amf_cfg->bcf_addr.uri_root;
  } else {
    std::string host = inet_ntoa(amf_cfg->bcf_addr.ipv4_addr);
    uint16_t port    = amf_cfg->bcf_addr.port;
    bcf_uri          = "http://" + host + ":" + std::to_string(port);
  }

  bcf_uri += "/nbcf_management/" + bcf_api_version + "/nf_instances/" +
             amf_instance_id;
  return bcf_uri;
}

//------------------------------------------------------------------------------
bool amf_app::is_shutdown_in_progress() const {
  return m_shutdown_started.load() &&
         (m_shutdown_state.load() != amf_shutdown_state_t::STOPPED);
}

//------------------------------------------------------------------------------
amf_shutdown_state_t amf_app::get_shutdown_state() const {
  return m_shutdown_state.load();
}

//------------------------------------------------------------------------------
bool amf_app::should_reject_new_async_request(const std::string& action) const {
  if (!is_shutdown_in_progress()) {
    return false;
  }

  Logger::amf_app().warn(
      "[AMF][Shutdown] Skip %s because shutdown is in progress",
      action.c_str());
  return true;
}

//------------------------------------------------------------------------------
void amf_app::notify_http_server_stopped() {
  m_http_server_stopped.store(true);
  if (m_shutdown_started.load()) {
    set_shutdown_state(amf_shutdown_state_t::HTTP_SERVER_STOPPED);
  }
  m_shutdown_cv.notify_all();
}

//------------------------------------------------------------------------------
void amf_app::notify_shutdown_complete() {
  set_shutdown_state(amf_shutdown_state_t::STOPPED);
  m_shutdown_cv.notify_all();
}

//------------------------------------------------------------------------------
void amf_app::dispatch_terminate_to_tasks() {
  if (m_shutdown_terminate_sent.exchange(true)) {
    Logger::amf_app().warn(
        "[AMF][Shutdown] Terminate already dispatched, ignore duplicate request");
    return;
  }

  Logger::amf_app().info("[AMF][Shutdown] Start terminating tasks");
  set_shutdown_state(amf_shutdown_state_t::TERMINATE_DISPATCHED);

  if (!itti_inst) {
    Logger::amf_app().warn(
        "[AMF][Shutdown] ITTI instance is null, cannot dispatch terminate");
    return;
  }

  itti_inst->send_terminate_msg(TASK_AMF_APP);
}

//------------------------------------------------------------------------------
void amf_app::trigger_shutdown(uint32_t timeout_ms) {
  if (m_shutdown_started.exchange(true)) {
    Logger::amf_app().warn(
        "[AMF][Shutdown] Shutdown already in progress, ignore duplicated request");
    return;
  }

  Logger::amf_app().info("[AMF][Shutdown] Shutdown requested");
  set_shutdown_state(amf_shutdown_state_t::SHUTDOWN_REQUESTED);

  // From this point forward, all new outbound async flows must be rejected by
  // should_reject_new_async_request(). The waiting below happens in the signal
  // / shutdown control thread, not in TASK_AMF_APP, so the ITTI consumer can
  // still receive and process SBI_BCF_DEREGISTER_NF_INSTANCE_RESPONSE.

  bool http_server_stopped = m_http_server_stopped.load();
  if (!http_server_stopped) {
    Logger::amf_app().info(
        "[AMF][Shutdown] Waiting for HTTP server stop confirmation before BCF deregistration");

    std::unique_lock<std::mutex> lock(m_shutdown_mutex);
    http_server_stopped = m_shutdown_cv.wait_for(
        lock, std::chrono::milliseconds(std::min<uint32_t>(timeout_ms, 1000)),
        [&]() { return m_http_server_stopped.load(); });
  }

  if (http_server_stopped) {
    set_shutdown_state(amf_shutdown_state_t::HTTP_SERVER_STOPPED);
    Logger::amf_app().info(
        "[AMF][Shutdown] HTTP server stopped, start BCF deregistration");
  } else {
    Logger::amf_app().warn(
        "[AMF][Shutdown] HTTP server stop notification not received, continue shutdown sequence");
  }

  if (!amf_cfg->register_bcf || !is_bcf_registered()) {
    Logger::amf_app().info(
        "[AMF][Shutdown] AMF is not registered with BCF, skip deregistration");
    m_bcf_dereg_done.store(true);
    m_bcf_dereg_success.store(false);
    dispatch_terminate_to_tasks();
    return;
  }

  {
    std::lock_guard<std::mutex> lock(m_shutdown_mutex);
    m_bcf_dereg_done.store(false);
    m_bcf_dereg_success.store(false);
    m_bcf_dereg_http_code = 0;
    m_bcf_dereg_uri.clear();
  }

  if (!deregister_from_bcf()) {
    Logger::amf_app().warn(
        "[AMF][Shutdown] Failed to dispatch BCF deregistration request, continue shutdown");
    dispatch_terminate_to_tasks();
    return;
  }

  bool dereg_completed = false;
  bool dereg_success   = false;
  uint32_t http_code   = 0;
  std::string dereg_uri;

  {
    std::unique_lock<std::mutex> lock(m_shutdown_mutex);
    dereg_completed = m_shutdown_cv.wait_for(
        lock, std::chrono::milliseconds(timeout_ms), [&]() {
          return m_bcf_dereg_done.load();
        });
    dereg_success = m_bcf_dereg_success.load();
    http_code     = m_bcf_dereg_http_code;
    dereg_uri     = m_bcf_dereg_uri;
  }

  if (!dereg_completed) {
    Logger::amf_app().warn(
        "[AMF][Shutdown] Deregistration timeout after %u ms, continue shutdown",
        timeout_ms);
  } else if (!dereg_success) {
    Logger::amf_app().warn(
        "[AMF][Shutdown] BCF deregistration completed with non-success response (HTTP %u, uri=%s)",
        http_code, dereg_uri.c_str());
  } else {
    Logger::amf_app().info(
        "[AMF][Shutdown] BCF deregistration completed, start terminating tasks");
  }

  dispatch_terminate_to_tasks();
}

//------------------------------------------------------------------------------
uint64_t amf_app::generate_amf_ue_ngap_id() {
  uint64_t tmp = 0;
  tmp          = __sync_fetch_and_add(&amf_app_ue_ngap_id_generator, 1);
  return tmp & 0x00ffffffff;  // 40 bits
}

//------------------------------------------------------------------------------
bool amf_app::ran_amf_id_2_ue_context(
    const std::string& ue_context_key, std::shared_ptr<ue_context>& uc) const {
  std::shared_lock lock(m_ue_ctx_key);
  if (ue_ctx_key.count(ue_context_key) > 0) {
    if (ue_ctx_key.at(ue_context_key) == nullptr) return false;
    uc = ue_ctx_key.at(ue_context_key);
    return true;
  }
  Logger::amf_app().warn(
      "No existing UE context associated with key %s", ue_context_key.c_str());
  return false;
}

//------------------------------------------------------------------------------
void amf_app::set_ran_amf_id_2_ue_context(
    const std::string& ue_context_key, const std::shared_ptr<ue_context>& uc) {
  std::unique_lock lock(m_ue_ctx_key);
  ue_ctx_key[ue_context_key] = uc;
}

//------------------------------------------------------------------------------
bool amf_app::supi_2_ue_context(
    const std::string& supi, std::shared_ptr<ue_context>& uc) const {
  std::shared_lock lock(m_supi2ue_ctx);
  if (supi2ue_ctx.count(supi) > 0) {
    if (supi2ue_ctx.at(supi) == nullptr) {
      Logger::amf_app().warn("No UE context with UE SUPI %s", supi.c_str());
      return false;
    }
    uc = supi2ue_ctx.at(supi);
    return true;
  }
  Logger::amf_app().warn("No UE context with UE SUPI %s", supi.c_str());
  return false;
}

//------------------------------------------------------------------------------
void amf_app::set_supi_2_ue_context(
    const std::string& supi, const std::shared_ptr<ue_context>& uc) {
  std::unique_lock lock(m_supi2ue_ctx);
  supi2ue_ctx[supi] = uc;
}

//------------------------------------------------------------------------------
bool amf_app::find_pdu_session_context(
    const std::string& supi, const std::uint8_t pdu_session_id,
    std::shared_ptr<pdu_session_context>& psc) {
  std::shared_ptr<ue_context> uc = {};
  if (!supi_2_ue_context(supi, uc)) return false;
  if (!uc->find_pdu_session_context(pdu_session_id, psc)) return false;
  return true;
}

//------------------------------------------------------------------------------
bool amf_app::get_pdu_sessions_context(
    const std::string& supi,
    std::vector<std::shared_ptr<pdu_session_context>>& sessions_ctx) {
  std::shared_ptr<ue_context> uc = {};
  if (!supi_2_ue_context(supi, uc)) return false;
  if (!uc->get_pdu_sessions_context(sessions_ctx)) return false;
  return true;
}

//------------------------------------------------------------------------------
bool amf_app::update_pdu_sessions_context(
    const std::string& supi, uint8_t pdu_session_id,
    const oai::_3gpp::model::SmContextStatusNotification& statusNotification) {
  std::shared_ptr<ue_context> uc = {};
  if (!supi_2_ue_context(supi, uc)) return false;
  auto pdu_session_status = statusNotification.getStatus().getEnumValue();
  if (pdu_session_status == oai::_3gpp::model::SmContextStatus_anyOf::
                                eSmContextStatus_anyOf::RELEASED) {
    if (uc->remove_pdu_sessions_context(pdu_session_id)) return true;
  }
  return false;
}

//------------------------------------------------------------------------------
evsub_id_t amf_app::generate_ev_subscription_id() {
  return evsub_id_generator.get_uid();
}

//------------------------------------------------------------------------------
n1n2sub_id_t amf_app::generate_n1n2_message_subscription_id() {
  return n1n2sub_id_generator.get_uid();
}

std::string amf_app::generate_amf_status_change_sub_id_generator() {
  return std::to_string(amf_status_change_sub_id_generator.get_uid());
}

//------------------------------------------------------------------------------
void amf_app::handle_itti_message(
    itti_n1n2_message_transfer_request& itti_msg) {
  if (itti_msg.is_ppi_set) {  // Paging procedure
    Logger::amf_app().info(
        "Handle ITTI N1N2 Message Transfer Request for Paging");
    auto paging_msg = std::make_shared<itti_paging>(TASK_AMF_APP, TASK_AMF_N2);
    amf_n1_inst->supi_2_amf_id(itti_msg.supi, paging_msg->amf_ue_ngap_id);
    amf_n1_inst->supi_2_ran_id(itti_msg.supi, paging_msg->ran_ue_ngap_id);

    int ret = itti_inst->send_msg(paging_msg);
    if (ret != RETURNok) {
      Logger::amf_app().error(
          "Could not send ITTI message %s to task TASK_AMF_N2",
          paging_msg->get_msg_name());
    }
  } else if (itti_msg.is_nrppa_pdu_set) {
    Logger::amf_app().info(
        "Handle ITTI N1N2 Message Transfer Request for NRPPa PDU");
    auto dl_msg = std::make_shared<itti_downlink_ue_associated_nrppa_transport>(
        TASK_AMF_APP, TASK_AMF_N2);
    dl_msg->nrppa_pdu  = bstrcpy(itti_msg.nrppa_pdu);
    dl_msg->routing_id = bstrcpy(itti_msg.routing_id);
    amf_n1_inst->supi_2_amf_id(itti_msg.supi, dl_msg->amf_ue_ngap_id);
    amf_n1_inst->supi_2_ran_id(itti_msg.supi, dl_msg->ran_ue_ngap_id);
    int ret = itti_inst->send_msg(dl_msg);
    if (ret != RETURNok) {
      Logger::amf_app().error(
          "Could not send ITTI message %s to task TASK_AMF_N2",
          dl_msg->get_msg_name());
    }
  } else if (itti_msg.is_n1sm_set or itti_msg.is_n2sm_set) {
    Logger::amf_app().info("Handle ITTI N1N2 Message Transfer Request");
    auto dl_msg =
        std::make_shared<itti_downlink_nas_transfer>(TASK_AMF_APP, TASK_AMF_N1);

    if (itti_msg.is_n1sm_set) {
      // Encode DL NAS TRANSPORT message(NAS message)
      auto dl = std::make_unique<DlNasTransport>();
      dl->SetPayloadContainerType(kN1SmInformation);
      dl->SetPayloadContainer(
          (uint8_t*) bdata(bstrcpy(itti_msg.n1sm)), blength(itti_msg.n1sm));
      dl->SetPduSessionId(itti_msg.pdu_session_id);

      uint32_t msg_len = dl->GetLength();
      Logger::nas_mm().debug("Size of DL NAS Transport message %ld", msg_len);
      uint8_t nas[msg_len] = {0};
      int encoded_size     = dl->Encode(nas, msg_len);
      oai::utils::output_wrapper::print_buffer(
          "amf_app", "N1N2 message transfer", nas, encoded_size);
      dl_msg->dl_nas = blk2bstr(nas, encoded_size);
    }

    if (!itti_msg.is_n2sm_set) {
      dl_msg->is_n2sm_set = false;
    } else {
      dl_msg->n2sm           = bstrcpy(itti_msg.n2sm);
      dl_msg->pdu_session_id = itti_msg.pdu_session_id;
      dl_msg->is_n2sm_set    = true;
      dl_msg->n2sm_info_type = itti_msg.n2sm_info_type;
    }
    amf_n1_inst->supi_2_amf_id(itti_msg.supi, dl_msg->amf_ue_ngap_id);
    amf_n1_inst->supi_2_ran_id(itti_msg.supi, dl_msg->ran_ue_ngap_id);

    int ret = itti_inst->send_msg(dl_msg);
    if (ret != RETURNok) {
      Logger::amf_app().error(
          "Could not send ITTI message %s to task TASK_AMF_N1",
          dl_msg->get_msg_name());
    }
  } else {
    Logger::amf_app().warn("Unknown N1N2 Message Transfer Request type");
  }
}

//------------------------------------------------------------------------------
void amf_app::handle_itti_message(
    itti_non_ue_n2_message_transfer_request& itti_msg) {
  if (itti_msg.is_nrppa_pdu_set) {
    Logger::amf_app().info(
        "Handle ITTI Non UE N2 Message Transfer Request for NRPPa PDU");
    auto dl_msg =
        std::make_shared<itti_downlink_non_ue_associated_nrppa_transport>(
            TASK_AMF_APP, TASK_AMF_N2);
    dl_msg->nrppa_pdu  = bstrcpy(itti_msg.nrppa_pdu);
    dl_msg->routing_id = bstrcpy(itti_msg.routing_id);

    dl_msg->global_ran_node_list = itti_msg.global_ran_node_list;

    int ret = itti_inst->send_msg(dl_msg);
    if (ret != RETURNok) {
      Logger::amf_app().error(
          "Could not send ITTI message %s to task TASK_AMF_N2",
          dl_msg->get_msg_name());
    }
  } else {
    Logger::amf_app().info(
        "Handle ITTI Non UE N2 Message Transfer Request: No NRPPa PDU "
        "available!");
  }
}

//------------------------------------------------------------------------------
void amf_app::handle_itti_message(
    itti_nas_signalling_establishment_request& itti_msg) {
  uint64_t amf_ue_ngap_id        = INVALID_AMF_UE_NGAP_ID;
  std::shared_ptr<ue_context> uc = {};

  // Generate amf_ue_ngap_id if necessary
  if ((amf_ue_ngap_id = itti_msg.amf_ue_ngap_id) == INVALID_AMF_UE_NGAP_ID) {
    amf_ue_ngap_id = generate_amf_ue_ngap_id();
  }

  // Get UE context, if the context doesn't exist, create a new one
  std::string ue_context_key =
      amf_conv::get_ue_context_key(itti_msg.ran_ue_ngap_id, amf_ue_ngap_id);
  if (!ran_amf_id_2_ue_context(ue_context_key, uc)) {
    Logger::amf_app().debug(
        "No existing UE Context, Create a new one with ran_amf_id %s",
        ue_context_key.c_str());
    uc = std::make_shared<ue_context>();
    set_ran_amf_id_2_ue_context(ue_context_key, uc);
  }

  // Update AMF UE NGAP ID
  std::shared_ptr<ue_ngap_context> unc = {};
  if (!amf_n2_inst->ran_ue_id_2_ue_ngap_context(
          itti_msg.ran_ue_ngap_id, itti_msg.gnb_id, unc)) {
    Logger::amf_app().error(
        "Could not find UE NGAP Context with ran_ue_ngap_id "
        "(" GNB_UE_NGAP_ID_FMT
        "), gNB ID "
        "(" GNB_ID_FMT ")",
        itti_msg.ran_ue_ngap_id, itti_msg.gnb_id);
  } else {
    unc->amf_ue_ngap_id = amf_ue_ngap_id;
    amf_n2_inst->set_amf_ue_ngap_id_2_ue_ngap_context(amf_ue_ngap_id, unc);
  }

  // Store related information
  uc->cgi = itti_msg.cgi;
  uc->tai = itti_msg.tai;
  if (itti_msg.rrc_cause != -1)
    uc->rrc_estb_cause = (e_Ngap_RRCEstablishmentCause) itti_msg.rrc_cause;
  if (itti_msg.ueCtxReq == -1)
    uc->is_ue_context_request = false;
  else
    uc->is_ue_context_request = true;

  uc->ran_ue_ngap_id = itti_msg.ran_ue_ngap_id;
  uc->amf_ue_ngap_id = amf_ue_ngap_id;
  uc->gnb_id         = itti_msg.gnb_id;

  std::string guti   = {};
  bool is_guti_valid = false;
  if (itti_msg.is_5g_s_tmsi_present) {
    guti = amf_conv::tmsi_to_guti(
        itti_msg.tai.mcc, itti_msg.tai.mnc, amf_cfg->guami.region_id,
        itti_msg._5g_s_tmsi);
    is_guti_valid = true;
    Logger::amf_app().debug("Receiving GUTI %s", guti.c_str());
  }

  // Send NAS PDU to task_amf_n1 for further processing
  auto itti_n1_msg =
      std::make_shared<itti_uplink_nas_data_ind>(TASK_AMF_APP, TASK_AMF_N1);

  itti_n1_msg->amf_ue_ngap_id              = amf_ue_ngap_id;
  itti_n1_msg->ran_ue_ngap_id              = itti_msg.ran_ue_ngap_id;
  itti_n1_msg->is_nas_signalling_estab_req = true;
  itti_n1_msg->nas_msg                     = itti_msg.nas_buf;
  itti_n1_msg->mcc                         = itti_msg.tai.mcc;
  itti_n1_msg->mnc                         = itti_msg.tai.mnc;
  itti_n1_msg->is_guti_valid               = is_guti_valid;
  if (is_guti_valid) {
    itti_n1_msg->guti = guti;
  }

  int ret = itti_inst->send_msg(itti_n1_msg);
  if (0 != ret) {
    Logger::amf_app().error(
        "Could not send ITTI message %s to task TASK_AMF_N1",
        itti_n1_msg->get_msg_name());
  }
}

//------------------------------------------------------------------------------
void amf_app::handle_itti_message(itti_sbi_n1_message_notification& itti_msg) {
  Logger::amf_app().info(
      "Target AMF, handling a N1 Message Notification from the initial AMF");

  // Step 1. Get UE, gNB related information

  // Get NAS message (RegistrationRequest, this message included
  // in N1 Message Notify is actually is RegistrationRequest from UE to the
  // initial AMF)
  bstring n1sm = nullptr;
  amf_conv::msg_str_2_msg_hex(itti_msg.n1sm, n1sm);

  // get RegistrationContextContainer including gNB info
  // UE context information, N1 message from UE, AN address
  oai::_3gpp::model::RegistrationContextContainer registration_context =
      itti_msg.notification_msg.getRegistrationCtxtContainer();

  // Step 2. Create gNB context if necessary

  // TODO: How to get SCTP-related information and establish a new SCTP
  // connection between the Target AMF and gNB?
  std::shared_ptr<gnb_context> gc = {};

  // GlobalRAN Node ID (~in NGSetupRequest)
  oai::_3gpp::model::GlobalRanNodeId ran_node_id =
      registration_context.getRanNodeId();
  // RAN UE NGAP ID
  uint32_t ran_ue_ngap_id = registration_context.getAnN2ApId();
  uint32_t gnb_id         = {};

  if (ran_node_id.gNbIdIsSet()) {
    oai::_3gpp::model::GNbId gnb_id_model = ran_node_id.getGNbId();
    try {
      gnb_id = std::stoul(gnb_id_model.getGNBValue(), nullptr, 10);
    } catch (const std::exception& e) {
      Logger::amf_app().warn(
          "Error when converting from string to uint32_t for gNB Value: %s",
          e.what());
      return;
    }

    gc->gnb_id = gnb_id;
    // TODO:   gc->gnb_name
    // TODO: DefaultPagingDRX
    // TODO: Supported TA List
    amf_n2_inst->set_gnb_id_2_gnb_context(gnb_id, gc);
  }

  // UserLocation getUserLocation()
  // std::string getAnN2IPv4Addr()
  // AllowedNssai getAllowedNssai()
  // std::vector<ConfiguredSnssai>& getConfiguredNssai();
  // rejectedNssaiInPlmn
  // rejectedNssaiInTa
  // std::string getInitialAmfName()

  // Step 3. Create UE Context
  oai::_3gpp::model::UeContext ue_ctx = registration_context.getUeContext();
  std::string supi                    = {};
  std::shared_ptr<ue_context> uc      = {};

  if (ue_ctx.supiIsSet()) {
    supi = ue_ctx.getSupi();
    // Update UE Context
    if (!supi_2_ue_context(supi, uc)) {
      // Create a new UE Context
      Logger::amf_app().debug(
          "No existing UE Context, Create a new one with SUPI %s",
          supi.c_str());
      uc                 = std::shared_ptr<ue_context>(new ue_context());
      uc->amf_ue_ngap_id = INVALID_AMF_UE_NGAP_ID;
      uc->supi           = supi;
      uc->gnb_id         = gnb_id;
      set_supi_2_ue_context(supi, uc);
    }
  }

  // TODO: 5gMmCapability
  // TODO: MmContext
  // TODO: PduSessionContext

  uint64_t amf_ue_ngap_id = INVALID_AMF_UE_NGAP_ID;
  // Generate AMF UE NGAP ID if necessary
  if (!uc) {  // No UE context existed
    amf_ue_ngap_id = generate_amf_ue_ngap_id();
  } else {
    if ((amf_ue_ngap_id = uc->amf_ue_ngap_id) == INVALID_AMF_UE_NGAP_ID) {
      amf_ue_ngap_id = generate_amf_ue_ngap_id();
    }
  }

  std::string ue_context_key =
      amf_conv::get_ue_context_key(ran_ue_ngap_id, amf_ue_ngap_id);
  if (!ran_amf_id_2_ue_context(ue_context_key, uc)) {
    if (!uc) {
      // Create a new UE Context
      Logger::amf_app().debug(
          "Create a new UE Context with UE Context Key",
          ue_context_key.c_str());
      uc         = std::make_shared<ue_context>();
      uc->gnb_id = gnb_id;
    }
    set_ran_amf_id_2_ue_context(ue_context_key, uc);
  }

  // Update info for UE context
  uc->amf_ue_ngap_id = amf_ue_ngap_id;
  uc->ran_ue_ngap_id = ran_ue_ngap_id;
  // RrcEstCause
  if (registration_context.rrcEstCauseIsSet()) {
    uint8_t rrc_cause = {};
    try {
      rrc_cause =
          std::stoul(registration_context.getRrcEstCause(), nullptr, 10);
    } catch (const std::exception& e) {
      Logger::amf_app().warn(
          "Error when converting from string to int for RrcEstCause: %s",
          e.what());
      rrc_cause = 0;
    }

    uc->rrc_estb_cause = (e_Ngap_RRCEstablishmentCause) rrc_cause;
  }
  // ueContextRequest
  uc->is_ue_context_request = registration_context.isUeContextRequest();

  // Step 4. Create UE NGAP Context if necessary
  // Create/Update UE NGAP Context
  std::shared_ptr<ue_ngap_context> unc = {};
  if (!amf_n2_inst->ran_ue_id_2_ue_ngap_context(ran_ue_ngap_id, gnb_id, unc)) {
    Logger::amf_app().debug(
        "Create a new UE NGAP context with ran_ue_ngap_id " GNB_UE_NGAP_ID_FMT,
        ran_ue_ngap_id);
    unc = std::shared_ptr<ue_ngap_context>(new ue_ngap_context());
    amf_n2_inst->set_ran_ue_ngap_id_2_ue_ngap_context(
        ran_ue_ngap_id, gnb_id, unc);
  }

  // Store related information into UE NGAP context
  unc->ran_ue_ngap_id = ran_ue_ngap_id;
  // TODO:  unc->sctp_stream_recv
  // TODO: unc->sctp_stream_send
  // TODO: gc->next_sctp_stream
  // TODO: unc->gnb_assoc_id
  // TODO: unc->tai

  // Step 5. Trigger the procedure following RegistrationRequest

  auto itti_n1_msg =
      std::make_shared<itti_uplink_nas_data_ind>(TASK_AMF_APP, TASK_AMF_N1);

  itti_n1_msg->amf_ue_ngap_id              = amf_ue_ngap_id;
  itti_n1_msg->ran_ue_ngap_id              = ran_ue_ngap_id;
  itti_n1_msg->is_nas_signalling_estab_req = true;
  itti_n1_msg->nas_msg                     = bstrcpy(n1sm);
  itti_n1_msg->mcc                         = ran_node_id.getPlmnId().getMcc();
  itti_n1_msg->mnc                         = ran_node_id.getPlmnId().getMnc();
  itti_n1_msg->is_guti_valid               = false;

  int ret = itti_inst->send_msg(itti_n1_msg);
  if (0 != ret) {
    Logger::amf_app().error(
        "Could not send ITTI message %s to task TASK_AMF_N1",
        itti_n1_msg->get_msg_name());
  }

  oai::utils::utils::bdestroy_wrapper(&n1sm);
  return;
}

//------------------------------------------------------------------------------
void amf_app::handle_itti_message(itti_sbi_n1n2_message_subscribe& itti_msg) {
  Logger::amf_app().info("Handle an N1N2MessageSubscribe from a NF");

  // Generate a subscription ID Id and store the corresponding information in a
  // map (subscription id, info)
  n1n2sub_id_t n1n2sub_id = generate_n1n2_message_subscription_id();
  auto subscription_data =
      std::make_shared<oai::_3gpp::model::UeN1N2InfoSubscriptionCreateData>(
          itti_msg.subscription_data);
  add_n1n2_message_subscription(
      itti_msg.ue_cxt_id, n1n2sub_id, subscription_data);

  std::string location = amf_sbi_helper::get_amf_n1n2_message_subscribe_uri(
      amf_cfg->sbi, itti_msg.ue_cxt_id, std::to_string((uint32_t) n1n2sub_id));

  // Trigger the response from AMF API Server
  oai::_3gpp::model::UeN1N2InfoSubscriptionCreatedData created_data = {};
  created_data.setN1n2NotifySubscriptionId(
      std::to_string((uint32_t) n1n2sub_id));
  nlohmann::json created_data_json = {};
  to_json(created_data_json, created_data);

  nlohmann::json response_data        = {};
  response_data[kSbiResponseJsonData] = created_data;
  response_data[kSbiResponseHttpResponseCode] =
      static_cast<uint32_t>(oai::common::sbi::http_status_code::CREATED);
  response_data[kSbiResponseHeaderLocation] = location;

  // Notify to the result
  if (itti_msg.promise_id > 0) {
    trigger_process_response(itti_msg.promise_id, response_data);
    return;
  }
}

//------------------------------------------------------------------------------
void amf_app::handle_itti_message(itti_sbi_n1n2_message_unsubscribe& itti_msg) {
  Logger::amf_app().info("Handle an N1N2MessageUnSubscribe from a NF");

  // Process the request and trigger the response from AMF API Server
  nlohmann::json response_data = {};
  if (remove_n1n2_message_subscription(
          itti_msg.ue_cxt_id, itti_msg.subscription_id)) {
    response_data[kSbiResponseHttpResponseCode] =
        static_cast<uint32_t>(oai::common::sbi::http_status_code::NO_CONTENT);
  } else {
    response_data[kSbiResponseHttpResponseCode] =
        static_cast<uint32_t>(oai::common::sbi::http_status_code::BAD_REQUEST);
    oai::_3gpp::model::ProblemDetails problem_details = {};
    // TODO set problem_details
    to_json(response_data["ProblemDetails"], problem_details);
  }

  // Notify to the result
  if (itti_msg.promise_id > 0) {
    trigger_process_response(itti_msg.promise_id, response_data);
    return;
  }
}

//------------------------------------------------------------------------------
void amf_app::handle_itti_message(itti_sbi_non_ue_n2_info_subscribe& itti_msg) {
  Logger::amf_app().info("Handle an NonUEN2InfoSubscribe from a NF");

  // Generate a subscription ID Id and store the corresponding information in a
  // map (subscription id, info)
  n1n2sub_id_t n2sub_id = generate_n1n2_message_subscription_id();
  auto subscription_data =
      std::make_shared<oai::_3gpp::model::NonUeN2InfoSubscriptionCreateData>(
          itti_msg.subscription_data);

  add_non_ue_n2_info_subscription(n2sub_id, subscription_data);

  std::string location = amf_sbi_helper::get_non_ue_n2_info_subscribe_uri(
      amf_cfg->sbi, std::to_string((uint32_t) n2sub_id));

  // Trigger the response from AMF API Server
  oai::_3gpp::model::NonUeN2InfoSubscriptionCreatedData created_data = {};

  created_data.setN2NotifySubscriptionId(std::to_string((uint32_t) n2sub_id));

  nlohmann::json created_data_json = {};
  to_json(created_data_json, created_data);

  nlohmann::json response_data        = {};
  response_data[kSbiResponseJsonData] = created_data;
  response_data[kSbiResponseHttpResponseCode] =
      static_cast<uint32_t>(oai::common::sbi::http_status_code::CREATED);
  response_data[kSbiResponseHeaderLocation] = location;

  // Notify to the result
  if (itti_msg.promise_id > 0) {
    trigger_process_response(itti_msg.promise_id, response_data);
    return;
  }
}

//------------------------------------------------------------------------------
void amf_app::handle_itti_message(
    itti_sbi_non_ue_n2_info_unsubscribe& itti_msg) {
  Logger::amf_app().info("Handle an NonUEN2InfoUnsubscribe from a NF");

  // Process the request and trigger the response from AMF API Server
  nlohmann::json response_data = {};
  if (remove_non_ue_n2_info_subscription(itti_msg.subscription_id)) {
    response_data[kSbiResponseHttpResponseCode] =
        static_cast<uint32_t>(oai::common::sbi::http_status_code::NO_CONTENT);
  } else {
    response_data[kSbiResponseHttpResponseCode] =
        static_cast<uint32_t>(oai::common::sbi::http_status_code::BAD_REQUEST);
    oai::_3gpp::model::ProblemDetails problem_details = {};
    // TODO set problem_details
    to_json(response_data["ProblemDetails"], problem_details);
  }

  // Notify to the result
  if (itti_msg.promise_id > 0) {
    trigger_process_response(itti_msg.promise_id, response_data);
    return;
  }
}
//------------------------------------------------------------------------------
void amf_app::handle_itti_message(
    itti_sbi_pdu_session_release_notif& itti_msg) {
  Logger::amf_app().info("Handle an PDU Session Release notification from SMF");

  // Process the request and trigger the response from AMF API Server
  nlohmann::json response_data = {};
  if (update_pdu_sessions_context(
          itti_msg.ue_id, itti_msg.pdu_session_id,
          itti_msg.smContextStatusNotification)) {
    Logger::amf_app().debug("Update PDU Session Release successfully");

    response_data[kSbiResponseHttpResponseCode] =
        static_cast<uint32_t>(oai::common::sbi::http_status_code::NO_CONTENT);

  } else {
    response_data[kSbiResponseHttpResponseCode] =
        static_cast<uint32_t>(oai::common::sbi::http_status_code::NO_CONTENT);
    // TODO check if we set problem_details
    Logger::amf_app().debug("Update PDU Session Release failed");
  }

  // Notify to the result
  if (itti_msg.promise_id > 0) {
    trigger_process_response(itti_msg.promise_id, response_data);
    return;
  }
}

//------------------------------------------------------------------------------
void amf_app::handle_itti_message(itti_sbi_amf_configuration& itti_msg) {
  Logger::amf_app().info("Handle an SBIAMFConfiguration from a NF");

  // Process the request and trigger the response from AMF API Server
  nlohmann::json response_data        = {};
  response_data[kSbiResponseJsonData] = {};
  if (read_amf_configuration(response_data[kSbiResponseJsonData])) {
    Logger::amf_app().debug(
        "AMF configuration:\n %s",
        response_data[kSbiResponseJsonData].dump().c_str());
    response_data[kSbiResponseHttpResponseCode] =
        static_cast<uint32_t>(oai::common::sbi::http_status_code::OK);
  } else {
    response_data[kSbiResponseHttpResponseCode] =
        static_cast<uint32_t>(oai::common::sbi::http_status_code::BAD_REQUEST);
    oai::_3gpp::model::ProblemDetails problem_details = {};
    // TODO set problem_details
    to_json(response_data["ProblemDetails"], problem_details);
  }

  // Notify to the result
  if (itti_msg.promise_id > 0) {
    trigger_process_response(itti_msg.promise_id, response_data);
    return;
  }
}

//---------------------------------------------------------------------------------------------
void amf_app::handle_itti_message(itti_sbi_update_amf_configuration& itti_msg) {
  Logger::amf_app().info("Handle a request UpdateAMFConfiguration from a NF");

  // Process the request and trigger the response from AMF API Server
  nlohmann::json response_data        = {};
  response_data[kSbiResponseJsonData] = itti_msg.configuration;

  if (update_amf_configuration(response_data[kSbiResponseJsonData])) {
    Logger::amf_app().debug(
        "AMF configuration:\n %s",
        response_data[kSbiResponseJsonData].dump().c_str());
    response_data[kSbiResponseHttpResponseCode] =
        static_cast<uint32_t>(oai::common::sbi::http_status_code::OK);

    // Update AMF profile
    generate_amf_profile();

    // Update AMF profile - register to BCF (NRF has been replaced by BCF)
    if (amf_cfg->support_features.enable_nf_registration) {
      register_to_bcf();
    }

  } else {
    response_data[kSbiResponseHttpResponseCode] =
        static_cast<uint32_t>(oai::common::sbi::http_status_code::BAD_REQUEST);
    oai::_3gpp::model::ProblemDetails problem_details = {};
    // TODO set problem_details
    to_json(response_data["ProblemDetails"], problem_details);
  }

  // Notify to the result
  if (itti_msg.promise_id > 0) {
    trigger_process_response(itti_msg.promise_id, response_data);
    return;
  }
}

//------------------------------------------------------------------------------
// BCF (Blockchain Function) Response Handlers
//------------------------------------------------------------------------------
void amf_app::handle_itti_message(
    itti_sbi_bcf_register_nf_instance_response& r) {
  Logger::amf_app().info("[AMF][BCF-REG] Registration response received from BCF");

  // --- Latency probe: reconstruct trace_id in app layer ---
  auto lp_tid = LP_BUILD_ID("AMF", "BCF_REG", r.amf_instance_id);

  if ((r.http_response_code == oai::common::sbi::http_status_code::CREATED) or
      (r.http_response_code == oai::common::sbi::http_status_code::OK)) {
    Logger::amf_app().info(
        "[AMF][BCF-REG] Registration SUCCESS at %s (HTTP %d)",
        r.bcf_uri.c_str(), r.http_response_code);

    LP_END(lp_tid, "REG_SUCCESS");

    // State transition: REGISTRATION_IN_PROGRESS → BCF_REGISTERED
    {
      std::lock_guard<std::mutex> lock(m_bcf_state_mutex);
      m_bcf_state = BcfLifecycleState::BCF_REGISTERED;
    }
    Logger::amf_app().info(
        "[AMF][BCF-REG] State → BCF_REGISTERED");

    if (m_security_audit) {
      m_security_audit->record_event(
          "NF_REGISTER", "register_response_received", "success", "",
          "BCF", "BCF",
          {{"http_status", r.http_response_code}, {"bcf_uri", r.bcf_uri}});
    }

    // Now that registration is confirmed, trigger BCF authentication
    // This is the ONLY place where auth is allowed to start after registration
    trigger_bcf_auth_after_registration();

  } else {
    Logger::amf_app().error(
        "[AMF][BCF-REG] Registration FAILED (HTTP %d)",
        r.http_response_code);

    LP_CANCEL(lp_tid);

    // State transition → FAILED
    {
      std::lock_guard<std::mutex> lock(m_bcf_state_mutex);
      m_bcf_state = BcfLifecycleState::FAILED;
    }
    Logger::amf_app().error(
        "[AMF][BCF-REG] State → FAILED, BCF authentication will NOT be attempted");

    if (m_security_audit) {
      m_security_audit->record_event(
          "NF_REGISTER", "register_response_received", "failure", "",
          "BCF", "BCF",
          {{"http_status", r.http_response_code}, {"bcf_uri", r.bcf_uri}});
    }
  }
}

//------------------------------------------------------------------------------
void amf_app::handle_itti_message(itti_sbi_bcf_update_nf_instance_response& r) {
  Logger::amf_app().debug("Handle BCF NF Update response");
  if ((r.http_response_code == oai::common::sbi::http_status_code::OK) or
      (r.http_response_code ==
       oai::common::sbi::http_status_code::NO_CONTENT)) {
    Logger::amf_app().debug("AMF has successfully updated registration at BCF");
  } else {
    Logger::amf_app().error(
        "AMF update at BCF failed with HTTP code: %d", r.http_response_code);
  }
}

//------------------------------------------------------------------------------
bool amf_app::handle_bcf_notification(const std::string& body_json) {
  if (!m_did_auth || !m_did_auth_enabled) {
    Logger::amf_app().warn("DIDAuth not available to handle BCF notification");
    return false;
  }

  try {
    // Forward to underlying DIDAuth module
    if (m_did_auth && m_did_auth->get_module()) {
      return m_did_auth->get_module()->handle_bcf_notification(body_json);
    }
    Logger::amf_app().warn("DIDAuth module pointer is null");
    return false;
  } catch (const std::exception& e) {
    Logger::amf_app().error("Exception while handling BCF notification: %s", e.what());
    return false;
  }
}

//------------------------------------------------------------------------------
void amf_app::handle_itti_message(
    itti_sbi_bcf_deregister_nf_instance_response& r) {
  Logger::amf_app().info(
      "[AMF][BCF-REG] Deregistration response received from SBI");

  const bool success =
      (r.http_response_code == oai::common::sbi::http_status_code::NO_CONTENT);

  {
    std::lock_guard<std::mutex> lock(m_shutdown_mutex);
    m_bcf_dereg_uri            = r.bcf_uri;
    m_bcf_dereg_http_code      = r.http_response_code;
    m_bcf_dereg_done.store(true);
    m_bcf_dereg_success.store(success);
    m_bcf_dereg_in_progress.store(false);
  }

  if (m_shutdown_started.load()) {
    set_shutdown_state(amf_shutdown_state_t::BCF_DEREG_DONE);
  }

  if (success) {
    Logger::amf_app().info(
        "[AMF][BCF-REG] Deregistration SUCCESS at %s (HTTP %d)",
        r.bcf_uri.c_str(), r.http_response_code);
  } else {
    Logger::amf_app().warn(
        "[AMF][BCF-REG] Deregistration FAILED at %s (HTTP %d)",
        r.bcf_uri.c_str(), r.http_response_code);
  }

  m_shutdown_cv.notify_all();
}

//------------------------------------------------------------------------------
void amf_app::remove_promise(const uint32_t id) {
  std::unique_lock lock(m_curl_handle_responses_sbi);
  curl_handle_responses_sbi.erase(id);
}

//------------------------------------------------------------------------------
void amf_app::handle_itti_message(itti_sbi_register_with_udm_response& r) {
  Logger::amf_app().debug("Handle SBI_REGISTER_WITH_UDM_RESPONSE response");

  uint32_t response_code = oai::common::sbi::http_status_code::NO_RESPONSE;
  if (r.response_data.find(kSbiResponseHttpResponseCode) !=
      r.response_data.end()) {
    response_code = r.response_data[kSbiResponseHttpResponseCode].get<int>();
  }

  if (response_code == oai::common::sbi::http_status_code::NO_CONTENT) {
    // TODO:
  } else if (response_code == oai::common::sbi::http_status_code::CREATED) {
    // Store location
    if (r.response_data.find(kSbiResponseHeaderLocation) !=
        r.response_data.end()) {
      std::shared_ptr<ue_context> uc = {};
      if (supi_2_ue_context(r.supi, uc)) {
        uc->amf_3gpp_access_location =
            r.response_data[kSbiResponseHeaderLocation].get<std::string>();
      }
    }
    // TODO:
  } else if (response_code == oai::common::sbi::http_status_code::OK) {
    // TODO:
  } else {
    Logger::amf_app().debug("AMF has failed to register to UDM.");
  }
}

//------------------------------------------------------------------------------
void amf_app::handle_itti_message(itti_sbi_retrieve_am_data_response& r) {
  Logger::amf_app().debug("Handle SBI_RETRIEVE_AM_DATA_RESPONSE response");

  uint32_t response_code = oai::common::sbi::http_status_code::NO_RESPONSE;
  if (r.response_data.find(kSbiResponseHttpResponseCode) !=
      r.response_data.end()) {
    response_code = r.response_data[kSbiResponseHttpResponseCode].get<int>();
  }

  if (response_code == oai::common::sbi::http_status_code::OK) {
    // Store Access and Mobility Subscription Data
    if (r.response_data.find(kSbiResponseJsonData) != r.response_data.end()) {
      std::shared_ptr<ue_context> uc = {};
      if (supi_2_ue_context(r.supi, uc)) {
        try {
          oai::_3gpp::model::AccessAndMobilitySubscriptionData am_data = {};
          from_json(r.response_data[kSbiResponseJsonData], am_data);
          //  uc->am_data =
          //  std::make_optional<oai::_3gpp::model::AccessAndMobilitySubscriptionData>(am_data);
        } catch (std::exception& e) {
          Logger::amf_app().warn(
              "Could not parse Access and Mobility Subscription Data from "
              "Json");
        }
      }
    }
  } else {
    Logger::amf_app().debug(
        "AMF has failed to get Access and Mobility Subscription Data from "
        "UDM.");
  }
}

//------------------------------------------------------------------------------
void amf_app::handle_itti_message(
    itti_sbi_retrieve_smf_selection_subscription_data_response& r) {
  Logger::amf_app().debug(
      "Handle SBI_RETRIEVE_SMF_SELECTION_SUBSCRIPTION_DATA_RESPONSE response");

  uint32_t response_code = oai::common::sbi::http_status_code::NO_RESPONSE;
  if (r.response_data.find(kSbiResponseHttpResponseCode) !=
      r.response_data.end()) {
    response_code = r.response_data[kSbiResponseHttpResponseCode].get<int>();
  }

  if (response_code == oai::common::sbi::http_status_code::OK) {
    // Store Access and Mobility Subscription Data
    if (r.response_data.find(kSbiResponseJsonData) != r.response_data.end()) {
      std::shared_ptr<ue_context> uc = {};
      if (supi_2_ue_context(r.supi, uc)) {
        try {
          oai::_3gpp::model::SmfSelectionSubscriptionData
              smf_selection_subscription_data = {};
          from_json(
              r.response_data[kSbiResponseJsonData],
              smf_selection_subscription_data);
          //  uc->smf_selection_subscription_data =
          //  std::make_optional<oai::model::udm::SmfSelectionSubscriptionData>(smf_selection_subscription_data);
        } catch (std::exception& e) {
          Logger::amf_app().warn(
              "Could not parse SMF Selection Subscription Data from "
              "Json");
        }
      }
    }
  } else {
    Logger::amf_app().debug(
        "AMF has failed to get SMF Selection Subscription Data from "
        "UDM.");
  }
}

//------------------------------------------------------------------------------
void amf_app::handle_itti_message(itti_sbi_am_policy_association_response& r) {
  Logger::amf_app().debug("Handle SBI_AM_POLICY_ASSOCIATION_RESPONSE response");

  uint32_t response_code = oai::common::sbi::http_status_code::NO_RESPONSE;
  if (r.response_data.find(kSbiResponseHttpResponseCode) !=
      r.response_data.end()) {
    response_code = r.response_data[kSbiResponseHttpResponseCode].get<int>();
  }

  if (response_code == oai::common::sbi::http_status_code::OK) {
    // Store PolicyAssociation
    if (r.response_data.find(kSbiResponseJsonData) != r.response_data.end()) {
      std::shared_ptr<ue_context> uc = {};
      if (supi_2_ue_context(r.supi, uc)) {
        try {
          oai::_3gpp::model::PolicyAssociation policy_association = {};
          from_json(r.response_data[kSbiResponseJsonData], policy_association);
          // Store the policy association in the UE context
          uc->policy_association =
              std::make_optional<oai::_3gpp::model::PolicyAssociation>(
                  policy_association);
          // Store the location of the Policy Association
          if (r.response_data.find(kSbiResponseHeaderLocation) !=
              r.response_data.end()) {
            uc->policy_association_location =
                r.response_data[kSbiResponseHeaderLocation].get<std::string>();
          }
        } catch (std::exception& e) {
          Logger::amf_app().warn(
              "Could not parse the Policy Association from "
              "Json");
        }
      }
    }
  } else {
    Logger::amf_app().debug(
        "AMF has failed to get the Policy Association from "
        "PCF.");
  }
}

//------------------------------------------------------------------------------
void amf_app::handle_itti_message(
    itti_sbi_am_policy_association_termination_response& r) {
  Logger::amf_app().debug(
      "Handle SBI_AM_POLICY_ASSOCIATION_TERMINATION_RESPONSE response");

  uint32_t response_code = oai::common::sbi::http_status_code::NO_RESPONSE;
  if (r.response_data.find(kSbiResponseHttpResponseCode) !=
      r.response_data.end()) {
    response_code = r.response_data[kSbiResponseHttpResponseCode].get<int>();
  }

  if (response_code == oai::common::sbi::http_status_code::NO_CONTENT) {
    // Remove PolicyAssociation
    std::shared_ptr<ue_context> uc = {};
    if (supi_2_ue_context(r.supi, uc)) {
      uc->policy_association_location = {};
      uc->policy_association          = {};
    }
  }
}

//------------------------------------------------------------------------------
void amf_app::handle_itti_message(
    itti_sbi_am_policy_association_update_response& r) {
  Logger::amf_app().debug(
      "Handle SBI_AM_POLICY_ASSOCIATION_UPDATE_RESPONSE response");

  uint32_t response_code = oai::common::sbi::http_status_code::NO_RESPONSE;
  if (r.response_data.find(kSbiResponseHttpResponseCode) !=
      r.response_data.end()) {
    response_code = r.response_data[kSbiResponseHttpResponseCode].get<int>();
  }

  if (response_code == oai::common::sbi::http_status_code::OK) {
    // Process Policy Update

    if (r.response_data.find(kSbiResponseJsonData) != r.response_data.end()) {
      std::shared_ptr<ue_context> uc = {};
      if (supi_2_ue_context(r.supi, uc)) {
        try {
          oai::_3gpp::model::PolicyUpdate policy_update = {};
          from_json(r.response_data[kSbiResponseJsonData], policy_update);

          // Store the updated policy association in the UE context
          oai::_3gpp::model::PolicyAssociation policy_association = {};
          // TODO:
          uc->policy_association =
              std::make_optional<oai::_3gpp::model::PolicyAssociation>(
                  policy_association);

        } catch (std::exception& e) {
          Logger::amf_app().warn(
              "Could not parse the Policy Association from "
              "Json");
        }
      }
    }
  }
}

//------------------------------------------------------------------------------
void amf_app::handle_itti_message(
    itti_sbi_am_policy_association_retrieval_response& r) {
  Logger::amf_app().debug(
      "Handle SBI_AM_POLICY_ASSOCIATION_RETRIEVAL_RESPONSE response");

  uint32_t response_code = oai::common::sbi::http_status_code::NO_RESPONSE;
  if (r.response_data.find(kSbiResponseHttpResponseCode) !=
      r.response_data.end()) {
    response_code = r.response_data[kSbiResponseHttpResponseCode].get<int>();
  }

  if (response_code == oai::common::sbi::http_status_code::OK) {
    // Process PolicyAssociation and update the UE context

    if (r.response_data.find(kSbiResponseJsonData) != r.response_data.end()) {
      std::shared_ptr<ue_context> uc = {};
      if (supi_2_ue_context(r.supi, uc)) {
        try {
          oai::_3gpp::model::PolicyAssociation policy_association = {};
          from_json(r.response_data[kSbiResponseJsonData], policy_association);
          uc->policy_association =
              std::make_optional<oai::_3gpp::model::PolicyAssociation>(
                  policy_association);

        } catch (std::exception& e) {
          Logger::amf_app().warn(
              "Could not parse the Policy Association from "
              "Json");
        }
      }
    }
  }
}

//------------------------------------------------------------------------------
void amf_app::handle_itti_message(
    itti_sbi_am_policy_update_notification& itti_msg) {
  Logger::amf_app().debug("Handle SBI_AM_POLICY_UPDATE_NOTIFICATION");

  nlohmann::json response_data = {};

  std::shared_ptr<ue_context> uc = {};
  if (supi_2_ue_context(itti_msg.supi, uc)) {
    // TODO: Store the updated policy association in the UE context
    oai::_3gpp::model::PolicyAssociation policy_association = {};
    uc->policy_association =
        std::make_optional<oai::_3gpp::model::PolicyAssociation>(
            policy_association);

    // TODO: Prepare the response
    oai::_3gpp::model::AmRequestedValueRep am_requested_value_rep = {};

    response_data[kSbiResponseHttpResponseCode] =
        static_cast<uint32_t>(oai::common::sbi::http_status_code::OK);
    to_json(response_data[kSbiResponseJsonData], am_requested_value_rep);

  } else {
    response_data[kSbiResponseHttpResponseCode] =
        static_cast<uint32_t>(oai::common::sbi::http_status_code::BAD_REQUEST);
    oai::_3gpp::model::ProblemDetails problem_details = {};
    // TODO set problem_details
    to_json(response_data[kSbiResponseJsonData], problem_details);
  }

  // Notify to the result
  if (itti_msg.promise_id > 0) {
    trigger_process_response(itti_msg.promise_id, response_data);
    return;
  }
}

//------------------------------------------------------------------------------
void amf_app::handle_itti_message(
    itti_sbi_am_policy_association_termination_notification& itti_msg) {
  Logger::amf_app().debug(
      "Handle SBI_AM_POLICY_ASSOCIATION_TERMINATION_NOTIFICATION");

  nlohmann::json response_data = {};
  // Process the Termination Notification and clear the policy association

  std::shared_ptr<ue_context> uc = {};
  if (supi_2_ue_context(itti_msg.supi, uc)) {
    uc->policy_association = std::nullopt;
  } else {
    response_data[kSbiResponseHttpResponseCode] =
        static_cast<uint32_t>(oai::common::sbi::http_status_code::BAD_REQUEST);
    oai::_3gpp::model::ProblemDetails problem_details = {};
    // TODO set problem_details
    to_json(response_data[kSbiResponseJsonData], problem_details);
  }

  // Notify to the result
  if (itti_msg.promise_id > 0) {
    trigger_process_response(itti_msg.promise_id, response_data);
    return;
  }
}

//------------------------------------------------------------------------------
void amf_app::handle_itti_message(
    itti_sbi_ue_context_in_smf_data_retrieval_response& r) {
  Logger::amf_app().debug(
      "Handle SBI_UE_CONTEXT_IN_SMF_DATA_RETRIEVAL_RESPONSE response");

  uint32_t response_code = oai::common::sbi::http_status_code::NO_RESPONSE;
  if (r.response_data.find(kSbiResponseHttpResponseCode) !=
      r.response_data.end()) {
    response_code = r.response_data[kSbiResponseHttpResponseCode].get<int>();
  }

  if (response_code == oai::common::sbi::http_status_code::OK) {
    // Process the response

    if (r.response_data.find(kSbiResponseJsonData) != r.response_data.end()) {
      std::shared_ptr<ue_context> uc = {};
      if (supi_2_ue_context(r.supi, uc)) {
        try {
          oai::_3gpp::model::UeContextInSmfData ue_context = {};
          from_json(r.response_data[kSbiResponseJsonData], ue_context);
          // Store the UE Context
          // TODO:
        } catch (std::exception& e) {
          Logger::amf_app().warn(
              "Could not parse the UeContextInSmfData from "
              "Json");
        }
      }
    }
  }
}

//------------------------------------------------------------------------------
void amf_app::handle_itti_message(
    itti_sbi_amf_status_change_subscribe_request& itti_msg) {
  Logger::amf_app().debug("Handle %s", itti_msg.get_msg_name());

  // Generate a subscription ID Id and store the corresponding information in a
  // map (subscription id, subscription data)
  std::string amf_status_change_sub_id =
      generate_amf_status_change_sub_id_generator();

  auto sd = std::make_shared<oai::_3gpp::model::SubscriptionData>(
      itti_msg.subscription_data);
  // Store subscription data
  add_amf_status_change_subscription(amf_status_change_sub_id, sd);

  nlohmann::json response_data = {};
  response_data[kSbiResponseHttpResponseCode] =
      static_cast<uint32_t>(oai::common::sbi::http_status_code::CREATED);
  response_data[kSbiResponseHeaderLocation] =
      amf_sbi_helper::get_amf_status_change_subscribe_uri(
          amf_cfg->sbi, amf_status_change_sub_id);

  // Notify to the result
  if (itti_msg.promise_id > 0) {
    trigger_process_response(itti_msg.promise_id, response_data);
    return;
  }

  return;
}

//------------------------------------------------------------------------------
void amf_app::handle_itti_message(
    itti_sbi_amf_status_change_unsubscribe_request& itti_msg) {
  Logger::amf_app().debug("Handle %s", itti_msg.get_msg_name());

  uint32_t response_code = oai::common::sbi::http_status_code::NO_RESPONSE;

  // Remove subscription data
  if (remove_amf_status_change_subscription(itti_msg.subscription_id)) {
    Logger::amf_app().debug(
        "AMF status change subscription %s is removed",
        itti_msg.subscription_id);
    response_code = oai::common::sbi::http_status_code::NO_CONTENT;
  } else {
    Logger::amf_app().debug(
        "AMF status change subscription %s could not be removed ",
        itti_msg.subscription_id);
    response_code = oai::common::sbi::http_status_code::NOT_FOUND;
  }

  nlohmann::json response_data                = {};
  response_data[kSbiResponseHttpResponseCode] = response_code;

  // Notify to the result
  if (itti_msg.promise_id > 0) {
    trigger_process_response(itti_msg.promise_id, response_data);
    return;
  }

  return;
}

//------------------------------------------------------------------------------
void amf_app::handle_itti_message(
    itti_sbi_amf_status_change_subscribe_modify& itti_msg) {
  Logger::amf_app().debug("Handle %s", itti_msg.get_msg_name());

  // Update subscription data
  auto sd = std::make_shared<oai::_3gpp::model::SubscriptionData>(
      itti_msg.subscription_data);

  uint32_t response_code = oai::common::sbi::http_status_code::NO_RESPONSE;

  if (update_amf_status_change_subscription(itti_msg.subscription_id, sd)) {
    Logger::amf_app().debug(
        "AMF status change subscription %s is updated",
        itti_msg.subscription_id);
    response_code = oai::common::sbi::http_status_code::NO_CONTENT;
  } else {
    Logger::amf_app().debug(
        "AMF status change subscription %s could not be updated ",
        itti_msg.subscription_id);
    response_code = oai::common::sbi::http_status_code::BAD_REQUEST;
  }

  nlohmann::json response_data                = {};
  response_data[kSbiResponseHttpResponseCode] = response_code;

  // Notify to the result
  if (itti_msg.promise_id > 0) {
    trigger_process_response(itti_msg.promise_id, response_data);
    return;
  }

  return;
}

//------------------------------------------------------------------------------
void amf_app::handle_itti_message(
    itti_sbi_provide_domain_selection_info& itti_msg) {
  Logger::amf_app().debug("Handle %s", itti_msg.get_msg_name());

  // TODO: process the request and prepare the response
  uint32_t response_code = oai::common::sbi::http_status_code::OK;

  oai::_3gpp::model::UeContextInfo ue_context_info = {};
  ue_context_info.setSupportVoPS(true);
  nlohmann::json ue_context_info_json = {};
  to_json(ue_context_info_json, ue_context_info);

  nlohmann::json response_data                = {};
  response_data[kSbiResponseJsonData]         = ue_context_info_json;
  response_data[kSbiResponseHttpResponseCode] = response_code;

  // Notify to the result
  if (itti_msg.promise_id > 0) {
    trigger_process_response(itti_msg.promise_id, response_data);
    return;
  }

  return;
}

//------------------------------------------------------------------------------
void amf_app::handle_itti_message(itti_sbi_provide_location_info& itti_msg) {
  Logger::amf_app().debug("Handle %s", itti_msg.get_msg_name());

  nlohmann::json response_data = {};
  uint32_t response_code = oai::common::sbi::http_status_code::BAD_REQUEST;

  std::shared_ptr<ue_context> uc = {};
  if (supi_2_ue_context(itti_msg.ue_context_id, uc)) {
    oai::_3gpp::model::ProvideLocInfo provide_loc_info = {};
    // Current Loc
    provide_loc_info.setCurrentLoc(true);

    // UserLocation
    oai::_3gpp::model::UserLocation user_location = {};
    oai::_3gpp::model::NrLocation nr_location     = {};
    oai::_3gpp::model::Tai tai                    = {};
    oai::_3gpp::model::PlmnId plmn_id             = {};
    plmn_id.setMcc(uc->tai.mcc);
    plmn_id.setMnc(uc->tai.mnc);
    tai.setPlmnId(plmn_id);
    tai.setTac(std::to_string(uc->tai.tac));

    nr_location.setTai(tai);
    // nr_location.setNcgi(uc->cgi);

    oai::_3gpp::model::GNbId gnb_id = {};
    gnb_id.setBitLength(32);
    gnb_id.setGNBValue(std::to_string(uc->gnb_id));
    oai::_3gpp::model::GlobalRanNodeId global_ran_node_id = {};
    global_ran_node_id.setGNbId(gnb_id);
    global_ran_node_id.setPlmnId(plmn_id);
    oai::_3gpp::model::Ncgi ncgi = {};
    // ncgi.setNid(""); //TODO:
    std::string nr_cell_id_str = {};
    amf_conv::int_to_string_hex(uc->cgi.nrCellId, nr_cell_id_str, 9);
    ncgi.setNrCellId(nr_cell_id_str);
    ncgi.setPlmnId(plmn_id);
    // nr_location.setTai(tai);
    nr_location.setGlobalGnbId(global_ran_node_id);
    nr_location.setNcgi(ncgi);
    user_location.setNrLocation(nr_location);

    provide_loc_info.setLocation(user_location);

    // RAT Type
    oai::_3gpp::model::RatType rat_type = {};
    rat_type.setEnumValue(oai::_3gpp::model::RatType_anyOf::eRatType_anyOf::NR);
    provide_loc_info.setRatType(rat_type);

    // Old GUAMI

    nlohmann::json provide_loc_info_json = {};
    to_json(provide_loc_info_json, provide_loc_info);
    response_data[kSbiResponseJsonData] = provide_loc_info_json;
  } else {
    // TODO: problem details
    response_code = oai::common::sbi::http_status_code::BAD_REQUEST;
  }

  response_data[kSbiResponseHttpResponseCode] = response_code;

  // Notify to the result
  if (itti_msg.promise_id > 0) {
    trigger_process_response(itti_msg.promise_id, response_data);
    return;
  }

  return;
}

//------------------------------------------------------------------------------
void amf_app::register_3gpp_access(std::shared_ptr<ue_context>& uc) const {
  if (should_reject_new_async_request("new UDM registration request")) {
    return;
  }

  Logger::amf_app().debug("AMF registers for 3GPP access with UDM");

  oai::_3gpp::model::Amf3GppAccessRegistration registration_data = {};
  // AMF Instance ID
  registration_data.setAmfInstanceId(amf_app_inst->get_nf_instance());
  // Callback URI
  std::string amf_callback_deregistration_notification_uri =
      oai::amf::api::amf_sbi_helper::
          get_amf_callback_deregistration_notification_uri(uc->supi);
  registration_data.setDeregCallbackUri(
      amf_callback_deregistration_notification_uri);
  // Initial Registration
  registration_data.setInitialRegistrationInd(true);
  // TODO: Pei
  // Guami
  oai::_3gpp::model::Guami guami       = {};
  oai::_3gpp::model::PlmnIdNid plmn_id = {};
  for (auto g : amf_cfg->guami_list) {
    if (boost::iequals(uc->tai.mcc, g.mcc) and
        boost::iequals(uc->tai.mnc, g.mnc)) {
      std::string amf_id = {};
      amf_conv::get_amf_id(g.region_id, g.amf_set_id, g.amf_pointer, amf_id);
      guami.setAmfId(amf_id);
      plmn_id.setMcc(g.mcc);
      plmn_id.setMnc(g.mnc);
      guami.setPlmnId(plmn_id);
      break;
    }
  }
  registration_data.setGuami(guami);
  // Rat type
  oai::_3gpp::model::RatType rat_type = {};
  rat_type.setEnumValue(oai::_3gpp::model::RatType_anyOf::eRatType_anyOf::NR);
  registration_data.setRatType(rat_type);

  // Send request to SBI to trigger registering to UDM and wait for the
  // response
  nlohmann::json registration_data_json = {};
  to_json(registration_data_json, registration_data);

  std::shared_ptr<itti_sbi_register_with_udm> itti_msg =
      std::make_shared<itti_sbi_register_with_udm>(TASK_AMF_APP, TASK_AMF_SBI);

  itti_msg->registration_data = registration_data_json;
  itti_msg->supi              = uc->supi;

  int ret = itti_inst->send_msg(itti_msg);
  if (0 != ret) {
    Logger::amf_app().error(
        "Could not send ITTI message %s to task TASK_AMF_SBI",
        itti_msg->get_msg_name());
  }
}

//------------------------------------------------------------------------------
void amf_app::get_access_and_mobility_subscription_data(
    std::shared_ptr<ue_context>& uc) const {
  if (should_reject_new_async_request(
          "new access and mobility subscription data retrieval")) {
    return;
  }

  Logger::amf_app().debug(
      "Retrieving a UE's Access and Mobility Subscription Data from UDM");

  oai::_3gpp::model::PlmnIdNid plmn_id = {};
  plmn_id.setMcc(uc->tai.mcc);
  plmn_id.setMnc(uc->tai.mnc);

  // Generate a promise and associate this promise to the ITTI message
  uint32_t promise_id = {};
  boost::shared_ptr<boost::promise<nlohmann::json>> p =
      boost::make_shared<boost::promise<nlohmann::json>>();
  amf_app_inst->store_promise(promise_id, p);
  boost::shared_future<nlohmann::json> f = p->get_future();
  Logger::amf_app().debug("Promise ID generated %ld", promise_id);

  std::shared_ptr<itti_sbi_retrieve_am_data> itti_msg =
      std::make_shared<itti_sbi_retrieve_am_data>(
          TASK_AMF_APP, TASK_AMF_SBI, promise_id);

  itti_msg->promise_id = promise_id;
  itti_msg->supi       = uc->supi;
  itti_msg->plmn_id    = plmn_id;

  int ret = itti_inst->send_msg(itti_msg);
  if (0 != ret) {
    Logger::amf_app().error(
        "Could not send ITTI message %s to task TASK_AMF_SBI",
        itti_msg->get_msg_name());
  }

  bool is_result_available = true;

  oai::_3gpp::model::AccessAndMobilitySubscriptionData am_data = {};

  // Wait for the response available and process accordingly
  std::optional<nlohmann::json> result_opt = std::nullopt;
  oai::utils::utils::wait_for_result(f, result_opt);
  if (result_opt.has_value()) {
    nlohmann::json result = result_opt.value();
    Logger::amf_app().debug("Got result for promise ID %ld", promise_id);
    if (result.find(kSbiResponseJsonData) != result.end()) {
      Logger::amf_app().debug(
          "Got Access and Mobility Subscription Data Retrievel response from "
          "UDM: %s",
          result[kSbiResponseJsonData].dump());

      uint32_t http_response_code =
          oai::common::sbi::http_status_code::NO_RESPONSE;
      if (result.find(kSbiResponseHttpResponseCode) != result.end()) {
        http_response_code = result[kSbiResponseHttpResponseCode].get<int>();
        if (http_response_code == oai::common::sbi::http_status_code::OK) {
          // Process the content
          try {
            from_json(result[kSbiResponseJsonData], am_data);
            is_result_available = true;
            // TODO: store AM Data
          } catch (std::exception& e) {
            Logger::amf_app().warn(
                "Could not parse Access and Mobility Subscription Data from "
                "Json");
            is_result_available = false;
          }
          // TODO: process locations
        }
      }

    } else {
      is_result_available = false;
    }

  } else {
    is_result_available = false;
  }

  if (!is_result_available) {
    Logger::amf_app().warn(
        "Could not get Access and Mobility Subscription Data from UDM");
  }
}

//------------------------------------------------------------------------------
void amf_app::get_smf_selection_subscription_data(
    std::shared_ptr<ue_context>& uc) const {
  if (should_reject_new_async_request(
          "new SMF selection subscription data retrieval")) {
    return;
  }

  Logger::amf_app().debug(
      "Retrieving SMF Selection Subscription Data from UDM");

  oai::_3gpp::model::PlmnIdNid plmn_id = {};
  plmn_id.setMcc(uc->tai.mcc);
  plmn_id.setMnc(uc->tai.mnc);

  std::shared_ptr<itti_sbi_retrieve_smf_selection_subscription_data> itti_msg =
      std::make_shared<itti_sbi_retrieve_smf_selection_subscription_data>(
          TASK_AMF_APP, TASK_AMF_SBI);

  itti_msg->supi    = uc->supi;
  itti_msg->plmn_id = plmn_id;

  int ret = itti_inst->send_msg(itti_msg);
  if (0 != ret) {
    Logger::amf_app().error(
        "Could not send ITTI message %s to task TASK_AMF_SBI",
        itti_msg->get_msg_name());
  }
}

//------------------------------------------------------------------------------
void amf_app::discover_pcf(std::shared_ptr<ue_context>& uc) {
  if (should_reject_new_async_request("new target NF discovery")) {
    return;
  }

  Logger::amf_app().debug("Discovering PCF for the UE");
  // TODO: enable PCF discovery feature flag:
  // amf_cfg->support_features.enable_pcf_discovery
  if (false) {
    oai::_3gpp::model::PlmnIdNid plmn_id = {};
    plmn_id.setMcc(uc->tai.mcc);
    plmn_id.setMnc(uc->tai.mnc);

    // Generate a promise and associate this promise to the ITTI message
    uint32_t promise_id = {};
    boost::shared_ptr<boost::promise<nlohmann::json>> p =
        boost::make_shared<boost::promise<nlohmann::json>>();
    amf_app_inst->store_promise(promise_id, p);
    boost::shared_future<nlohmann::json> f = p->get_future();
    Logger::amf_app().debug("Promise ID generated %ld", promise_id);

    std::shared_ptr<itti_sbi_pcf_discovery> itti_msg =
        std::make_shared<itti_sbi_pcf_discovery>(
            TASK_AMF_APP, TASK_AMF_SBI, promise_id);

    itti_msg->promise_id = promise_id;
    itti_msg->supi       = uc->supi;
    // itti_msg->snssai     = uc->snssai;
    itti_msg->plmn_id = plmn_id;
    // TODO: add support for PCF Set ID
    // TODO: add support for PCF Group ID
    // itti_msg->dnn = uc->dnn;
    // TODO: add support for PCF Selection Assistance Info and PCF ID(s) serving
    // the established PDU Sessions

    int ret = itti_inst->send_msg(itti_msg);
    if (0 != ret) {
      Logger::amf_app().error(
          "Could not send ITTI message %s to task TASK_AMF_SBI",
          itti_msg->get_msg_name());
    }

    bool is_result_available = false;

    oai::_3gpp::model::SearchResult search_result = {};

    std::string pcf_addr = {};

    // Wait for the response available and process accordingly
    std::optional<nlohmann::json> result_opt = std::nullopt;
    oai::utils::utils::wait_for_result(f, result_opt);
    if (result_opt.has_value()) {
      nlohmann::json result = result_opt.value();
      Logger::amf_app().debug("Got result for promise ID %ld", promise_id);
      if (result.find(kSbiResponseJsonData) != result.end()) {
        Logger::amf_app().debug(
            "Got Search Result response from "
            "NRF: %s",
            result[kSbiResponseJsonData].dump());

        uint32_t http_response_code =
            oai::common::sbi::http_status_code::NO_RESPONSE;
        if (result.find(kSbiResponseHttpResponseCode) != result.end()) {
          http_response_code = result[kSbiResponseHttpResponseCode].get<int>();
          if (http_response_code == oai::common::sbi::http_status_code::OK) {
            // Process the content
            try {
              from_json(result[kSbiResponseJsonData], search_result);
              std::vector<oai::_3gpp::model::NFProfile> nf_instances =
                  search_result.getNfInstances();
              for (auto const& it : nf_instances) {
                // PCF info
                if (it.pcfInfoIsSet()) {
                  oai::_3gpp::model::PcfInfo pcf_info = it.getPcfInfo();
                }

                // TODO: PCF selection

                // IPv4 addresses (get first IP v4 address)
                if (it.ipv4AddressesIsSet()) {
                  if (it.getIpv4Addresses().size() == 0) {
                    Logger::amf_app().warn(
                        "No IPv4 Addresses found in Search Result");
                  } else {
                    pcf_addr = it.getIpv4Addresses().at(0);
                    break;
                  }
                }

                Logger::amf_app().debug("PCF Address: %s", pcf_addr.c_str());
                // TODO: Port
              }

              if (pcf_addr.empty()) {
                Logger::amf_app().warn("No PCF Address found in Search Result");
                is_result_available = false;
              } else {
                // Store PCF URI in UE context
                std::string pcf_uri_root = {};
                uint32_t pcf_port        = DEFAULT_HTTP2_PORT;
                pcf_uri_root.append(pcf_addr).append(":").append(
                    std::to_string(pcf_port));
                uc->pcf_addr.uri_root    = pcf_uri_root;
                uc->pcf_addr.api_version = "v1";  // TODO: get from PCF
                is_result_available      = true;
              }

            } catch (std::exception& e) {
              Logger::amf_app().warn(
                  "Could not parse Search Result from "
                  "Json");
              is_result_available = false;
            }
          }
        }

      } else {
        is_result_available = false;
      }

    } else {
      is_result_available = false;
    }

    if (!is_result_available) {
      Logger::amf_app().warn("Could not get Search Result from NRF");
    }
  } else {
    // Store PCF Addr in UE context
    uc->pcf_addr = amf_cfg->pcf_addr;
  }
}

//------------------------------------------------------------------------------
void amf_app::perform_am_policy_association(std::shared_ptr<ue_context>& uc) {
  if (should_reject_new_async_request("new PCF policy association request")) {
    return;
  }

  Logger::amf_app().debug("Perform AM Policy Association with PCF for the UE");

  oai::_3gpp::model::PolicyAssociationRequest policy_assc_request = {};
  policy_assc_request.setSupi(uc->supi);
  // Set Notification URI
  std::string notification_uri =
      amf_sbi_helper::get_pcf_policy_update_notification_uri(uc->supi);
  policy_assc_request.setNotificationUri(notification_uri);
  // TODO: Add support for Support Features
  std::string support_features = {};
  policy_assc_request.setSuppFeat(support_features);

  // Send request to SBI to trigger AM Policy Associtiation with PCF

  std::shared_ptr<itti_sbi_am_policy_association> itti_msg =
      std::make_shared<itti_sbi_am_policy_association>(
          TASK_AMF_APP, TASK_AMF_SBI);

  itti_msg->policy_assoc_req = policy_assc_request;

  int ret = itti_inst->send_msg(itti_msg);
  if (0 != ret) {
    Logger::amf_app().error(
        "Could not send ITTI message %s to task TASK_AMF_SBI",
        itti_msg->get_msg_name());
  }
}

//------------------------------------------------------------------------------
void amf_app::perform_am_policy_association_termination(
    const std::shared_ptr<ue_context>& uc) {
  if (should_reject_new_async_request(
          "new PCF policy association termination request")) {
    return;
  }

  Logger::amf_app().debug(
      "Perform AM Policy Association Termination with PCF for the UE");

  // Send request to SBI to trigger AM Policy Associtiation Termination with PCF
  std::shared_ptr<itti_sbi_am_policy_association_termination> itti_msg =
      std::make_shared<itti_sbi_am_policy_association_termination>(
          TASK_AMF_APP, TASK_AMF_SBI);

  itti_msg->supi = uc->supi;

  int ret = itti_inst->send_msg(itti_msg);
  if (0 != ret) {
    Logger::amf_app().error(
        "Could not send ITTI message %s to task TASK_AMF_SBI",
        itti_msg->get_msg_name());
  }
}

//------------------------------------------------------------------------------
void amf_app::perform_am_policy_association_update(
    const std::shared_ptr<ue_context>& uc) {
  if (should_reject_new_async_request(
          "new PCF policy association update request")) {
    return;
  }

  Logger::amf_app().debug(
      "Perform AM Policy Association Update with PCF for the UE");

  oai::_3gpp::model::PolicyAssociationUpdateRequest policy_assc_update_request =
      {};
  // Set the info that AMF wants to update e.g., Notification URI, AMBR, Slice
  // MBRS, SMF Selection Data, etc.

  // Send request to SBI to trigger AM Policy Associtiation Update with PCF
  std::shared_ptr<itti_sbi_am_policy_association_update> itti_msg =
      std::make_shared<itti_sbi_am_policy_association_update>(
          TASK_AMF_APP, TASK_AMF_SBI);

  itti_msg->supi                    = uc->supi;
  itti_msg->policy_assoc_update_req = policy_assc_update_request;

  int ret = itti_inst->send_msg(itti_msg);
  if (0 != ret) {
    Logger::amf_app().error(
        "Could not send ITTI message %s to task TASK_AMF_SBI",
        itti_msg->get_msg_name());
  }
}

//------------------------------------------------------------------------------
void amf_app::get_am_policy_association(const std::shared_ptr<ue_context>& uc) {
  if (should_reject_new_async_request(
          "new PCF policy association retrieval request")) {
    return;
  }

  Logger::amf_app().debug("Retrieve AM Policy Association for the UE");

  // Send request to SBI to trigger AM Policy Associtiation Retrieval with PCF
  std::shared_ptr<itti_sbi_am_policy_association_retrieval> itti_msg =
      std::make_shared<itti_sbi_am_policy_association_retrieval>(
          TASK_AMF_APP, TASK_AMF_SBI);

  itti_msg->supi = uc->supi;

  int ret = itti_inst->send_msg(itti_msg);
  if (0 != ret) {
    Logger::amf_app().error(
        "Could not send ITTI message %s to task TASK_AMF_SBI",
        itti_msg->get_msg_name());
  }
}

//------------------------------------------------------------------------------
void amf_app::get_ue_context_in_smf_data(
    const std::shared_ptr<ue_context>& uc) {
  if (should_reject_new_async_request(
          "new UE context in SMF data retrieval request")) {
    return;
  }

  Logger::amf_app().debug("Retrieve UE Context In SMF Data");

  // Send request to SBI to trigger UE Context In SMF Data Retrieval with UDM
  std::shared_ptr<itti_sbi_ue_context_in_smf_data_retrieval> itti_msg =
      std::make_shared<itti_sbi_ue_context_in_smf_data_retrieval>(
          TASK_AMF_APP, TASK_AMF_SBI);
  itti_msg->supi = uc->supi;
  int ret        = itti_inst->send_msg(itti_msg);
  if (0 != ret) {
    Logger::amf_app().error(
        "Could not send ITTI message %s to task TASK_AMF_SBI",
        itti_msg->get_msg_name());
  }
}

//---------------------------------------------------------------------------------------------
bool amf_app::read_amf_configuration(nlohmann::json& json_data) {
  amf_cfg->to_json(json_data);
  return true;
}

//---------------------------------------------------------------------------------------------
bool amf_app::update_amf_configuration(nlohmann::json& json_data) {
  if (stacs.get_number_connected_gnbs() > 0) {
    Logger::amf_app().info(
        "Could not update AMF configuration (connected with gNBs)");
    return false;
  }
  return amf_cfg->from_json(json_data);
}

//---------------------------------------------------------------------------------------------
void amf_app::get_number_registered_ues(uint32_t& num_ues) const {
  std::shared_lock lock(m_amf_ue_ngap_id2ue_ctx);
  num_ues = amf_ue_ngap_id2ue_ctx.size();
  return;
}

//---------------------------------------------------------------------------------------------
uint32_t amf_app::get_number_registered_ues() const {
  std::shared_lock lock(m_amf_ue_ngap_id2ue_ctx);
  return amf_ue_ngap_id2ue_ctx.size();
}

//---------------------------------------------------------------------------------------------
void amf_app::add_n1n2_message_subscription(
    const std::string& ue_ctx_id, const n1n2sub_id_t& sub_id,
    std::shared_ptr<oai::_3gpp::model::UeN1N2InfoSubscriptionCreateData>&
        subscription_data) {
  Logger::amf_app().debug("Add an N1N2 Message Subscribe (Sub ID %d)", sub_id);
  std::unique_lock lock(m_n1n2_message_subscribe);
  n1n2_message_subscribe.emplace(
      std::make_pair(ue_ctx_id, sub_id), subscription_data);
}

//---------------------------------------------------------------------------------------------
bool amf_app::remove_n1n2_message_subscription(
    const std::string& ue_ctx_id, const std::string& sub_id) {
  Logger::amf_app().debug(
      "Remove an N1N2 Message Subscribe (UE Context ID %s, Sub ID %s)",
      ue_ctx_id.c_str(), sub_id.c_str());

  // Verify Subscription ID
  n1n2sub_id_t n1n2sub_id = {};
  try {
    n1n2sub_id = std::stoi(sub_id);
  } catch (const std::exception& err) {
    Logger::amf_app().warn(
        "Received a Unsubscribe Request, couldn't find the corresponding "
        "subscription");
    return false;
  }

  // Remove from the list
  std::unique_lock lock(m_n1n2_message_subscribe);
  if (n1n2_message_subscribe.erase(std::make_pair(ue_ctx_id, n1n2sub_id)) == 1)
    return true;
  else
    return false;
  return true;
}

//---------------------------------------------------------------------------------------------
void amf_app::find_n1n2_info_subscriptions(
    const std::string& ue_ctx_id,
    std::optional<
        oai::_3gpp::model::N1MessageClass_anyOf::eN1MessageClass_anyOf>&
        n1_message_class,
    std::optional<
        oai::_3gpp::model::N2InformationClass_anyOf::eN2InformationClass_anyOf>&
        n2_info_class,
    std::map<
        n1n2sub_id_t,
        std::shared_ptr<oai::_3gpp::model::UeN1N2InfoSubscriptionCreateData>>&
        subscriptions) {
  Logger::amf_app().debug("Find an N1N2 Info Subscription");

  std::shared_lock lock(m_n1n2_message_subscribe);
  for (auto subscription : n1n2_message_subscribe) {
    if ((subscription.first.first == ue_ctx_id)) {
      if (n1_message_class.has_value()) {
        if (subscription.second.get()->getN1MessageClass().getEnumValue() ==
            n1_message_class.value()) {
          subscriptions.insert(
              std::pair<
                  n1n2sub_id_t,
                  std::shared_ptr<
                      oai::_3gpp::model::UeN1N2InfoSubscriptionCreateData>>(
                  subscription.first.second, subscription.second));
        }
      }
      if (n2_info_class.has_value()) {
        if (subscription.second.get()->getN2InformationClass().getEnumValue() ==
            n2_info_class.value()) {
          subscriptions.insert(
              std::pair<
                  n1n2sub_id_t,
                  std::shared_ptr<
                      oai::_3gpp::model::UeN1N2InfoSubscriptionCreateData>>(
                  subscription.first.second, subscription.second));
        }
      }
    }
  }
}

//---------------------------------------------------------------------------------------------
void amf_app::add_non_ue_n2_info_subscription(
    const n1n2sub_id_t& sub_id,
    std::shared_ptr<oai::_3gpp::model::NonUeN2InfoSubscriptionCreateData>&
        subscription_data) {
  Logger::amf_app().debug(
      "Add an Non UE N2 Info Subscribe (Sub ID %d)", sub_id);
  std::unique_lock lock(m_non_ue_n2_info_subscribe);
  non_ue_n2_info_subscribe.emplace(std::make_pair(sub_id, subscription_data));
}

//---------------------------------------------------------------------------------------------
bool amf_app::remove_non_ue_n2_info_subscription(const std::string& sub_id) {
  Logger::amf_app().debug(
      "Remove an Non UE N2 Info Unsubscribe (Sub ID %s)", sub_id.c_str());

  // Verify Subscription ID
  n1n2sub_id_t n2sub_id = {};
  try {
    n2sub_id = std::stoi(sub_id);
  } catch (const std::exception& err) {
    Logger::amf_app().warn(
        "Received a Unsubscribe Request, could not find the corresponding "
        "subscription");
    return false;
  }

  // Remove from the list
  std::unique_lock lock(m_non_ue_n2_info_subscribe);
  if (non_ue_n2_info_subscribe.erase(n2sub_id) == 1)
    return true;
  else
    return false;

  return false;
}

//---------------------------------------------------------------------------------------------
void amf_app::find_non_ue_n2_info_subscriptions(
    const std::string& nf_id,
    const oai::_3gpp::model::N2InformationClass_anyOf::
        eN2InformationClass_anyOf& n2_info_class,
    std::map<
        n1n2sub_id_t,
        std::shared_ptr<oai::_3gpp::model::NonUeN2InfoSubscriptionCreateData>>&
        subscriptions) {
  Logger::amf_app().debug("Find an Non UE N2 Info Subscription");

  std::shared_lock lock(m_non_ue_n2_info_subscribe);
  for (const auto& subscription : non_ue_n2_info_subscribe) {
    if ((subscription.second->getN2InformationClass().getEnumValue() ==
         n2_info_class) and
        (subscription.second->getNfId() == nf_id)) {
      subscriptions.insert(
          std::pair<
              n1n2sub_id_t,
              std::shared_ptr<
                  oai::_3gpp::model::NonUeN2InfoSubscriptionCreateData>>(
              subscription.first, subscription.second));
    }
  }
}

//------------------------------------------------------------------------------
uint32_t amf_app::generate_random_tmsi() {
  // Use the getrandom() system call
  // Note: for RHEL only supported by RHEL 8 Beta+
  uint32_t rand_number_generated;
  if (getrandom(&rand_number_generated, sizeof(uint32_t), GRND_NONBLOCK) ==
      -1) {
    Logger::amf_app().warn(
        "Error when generating a random number using getrandom()");
  } else {
    Logger::amf_app().debug(
        "Random number generated: %ld", rand_number_generated);
  }

  return rand_number_generated;
}

//------------------------------------------------------------------------------
bool amf_app::generate_5g_guti(
    const uint32_t ranid, const long amfid, std::string& mcc, std::string& mnc,
    uint32_t& tmsi) {
  std::string ue_context_key     = amf_conv::get_ue_context_key(ranid, amfid);
  std::shared_ptr<ue_context> uc = {};

  if (!ran_amf_id_2_ue_context(ue_context_key, uc)) return false;

  mcc      = uc->tai.mcc;
  mnc      = uc->tai.mnc;
  tmsi     = generate_random_tmsi();
  uc->tmsi = tmsi;
  return true;
}

//------------------------------------------------------------------------------
evsub_id_t amf_app::handle_event_exposure_subscription(
    std::shared_ptr<itti_sbi_event_exposure_request> msg) {
  Logger::amf_app().info(
      "Handle an Event Exposure Subscription Request from a NF");

  // Generate a subscription ID Id and store the corresponding information in a
  // map (subscription id, info)
  evsub_id_t evsub_id = generate_ev_subscription_id();

  std::vector<amf_event_t> event_subscriptions =
      msg->event_exposure.get_event_subs();

  // store subscription
  for (auto i : event_subscriptions) {
    auto ss    = std::make_shared<amf_subscription>();
    ss->sub_id = evsub_id;
    if (msg->event_exposure.is_supi_is_set()) {
      ss->supi        = msg->event_exposure.get_supi();
      ss->supi_is_set = true;
    }
    ss->notify_correlation_id = msg->event_exposure.get_notify_correlation_id();
    ss->notify_uri            = msg->event_exposure.get_notify_uri();
    ss->nf_id                 = msg->event_exposure.get_nf_id();
    ss->ev_type               = i.type;
    add_event_subscription(evsub_id, i.type, ss);

    if (i.type == LOCATION_REPORT) {
      // Determine Location
      if (amf_cfg->support_features.enable_lmf)
        handle_determine_location_request();
    }
    ss->display();
  }
  return evsub_id;
}

//---------------------------------------------------------------------------------------------
bool amf_app::handle_event_exposure_delete(const std::string& subscription_id) {
  // verify Subscription ID
  evsub_id_t sub_id = {};
  try {
    sub_id = std::stoi(subscription_id);
  } catch (const std::exception& err) {
    Logger::amf_app().warn(
        "Received a Unsubscribe Request, couldn't find the corresponding "
        "subscription");
    return false;
  }

  return remove_event_subscription(sub_id);
}

//------------------------------------------------------------------------------
bool amf_app::handle_nf_status_notification(
    std::shared_ptr<itti_sbi_notification_data>& msg,
    oai::_3gpp::model::ProblemDetails& problem_details, uint32_t& http_code) {
  // NRF notifications are no longer expected since BCF has replaced NRF
  Logger::amf_app().warn(
      "Received NF status notification but NRF is deprecated (BCF is used)");
  http_code =
      static_cast<uint32_t>(oai::common::sbi::http_status_code::NO_CONTENT);
  return true;
}

//------------------------------------------------------------------------------
void amf_app::handle_determine_location_request() {
  for (const auto& kvp : supi2ue_ctx) {
    nlohmann::json input_data = {};
    input_data["supi"]        = kvp.first;

    // Generate a promise and associate this promise to the ITTI message
    uint32_t promise_id = generate_promise_id();
    Logger::amf_app().debug("Promise ID generated %d", promise_id);

    auto itti_msg = std::make_shared<itti_sbi_determine_location_request>(
        TASK_AMF_APP, TASK_AMF_SBI, promise_id);

    auto p = boost::make_shared<boost::promise<nlohmann::json>>();
    boost::shared_future<nlohmann::json> f = p->get_future();
    add_promise(promise_id, p);

    itti_msg->input_data = input_data;
    itti_msg->promise_id = promise_id;

    int ret = itti_inst->send_msg(itti_msg);
    if (0 != ret) {
      Logger::amf_app().error(
          "Could not send ITTI message %s to task TASK_AMF_SBI",
          itti_msg->get_msg_name());
    }

    // Wait for the response available and process accordingly
    std::optional<nlohmann::json> location_data = std::nullopt;
    oai::utils::utils::wait_for_result(f, location_data);
    if (location_data.has_value()) {
      nlohmann::json location_data_json = location_data.value();

      uint32_t http_response_code = 0;
      if (location_data_json.find(kSbiResponseHttpResponseCode) !=
          location_data_json.end()) {
        http_response_code =
            location_data_json[kSbiResponseHttpResponseCode].get<int>();
        // TODO:
      }
      if (location_data_json.find(kSbiResponseJsonData) !=
          location_data_json.end()) {
        ;
        Logger::amf_app().info(
            "Determine Location Response (SUPI: %s) : \n%s", kvp.first,
            location_data_json[kSbiResponseJsonData].dump(2).c_str());
      }
    } else {
      Logger::amf_app().error(
          "Determine Location failed (SUPI: %s)...\n", kvp.first);
    }
  }
}
//------------------------------------------------------------------------------
void amf_app::generate_uuid() {
  // Try to read nfInstanceId from extended_amf_profile.json (generated by did-proxy)
  // This ensures AMF uses the same ID as the DID
  if (!amf_cfg->extended_profile_path.empty()) {
    try {
      std::ifstream file(amf_cfg->extended_profile_path);
      if (file.is_open()) {
        nlohmann::json extended_profile;
        file >> extended_profile;
        file.close();
        
        if (extended_profile.contains("nfInstanceId") && 
            extended_profile["nfInstanceId"].is_string()) {
          amf_instance_id = extended_profile["nfInstanceId"].get<std::string>();
          Logger::amf_app().info(
              "Using nfInstanceId from extended profile: %s", 
              amf_instance_id.c_str());
          return;
        }
      }
    } catch (const std::exception& e) {
      Logger::amf_app().warn(
          "Failed to read nfInstanceId from extended profile: %s, generating new UUID",
          e.what());
    }
  }
  
  // Fallback: generate a new UUID
  amf_instance_id = to_string(boost::uuids::random_generator()());
  Logger::amf_app().info("Generated new nfInstanceId: %s", amf_instance_id.c_str());
}

//---------------------------------------------------------------------------------------------
void amf_app::add_event_subscription(
    const evsub_id_t& sub_id, const amf_event_type_t& ev,
    std::shared_ptr<amf_subscription> ss) {
  Logger::amf_app().debug(
      "Add an Event subscription (Sub ID %d, Event %d)", sub_id, (uint8_t) ev);
  std::unique_lock lock(m_amf_event_subscriptions);
  amf_event_subscriptions.emplace(std::make_pair(sub_id, ev), ss);
}

//---------------------------------------------------------------------------------------------
bool amf_app::remove_event_subscription(const evsub_id_t& sub_id) {
  Logger::amf_app().debug("Remove an Event subscription (Sub ID %d)", sub_id);
  std::unique_lock lock(m_amf_event_subscriptions);
  for (auto it = amf_event_subscriptions.cbegin();
       it != amf_event_subscriptions.cend();) {
    if ((uint8_t) std::get<0>(it->first) == (uint32_t) sub_id) {
      Logger::amf_app().debug(
          "Found an event subscription (Event ID %d)",
          (uint8_t) std::get<0>(it->first));
      amf_event_subscriptions.erase(it++);
      // it = amf_event_subscriptions.erase(it)
      return true;
    } else {
      ++it;
    }
  }
  return false;
}

//---------------------------------------------------------------------------------------------
void amf_app::get_ee_subscriptions(
    const amf_event_type_t& ev,
    std::vector<std::shared_ptr<amf_subscription>>& subscriptions) {
  for (auto const& i : amf_event_subscriptions) {
    if ((uint8_t) std::get<1>(i.first) == (uint8_t) ev) {
      Logger::amf_app().debug(
          "Found an event subscription (Event ID %d, Event %d)",
          (uint8_t) std::get<0>(i.first), (uint8_t) ev);
      subscriptions.push_back(i.second);
    }
  }
}

//---------------------------------------------------------------------------------------------
void amf_app::get_ee_subscriptions(
    const evsub_id_t& sub_id,
    std::vector<std::shared_ptr<amf_subscription>>& subscriptions) {
  for (auto const& i : amf_event_subscriptions) {
    if (i.first.first == sub_id) {
      subscriptions.push_back(i.second);
    }
  }
}

//---------------------------------------------------------------------------------------------
void amf_app::get_ee_subscriptions(
    const amf_event_type_t& ev, std::string& supi,
    std::vector<std::shared_ptr<amf_subscription>>& subscriptions) {
  for (auto const& i : amf_event_subscriptions) {
    if ((i.first.second == ev) && (i.second->supi == supi)) {
      subscriptions.push_back(i.second);
    }
  }
}

//---------------------------------------------------------------------------------------------
void amf_app::generate_amf_profile() {
  nf_instance_profile.set_nf_instance_id(amf_instance_id);
  nf_instance_profile.set_nf_instance_name(amf_cfg->amf_name);
  nf_instance_profile.set_nf_type("AMF");
  nf_instance_profile.set_nf_status("REGISTERED");
  nf_instance_profile.set_nf_heartBeat_timer(
      50);                                   // TODO: remove hardcoded value
  nf_instance_profile.set_nf_priority(1);    // TODO: remove hardcoded value
  nf_instance_profile.set_nf_capacity(100);  // TODO: remove hardcoded value
  nf_instance_profile.delete_nf_ipv4_addresses();
  nf_instance_profile.add_nf_ipv4_addresses(amf_cfg->sbi.addr4);

  // NF services
  // IP Endpoint (common for each service)
  ip_endpoint_t endpoint = {};
  endpoint.ipv4_address  = amf_cfg->sbi.addr4;
  endpoint.transport     = "TCP";
  endpoint.port          = amf_cfg->sbi.port;

  // namf_communication
  oai::common::sbi::nf_service_t nf_service = {};
  nf_service.service_instance_id            = amf_instance_id;
  nf_service.service_name                   = "namf-comm";
  nf_service_version_t version              = {};
  if (amf_cfg->sbi.api_version.has_value())
    version.api_version_in_uri =
        amf_cfg->sbi.api_version.value_or(DEFAULT_SBI_API_VERSION);
  version.api_full_version = "1.0.0";  // TODO: to be updated
  nf_service.versions.push_back(version);
  nf_service.scheme            = "http";
  nf_service.nf_service_status = "REGISTERED";

  nf_service.ip_endpoints.push_back(endpoint);

  nf_instance_profile.add_nf_service_list(nf_service);

  // namf-evts
  oai::common::sbi::nf_service_t nf_service_events = {};
  nf_service_events.service_instance_id            = "namf-evts";
  nf_service_events.service_name                   = "namf-evts";
  nf_service_version_t version_events              = {};
  if (amf_cfg->sbi.api_version.has_value())
    version_events.api_version_in_uri =
        amf_cfg->sbi.api_version.value_or(DEFAULT_SBI_API_VERSION);
  version_events.api_full_version = "1.0.0";  // TODO: to be updated
  nf_service_events.versions.push_back(version_events);
  nf_service_events.scheme            = "http";
  nf_service_events.nf_service_status = "REGISTERED";
  nf_service_events.ip_endpoints.push_back(endpoint);

  nf_instance_profile.delete_nf_services();
  nf_instance_profile.add_nf_service(nf_service);
  nf_instance_profile.add_nf_service(nf_service_events);

  // TODO: custom info
  // AMF info
  oai::common::sbi::amf_info_t info = {};
  oai::utils::conv::int_to_string_hex(
      amf_cfg->guami.region_id, info.amf_region_id, AMF_REGION_ID_LENGTH);
  oai::utils::conv::int_to_string_hex(
      amf_cfg->guami.amf_set_id, info.amf_set_id, AMF_SET_ID_LENGTH);
  for (auto g : amf_cfg->guami_list) {
    guami_t guami = {};
    amf_conv::get_amf_id(
        g.region_id, g.amf_set_id, g.amf_pointer, guami.amf_id);
    guami.plmn.mcc = g.mcc;
    guami.plmn.mnc = g.mnc;
    info.guami_list.push_back(guami);
  }

  nf_instance_profile.set_amf_info(info);

  std::vector<snssai_t> amf_snssai;
  for (auto p : amf_cfg->plmn_list) {
    for (auto s : p.slice_list) {
      amf_snssai.push_back(s);
    }
  }
  nf_instance_profile.set_nf_snssais(amf_snssai);

  // Display the profile
  nf_instance_profile.display();
}

//---------------------------------------------------------------------------------------------
std::string amf_app::get_nf_instance() const {
  return amf_instance_id;
}

//------------------------------------------------------------------------------
nlohmann::json amf_app::build_amf_profile_for_ausf_request() const {
  nlohmann::json profile = nlohmann::json::object();
  nf_instance_profile.to_json(profile);

  profile["nfInstanceId"] = amf_instance_id;
  profile["nfType"]       = "AMF";

  if (!profile.contains("plmnList") || !profile["plmnList"].is_array()) {
    profile["plmnList"] = nlohmann::json::array();
  }
  if (profile["plmnList"].empty()) {
    for (const auto& plmn : amf_cfg->plmn_list) {
      profile["plmnList"].push_back({
          {"mcc", plmn.mcc},
          {"mnc", plmn.mnc},
      });
    }
  }

  if (!profile.contains("sNssais") || !profile["sNssais"].is_array()) {
    profile["sNssais"] = nlohmann::json::array();
  }
  if (profile["sNssais"].empty()) {
    std::set<std::pair<int, std::string>> unique_snssais = {};
    for (const auto& plmn : amf_cfg->plmn_list) {
      for (const auto& slice : plmn.slice_list) {
        const auto key = std::make_pair(slice.sst, slice.sd);
        if (unique_snssais.insert(key).second) {
          profile["sNssais"].push_back({
              {"sst", slice.sst},
              {"sd", slice.sd},
          });
        }
      }
    }
  }

  if (!profile.contains("ipv4Addresses") || !profile["ipv4Addresses"].is_array() ||
      profile["ipv4Addresses"].empty()) {
    profile["ipv4Addresses"] = nlohmann::json::array(
        {std::string(inet_ntoa(amf_cfg->sbi.addr4))});
  }

  if (!profile.contains("fqdn") || !profile["fqdn"].is_string() ||
      profile["fqdn"].get<std::string>().empty()) {
    if (!amf_cfg->extended_profile_path.empty()) {
      try {
        std::ifstream file(amf_cfg->extended_profile_path);
        if (file.is_open()) {
          nlohmann::json extended_profile = {};
          file >> extended_profile;
          if (extended_profile.contains("fqdn") &&
              extended_profile["fqdn"].is_string() &&
              !extended_profile["fqdn"].get<std::string>().empty()) {
            profile["fqdn"] = extended_profile["fqdn"];
          }
        }
      } catch (const std::exception& e) {
        Logger::amf_app().warn(
            "Failed to read fqdn from extended profile for AUSF request: %s",
            e.what());
      }
    }
  }

  if (!profile.contains("fqdn") || !profile["fqdn"].is_string() ||
      profile["fqdn"].get<std::string>().empty()) {
    profile["fqdn"] = amf_cfg->amf_name;
  }

  return profile;
}

//------------------------------------------------------------------------------
// BCF Registration Functions (NRF has been replaced by BCF)
//------------------------------------------------------------------------------
nlohmann::json amf_app::read_extended_profile_from_file() {
  Logger::amf_app().debug(
      "Reading extended profile from file: %s",
      amf_cfg->extended_profile_path.c_str());

  nlohmann::json extended_profile = {};

  // Check if file exists
  std::ifstream file(amf_cfg->extended_profile_path);
  if (!file.is_open()) {
    Logger::amf_app().error(
        "Failed to open extended profile file: %s",
        amf_cfg->extended_profile_path.c_str());
    return extended_profile;
  }

  try {
    // Read and parse JSON from file
    file >> extended_profile;
    Logger::amf_app().info(
        "Successfully read extended profile from file");
    
    // Log DID if present
    if (extended_profile.contains("did")) {
      Logger::amf_app().info(
          "Extended profile contains DID: %s",
          extended_profile["did"].get<std::string>().c_str());
    }

    // Read and store hardware ID from extended profile (generated by did-proxy)
    if (extended_profile.contains("hardwareId")) {
      m_hardware_id = extended_profile["hardwareId"].get<std::string>();
      Logger::amf_app().info(
          "Hardware ID loaded from extended profile: %s...",
          m_hardware_id.substr(0, 16).c_str());
    }
  } catch (const nlohmann::json::parse_error& e) {
    Logger::amf_app().error(
        "Failed to parse extended profile JSON: %s", e.what());
  } catch (const std::exception& e) {
    Logger::amf_app().error(
        "Failed to read extended profile: %s", e.what());
  }

  file.close();
  return extended_profile;
}

//------------------------------------------------------------------------------
void amf_app::register_to_bcf() {
  if (should_reject_new_async_request("new BCF registration request")) {
    return;
  }

  if (!amf_cfg->register_bcf) {
    Logger::amf_app().debug("BCF registration is disabled");
    return;
  }

  // --- Latency probe: start BCF registration trace ---
  auto lp_tid = LP_BUILD_ID("AMF", "BCF_REG", amf_instance_id);
  LP_START("AMF", "BCF_REG", lp_tid);

  Logger::amf_app().info(
      "[AMF][BCF-REG] Preparing registration request to BCF");

  // Fetch extended profile from DID Proxy
  nlohmann::json extended_profile = read_extended_profile_from_file();
  if (extended_profile.empty()) {
    Logger::amf_app().error(
        "[AMF][BCF-REG] Failed to fetch extended profile from DID Proxy, "
        "skipping BCF registration");
    {
      std::lock_guard<std::mutex> lock(m_bcf_state_mutex);
      m_bcf_state = BcfLifecycleState::FAILED;
    }
    LP_CANCEL(lp_tid);
    return;
  }

  // Build BCF URI
  std::string bcf_uri = {};
  std::string bcf_api_version = "v1";
  if (!amf_cfg->bcf_addr.api_version.empty()) {
    bcf_api_version = amf_cfg->bcf_addr.api_version;
  }

  if (!amf_cfg->bcf_addr.uri_root.empty()) {
    bcf_uri = amf_cfg->bcf_addr.uri_root;
  } else {
    std::string host = inet_ntoa(amf_cfg->bcf_addr.ipv4_addr);
    uint16_t port = amf_cfg->bcf_addr.port;
    bcf_uri = "http://" + host + ":" + std::to_string(port);
  }
  bcf_uri += "/nbcf_management/" + bcf_api_version + "/nf_instances/" +
             amf_instance_id;

  Logger::amf_app().info(
      "[AMF][BCF-REG] Sending registration ITTI message to SBI task, "
      "bcf_uri=%s",
      bcf_uri.c_str());

  // Send ITTI message to SBI task
  LP_MARK(lp_tid, "REG_REQUEST_DISPATCH");
  auto itti_msg = std::make_shared<itti_sbi_bcf_register_nf_instance_request>(
      TASK_AMF_APP, TASK_AMF_SBI);
  itti_msg->extended_profile = extended_profile;
  itti_msg->bcf_uri          = bcf_uri;
  itti_msg->amf_instance_id  = amf_instance_id;

  int ret = itti_inst->send_msg(itti_msg);
  if (RETURNok != ret) {
    Logger::amf_app().error(
        "[AMF][BCF-REG] Could not send ITTI message %s to task TASK_AMF_SBI",
        itti_msg->get_msg_name());
    LP_CANCEL(lp_tid);
  }
}

//------------------------------------------------------------------------------
void amf_app::update_bcf_registration() {
  if (should_reject_new_async_request("new BCF update registration request")) {
    return;
  }

  if (!amf_cfg->register_bcf) {
    Logger::amf_app().debug("BCF registration is disabled");
    return;
  }

  Logger::amf_app().debug(
      "Send ITTI msg to SBI task to trigger the update request to BCF");

  // Fetch updated extended profile from DID Proxy
  nlohmann::json extended_profile = read_extended_profile_from_file();
  if (extended_profile.empty()) {
    Logger::amf_app().error(
        "Failed to fetch extended profile from DID Proxy, skipping BCF update");
    return;
  }

  // Build BCF URI
  std::string bcf_uri = {};
  std::string bcf_api_version = "v1";
  if (!amf_cfg->bcf_addr.api_version.empty()) {
    bcf_api_version = amf_cfg->bcf_addr.api_version;
  }

  if (!amf_cfg->bcf_addr.uri_root.empty()) {
    bcf_uri = amf_cfg->bcf_addr.uri_root;
  } else {
    std::string host = inet_ntoa(amf_cfg->bcf_addr.ipv4_addr);
    uint16_t port = amf_cfg->bcf_addr.port;
    bcf_uri = "http://" + host + ":" + std::to_string(port);
  }
  bcf_uri += "/nbcf_management/" + bcf_api_version + "/nf_instances/" +
             amf_instance_id;

  // Prepare patch items from extended profile
  std::vector<oai::_3gpp::model::PatchItem> patch_items;
  oai::_3gpp::model::PatchItem patch_item = {};
  oai::_3gpp::model::PatchOperation op;
  op.setEnumValue(
      oai::_3gpp::model::PatchOperation_anyOf::ePatchOperation_anyOf::REPLACE);
  patch_item.setOp(op);
  patch_item.setPath("/nfProfile");
  patch_item.setValue(extended_profile);
  patch_items.push_back(patch_item);

  // Send ITTI message to SBI task
  auto itti_msg = std::make_shared<itti_sbi_bcf_update_nf_instance_request>(
      TASK_AMF_APP, TASK_AMF_SBI);
  itti_msg->patch_items       = patch_items;
  itti_msg->bcf_uri           = bcf_uri;
  itti_msg->amf_instance_id   = amf_instance_id;

  int ret = itti_inst->send_msg(itti_msg);
  if (RETURNok != ret) {
    Logger::amf_app().error(
        "Could not send ITTI message %s to task TASK_AMF_SBI",
        itti_msg->get_msg_name());
  }
}

//------------------------------------------------------------------------------
bool amf_app::deregister_from_bcf() {
  if (!amf_cfg->register_bcf) {
    Logger::amf_app().debug("BCF registration is disabled");
    return false;
  }

  if (m_bcf_dereg_in_progress.exchange(true)) {
    Logger::amf_app().warn(
        "[AMF][Shutdown] BCF deregistration already in progress, ignore duplicate request");
    return true;
  }

  set_shutdown_state(amf_shutdown_state_t::BCF_DEREG_IN_PROGRESS);

  Logger::amf_app().info(
      "[AMF][BCF-REG] Preparing deregistration request to BCF");

  const std::string bcf_uri = build_bcf_nf_instance_uri();

  {
    std::lock_guard<std::mutex> lock(m_shutdown_mutex);
    m_bcf_dereg_uri       = bcf_uri;
    m_bcf_dereg_http_code = 0;
  }

  Logger::amf_app().info(
      "[AMF][BCF-REG] Sending deregistration request to SBI, bcf_uri=%s",
      bcf_uri.c_str());

  // Send ITTI message to SBI task
  auto itti_msg = std::make_shared<itti_sbi_bcf_deregister_nf_instance_request>(
      TASK_AMF_APP, TASK_AMF_SBI);
  itti_msg->bcf_uri          = bcf_uri;
  itti_msg->amf_instance_id  = amf_instance_id;

  int ret = itti_inst->send_msg(itti_msg);
  if (RETURNok != ret) {
    Logger::amf_app().error(
        "[AMF][BCF-REG] Could not send ITTI message %s to task TASK_AMF_SBI",
        itti_msg->get_msg_name());
    m_bcf_dereg_in_progress.store(false);
    return false;
  }

  return true;
}

//------------------------------------------------------------------------------
// Helper function to serialize NfProfile to JSON string
static std::string nf_profile_to_json_string(const oai::common::bcf::NfProfile& profile) {
  nlohmann::json j;
  j["nfInstanceId"] = profile.nf_instance_id;
  j["nfType"] = oai::common::bcf::nf_type_to_string(profile.nf_type);
  j["nfStatus"] = oai::common::bcf::nf_status_to_string(profile.nf_status);
  
  if (!profile.did.empty()) j["did"] = profile.did;
  if (!profile.fqdn.empty()) j["fqdn"] = profile.fqdn;
  if (!profile.ipv4_addresses.empty()) j["ipv4Addresses"] = profile.ipv4_addresses;
  if (!profile.ipv6_addresses.empty()) j["ipv6Addresses"] = profile.ipv6_addresses;
  if (!profile.plmn_list.empty()) {
    j["plmnList"] = nlohmann::json::array();
    for (const auto& plmn : profile.plmn_list) {
      j["plmnList"].push_back(plmn.to_json());
    }
  }
  if (!profile.snssai_list.empty()) {
    j["sNssais"] = nlohmann::json::array();
    for (const auto& snssai : profile.snssai_list) {
      j["sNssais"].push_back(snssai.to_json());
    }
  }
  if (!profile.per_plmn_snssai_list.empty()) {
    j["perPlmnSnssaiList"] = nlohmann::json::array();
    for (const auto& item : profile.per_plmn_snssai_list) {
      j["perPlmnSnssaiList"].push_back(item.to_json());
    }
  }
  
  j["priority"] = profile.priority;
  j["capacity"] = profile.capacity;
  j["load"] = profile.load;
  if (!profile.locality.empty()) j["locality"] = profile.locality;
  
  // nfServices
  if (!profile.nf_services.empty()) {
    nlohmann::json services = nlohmann::json::array();
    for (const auto& svc : profile.nf_services) {
      nlohmann::json svc_json;
      svc_json["serviceInstanceId"] = svc.service_instance_id;
      svc_json["serviceName"] = svc.service_name;
      svc_json["scheme"] = svc.scheme;
      if (!svc.fqdn.empty()) svc_json["fqdn"] = svc.fqdn;
      if (!svc.api_prefix.empty()) svc_json["apiPrefix"] = svc.api_prefix;
      if (!svc.versions.empty()) svc_json["versions"] = svc.versions;
      
      if (!svc.ip_endpoints.empty()) {
        nlohmann::json eps = nlohmann::json::array();
        for (const auto& ep : svc.ip_endpoints) {
          nlohmann::json ep_json;
          if (!ep.ipv4_address.empty()) ep_json["ipv4Address"] = ep.ipv4_address;
          if (!ep.ipv6_address.empty()) ep_json["ipv6Address"] = ep.ipv6_address;
          if (ep.port > 0) ep_json["port"] = ep.port;
          if (!ep.transport.empty()) ep_json["transport"] = ep.transport;
          eps.push_back(ep_json);
        }
        svc_json["ipEndPoints"] = eps;
      }
      services.push_back(svc_json);
    }
    j["nfServices"] = services;
  }
  
  return j.dump();
}

namespace {

std::string normalize_ausf_uri(std::string uri) {
  if (uri.empty()) {
    return {};
  }

  if (uri.rfind("http://", 0) != 0 && uri.rfind("https://", 0) != 0) {
    uri = "http://" + uri;
  }

  return uri;
}

std::vector<oai::common::bcf::PlmnId> get_local_amf_plmns_for_ausf_selection() {
  std::vector<oai::common::bcf::PlmnId> local_plmns = {};

  if (amf_cfg) {
    for (const auto& plmn : amf_cfg->plmn_list) {
      local_plmns.push_back({plmn.mcc, plmn.mnc});
    }

    if (local_plmns.empty()) {
      for (const auto& guami : amf_cfg->guami_list) {
        local_plmns.push_back({guami.mcc, guami.mnc});
      }
    }

    if (local_plmns.empty() && !amf_cfg->guami.mcc.empty() &&
        !amf_cfg->guami.mnc.empty()) {
      local_plmns.push_back({amf_cfg->guami.mcc, amf_cfg->guami.mnc});
    }
  }

  return local_plmns;
}

size_t select_random_index(const size_t size) {
  std::random_device random_device;
  std::mt19937 generator(random_device());
  std::uniform_int_distribution<size_t> distribution(0, size - 1);
  return distribution(generator);
}

struct ausf_selection_candidate_t {
  std::string nf_instance_id;
  std::string nf_type;
  std::string uri;
  std::string did;
  std::string api_version;
  oai::common::bcf::NfProfile profile;
};

std::string normalize_snssai_sd(std::string sd) {
  if (sd.empty()) {
    return {};
  }

  if (sd.rfind("0x", 0) == 0 || sd.rfind("0X", 0) == 0) {
    sd = sd.substr(2);
  }

  std::transform(sd.begin(), sd.end(), sd.begin(), [](unsigned char c) {
    return std::toupper(c);
  });

  if (sd == "FFFFFF") {
    return {};
  }

  return sd;
}

std::string snssai_to_string(const oai::common::bcf::Snssai& snssai) {
  std::ostringstream ss;
  ss << "sst=" << static_cast<int>(snssai.sst);
  const auto normalized_sd = normalize_snssai_sd(snssai.sd);
  if (!normalized_sd.empty()) {
    ss << ",sd=" << normalized_sd;
  }
  return ss.str();
}

std::string snssai_list_to_string(
    const std::vector<oai::common::bcf::Snssai>& snssais) {
  if (snssais.empty()) {
    return "[]";
  }

  std::ostringstream ss;
  ss << "[";
  for (size_t i = 0; i < snssais.size(); ++i) {
    if (i > 0) {
      ss << ";";
    }
    ss << snssai_to_string(snssais[i]);
  }
  ss << "]";
  return ss.str();
}

std::string plmn_to_string(const oai::common::bcf::PlmnId& plmn) {
  return plmn.mcc + "/" + plmn.mnc;
}

std::string plmn_list_to_string(
    const std::vector<oai::common::bcf::PlmnId>& plmns) {
  if (plmns.empty()) {
    return "[]";
  }

  std::ostringstream ss;
  ss << "[";
  for (size_t i = 0; i < plmns.size(); ++i) {
    if (i > 0) {
      ss << ",";
    }
    ss << plmn_to_string(plmns[i]);
  }
  ss << "]";
  return ss.str();
}

void append_unique_plmn(
    std::vector<oai::common::bcf::PlmnId>& plmns,
    const oai::common::bcf::PlmnId& plmn) {
  if (plmn.mcc.empty() && plmn.mnc.empty()) {
    return;
  }

  if (std::find(plmns.begin(), plmns.end(), plmn) == plmns.end()) {
    plmns.push_back(plmn);
  }
}

void append_unique_snssai(
    std::vector<oai::common::bcf::Snssai>& snssais,
    const oai::common::bcf::Snssai& snssai) {
  oai::common::bcf::Snssai normalized = snssai;
  normalized.sd                       = normalize_snssai_sd(normalized.sd);
  if (std::find(snssais.begin(), snssais.end(), normalized) == snssais.end()) {
    snssais.push_back(normalized);
  }
}

std::vector<oai::common::bcf::PlmnId> collect_profile_plmns(
    const oai::common::bcf::NfProfile& profile) {
  std::vector<oai::common::bcf::PlmnId> plmns = {};
  for (const auto& plmn : profile.plmn_list) {
    append_unique_plmn(plmns, plmn);
  }
  for (const auto& item : profile.per_plmn_snssai_list) {
    append_unique_plmn(plmns, item.plmn_id);
  }
  return plmns;
}

std::vector<oai::common::bcf::Snssai> collect_profile_snssais(
    const oai::common::bcf::NfProfile& profile) {
  std::vector<oai::common::bcf::Snssai> snssais = {};
  for (const auto& snssai : profile.snssai_list) {
    append_unique_snssai(snssais, snssai);
  }
  for (const auto& item : profile.per_plmn_snssai_list) {
    for (const auto& snssai : item.snssai_list) {
      append_unique_snssai(snssais, snssai);
    }
  }
  return snssais;
}

std::string per_plmn_snssai_list_to_string(
    const std::vector<oai::common::bcf::PerPlmnSnssaiItem>& items) {
  if (items.empty()) {
    return "[]";
  }

  std::ostringstream ss;
  ss << "[";
  for (size_t i = 0; i < items.size(); ++i) {
    if (i > 0) {
      ss << ";";
    }
    ss << plmn_to_string(items[i].plmn_id) << ":"
       << snssai_list_to_string(items[i].snssai_list);
  }
  ss << "]";
  return ss.str();
}

bool matches_snssai_policy(
    const std::vector<oai::common::bcf::Snssai>& ue_snssais,
    const oai::common::bcf::NfProfile& profile) {
  if (ue_snssais.empty()) {
    return true;
  }

  const auto candidate_snssais = collect_profile_snssais(profile);
  if (candidate_snssais.empty()) {
    return false;
  }

  // Current minimum viable policy uses SST-only matching to avoid
  // over-constraining AUSF selection when profiles only advertise SST.
  for (const auto& ue_snssai : ue_snssais) {
    for (const auto& candidate_snssai : candidate_snssais) {
      if (ue_snssai.sst == candidate_snssai.sst) {
        return true;
      }
    }
  }
  return false;
}

bool matches_local_plmn_policy(
    const std::vector<oai::common::bcf::PlmnId>& local_plmns,
    const oai::common::bcf::NfProfile& profile) {
  if (local_plmns.empty()) {
    return false;
  }

  const auto candidate_plmns = collect_profile_plmns(profile);
  return std::any_of(
      candidate_plmns.begin(), candidate_plmns.end(),
      [&local_plmns](const oai::common::bcf::PlmnId& candidate_plmn) {
        return std::find(
                   local_plmns.begin(), local_plmns.end(), candidate_plmn) !=
               local_plmns.end();
      });
}

bool select_ausf_by_local_policy(
    const std::vector<ausf_selection_candidate_t>& candidates,
    const std::vector<oai::common::bcf::Snssai>& ue_snssais,
    const std::vector<oai::common::bcf::PlmnId>& local_plmns,
    const std::string& source, ausf_selection_candidate_t& selected_candidate,
    std::string& failure_reason) {
  Logger::amf_app().info(
      "[AMF][AUSFSelection] Start local AUSF selection source=%s candidates=%zu",
      source.c_str(), candidates.size());
  Logger::amf_app().info(
      "[AMF][AUSFSelection] UE S-NSSAI=%s",
      snssai_list_to_string(ue_snssais).c_str());
  Logger::amf_app().info(
      "[AMF][AUSFSelection] Local PLMN=%s",
      plmn_list_to_string(local_plmns).c_str());

  if (candidates.empty()) {
    failure_reason = "empty_candidate_list";
    Logger::amf_app().error(
        "[AMF][AUSFSelection] AUSF selection failed: empty candidate list");
    return false;
  }

  std::vector<size_t> base_candidates = {};
  std::vector<size_t> plmn_matched_candidates = {};

  if (ue_snssais.empty()) {
    Logger::amf_app().warn(
        "[AMF][AUSFSelection] UE S-NSSAI is unavailable, skipping S-NSSAI pre-filter");
  }

  for (size_t i = 0; i < candidates.size(); ++i) {
    const auto& candidate = candidates[i];
    const auto candidate_plmns = collect_profile_plmns(candidate.profile);
    const auto candidate_snssais = collect_profile_snssais(candidate.profile);
    const bool snssai_match =
        matches_snssai_policy(ue_snssais, candidate.profile);
    const bool plmn_match =
        snssai_match && matches_local_plmn_policy(local_plmns, candidate.profile);

    Logger::amf_app().info(
        "[AMF][AUSFSelection] Candidate nfInstanceId=%s nfType=%s plmnList=%s sNssais=%s perPlmnSnssaiList=%s snssaiMatch=%s plmnMatch=%s",
        candidate.nf_instance_id.c_str(), candidate.nf_type.c_str(),
        plmn_list_to_string(candidate_plmns).c_str(),
        snssai_list_to_string(candidate_snssais).c_str(),
        per_plmn_snssai_list_to_string(candidate.profile.per_plmn_snssai_list)
            .c_str(),
        snssai_match ? "MATCH" : "NO_MATCH",
        plmn_match ? "MATCH" : "NO_MATCH");

    if (!ue_snssais.empty() && !snssai_match) {
      continue;
    }

    base_candidates.push_back(i);
    if (plmn_match) {
      plmn_matched_candidates.push_back(i);
    }
  }

  Logger::amf_app().info(
      "[AMF][AUSFSelection] S-NSSAI matched AUSF count=%zu",
      base_candidates.size());
  Logger::amf_app().info(
      "[AMF][AUSFSelection] PLMN matched AUSF count=%zu",
      plmn_matched_candidates.size());

  if (base_candidates.empty()) {
    failure_reason = "no_s_nssai_matched_ausf";
    Logger::amf_app().error(
        "[AMF][AUSFSelection] AUSF selection failed: no AUSF matched UE S-NSSAI=%s",
        snssai_list_to_string(ue_snssais).c_str());
    return false;
  }

  const auto& final_pool =
      plmn_matched_candidates.empty() ? base_candidates : plmn_matched_candidates;

  if (plmn_matched_candidates.empty() && !local_plmns.empty()) {
    Logger::amf_app().warn(
        "[AMF][AUSFSelection] No PLMN-matched AUSF found after S-NSSAI filtering, fallback to S-NSSAI-matched pool");
  }

  size_t selected_index = final_pool.front();
  if (final_pool.size() == 1) {
    Logger::amf_app().info(
        "[AMF][AUSFSelection] Single AUSF candidate selected nfInstanceId=%s",
        candidates[selected_index].nf_instance_id.c_str());
  } else {
    selected_index = final_pool[select_random_index(final_pool.size())];
    Logger::amf_app().info(
        "[AMF][AUSFSelection] Multiple AUSF candidates matched count=%zu randomlySelected=%s",
        final_pool.size(), candidates[selected_index].nf_instance_id.c_str());
  }

  selected_candidate = candidates[selected_index];
  Logger::amf_app().info(
      "[AMF][AUSFSelection] Final selected AUSF nfInstanceId=%s uri=%s",
      selected_candidate.nf_instance_id.c_str(),
      selected_candidate.uri.c_str());
  return true;
}

bool build_selected_ausf_endpoint(
    const oai::common::bcf::NfProfile& profile, const std::string& fallback_uri,
    const std::string& fallback_did, std::string& ausf_uri,
    std::string& ausf_did, std::string& ausf_api_version) {
  ausf_uri = profile.get_service_base_uri("nausf-auth");
  if (ausf_uri.empty()) {
    ausf_uri = profile.get_uri(false, 8081);
  }
  if (ausf_uri.empty()) {
    ausf_uri = fallback_uri;
  }
  ausf_uri = normalize_ausf_uri(ausf_uri);

  if (ausf_uri.empty()) {
    return false;
  }

  ausf_did = profile.did.empty() ? fallback_did : profile.did;
  ausf_api_version = "v1";
  for (const auto& svc : profile.nf_services) {
    if (svc.service_name == "nausf-auth" && !svc.versions.empty()) {
      ausf_api_version = svc.versions[0];
      break;
    }
  }

  return true;
}

}  // namespace

//------------------------------------------------------------------------------
bool amf_app::discover_ausf_from_bcf(
    std::string& ausf_uri, std::string& ausf_did,
    std::string& ausf_api_version,
    const std::vector<oai::common::bcf::Snssai>& ue_snssais) {
  if (should_reject_new_async_request("new AUSF discovery request")) {
    return false;
  }
  
  // ===========================================================================
  // Phase 1: 服务发现触发原因 - 明确为什么需要发现 AUSF
  // ===========================================================================
  Logger::amf_app().info(
      "========================================================================");
  Logger::amf_app().info(
      "[BCF Discovery] === AUSF Service Discovery Phase Start ===");
  Logger::amf_app().info(
      "========================================================================");
  
  Logger::amf_app().info(
      "[BCF Discovery] Trigger Reason: UE Authentication requires AUSF service");
  Logger::amf_app().info(
      "[BCF Discovery] AMF Instance ID: %s", amf_instance_id.c_str());
  Logger::amf_app().info(
      "[BCF Discovery] AMF Name: %s", amf_cfg->amf_name.c_str());

  const auto local_plmns = get_local_amf_plmns_for_ausf_selection();

  if (m_did_auth && m_did_auth->get_module()) {
    auto cached_ausf_entries =
        m_did_auth->get_module()->get_cached_target_nfs("AUSF");
    if (!cached_ausf_entries.empty()) {
      Logger::amf_app().info(
          "[BCF Discovery] Current state: Found %zu cached AUSF profile(s) from BCF notifications, trying local selection first",
          cached_ausf_entries.size());
      std::vector<ausf_selection_candidate_t> candidates = {};
      for (const auto& entry : cached_ausf_entries) {
        ausf_selection_candidate_t candidate = {};
        candidate.profile                  = entry.nf_profile;
        candidate.nf_instance_id           =
            !entry.nf_instance_id.empty() ? entry.nf_instance_id
                                          : entry.nf_profile.nf_instance_id;
        candidate.nf_type =
            !entry.nf_type.empty()
                ? entry.nf_type
                : oai::common::bcf::nf_type_to_string(entry.nf_profile.nf_type);
        if (!build_selected_ausf_endpoint(
                entry.nf_profile, entry.nf_uri, entry.nf_did, candidate.uri,
                candidate.did, candidate.api_version)) {
          Logger::amf_app().warn(
              "[AMF][AUSFSelection] Skipping cached AUSF nfInstanceId=%s because no reachable URI can be constructed",
              candidate.nf_instance_id.c_str());
          continue;
        }
        candidates.push_back(candidate);
      }

      if (!candidates.empty()) {
        ausf_selection_candidate_t selected_candidate = {};
        std::string failure_reason                    = {};
        if (select_ausf_by_local_policy(
                candidates, ue_snssais, local_plmns, "cache",
                selected_candidate, failure_reason)) {
          ausf_uri         = selected_candidate.uri;
          ausf_did         = selected_candidate.did;
          ausf_api_version = selected_candidate.api_version;

          Logger::amf_app().info(
              "[BCF Discovery] Using locally selected AUSF from subscription cache, skipping live BCF query");
          return true;
        }

        Logger::amf_app().warn(
            "[BCF Discovery] Local AUSF selection from cache failed reason=%s, fallback to live BCF discovery",
            failure_reason.c_str());
      }

      Logger::amf_app().warn(
          "[BCF Discovery] Cached AUSF entries exist but none is currently usable, fallback to live BCF discovery");
    } else {
      Logger::amf_app().info(
          "[BCF Discovery] Current state: No cached AUSF profile available, need to discover AUSF from BCF");
    }
  } else {
    Logger::amf_app().info(
        "[BCF Discovery] Current state: DIDAuth cache unavailable, need to discover AUSF from BCF");
  }
  
  // ===========================================================================
  // Phase 2: 初始化 BCF 客户端并准备发现请求
  // ===========================================================================
  Logger::amf_app().info(
      "[BCF Discovery] Phase 2: Preparing BCF NF Discovery request");
  
  auto& bcf_client = oai::common::bcf::get_bcf_nf_discovery_client();

  // Configure BCF endpoint
  std::string bcf_uri;
  std::string bcf_api_version = amf_cfg->bcf_addr.api_version.empty() ? "v1" : amf_cfg->bcf_addr.api_version;
  
  if (!amf_cfg->bcf_addr.uri_root.empty()) {
    bcf_uri = amf_cfg->bcf_addr.uri_root;
  } else {
    std::string host = inet_ntoa(amf_cfg->bcf_addr.ipv4_addr);
    uint16_t port = amf_cfg->bcf_addr.port;
    bcf_uri = "http://" + host + ":" + std::to_string(port);
  }
  
  bcf_client.set_bcf_uri(bcf_uri);
  bcf_client.set_bcf_api_version(bcf_api_version);
  bcf_client.set_local_nf_info(
      oai::common::bcf::NfType::NF_TYPE_AMF,
      amf_instance_id,
      amf_cfg->amf_name);
  bcf_client.set_selection_strategy(
      oai::common::bcf::NfSelectionStrategy::PRIORITY_BASED);

  // Build discovery criteria
  oai::common::bcf::NfDiscoveryCriteria criteria;
  criteria.target_nf_type = oai::common::bcf::NfType::NF_TYPE_AUSF;
  criteria.requester_nf_type = oai::common::bcf::NfType::NF_TYPE_AMF;
  criteria.requester_nf_instance_id = amf_instance_id;
  criteria.service_name = "nausf-auth";
  criteria.max_results = 10;
  
  // Log the request details
  Logger::amf_app().info(
      "[BCF Discovery] BCF Endpoint: %s", bcf_uri.c_str());
  Logger::amf_app().info(
      "[BCF Discovery] BCF API Version: %s", bcf_api_version.c_str());
  Logger::amf_app().info(
      "[BCF Discovery] Request Parameters:");
  Logger::amf_app().info(
      "[BCF Discovery]   - target_nf_type: AUSF");
  Logger::amf_app().info(
      "[BCF Discovery]   - requester_nf_type: AMF");
  Logger::amf_app().info(
      "[BCF Discovery]   - requester_nf_instance_id: %s", amf_instance_id.c_str());
  Logger::amf_app().info(
      "[BCF Discovery]   - service_names: nausf-auth");
  Logger::amf_app().info(
      "[BCF Discovery]   - max_results: 10");

  // ===========================================================================
  // Phase 3: 向 BCF 发送发现请求
  // ===========================================================================
  Logger::amf_app().info(
      "[BCF Discovery] Phase 3: Sending NF Discovery request to BCF...");
  
  auto discovery_response = bcf_client.discover_nf(criteria);

  // ===========================================================================
  // Phase 4: 处理 BCF 响应 - 打印所有返回的 AUSF 实例
  // ===========================================================================
  Logger::amf_app().info(
      "[BCF Discovery] Phase 4: Processing BCF discovery response");
  
  if (!discovery_response.success) {
    Logger::amf_app().error(
        "[BCF Discovery] BCF discovery request failed: %s",
        discovery_response.error_message.c_str());
    Logger::amf_app().error(
        "[BCF Discovery] === AUSF Service Discovery Phase FAILED ===");
    return false;
  }
  
  size_t instance_count = discovery_response.nf_profiles.size();
  Logger::amf_app().info(
      "[BCF Discovery] Received AUSF discovery response from BCF: %zu AUSF instance(s) found",
      instance_count);
  
  if (instance_count == 0) {
    Logger::amf_app().error(
        "[BCF Discovery] No AUSF instances available in BCF!");
    Logger::amf_app().error(
        "[BCF Discovery] Please ensure AUSF is registered with BCF before starting UE authentication");
    Logger::amf_app().error(
        "[BCF Discovery] === AUSF Service Discovery Phase FAILED ===");
    return false;
  }
  
  // Print each AUSF profile as JSON
  Logger::amf_app().info(
      "[BCF Discovery] --- AUSF Instance Profiles from BCF ---");
  for (size_t i = 0; i < instance_count; ++i) {
    const auto& profile = discovery_response.nf_profiles[i];
    std::string json_str = nf_profile_to_json_string(profile);
    Logger::amf_app().debug(
        "[BCF Discovery] AUSF Instance [%zu/%zu] NF Profile (JSON):", 
        i, instance_count);
    Logger::amf_app().debug(
        "[BCF Discovery] %s", json_str.c_str());
  }
  Logger::amf_app().info(
      "[BCF Discovery] --- End of AUSF Instance Profiles ---");

  // ===========================================================================
  // Phase 5: AUSF 选择 - 根据策略选择一个 AUSF
  // ===========================================================================
  Logger::amf_app().info(
      "[BCF Discovery] Phase 5: Selecting AUSF instance");
  Logger::amf_app().info(
      "[BCF Discovery] Selection Strategy: LOCAL_AUSF_POLICY (S-NSSAI -> PLMN -> random)");

  std::vector<ausf_selection_candidate_t> discovered_candidates = {};
  for (const auto& profile : discovery_response.nf_profiles) {
    ausf_selection_candidate_t candidate = {};
    candidate.profile                    = profile;
    candidate.nf_instance_id             = profile.nf_instance_id;
    candidate.nf_type =
        oai::common::bcf::nf_type_to_string(profile.nf_type);
    if (!build_selected_ausf_endpoint(
            profile, "", profile.did, candidate.uri, candidate.did,
            candidate.api_version)) {
      Logger::amf_app().warn(
          "[AMF][AUSFSelection] Skipping discovered AUSF nfInstanceId=%s because no reachable URI can be constructed",
          profile.nf_instance_id.c_str());
      continue;
    }
    discovered_candidates.push_back(candidate);
  }

  ausf_selection_candidate_t selected_candidate = {};
  std::string failure_reason                    = {};
  if (!select_ausf_by_local_policy(
          discovered_candidates, ue_snssais, local_plmns, "live-discovery",
          selected_candidate, failure_reason)) {
    Logger::amf_app().error(
        "[BCF Discovery] Failed to select AUSF from discovery results reason=%s",
        failure_reason.c_str());
    Logger::amf_app().error(
        "[BCF Discovery] === AUSF Service Discovery Phase FAILED ===");
    return false;
  }

  const auto& ausf_profile = selected_candidate.profile;
  
  Logger::amf_app().info(
      "[BCF Discovery] Selection result: Chose AUSF instance '%s' (priority=%d, capacity=%d, load=%d)",
      ausf_profile.nf_instance_id.c_str(),
      ausf_profile.priority,
      ausf_profile.capacity,
      ausf_profile.load);

  // ===========================================================================
  // Phase 6: 构建 AUSF 服务 URI
  // ===========================================================================
  Logger::amf_app().info(
      "[BCF Discovery] Phase 6: Constructing AUSF service URI");
  ausf_uri         = selected_candidate.uri;
  ausf_did         = selected_candidate.did;
  ausf_api_version = selected_candidate.api_version;

  Logger::amf_app().info(
      "[BCF Discovery] Constructed AUSF Base URI: %s", ausf_uri.c_str());

  // ===========================================================================
  // Phase 7: 服务发现完成 - 打印最终选定的 AUSF 关键信息
  // ===========================================================================
  Logger::amf_app().info(
      "------------------------------------------------------------------------");
  Logger::amf_app().info(
      "[BCF Discovery] === AUSF Service Discovery COMPLETED ===");
  Logger::amf_app().info(
      "------------------------------------------------------------------------");
  Logger::amf_app().info(
      "[BCF Discovery] Final Selected AUSF Summary:");
  Logger::amf_app().info(
      "[BCF Discovery]   - NF Instance ID : %s", ausf_profile.nf_instance_id.c_str());
  Logger::amf_app().info(
      "[BCF Discovery]   - AUSF DID       : %s", ausf_did.empty() ? "N/A (DID not configured)" : ausf_did.c_str());
  Logger::amf_app().info(
      "[BCF Discovery]   - AUSF Base URI  : %s", ausf_uri.c_str());
  Logger::amf_app().info(
      "[BCF Discovery]   - API Version    : %s", ausf_api_version.c_str());
  Logger::amf_app().info(
      "[BCF Discovery]   - NF Status      : %s", 
      oai::common::bcf::nf_status_to_string(ausf_profile.nf_status).c_str());
  Logger::amf_app().info(
      "[BCF Discovery]   - Priority       : %d", ausf_profile.priority);
  Logger::amf_app().info(
      "[BCF Discovery]   - Capacity       : %d", ausf_profile.capacity);
  Logger::amf_app().info(
      "[BCF Discovery]   - Load           : %d%%", ausf_profile.load);
  Logger::amf_app().info(
      "------------------------------------------------------------------------");
  Logger::amf_app().info(
      "[BCF Discovery] Service discovery phase complete. Ready for DID mutual authentication.");
  Logger::amf_app().info(
      "========================================================================");

  return true;
}

//------------------------------------------------------------------------------
bool amf_app::query_nf_instances_from_bcf(
    const std::string& nf_type,
    std::vector<oai::common::bcf::NfProfile>& nf_profiles) {
  if (should_reject_new_async_request("new BCF NF query request")) {
    return false;
  }

  Logger::amf_app().debug(
      "[BCF Discovery] Querying NF instances of type '%s' using BCF framework", nf_type.c_str());

  if (!amf_cfg->register_bcf) {
    Logger::amf_app().warn(
        "[BCF Discovery] BCF registration is disabled, cannot query NF instances");
    return false;
  }

  // Initialize BCF NF Discovery client
  auto& bcf_client = oai::common::bcf::get_bcf_nf_discovery_client();

  // Configure BCF client
  std::string bcf_uri;
  if (!amf_cfg->bcf_addr.uri_root.empty()) {
    bcf_uri = amf_cfg->bcf_addr.uri_root;
  } else {
    std::string host = inet_ntoa(amf_cfg->bcf_addr.ipv4_addr);
    uint16_t port = amf_cfg->bcf_addr.port;
    bcf_uri = "http://" + host + ":" + std::to_string(port);
  }
  
  bcf_client.set_bcf_uri(bcf_uri);
  bcf_client.set_bcf_api_version(
      amf_cfg->bcf_addr.api_version.empty() ? "v1" : amf_cfg->bcf_addr.api_version);
  bcf_client.set_local_nf_info(
      oai::common::bcf::NfType::NF_TYPE_AMF,
      amf_instance_id,
      amf_cfg->amf_name);

  // Build discovery criteria
  oai::common::bcf::NfDiscoveryCriteria criteria;
  criteria.target_nf_type = oai::common::bcf::string_to_nf_type(nf_type);
  criteria.requester_nf_type = oai::common::bcf::NfType::NF_TYPE_AMF;
  criteria.requester_nf_instance_id = amf_instance_id;
  criteria.max_results = 10;

  // Perform discovery
  auto result = bcf_client.discover_nf(criteria);

  if (!result.success) {
    Logger::amf_app().error(
        "[BCF Discovery] BCF query failed: %s", result.error_message.c_str());
    return false;
  }

  if (result.nf_profiles.empty()) {
    Logger::amf_app().warn(
        "[BCF Discovery] No %s instances found in BCF", nf_type.c_str());
    return false;
  }

  // Copy the discovered profiles directly (using common BCF types)
  for (const auto& profile : result.nf_profiles) {
    nf_profiles.push_back(profile);
    Logger::amf_app().debug(
        "[BCF Discovery] Found NF: type=%s, id=%s, did=%s",
        oai::common::bcf::nf_type_to_string(profile.nf_type).c_str(),
        profile.nf_instance_id.c_str(),
        profile.did.empty() ? "N/A" : profile.did.c_str());
  }

  Logger::amf_app().info(
      "[BCF Discovery] Query completed, found %zu valid NF instance(s)",
      nf_profiles.size());

  return true;
}

//---------------------------------------------------------------------------------------------
void amf_app::add_promise(
    const uint32_t pid,
    const boost::shared_ptr<boost::promise<nlohmann::json>>& p) {
  std::unique_lock lock(m_curl_handle_responses_sbi);
  curl_handle_responses_sbi.emplace(pid, p);
}

//---------------------------------------------------------------------------------------------
void amf_app::store_promise(
    uint32_t& pid, const boost::shared_ptr<boost::promise<nlohmann::json>>& p) {
  // Generate promise ID
  pid = generate_promise_id();
  std::unique_lock lock(m_curl_handle_responses_sbi);
  curl_handle_responses_sbi.emplace(pid, p);
}

//------------------------------------------------------------------------------
void amf_app::trigger_process_response(
    const uint32_t pid, const nlohmann::json& json_data) {
  Logger::amf_app().debug(
      "Trigger process response: Set promise with ID %u "
      "to ready",
      pid);
  std::unique_lock lock(m_curl_handle_responses_sbi);
  if (curl_handle_responses_sbi.count(pid) > 0) {
    curl_handle_responses_sbi[pid]->set_value(json_data);
    // Remove this promise from list
    curl_handle_responses_sbi.erase(pid);
  }
}

//------------------------------------------------------------------------------
void amf_app::trigger_pdu_session_release(
    const std::shared_ptr<ue_context>& uc) const {
  Logger::amf_app().debug("Trigger PDU Session Release towards SMF");
  std::vector<std::shared_ptr<pdu_session_context>> sessions_ctx;

  if (uc->get_pdu_sessions_context(sessions_ctx)) {
    // Send request to SMF to release all existing PDU sessions
    std::map<uint32_t, boost::shared_future<nlohmann::json>> smf_responses;
    for (auto session : sessions_ctx) {
      auto itti_msg = std::make_shared<itti_nsmf_pdusession_release_sm_context>(
          TASK_AMF_N2, TASK_AMF_SBI);

      // Generate a promise and associate this promise to the ITTI message
      uint32_t promise_id = generate_promise_id();
      Logger::amf_app().debug("Promise ID generated %d", promise_id);

      auto p = boost::make_shared<boost::promise<nlohmann::json>>();
      boost::shared_future<nlohmann::json> f = p->get_future();

      // Store the future to be processed later
      smf_responses.emplace(promise_id, f);
      amf_app_inst->add_promise(promise_id, p);

      itti_msg->supi             = uc->supi;
      itti_msg->pdu_session_id   = session->pdu_session_id;
      itti_msg->promise_id       = promise_id;
      itti_msg->context_location = session->smf_info.context_location;

      int ret = itti_inst->send_msg(itti_msg);
      if (0 != ret) {
        Logger::amf_app().error(
            "Could not send ITTI message %s to task TASK_AMF_SBI",
            itti_msg->get_msg_name());
      }
    }

    while (!smf_responses.empty()) {
      // Wait for the result available and process accordingly
      std::optional<nlohmann::json> result_opt = std::nullopt;
      oai::utils::utils::wait_for_result(
          smf_responses.begin()->second, result_opt);

      if (result_opt.has_value()) {
        nlohmann::json result = result_opt.value();
        Logger::amf_app().debug(
            "Got result for promise ID %d, json content %s",
            smf_responses.begin()->first, result.dump());

        uint32_t http_response_code = 0;
        if (result.find(kSbiResponseHttpResponseCode) != result.end()) {
          http_response_code = result[kSbiResponseHttpResponseCode].get<int>();
          // Remove PDU session
          // TODO for multiple sessions
          if ((http_response_code == oai::common::sbi::http_status_code::OK) or
              (http_response_code ==
               oai::common::sbi::http_status_code::NO_CONTENT)) {
            for (auto session : sessions_ctx) {
              uc->remove_pdu_sessions_context(session->pdu_session_id);
            }
          }
        } else {
          // TODO:
        }
      }
      smf_responses.erase(smf_responses.begin());
    }

  } else {
    Logger::amf_app().debug("No PDU session available");
  }
}

//------------------------------------------------------------------------------
void amf_app::trigger_pdu_session_up_deactivation(
    const std::shared_ptr<ue_context>& uc) const {
  Logger::amf_app().debug("Trigger PDU Session UP Deactivation towards SMF");

  std::vector<std::shared_ptr<pdu_session_context>> sessions_ctx;
  if (uc->get_pdu_sessions_context(sessions_ctx)) {
    // Send PDUSessionUpdateSMContextRequest to SMF for each PDU session
    std::map<uint32_t, boost::shared_future<nlohmann::json>> curl_responses;
    for (auto session : sessions_ctx) {
      Logger::amf_app().debug("PDU Session ID %d", session->pdu_session_id);
      // Generate a promise and associate this promise to the curl handle
      uint32_t promise_id = generate_promise_id();
      Logger::amf_app().debug("Promise ID generated %d", promise_id);

      auto p = boost::make_shared<boost::promise<nlohmann::json>>();
      boost::shared_future<nlohmann::json> f = p->get_future();

      // Store the future to be processed later
      curl_responses.emplace(session->pdu_session_id, f);
      amf_app_inst->add_promise(promise_id, p);

      Logger::amf_app().debug(
          "Sending ITTI to trigger PDUSessionUpdateSMContextRequest to SMF to "
          "task TASK_AMF_SBI");

      auto itti_n11_msg =
          std::make_shared<itti_nsmf_pdusession_update_sm_context>(
              TASK_NGAP, TASK_AMF_SBI);

      itti_n11_msg->pdu_session_id = session->pdu_session_id;
      itti_n11_msg->is_n2sm_set    = false;
      itti_n11_msg->amf_ue_ngap_id = uc->amf_ue_ngap_id;
      itti_n11_msg->ran_ue_ngap_id = uc->ran_ue_ngap_id;
      itti_n11_msg->supi           = uc->supi;
      itti_n11_msg->pdu_session_id = session->pdu_session_id;
      itti_n11_msg->promise_id     = promise_id;
      itti_n11_msg->up_cnx_state   = "DEACTIVATED";

      int ret = itti_inst->send_msg(itti_n11_msg);
      if (0 != ret) {
        Logger::amf_app().error(
            "Could not send ITTI message %s to task TASK_AMF_SBI",
            itti_n11_msg->get_msg_name());
      }
    }

    bool is_up_activated = true;
    while (!curl_responses.empty()) {
      // Wait for the result available and process accordingly
      std::optional<nlohmann::json> result_opt = std::nullopt;
      oai::utils::utils::wait_for_result(
          curl_responses.begin()->second, result_opt);

      if (result_opt.has_value()) {
        nlohmann::json result = result_opt.value();
        Logger::amf_app().debug(
            "Got result from a promise with PDU Session Id %d, json content %s",
            curl_responses.begin()->first, result.dump());

        uint32_t http_response_code = 0;
        if (result.find(kSbiResponseHttpResponseCode) != result.end()) {
          is_up_activated    = is_up_activated && true;
          http_response_code = result[kSbiResponseHttpResponseCode].get<int>();

          if ((http_response_code == oai::common::sbi::http_status_code::OK) or
              (http_response_code ==
               oai::common::sbi::http_status_code::NO_CONTENT)) {
            uc->set_up_cnx_state(
                curl_responses.begin()->first,
                up_cnx_state_e::UPCNX_STATE_DEACTIVATED);
          }

        } else {
          is_up_activated = false;
          Logger::amf_app().warn("Could not get the HTTP response code");
        }
      } else {
        is_up_activated = false;
        Logger::amf_app().warn("Could not get the HTTP response code");
      }

      curl_responses.erase(curl_responses.begin());
    }
  } else {
    Logger::amf_app().debug("No PDU session available");
  }
}

//------------------------------------------------------------------------------
bool amf_app::trigger_pdu_session_up_activation(
    const std::shared_ptr<ue_context>& uc) const {
  Logger::amf_app().debug("Trigger PDU Session UP Activation towards SMF");
  bool activation_result = false;

  std::vector<std::shared_ptr<pdu_session_context>> sessions_ctx;
  if (uc->get_pdu_sessions_context(sessions_ctx)) {
    // Send PDUSessionUpdateSMContextRequest to SMF for each PDU session
    std::map<uint32_t, boost::shared_future<nlohmann::json>> curl_responses;
    for (auto session : sessions_ctx) {
      Logger::amf_app().debug("PDU Session ID %d", session->pdu_session_id);
      // Generate a promise and associate this promise to the curl handle
      uint32_t promise_id = generate_promise_id();
      Logger::amf_app().debug("Promise ID generated %d", promise_id);

      auto p = boost::make_shared<boost::promise<nlohmann::json>>();
      boost::shared_future<nlohmann::json> f = p->get_future();

      // Store the future to be processed later
      curl_responses.emplace(session->pdu_session_id, f);
      amf_app_inst->add_promise(promise_id, p);

      Logger::amf_app().debug(
          "Sending ITTI to trigger PDUSessionUpdateSMContextRequest to SMF to "
          "task TASK_AMF_SBI");

      auto itti_n11_msg =
          std::make_shared<itti_nsmf_pdusession_update_sm_context>(
              TASK_NGAP, TASK_AMF_SBI);

      itti_n11_msg->pdu_session_id = session->pdu_session_id;
      itti_n11_msg->is_n2sm_set    = false;
      itti_n11_msg->amf_ue_ngap_id = uc->amf_ue_ngap_id;
      itti_n11_msg->ran_ue_ngap_id = uc->ran_ue_ngap_id;
      itti_n11_msg->supi           = uc->supi;
      itti_n11_msg->pdu_session_id = session->pdu_session_id;
      itti_n11_msg->promise_id     = promise_id;
      itti_n11_msg->up_cnx_state   = "ACTIVATING";

      int ret = itti_inst->send_msg(itti_n11_msg);
      if (0 != ret) {
        Logger::amf_app().error(
            "Could not send ITTI message %s to task TASK_AMF_SBI",
            itti_n11_msg->get_msg_name());
        return false;
      }
    }

    while (!curl_responses.empty()) {
      // Wait for the result available and process accordingly
      std::optional<nlohmann::json> result_opt = std::nullopt;
      oai::utils::utils::wait_for_result(
          curl_responses.begin()->second, result_opt);

      if (result_opt.has_value()) {
        nlohmann::json result = result_opt.value();
        Logger::amf_app().debug(
            "Got result from a promise for PDU session Id %d, json content %s",
            curl_responses.begin()->first, result.dump());

        uint32_t http_response_code = 0;
        if (result.find(kSbiResponseHttpResponseCode) != result.end()) {
          http_response_code = result[kSbiResponseHttpResponseCode].get<int>();
          if ((http_response_code == oai::common::sbi::http_status_code::OK) or
              (http_response_code ==
               oai::common::sbi::http_status_code::NO_CONTENT)) {
            uc->set_up_cnx_state(
                curl_responses.begin()->first,
                up_cnx_state_e::UPCNX_STATE_ACTIVATED);
            activation_result = activation_result && true;
          } else {
            Logger::amf_app().warn(
                "Failed to activate the UP for this PDU session (PDU Session "
                "Id %d)!",
                curl_responses.begin()->first);
            activation_result = false;
          }
        }
      } else {
        Logger::amf_app().warn("Could not get response from SMF");
        activation_result = false;
      }

      curl_responses.erase(curl_responses.begin());
    }
  } else {
    Logger::amf_app().debug("No PDU session available");
  }
  return activation_result;
}

//------------------------------------------------------------------------------
bool amf_app::trigger_pdu_session_up_activation(
    uint8_t pdu_session_id, const std::shared_ptr<ue_context>& uc) const {
  Logger::amf_app().debug("Trigger PDU Session UP Activation towards SMF");

  std::shared_ptr<pdu_session_context> psc = {};
  if (uc->find_pdu_session_context(pdu_session_id, psc)) {
    // Send PDUSessionUpdateSMContextRequest to SMF
    Logger::amf_app().debug("PDU Session ID %d", pdu_session_id);
    // Generate a promise and associate this promise to the curl handle
    uint32_t promise_id = generate_promise_id();
    Logger::amf_app().debug("Promise ID generated %d", promise_id);

    auto p = boost::make_shared<boost::promise<nlohmann::json>>();
    boost::shared_future<nlohmann::json> f = p->get_future();

    amf_app_inst->add_promise(promise_id, p);

    Logger::amf_app().debug(
        "Sending ITTI to trigger PDUSessionUpdateSMContextRequest to SMF to "
        "task TASK_AMF_SBI");

    auto itti_n11_msg =
        std::make_shared<itti_nsmf_pdusession_update_sm_context>(
            TASK_NGAP, TASK_AMF_SBI);

    itti_n11_msg->pdu_session_id = pdu_session_id;
    itti_n11_msg->is_n2sm_set    = false;
    itti_n11_msg->amf_ue_ngap_id = uc->amf_ue_ngap_id;
    itti_n11_msg->ran_ue_ngap_id = uc->ran_ue_ngap_id;
    itti_n11_msg->supi           = uc->supi;
    itti_n11_msg->pdu_session_id = pdu_session_id;
    itti_n11_msg->promise_id     = promise_id;
    itti_n11_msg->up_cnx_state   = "ACTIVATING";

    int ret = itti_inst->send_msg(itti_n11_msg);
    if (0 != ret) {
      Logger::amf_app().error(
          "Could not send ITTI message %s to task TASK_AMF_SBI",
          itti_n11_msg->get_msg_name());
      return false;
    }

    // Wait for the result available and process accordingly
    std::optional<nlohmann::json> result_opt = std::nullopt;
    oai::utils::utils::wait_for_result(f, result_opt);

    if (result_opt.has_value()) {
      nlohmann::json result = result_opt.value();
      Logger::amf_app().debug(
          "Got result from a promise (promise Id %ld) for PDU session Id %d, "
          "JSON content %s",
          promise_id, pdu_session_id, result.dump());

      uint32_t http_response_code = 0;
      if (result.find(kSbiResponseHttpResponseCode) != result.end()) {
        http_response_code = result[kSbiResponseHttpResponseCode].get<int>();
        if ((http_response_code == oai::common::sbi::http_status_code::OK) or
            (http_response_code ==
             oai::common::sbi::http_status_code::NO_CONTENT)) {
          uc->set_up_cnx_state(
              pdu_session_id, up_cnx_state_e::UPCNX_STATE_ACTIVATED);
          return true;
        } else {
          Logger::amf_app().warn(
              "Failed to activate the UP for this PDU session!");
        }
      }
    } else {
      Logger::amf_app().warn("Could not get response from SMF");
    }

  } else {
    Logger::amf_app().warn("Could not find PDU session info");
  }

  return false;
}

//------------------------------------------------------------------------------
void amf_app::add_amf_status_change_subscription(
    const std::string& subscription_id,
    const std::shared_ptr<oai::_3gpp::model::SubscriptionData>& sd) {
  Logger::amf_app().debug(
      "Add an AMF Status Change Subscription (Sub ID %s)", subscription_id);
  std::unique_lock lock(m_amf_status_change_subscriptions);
  amf_status_change_subscriptions.emplace(subscription_id, sd);
}

//------------------------------------------------------------------------------
bool amf_app::remove_amf_status_change_subscription(
    const std::string& subscription_id) {
  std::unique_lock lock(m_amf_status_change_subscriptions);
  if (amf_status_change_subscriptions.count(subscription_id) > 0) {
    amf_status_change_subscriptions.erase(subscription_id);
    return true;
  }
  return false;
}

//------------------------------------------------------------------------------
bool amf_app::update_amf_status_change_subscription(
    const std::string& subscription_id,
    const std::shared_ptr<oai::_3gpp::model::SubscriptionData>& sd) {
  std::unique_lock lock(m_amf_status_change_subscriptions);
  // Update the subscription if it exists, otherwise add a new one
  amf_status_change_subscriptions[subscription_id] = sd;
  return true;
}

//------------------------------------------------------------------------------
std::vector<std::string> amf_app::get_amf_status_change_subscription_uris(
    const std::vector<oai::_3gpp::model::Guami>& guamis) {
  std::vector<std::string> uris;
  // TODO: filter the subscriptions based on the guami list
  std::shared_lock lock(m_amf_status_change_subscriptions);
  for (auto const& it : amf_status_change_subscriptions) {
    if (it.second) {
      uris.push_back(it.second->getAmfStatusUri());
    }
  }
  return uris;
}

//------------------------------------------------------------------------------
void amf_app::perform_amf_status_change_notification(
    const oai::_3gpp::model::StatusChange& status_change) {
  // Prepare the info
  oai::_3gpp::model::AmfStatusChangeNotification
      amf_status_change_notification               = {};
  oai::_3gpp::model::AmfStatusInfo amf_status_info = {};
  std::vector<oai::_3gpp::model::AmfStatusInfo> amf_status_info_list;

  // Guami List
  oai::_3gpp::model::Guami guami = {};
  std::vector<oai::_3gpp::model::Guami> guamis;
  oai::_3gpp::model::PlmnIdNid plmn_id = {};
  for (auto g : amf_cfg->guami_list) {
    std::string amf_id = {};
    amf_conv::get_amf_id(g.region_id, g.amf_set_id, g.amf_pointer, amf_id);
    guami.setAmfId(amf_id);
    plmn_id.setMcc(g.mcc);
    plmn_id.setMnc(g.mnc);
    guami.setPlmnId(plmn_id);
    guamis.push_back(guami);
  }
  amf_status_info.setGuamiList(guamis);

  // Status Change
  amf_status_info.setStatusChange(status_change);
  // Target AMF removal
  amf_status_info.setTargetAmfRemoval(amf_cfg->amf_name);
  // target AMF failure

  amf_status_info_list.push_back(amf_status_info);
  amf_status_change_notification.setAmfStatusInfoList(amf_status_info_list);

  std::vector<std::string> notification_uris =
      get_amf_status_change_subscription_uris(guamis);

  // Send request to SBI to send AMF status change notification to subscribed NF
  // instances
  auto itti_msg = std::make_shared<itti_sbi_amf_status_change_notification>(
      TASK_AMF_APP, TASK_AMF_SBI);
  itti_msg->amf_status_change_notification = amf_status_change_notification;
  itti_msg->notification_uris              = notification_uris;

  int ret = itti_inst->send_msg(itti_msg);
  if (RETURNok != ret) {
    Logger::amf_app().error(
        "Could not send ITTI message %s to task TASK_AMF_SBI",
        itti_msg->get_msg_name());
  }
}

//==============================================================================
// BCF Authentication — Identity & Crypto Initialization
//==============================================================================

//------------------------------------------------------------------------------
bool amf_app::init_did_auth_module() {
  Logger::amf_app().info("[Identity] Initializing BCF authentication module");

  // Check if BCF auth is enabled in config
  // Enable if BCF registration is enabled and BCF address is configured
  if (!amf_cfg->register_bcf || amf_cfg->bcf_addr.uri_root.empty()) {
    Logger::amf_app().info(
        "[Identity] BCF authentication disabled (BCF registration not enabled or BCF address not configured)");
    m_did_auth_enabled = false;
    return true;
  }

  try {
    // Read local DID and keys from extended profile
    nlohmann::json extended_profile = read_extended_profile_from_file();
    if (extended_profile.empty()) {
      Logger::amf_app().warn(
          "[Identity] Cannot initialize: extended profile not available");
      m_did_auth_enabled = false;
      return false;
    }

    std::string local_did;
    if (extended_profile.contains("did")) {
      local_did = extended_profile["did"].get<std::string>();
    } else {
      Logger::amf_app().warn("DID not found in extended profile");
      m_did_auth_enabled = false;
      return false;
    }

    // Use amf_instance_id (set by generate_uuid() before this call)
    // This ID matches the nfInstanceId from extended profile or is a generated UUID
    Logger::amf_app().debug(
        "Using AMF instance ID for key lookup: %s", amf_instance_id.c_str());

    // Key directory and file path based on NF instance ID
    std::string key_dir = amf_cfg->key_store_path.empty()
                              ? "/usr/local/etc/oai/keys"
                              : amf_cfg->key_store_path;
    std::string private_key_path = key_dir + "/" + amf_instance_id + "_private.hex";

    Logger::amf_app().debug(
        "Looking for private key file: %s", private_key_path.c_str());

    // Check if the key file exists
    if (!std::filesystem::exists(private_key_path)) {
      // Try alternative: check if privateKey is in extended profile
      std::string private_key_hex;
      if (extended_profile.contains("privateKey")) {
        private_key_hex = extended_profile["privateKey"].get<std::string>();
      } else if (extended_profile.contains("private_key")) {
        private_key_hex = extended_profile["private_key"].get<std::string>();
      }

      if (!private_key_hex.empty()) {
        Logger::amf_app().debug("Using private key from extended profile");
        // Write to expected location
        std::filesystem::create_directories(key_dir);
        std::ofstream key_file(private_key_path);
        if (key_file.is_open()) {
          key_file << private_key_hex;
          key_file.close();
          Logger::amf_app().debug(
              "Wrote private key to %s", private_key_path.c_str());
        }
      } else {
        Logger::amf_app().error(
            "Private key file not found: %s", private_key_path.c_str());
        m_did_auth_enabled = false;
        return false;
      }
    }

    // Get NF instance ID from amf_instance_id (set earlier by generate_uuid() or from config)
    // This ensures the BCF auth module uses the same instance ID as the AMF
    std::string nf_instance_id = amf_instance_id;
    if (nf_instance_id.empty()) {
      Logger::amf_app().warn(
          "[Identity] amf_instance_id is empty, trying to get from extended profile");
      if (extended_profile.contains("nfInstanceId")) {
        nf_instance_id = extended_profile["nfInstanceId"].get<std::string>();
      }
    }
    
    Logger::amf_app().info(
        "[Identity] Creating BCF auth module with nf_type=AMF, nf_instance_id=%s",
        nf_instance_id.empty() ? "(empty)" : nf_instance_id.c_str());

    // Create BCF auth instance (BCF interaction via callbacks, not direct client)
    m_did_auth = std::make_unique<oai::amf::did_auth::DIDAuth>(
        local_did, private_key_path, "AMF", nf_instance_id);

    if (!m_did_auth->initialize()) {
      Logger::amf_app().error("[Identity] Failed to initialize BCF auth module");
      m_did_auth.reset();
      m_did_auth_enabled = false;
      return false;
    }

    // Set HTTP callback for initiator mode (using amf_sbi)
    m_did_auth->set_http_request_callback(
        [](const std::string& uri, const std::string& method,
           const std::string& body, std::string& response_body,
           uint32_t& response_code) -> bool {
          return amf_sbi_inst->send_did_auth_request(
              uri, method, body, response_body, response_code);
        });

    // Set BCF callbacks for public key queries
    // Public key query callback - queries BCF for a DID's public key
    // IMPORTANT: Public keys MUST be obtained from BCF, NOT extracted from DID string
    // This ensures proper verification against blockchain-registered identity
    std::string bcf_uri_root = amf_cfg->bcf_addr.uri_root;
    m_did_auth->set_public_key_query_callback(
        [bcf_uri_root](const std::string& did) -> oai::amf::did_auth::public_key_response_t {
          oai::amf::did_auth::public_key_response_t response;
          response.did   = did;
          response.found = false;

          // =====================================================================
          // BCF Query for DID Document / Public Key
          // Per security requirements, public keys MUST be obtained from BCF
          // to verify DID registration status on blockchain
          // =====================================================================
          
          if (bcf_uri_root.empty()) {
            // BCF not configured - this is a security error in production
            Logger::amf_app().error(
                "[BCF Auth] BCF not configured! Cannot verify DID: %s. "
                "Public key retrieval from DID string is DISABLED for security.",
                did.c_str());
            response.error_message = "BCF not configured - cannot verify DID identity";
            response.found = false;
            return response;
          }

          // Query BCF for DID Document
          // GET /nbcf_did/v1/did_document/{did}
          std::string query_uri = bcf_uri_root + "/nbcf_did/v1/did_document/" + did;
          
          std::string response_body;
          uint32_t response_code = 0;
          
          if (!amf_sbi_inst->send_did_auth_request(
                  query_uri, "GET", "", response_body, response_code)) {
            Logger::amf_app().error(
                "[BCF Auth] Failed to connect to BCF at %s for DID: %s",
                bcf_uri_root.c_str(), did.c_str());
            response.error_message = "Failed to connect to BCF";
            return response;
          }
          
          if (response_code != 200) {
            Logger::amf_app().error(
                "[BCF Auth] BCF query failed: HTTP %d for DID: %s",
                response_code, did.c_str());
            response.error_message = "BCF returned error: HTTP " + std::to_string(response_code);
            return response;
          }
          
          if (response_body.empty()) {
            Logger::amf_app().error(
                "[BCF Auth] BCF returned empty response for DID: %s", did.c_str());
            response.error_message = "BCF returned empty response";
            return response;
          }
          
          try {
            nlohmann::json bcf_resp = nlohmann::json::parse(response_body);
            
            // Parse DID Document response
            // Expected format from BCF:
            // {
            //   "found": true,
            //   "did_document": {
            //     "id": "did:oai5gc:...",
            //     "verificationMethod": [{
            //       "id": "#key-1",
            //       "type": "EcdsaSecp256k1VerificationKey2019",
            //       "publicKeyHex": "04..."
            //     }],
            //     ...
            //   },
            //   "public_key": "04...",  // convenience field
            //   "nf_type": "AUSF",
            //   "nf_instance_id": "..."
            // }
            
            if (!bcf_resp.contains("found") || !bcf_resp["found"].get<bool>()) {
              std::string error_msg = bcf_resp.value("error_message", "DID not registered in BCF");
              Logger::amf_app().error(
                  "[BCF Auth] DID not found in BCF: %s - Error: %s",
                  did.c_str(), error_msg.c_str());
              response.error_message = error_msg;
              return response;
            }
            
            // Extract public key from response
            std::string public_key;
            
            // Try direct public_key field first (convenience)
            if (bcf_resp.contains("public_key") && !bcf_resp["public_key"].get<std::string>().empty()) {
              public_key = bcf_resp["public_key"].get<std::string>();
            }
            // Otherwise parse from DID Document verificationMethod
            else if (bcf_resp.contains("did_document")) {
              nlohmann::json did_doc = bcf_resp["did_document"];
              if (did_doc.contains("verificationMethod") && did_doc["verificationMethod"].is_array()) {
                for (const auto& vm : did_doc["verificationMethod"]) {
                  if (vm.contains("publicKeyHex")) {
                    public_key = vm["publicKeyHex"].get<std::string>();
                    break;
                  }
                  if (vm.contains("publicKeyMultibase")) {
                    // TODO: Convert multibase to hex if needed
                    std::string multibase = vm["publicKeyMultibase"].get<std::string>();
                    if (multibase.length() > 1 && multibase[0] == 'z') {
                      // Base58 encoding, need conversion
                      Logger::amf_app().warn(
                          "[BCF Auth] publicKeyMultibase conversion not implemented");
                    }
                  }
                }
              }
            }
            
            if (public_key.empty()) {
              Logger::amf_app().error(
                  "[BCF Auth] BCF response missing public key for DID: %s",
                  did.c_str());
              response.error_message = "DID Document missing public key";
              return response;
            }
            
            response.found = true;
            response.public_key = public_key;
            response.nf_type = bcf_resp.value("nf_type", "");
            response.nf_instance_id = bcf_resp.value("nf_instance_id", "");
            
            Logger::amf_app().info(
                "[BCF Auth] BCF verified DID: %s, nf_type: %s",
                did.substr(0, 32).c_str(), response.nf_type.c_str());
            Logger::amf_app().debug(
                "[BCF Auth] Public key from BCF (first 40 chars): %s...",
                public_key.substr(0, 40).c_str());
                
          } catch (const nlohmann::json::exception& e) {
            Logger::amf_app().error(
                "[BCF Auth] Failed to parse BCF response for DID %s: %s",
                did.c_str(), e.what());
            response.error_message = std::string("Failed to parse BCF response: ") + e.what();
          }

          return response;
        });

    // Configure NF endpoints directly from config (similar to AUSF, UDM, etc.)
    // No dynamic NF discovery - use configured addresses
    if (!amf_cfg->smf_addr.uri_root.empty()) {
      m_did_auth->configure_nf_endpoint(
          "SMF", amf_cfg->smf_addr.uri_root, amf_cfg->smf_addr.api_version);
    }
    if (!amf_cfg->ausf_addr.uri_root.empty()) {
      m_did_auth->configure_nf_endpoint(
          "AUSF", amf_cfg->ausf_addr.uri_root, amf_cfg->ausf_addr.api_version);
    }
    if (!amf_cfg->udm_addr.uri_root.empty()) {
      m_did_auth->configure_nf_endpoint(
          "UDM", amf_cfg->udm_addr.uri_root, amf_cfg->udm_addr.api_version);
    }
    if (!amf_cfg->nssf_addr.uri_root.empty()) {
      m_did_auth->configure_nf_endpoint(
          "NSSF", amf_cfg->nssf_addr.uri_root, amf_cfg->nssf_addr.api_version);
    }
    if (!amf_cfg->pcf_addr.uri_root.empty()) {
      m_did_auth->configure_nf_endpoint(
          "PCF", amf_cfg->pcf_addr.uri_root, amf_cfg->pcf_addr.api_version);
    }
    if (!amf_cfg->bcf_addr.uri_root.empty()) {
      m_did_auth->configure_nf_endpoint(
          "BCF", amf_cfg->bcf_addr.uri_root, amf_cfg->bcf_addr.api_version);
    }

    Logger::amf_app().debug("Configured NF endpoints from config file");

    // =========================================================================
    // Configure BCF single-direction authentication (new - replaces mutual auth)
    // NF → BCF: authenticate to get token for accessing target NFs
    // =========================================================================
    if (!amf_cfg->bcf_addr.uri_root.empty()) {
      Logger::amf_app().info(
          "[BCF Auth] Configuring BCF self-authentication, BCF URI: %s",
          amf_cfg->bcf_addr.uri_root.c_str());

      m_did_auth->configure_bcf_auth(amf_cfg->bcf_addr.uri_root);
      // Configure notification URI so BCF can POST notifications back to AMF
      try {
        // Construct AMF callback URI from source values and always keep scheme.
        std::string callback_host = std::string(inet_ntoa(amf_cfg->sbi.addr4));
        std::string callback_port = std::to_string(amf_cfg->sbi.port);
        std::string callback_root =
            std::string("http://") + callback_host + ":" + callback_port;
        std::string api_ver =
            amf_cfg->sbi.api_version.value_or(std::string("v1"));
        std::string notification_uri =
            callback_root + amf_sbi_helper::AmfCallbackBase() +
            std::string("/nbcf_management/") + api_ver +
            std::string("/notifications");

        if (!notification_uri.empty() &&
            notification_uri.rfind("http://", 0) != 0 &&
            notification_uri.rfind("https://", 0) != 0) {
          notification_uri = "http://" + notification_uri;
        }

        if (m_did_auth && m_did_auth->get_module()) {
          std::string notification_transport =
              amf_cfg->support_features.http_version == 1 ? "http1-json"
                                                          : "auto";
          m_did_auth->get_module()->set_bcf_notification_uri(notification_uri);
          m_did_auth->get_module()->set_bcf_notification_transport(
              notification_transport);
          Logger::amf_app().info(
              "[BCF Auth] Set BCF notification callback uri=%s transport=%s",
              notification_uri.c_str(), notification_transport.c_str());
        } else {
          Logger::amf_app().warn("[BCF Auth] DIDAuth module not available to set notification URI");
        }
      } catch (const std::exception& e) {
        Logger::amf_app().warn("[BCF Auth] Failed to set BCF notification URI: %s", e.what());
      }
      Logger::amf_app().info(
          "[BCF Auth] BCF self-authentication configured successfully");
    } else {
      Logger::amf_app().warn(
          "[BCF Auth] BCF URI not configured, BCF auth will not be available");
    }

    m_did_auth_enabled = true;
    // State transition: INIT → DID_READY
    {
      std::lock_guard<std::mutex> lock(m_bcf_state_mutex);
      m_bcf_state = BcfLifecycleState::DID_READY;
    }
    Logger::amf_app().info(
        "[AMF][INIT] Local identity loaded successfully, DID: %s",
        local_did.c_str());
    Logger::amf_app().info(
        "[AMF][INIT] State → DID_READY (awaiting BCF registration via start())");
    return true;

  } catch (const std::exception& e) {
    Logger::amf_app().error(
        "Exception during BCF auth initialization: %s", e.what());
    m_did_auth.reset();
    m_did_auth_enabled = false;
    return false;
  }
}

//------------------------------------------------------------------------------
void amf_app::init_security_audit_module() {
  const std::string nf_instance_id =
      amf_instance_id.empty() ? std::string("amf-unknown") : amf_instance_id;
  const std::string local_did = get_local_did();

  m_security_audit =
      std::make_unique<oai::common::audit::security_audit>(
          "AMF", "AMF", nf_instance_id);
  m_security_audit->set_identity(local_did, "AMF", nf_instance_id);
  m_security_audit->set_summary_submit_callback(
      [this](
          const oai::common::audit::security_audit_summary& summary,
          std::string& response_body, std::uint32_t& response_code) -> bool {
        return submit_security_audit_summary(
            summary, response_body, response_code);
      });

  m_security_audit->record_event(
      "IDENTITY_SETUP", "identity_setup_completed",
      local_did.empty() ? "partial" : "success", "", "BCF", "BCF",
      {{"nf_instance_id", nf_instance_id}});

  Logger::amf_app().info(
      "[AMF][AUDIT] Security audit initialized: session_id=%s did=%s",
      m_security_audit->session_id().c_str(),
      local_did.empty() ? "(empty)" : local_did.c_str());
}

//------------------------------------------------------------------------------
std::string amf_app::get_local_did() const {
  return m_did_auth ? m_did_auth->get_local_did() : "";
}

//------------------------------------------------------------------------------
bool amf_app::submit_security_audit_summary(
    const oai::common::audit::security_audit_summary& summary,
    std::string& response_body,
    std::uint32_t& response_code) {
  response_body.clear();
  response_code = 0;

  if (!amf_cfg || !amf_cfg->register_bcf || amf_cfg->bcf_addr.uri_root.empty()) {
    Logger::amf_app().debug(
        "[AMF][AUDIT] Skip session digest submit: BCF is not enabled");
    return false;
  }
  if (!http_client_inst) {
    Logger::amf_app().warn(
        "[AMF][AUDIT] Cannot submit session digest: HTTP client unavailable");
    return false;
  }

  std::string auth_token;
  if (!ensure_bcf_auth(auth_token) || auth_token.empty()) {
    Logger::amf_app().warn(
        "[AMF][AUDIT] Cannot submit session digest: BCF token unavailable");
    return false;
  }

  std::string bcf_uri = amf_cfg->bcf_addr.uri_root;
  while (!bcf_uri.empty() && bcf_uri.back() == '/') {
    bcf_uri.pop_back();
  }
  const std::string uri = bcf_uri + "/nbcf_audit/v1/session-digests";

  nlohmann::json body = summary.to_session_digest_json();
  body["subject_did"] = body.value("subject_did", std::string()).empty()
                            ? get_local_did()
                            : body.value("subject_did", std::string());
  body["token_fingerprint"] =
      oai::common::audit::security_audit::fingerprint_token(auth_token);

  oai::http::request request =
      http_client_inst->prepare_json_request(uri, body.dump());
  request.headers.insert({"Authorization", "Bearer " + auth_token});
  request.headers.insert({"X-Session-ID", summary.session_id});
  request.headers.insert({"X-Interaction-ID", summary.interaction_id});
  request.headers.insert(
      {"X-Subject-DID", body.value("subject_did", std::string())});
  request.headers.insert({"X-Peer-DID", summary.peer_DID});
  request.headers.insert({"X-Subject-NF-Type", "AMF"});
  request.headers.insert({"X-Peer-NF-Type", summary.peer_type});

  auto response = http_client_inst->send_http_request(
      oai::common::sbi::method_e::POST, request);
  response_code = static_cast<std::uint32_t>(response.status_code);
  response_body = response.body;

  const bool ok = response.status_code >= 200 && response.status_code < 300;
  if (ok) {
    Logger::amf_app().info(
        "[AMF][AUDIT] Session digest anchored: session_id=%s seq=%llu stage=%s",
        summary.session_id.c_str(),
        static_cast<unsigned long long>(summary.summary_seq),
        summary.stage.c_str());
  } else {
    Logger::amf_app().warn(
        "[AMF][AUDIT] Session digest submit failed: http=%u body=%s",
        response_code, response_body.empty() ? "{}" : response_body.c_str());
  }
  return ok;
}

//------------------------------------------------------------------------------
// NOTE: handle_did_auth_init has been removed.
// AMF no longer acts as a responder in NF-NF mutual authentication.
// BCF single-direction auth (NF → BCF → token) replaces the old mutual auth.
// The HTTP endpoints /nf_auth/v1/mutual_auth/init and /complete are deprecated.
//------------------------------------------------------------------------------
bool amf_app::handle_did_auth_init(
    const std::string& initiator_did,
    const std::string& nonce,
    uint64_t timestamp,
    const std::string& nf_type,
    const std::string& source_address,
    nlohmann::json& response_json,
    int& http_code) {
  Logger::amf_app().warn(
      "[BCF Auth] Mutual auth init endpoint is DEPRECATED. "
      "Use BCF self-auth instead.");
  response_json["error"]   = "deprecated";
  response_json["message"] = "NF-NF mutual authentication is deprecated. "
                             "Use BCF single-direction auth (POST /nbcf_auth/v1/auth/init).";
  http_code = 410;  // Gone
  return false;
}

//------------------------------------------------------------------------------
// NOTE: handle_did_auth_complete has been removed.
// AMF no longer acts as a responder in NF-NF mutual authentication.
// BCF single-direction auth (NF → BCF → token) replaces the old mutual auth.
//------------------------------------------------------------------------------
bool amf_app::handle_did_auth_complete(
    const std::string& session_id,
    const std::string& initiator_signature,
    const std::string& initiator_did,
    const std::string& responder_did,
    uint64_t timestamp_ms,
    const std::string& source_address,
    nlohmann::json& response_json,
    int& http_code) {
  Logger::amf_app().warn(
      "[BCF Auth] Mutual auth complete endpoint is DEPRECATED. "
      "Use BCF self-auth instead.");
  response_json["error"]   = "deprecated";
  response_json["message"] = "NF-NF mutual authentication is deprecated. "
                             "Use BCF single-direction auth (POST /nbcf_auth/v1/auth/verify).";
  http_code = 410;  // Gone
  return false;
}

//------------------------------------------------------------------------------
// NOTE: handle_did_auth_status has been removed.
// Session status queries for mutual auth are no longer applicable.
//------------------------------------------------------------------------------
bool amf_app::handle_did_auth_status(
    const std::string& session_id,
    nlohmann::json& response_json,
    int& http_code) {
  Logger::amf_app().warn(
      "[BCF Auth] Mutual auth status endpoint is DEPRECATED.");
  response_json["error"]   = "deprecated";
  response_json["message"] = "Mutual auth session status is deprecated.";
  http_code = 410;  // Gone
  return false;
}

//------------------------------------------------------------------------------
// NOTE: initiate_did_auth (per-request, UE-triggered) has been removed.
// BCF auth is now performed proactively at startup via authenticate_to_bcf().
// Per-request token usage should call ensure_bcf_auth() instead.
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
bool amf_app::is_peer_authenticated(const std::string& peer_did) {
  if (!m_did_auth_enabled || !m_did_auth) {
    return false;
  }
  return m_did_auth->is_peer_authenticated(peer_did);
}

//------------------------------------------------------------------------------
std::string amf_app::get_peer_auth_token(const std::string& peer_did) {
  if (!m_did_auth_enabled || !m_did_auth) {
    return "";
  }
  return m_did_auth->get_peer_auth_token(peer_did);
}

//------------------------------------------------------------------------------
void amf_app::cleanup_did_auth_sessions() {
  if (!m_did_auth_enabled || !m_did_auth) {
    return;
  }

  Logger::amf_app().debug("Cleaning up expired BCF auth sessions");
  m_did_auth->cleanup_expired_sessions();
}

// =============================================================================
// BCF Lifecycle State Accessors
// =============================================================================

//------------------------------------------------------------------------------
BcfLifecycleState amf_app::get_bcf_state() const {
  std::lock_guard<std::mutex> lock(m_bcf_state_mutex);
  return m_bcf_state;
}

//------------------------------------------------------------------------------
bool amf_app::is_bcf_registered() const {
  std::lock_guard<std::mutex> lock(m_bcf_state_mutex);
  return m_bcf_state >= BcfLifecycleState::BCF_REGISTERED &&
         m_bcf_state != BcfLifecycleState::FAILED;
}

//------------------------------------------------------------------------------
void amf_app::trigger_bcf_auth_after_registration() {
  if (should_reject_new_async_request("new BCF auth/subscription request")) {
    return;
  }

  // Gate: only allowed when state == BCF_REGISTERED
  {
    std::lock_guard<std::mutex> lock(m_bcf_state_mutex);
    if (m_bcf_state != BcfLifecycleState::BCF_REGISTERED) {
      Logger::amf_app().error(
          "[AMF][BCF-AUTH] REFUSED: cannot start auth, current state is %s "
          "(required: BCF_REGISTERED)",
          bcf_state_to_string(m_bcf_state));
      return;
    }
    m_bcf_state = BcfLifecycleState::AUTH_IN_PROGRESS;
  }

  Logger::amf_app().info(
      "[AMF][BCF-AUTH] State → AUTH_IN_PROGRESS, "
      "registration confirmed, starting auth init to BCF");

  if (!m_did_auth_enabled || !m_did_auth) {
    Logger::amf_app().error(
        "[AMF][BCF-AUTH] BCF auth module not available, cannot authenticate");
    std::lock_guard<std::mutex> lock(m_bcf_state_mutex);
    m_bcf_state = BcfLifecycleState::FAILED;
    return;
  }

  // Perform BCF authentication synchronously
  std::string startup_token;
  bool success = false;

  try {
    Logger::amf_app().info(
        "[AMF][BCF-AUTH] Sending auth init request to BCF...");

    success = m_did_auth->authenticate_to_bcf(startup_token);
  } catch (const std::exception& e) {
    Logger::amf_app().error(
        "[AMF][BCF-AUTH] Exception during BCF authentication: %s", e.what());
  }

  if (success) {
    // State transition: AUTH_IN_PROGRESS → TOKEN_READY
    {
      std::lock_guard<std::mutex> lock(m_bcf_state_mutex);
      m_bcf_state = BcfLifecycleState::TOKEN_READY;
    }
    Logger::amf_app().info(
        "[AMF][BCF-AUTH] Auth result received, access token cached (token: %s...)",
        startup_token.length() > 24
            ? startup_token.substr(0, 24).c_str()
            : startup_token.c_str());
    Logger::amf_app().info(
        "[AMF][TOKEN] State → TOKEN_READY, token ready for future SBI requests");

    if (m_security_audit) {
      const std::string token_fp =
          oai::common::audit::security_audit::fingerprint_token(startup_token);
      m_security_audit->record_event(
          "AUTH_VERIFY", "auth_result_received", "success", "", "BCF",
          "BCF", {{"bcf_state", "TOKEN_READY"}}, token_fp);
      m_security_audit->record_event(
          "TOKEN_ISSUED", "token_issued", "success", "", "BCF", "BCF",
          {{"token_fingerprint", token_fp}}, token_fp);
      m_security_audit->checkpoint(
          "bcf_auth_completed", "", "BCF", "BCF", "checkpoint");
    }

      // Authentication and authorization are considered complete at this point.
      // Only after the AMF-level state is updated and logged do we trigger
      // subscription creation. This enforces the strict ordering required.
      try {
        if (should_reject_new_async_request("BCF subscription creation")) {
          Logger::amf_app().warn(
              "[AMF][BCF-SUB] Skip subscription creation because shutdown is in progress");
          return;
        }

        Logger::amf_app().info(
            "[AMF][BCF-AUTH] Authentication and authorization completed, starting subscription phase");
        if (m_did_auth && m_did_auth->get_module() && m_did_auth->get_module()->get_bcf_auth_client()) {
          auto client = m_did_auth->get_module()->get_bcf_auth_client();
          // create_subscription will itself check token authorized state
          bool sub_ok = false;
          try {
            sub_ok = client->create_subscription();
          } catch (const std::exception& e) {
            Logger::amf_app().warn("[AMF][BCF-SUB] Exception during create_subscription: %s", e.what());
            sub_ok = false;
          }
          if (sub_ok) {
            Logger::amf_app().info("[AMF][BCF-SUB] State → SUBSCRIPTION_CREATED");
            // Fetch last subscription response and let DIDAuth process full NF profiles
            try {
              nlohmann::json resp = client->get_last_subscription_response();
              if (!resp.is_null()) {
                if (m_did_auth && m_did_auth->get_module()) {
                  bool ok = m_did_auth->get_module()->handle_subscription_response(resp);
                  if (!ok) Logger::amf_app().warn("[AMF][BCF-SUB] DIDAuth failed to process subscription response");
                }
              }
            } catch (const std::exception& e) {
              Logger::amf_app().warn("[AMF][BCF-SUB] Exception processing subscription response: %s", e.what());
            }
          } else {
            Logger::amf_app().warn("[AMF][BCF-SUB] Subscription creation did not succeed (non-fatal)");
          }
        } else {
          Logger::amf_app().warn("[AMF][BCF-SUB] DIDAuth/BCF client not available to create subscription");
        }
      } catch (const std::exception& e) {
        Logger::amf_app().warn("[AMF][BCF-SUB] Exception during subscription creation: %s", e.what());
      }
  } else {
    Logger::amf_app().warn(
        "[AMF][BCF-AUTH] BCF authentication FAILED. "
        "Will retry on first UE auth request via ensure_bcf_auth().");
    // Stay at BCF_REGISTERED so retries are allowed
    {
      std::lock_guard<std::mutex> lock(m_bcf_state_mutex);
      m_bcf_state = BcfLifecycleState::BCF_REGISTERED;
    }
    Logger::amf_app().info(
        "[AMF][BCF-AUTH] State → BCF_REGISTERED (auth failed, retry allowed)");
    if (m_security_audit) {
      m_security_audit->record_event(
          "AUTH_VERIFY", "auth_result_received", "failure", "", "BCF",
          "BCF", {{"bcf_state", "BCF_REGISTERED"}});
    }
  }
}

// =============================================================================
// BCF Single-Direction Authentication (New - replaces NF-A/NF-B mutual auth)
// =============================================================================

//------------------------------------------------------------------------------
bool amf_app::authenticate_to_bcf(std::string& auth_token) {
  if (should_reject_new_async_request("new BCF auth init/verify request")) {
    return false;
  }

  if (!m_did_auth_enabled || !m_did_auth) {
    Logger::amf_app().warn(
        "[BCF Auth] BCF auth not enabled, skipping BCF authentication");
    return false;
  }

  // Gate: must be registered with BCF before authenticating
  if (!is_bcf_registered()) {
    BcfLifecycleState cur = get_bcf_state();
    Logger::amf_app().error(
        "[BCF Auth] REFUSED: cannot authenticate, AMF not registered with BCF "
        "(current state: %s). Registration must succeed first.",
        bcf_state_to_string(cur));
    return false;
  }

  try {
    Logger::amf_app().info(
        "[BCF Auth] Authenticating self to BCF...");

    // Use BCF self-auth (NF → BCF → self token)
    bool result = m_did_auth->authenticate_to_bcf(auth_token);

    if (result) {
      Logger::amf_app().info(
          "[BCF Auth] Successfully obtained BCF access token (token: %s...)",
          auth_token.length() > 24 ? auth_token.substr(0, 24).c_str() : auth_token.c_str());
    } else {
      Logger::amf_app().error(
          "[BCF Auth] Failed to authenticate self to BCF");
    }

    return result;

  } catch (const std::exception& e) {
    Logger::amf_app().error(
        "[BCF Auth] Exception during BCF authentication: %s", e.what());
    return false;
  }
}

//------------------------------------------------------------------------------
bool amf_app::ensure_bcf_auth(std::string& auth_token) {
  if (should_reject_new_async_request("new BCF auth ensure request")) {
    return false;
  }

  if (!m_did_auth_enabled || !m_did_auth) {
    Logger::amf_app().warn(
        "[BCF Auth] BCF auth not enabled, skipping BCF authentication");
    return false;
  }

  // Gate: must be registered with BCF before authenticating
  if (!is_bcf_registered()) {
    BcfLifecycleState cur = get_bcf_state();
    Logger::amf_app().warn(
        "[BCF Auth] Cannot ensure BCF auth: AMF not registered with BCF "
        "(current state: %s)",
        bcf_state_to_string(cur));
    return false;
  }

  try {
    // ensure_bcf_auth checks token cache first, only contacts BCF if needed
    bool result = m_did_auth->ensure_bcf_auth(auth_token);

    if (result) {
      // If we just obtained a token and state was BCF_REGISTERED, upgrade
      {
        std::lock_guard<std::mutex> lock(m_bcf_state_mutex);
        if (m_bcf_state == BcfLifecycleState::BCF_REGISTERED) {
          m_bcf_state = BcfLifecycleState::TOKEN_READY;
          Logger::amf_app().info(
              "[AMF][TOKEN] State → TOKEN_READY (via ensure_bcf_auth)");
        }
      }
      Logger::amf_app().debug(
          "[BCF Auth] BCF access token ensured (token: %s...)",
          auth_token.length() > 24 ? auth_token.substr(0, 24).c_str() : auth_token.c_str());
    } else {
      Logger::amf_app().error(
          "[BCF Auth] Failed to ensure BCF self auth");
    }

    return result;

  } catch (const std::exception& e) {
    Logger::amf_app().error(
        "[BCF Auth] Exception during ensure_bcf_auth: %s", e.what());
    return false;
  }
}
