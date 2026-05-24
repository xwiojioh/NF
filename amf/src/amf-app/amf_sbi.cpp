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

#include "amf_sbi.hpp"

#include <nlohmann/json.hpp>
#include <sstream>

#include "3gpp_24.501.hpp"
#include "3gpp_29.500.h"
#include "3gpp_29.502.h"
#include "AmfEventReport.h"
#include "amf.hpp"
#include "amf_app.hpp"
#include "amf_config.hpp"
#include "amf_conversions.hpp"
#include "amf_n1.hpp"
#include "amf_sbi_helper.hpp"
#include "http_client.hpp"
#include "itti.hpp"
#include "itti_msg_amf_app.hpp"
#include "itti_msg_n2.hpp"
#include "mime_parser.hpp"
#include "nas_context.hpp"
#include "output_wrapper.hpp"
#include "security_audit.hpp"
#include "ue_context.hpp"
#include "utils.hpp"
#include "Guami.h"

// Latency measurement probes (enabled via -DENABLE_LATENCY_PROBE)
#include "latency_probe.hpp"
#include "string.hpp"

using namespace oai::config;
using namespace amf_application;
using namespace oai::amf::api;
extern itti_mw* itti_inst;
extern std::unique_ptr<oai::config::amf_config> amf_cfg;
extern amf_sbi* amf_sbi_inst;
extern amf_n1* amf_n1_inst;
extern amf_app* amf_app_inst;
extern std::shared_ptr<oai::http::http_client> http_client_inst;

//------------------------------------------------------------------------------
static bool reject_outbound_request_during_shutdown(
    const std::string& action, uint32_t promise_id = 0) {
  if (!amf_app_inst) {
    return false;
  }

  if (!amf_app_inst->should_reject_new_async_request(action)) {
    return false;
  }

  if (promise_id > 0) {
    nlohmann::json response_data = {};
    response_data[kSbiResponseHttpResponseCode] =
        static_cast<uint32_t>(
            oai::common::sbi::http_status_code::SERVICE_UNAVAILABLE);
    response_data[kSbiResponseJsonData] = {
        {"error", "shutdown_in_progress"},
        {"message", "AMF shutdown is in progress"}};
    amf_app_inst->trigger_process_response(promise_id, response_data);
  }

  return true;
}

//------------------------------------------------------------------------------
static std::string get_current_bcf_access_token() {
  if (!amf_app_inst || !amf_app_inst->is_did_auth_enabled()) {
    return {};
  }

  std::string token = {};
  if (!amf_app_inst->ensure_bcf_auth(token) || token.empty()) {
    return {};
  }

  return token;
}

//------------------------------------------------------------------------------
static void add_bearer_token_header(
    oai::http::request& http_request, const std::string& access_token) {
  http_request.headers.insert({"Authorization", "Bearer " + access_token});
}

//------------------------------------------------------------------------------
static nlohmann::json build_ue_auth_request_with_token(
    const oai::_3gpp::model::AuthenticationInfo& authentication_info,
    const nlohmann::json& amf_profile) {
  nlohmann::json json_data = {};
  to_json(json_data, authentication_info);
  json_data["amfProfile"] = amf_profile;
  return json_data;
}

//------------------------------------------------------------------------------
static std::string build_amf_profile_summary(
    const nlohmann::json& amf_profile) {
  std::ostringstream summary = {};
  summary << "nfInstanceId="
          << amf_profile.value("nfInstanceId", std::string("N/A"))
          << ", nfType="
          << amf_profile.value("nfType", std::string("N/A"))
          << ", fqdn="
          << amf_profile.value("fqdn", std::string("N/A"))
          << ", plmnCount="
          << (amf_profile.contains("plmnList") &&
                      amf_profile["plmnList"].is_array()
                  ? amf_profile["plmnList"].size()
                  : 0)
          << ", sNssaiCount="
          << (amf_profile.contains("sNssais") &&
                      amf_profile["sNssais"].is_array()
                  ? amf_profile["sNssais"].size()
                  : 0)
          << ", ipv4Count="
          << (amf_profile.contains("ipv4Addresses") &&
                      amf_profile["ipv4Addresses"].is_array()
                  ? amf_profile["ipv4Addresses"].size()
                  : 0);
  return summary.str();
}

//------------------------------------------------------------------------------
void amf_sbi_task(void*) {
  const task_id_t task_id = TASK_AMF_SBI;
  itti_inst->notify_task_ready(task_id);
  do {
    std::shared_ptr<itti_msg> shared_msg = itti_inst->receive_msg(task_id);
    auto* msg                            = shared_msg.get();
    switch (msg->msg_type) {
      case NSMF_PDU_SESSION_CREATE_SM_CTX: {
        Logger::amf_sbi().info("Running ITTI_SMF_PDU_SESSION_CREATE_SM_CTX");
        itti_nsmf_pdusession_create_sm_context* m =
            dynamic_cast<itti_nsmf_pdusession_create_sm_context*>(msg);
        if (!m) break;
        amf_sbi_inst->handle_itti_message(std::ref(*m));
      } break;

      case NSMF_PDU_SESSION_UPDATE_SM_CTX: {
        Logger::amf_sbi().info(
            "Receive Nsmf_PDUSessionUpdateSMContext, handling ...");
        itti_nsmf_pdusession_update_sm_context* m =
            dynamic_cast<itti_nsmf_pdusession_update_sm_context*>(msg);
        if (!m) break;
        amf_sbi_inst->handle_itti_message(std::ref(*m));
      } break;

      case NSMF_PDU_SESSION_RELEASE_SM_CTX: {
        Logger::amf_sbi().info(
            "Receive Nsmf_PDUSessionReleaseSMContext, handling ...");
        itti_nsmf_pdusession_release_sm_context* m =
            dynamic_cast<itti_nsmf_pdusession_release_sm_context*>(msg);
        if (!m) break;
        amf_sbi_inst->handle_itti_message(std::ref(*m));
      } break;

      case PDU_SESSION_RESOURCE_SETUP_RESPONSE: {
        Logger::amf_sbi().info(
            "Receive PDU Session Resource Setup response, handling ...");
        itti_pdu_session_resource_setup_response* m =
            dynamic_cast<itti_pdu_session_resource_setup_response*>(msg);
        if (!m) break;
        amf_sbi_inst->handle_itti_message(std::ref(*m));
      } break;

      case SBI_REGISTER_NF_INSTANCE_REQUEST: {
        Logger::amf_sbi().info(
            "Receive Register NF Instance Request, handling ...");
        itti_sbi_register_nf_instance_request* m =
            dynamic_cast<itti_sbi_register_nf_instance_request*>(msg);
        if (!m) break;
        amf_sbi_inst->handle_itti_message(std::ref(*m));
      } break;

      case SBI_UPDATE_NF_INSTANCE_REQUEST: {
        Logger::amf_sbi().info(
            "Receive Update NF Instance Request, handling ...");
        itti_sbi_update_nf_instance_request* m =
            dynamic_cast<itti_sbi_update_nf_instance_request*>(msg);
        if (!m) break;
        amf_sbi_inst->handle_itti_message(std::ref(*m));
      } break;

      case SBI_DEREGISTER_NF_INSTANCE_REQUEST: {
        Logger::amf_sbi().info(
            "Receive Deregister NF Instance Request, handling ...");
        itti_sbi_deregister_nf_instance_request* m =
            dynamic_cast<itti_sbi_deregister_nf_instance_request*>(msg);
        if (!m) break;
        amf_sbi_inst->handle_itti_message(std::ref(*m));
      } break;

      // BCF (Blockchain Function) Registration for DID-based Identity
      case SBI_BCF_REGISTER_NF_INSTANCE_REQUEST: {
        Logger::amf_sbi().info(
            "Receive BCF Register NF Instance Request, handling ...");
        itti_sbi_bcf_register_nf_instance_request* m =
            dynamic_cast<itti_sbi_bcf_register_nf_instance_request*>(msg);
        if (!m) break;
        amf_sbi_inst->handle_itti_message(std::ref(*m));
      } break;

      case SBI_BCF_UPDATE_NF_INSTANCE_REQUEST: {
        Logger::amf_sbi().info(
            "Receive BCF Update NF Instance Request, handling ...");
        itti_sbi_bcf_update_nf_instance_request* m =
            dynamic_cast<itti_sbi_bcf_update_nf_instance_request*>(msg);
        if (!m) break;
        amf_sbi_inst->handle_itti_message(std::ref(*m));
      } break;

      case SBI_BCF_DEREGISTER_NF_INSTANCE_REQUEST: {
        Logger::amf_sbi().info(
            "Receive BCF Deregister NF Instance Request, handling ...");
        itti_sbi_bcf_deregister_nf_instance_request* m =
            dynamic_cast<itti_sbi_bcf_deregister_nf_instance_request*>(msg);
        if (!m) break;
        amf_sbi_inst->handle_itti_message(std::ref(*m));
      } break;

      case SBI_NOTIFY_SUBSCRIBED_EVENT: {
        Logger::amf_sbi().info(
            "Receive Notify Subscribed Event Request, handling ...");
        itti_sbi_notify_subscribed_event* m =
            dynamic_cast<itti_sbi_notify_subscribed_event*>(msg);
        if (!m) break;
        amf_sbi_inst->handle_itti_message(std::ref(*m));
      } break;

      case SBI_SLICE_SELECTION_SUBSCRIPTION_DATA: {
        Logger::amf_sbi().info(
            "Receive Slice Selection Subscription Data Retrieval Request, "
            "handling ...");
        itti_sbi_slice_selection_subscription_data* m =
            dynamic_cast<itti_sbi_slice_selection_subscription_data*>(msg);
        if (!m) break;
        amf_sbi_inst->handle_itti_message(std::ref(*m));
      } break;

      case SBI_NETWORK_SLICE_SELECTION_INFORMATION: {
        Logger::amf_sbi().info(
            "Receive Network Slice Selection Information Request, "
            "handling ...");
        itti_sbi_network_slice_selection_information* m =
            dynamic_cast<itti_sbi_network_slice_selection_information*>(msg);
        if (!m) break;
        amf_sbi_inst->handle_itti_message(std::ref(*m));
      } break;

      case SBI_NETWORK_SLICE_SELECTION_DISCOVERY: {
        Logger::amf_sbi().info(
            "Receive Network Slice Selection Discovery, "
            "handling ...");
        itti_sbi_network_slice_selection_discovery* m =
            dynamic_cast<itti_sbi_network_slice_selection_discovery*>(msg);
        if (!m) break;
        amf_sbi_inst->handle_itti_message(std::ref(*m));
      } break;

      case SBI_N1_MESSAGE_NOTIFY: {
        Logger::amf_sbi().info(
            "Receive N1 Message Notify message, "
            "handling ...");
        itti_sbi_n1_message_notify* m =
            dynamic_cast<itti_sbi_n1_message_notify*>(msg);
        if (!m) break;
        amf_sbi_inst->handle_itti_message(std::ref(*m));
      } break;

      case SBI_N2_INFO_NOTIFY: {
        Logger::amf_sbi().info(
            "Receive N2 Info Notify message, "
            "handling ...");
        itti_sbi_n2_info_notify* m =
            dynamic_cast<itti_sbi_n2_info_notify*>(msg);
        if (!m) break;
        amf_sbi_inst->handle_itti_message(std::ref(*m));
      } break;

      case SBI_NF_INSTANCE_DISCOVERY: {
        Logger::amf_sbi().info(
            "Receive N1 NF Instance Discovery message, "
            "handling ...");
        itti_sbi_nf_instance_discovery* m =
            dynamic_cast<itti_sbi_nf_instance_discovery*>(msg);
        if (!m) break;
        amf_sbi_inst->handle_itti_message(std::ref(*m));
      } break;

      case SBI_DETERMINE_LOCATION_REQUEST: {
        Logger::amf_sbi().info(
            "Receive Determine Location Request message, "
            "handling ...");
        itti_sbi_determine_location_request* m =
            dynamic_cast<itti_sbi_determine_location_request*>(msg);
        if (!m) break;
        amf_sbi_inst->handle_itti_message(std::ref(*m));
      } break;

      case SBI_UE_AUTHENTICATION_REQUEST: {
        Logger::amf_sbi().info(
            "Receive UE Authentication Request message, "
            "handling ...");
        itti_sbi_ue_authentication_request* m =
            dynamic_cast<itti_sbi_ue_authentication_request*>(msg);
        if (!m) break;
        amf_sbi_inst->handle_itti_message(std::ref(*m));
      } break;

      case SBI_UE_AUTHENTICATION_CONFIRMATION: {
        Logger::amf_sbi().info(
            "Receive UE Authentication Confirmation message, "
            "handling ...");
        itti_sbi_ue_authentication_confirmation* m =
            dynamic_cast<itti_sbi_ue_authentication_confirmation*>(msg);
        if (!m) break;
        amf_sbi_inst->handle_itti_message(std::ref(*m));
      } break;

      case SBI_REGISTER_WITH_UDM: {
        Logger::amf_sbi().info(
            "Receive AMF Registration for 3GPP Access message, "
            "handling ...");
        itti_sbi_register_with_udm* m =
            dynamic_cast<itti_sbi_register_with_udm*>(msg);
        if (!m) break;
        amf_sbi_inst->handle_itti_message(std::ref(*m));
      } break;

      case SBI_RETRIEVE_AM_DATA: {
        Logger::amf_sbi().info(
            "Receive Access and Mobility Subscription Data Retrieval message, "
            "handling ...");
        itti_sbi_retrieve_am_data* m =
            dynamic_cast<itti_sbi_retrieve_am_data*>(msg);
        if (!m) break;
        amf_sbi_inst->handle_itti_message(std::ref(*m));
      } break;

      case SBI_RETRIEVE_SMF_SELECTION_SUBSCRIPTION_DATA: {
        Logger::amf_sbi().info(
            "Receive SMF Selection Subscription Data Retrieval message, "
            "handling ...");
        itti_sbi_retrieve_smf_selection_subscription_data* m =
            dynamic_cast<itti_sbi_retrieve_smf_selection_subscription_data*>(
                msg);
        if (!m) break;
        amf_sbi_inst->handle_itti_message(std::ref(*m));
      } break;

      case SBI_PCF_DISCOVERY: {
        Logger::amf_sbi().info(
            "Receive PCF Discovery message, "
            "handling ...");
        itti_sbi_pcf_discovery* m = dynamic_cast<itti_sbi_pcf_discovery*>(msg);
        if (!m) break;
        amf_sbi_inst->handle_itti_message(std::ref(*m));
      } break;

      case SBI_AM_POLICY_ASSOCIATION: {
        Logger::amf_sbi().info(
            "Receive AM Policy Association message, "
            "handling ...");
        itti_sbi_am_policy_association* m =
            dynamic_cast<itti_sbi_am_policy_association*>(msg);
        if (!m) break;
        amf_sbi_inst->handle_itti_message(std::ref(*m));
      } break;

      case SBI_AM_POLICY_ASSOCIATION_TERMINATION: {
        Logger::amf_sbi().info(
            "Receive AM Policy Association Termination message, "
            "handling ...");
        itti_sbi_am_policy_association_termination* m =
            dynamic_cast<itti_sbi_am_policy_association_termination*>(msg);
        if (!m) break;
        amf_sbi_inst->handle_itti_message(std::ref(*m));
      } break;

      case SBI_AM_POLICY_ASSOCIATION_UPDATE: {
        Logger::amf_sbi().info(
            "Receive AM Policy Association Update message, "
            "handling ...");
        itti_sbi_am_policy_association_update* m =
            dynamic_cast<itti_sbi_am_policy_association_update*>(msg);
        if (!m) break;
        amf_sbi_inst->handle_itti_message(std::ref(*m));
      } break;

      case SBI_AM_POLICY_ASSOCIATION_RETRIEVAL: {
        Logger::amf_sbi().info(
            "Receive AM Policy Association Retrieval message, "
            "handling ...");
        itti_sbi_am_policy_association_retrieval* m =
            dynamic_cast<itti_sbi_am_policy_association_retrieval*>(msg);
        if (!m) break;
        amf_sbi_inst->handle_itti_message(std::ref(*m));
      } break;

      case SBI_UE_CONTEXT_IN_SMF_DATA_RETRIEVAL: {
        Logger::amf_sbi().info(
            "Receive UE Context In SMF Data Retrieval message, "
            "handling ...");
        itti_sbi_ue_context_in_smf_data_retrieval* m =
            dynamic_cast<itti_sbi_ue_context_in_smf_data_retrieval*>(msg);
        if (!m) break;
        amf_sbi_inst->handle_itti_message(std::ref(*m));
      } break;

      case TERMINATE: {
        if (itti_msg_terminate* terminate =
                dynamic_cast<itti_msg_terminate*>(msg)) {
          Logger::amf_sbi().info("Received terminate message");
          itti_inst->mark_task_ended(task_id);
          return;
        }
      } break;
      default: {
        Logger::amf_sbi().info(
            "Receive unknown message type %d", msg->msg_type);
      }
    }
  } while (true);
}

//------------------------------------------------------------------------------
amf_sbi::amf_sbi() {
  if (itti_inst->create_task(TASK_AMF_SBI, amf_sbi_task, nullptr)) {
    Logger::amf_sbi().error("Cannot create task TASK_AMF_SBI");
    throw std::runtime_error("Cannot create task TASK_AMF_SBI");
  }
  Logger::amf_sbi().startup("amf_sbi started");
}

//------------------------------------------------------------------------------
amf_sbi::~amf_sbi() {}

//------------------------------------------------------------------------------
void amf_sbi::handle_itti_message(
    itti_pdu_session_resource_setup_response& itti_msg) {
  // TODO:
}

//------------------------------------------------------------------------------
void amf_sbi::handle_itti_message(
    itti_nsmf_pdusession_update_sm_context& itti_msg) {
  std::string ue_context_key = amf_conv::get_ue_context_key(
      itti_msg.ran_ue_ngap_id, itti_msg.amf_ue_ngap_id);
  std::shared_ptr<ue_context> uc = {};
  if (!amf_app_inst->ran_amf_id_2_ue_context(ue_context_key, uc)) return;

  std::string supi = uc->supi;

  Logger::amf_sbi().debug(
      "Send PDU Session Update SM Context Request to SMF (SUPI %s, PDU Session "
      "ID %d)",
      supi.c_str(), itti_msg.pdu_session_id);

  std::shared_ptr<pdu_session_context> psc = {};
  if (!uc->find_pdu_session_context(itti_msg.pdu_session_id, psc)) return;

  std::string remote_uri = {};
  if (!amf_sbi_helper::get_smf_pdu_session_context_uri(psc, remote_uri)) {
    Logger::amf_sbi().error("Could not find Nsmf_PDUSession URI");
    return;
  }
  remote_uri += NSMF_PDU_SESSION_MODIFY;

  Logger::amf_sbi().debug("SMF URI: %s", remote_uri.c_str());

  std::string n1sm_msg                      = {};
  std::string n2sm_msg                      = {};
  nlohmann::json pdu_session_update_request = {};

  if (itti_msg.is_n1sm_set) {
    pdu_session_update_request[oai::utils::N1_SM_CONTENT_ID]["contentId"] =
        oai::utils::N1_SM_CONTENT_ID;
    amf_conv::octet_stream_2_hex_stream(
        (uint8_t*) bdata(itti_msg.n1sm), blength(itti_msg.n1sm), n1sm_msg);
  }

  if (itti_msg.is_n2sm_set) {
    pdu_session_update_request["n2SmInfoType"] = itti_msg.n2sm_info_type;
    pdu_session_update_request["n2SmInfo"]["contentId"] =
        oai::utils::N2_SM_CONTENT_ID;
    amf_conv::octet_stream_2_hex_stream(
        (uint8_t*) bdata(itti_msg.n2sm), blength(itti_msg.n2sm), n2sm_msg);
  }

  // For N2 HO
  if (itti_msg.ho_state.compare("PREPARING") == 0) {
    pdu_session_update_request["hoState"] = "PREPARING";
  } else if (itti_msg.ho_state.compare("PREPARED") == 0) {
    pdu_session_update_request["hoState"] = "PREPARED";
  } else if (itti_msg.ho_state.compare("COMPLETED") == 0) {
    pdu_session_update_request["hoState"] = "COMPLETED";
  }

  // For Deactivation of User Plane connectivity
  if (itti_msg.up_cnx_state.compare("DEACTIVATED") == 0) {
    pdu_session_update_request["upCnxState"] = "DEACTIVATED";
  }

  // For Service Request
  if (itti_msg.up_cnx_state.compare("ACTIVATING") == 0) {
    pdu_session_update_request["upCnxState"] = "ACTIVATING";
  }

  std::string json_part = pdu_session_update_request.dump();

  bool request_result = send_http_request(
      remote_uri, json_part, n1sm_msg, n2sm_msg, supi, itti_msg.pdu_session_id,
      amf_cfg->support_features.http_version, itti_msg.promise_id);

  if (request_result and
      (itti_msg.n2sm_info_type.compare("PDU_RES_SETUP_RSP") == 0)) {
    psc->up_cnx_state = up_cnx_state_e::UPCNX_STATE_ACTIVATED;
  }

  if (request_result and
      (itti_msg.n2sm_info_type.compare("PDU_RES_SETUP_FAIL") == 0)) {
    psc->up_cnx_state = up_cnx_state_e::UPCNX_STATE_DEACTIVATED;
  }
}

//------------------------------------------------------------------------------
void amf_sbi::handle_itti_message(itti_nsmf_pdusession_create_sm_context& smf) {
  Logger::amf_sbi().debug("Handle ITTI SMF_PDU_SESSION_CREATE_SM_CTX");

  std::shared_ptr<nas_context> nc = {};
  if (!amf_n1_inst->amf_ue_id_2_nas_context(smf.amf_ue_ngap_id, nc)) return;

  std::string ue_context_key =
      amf_conv::get_ue_context_key(nc->ran_ue_ngap_id, nc->amf_ue_ngap_id);
  std::shared_ptr<ue_context> uc = {};
  Logger::amf_sbi().info(
      "Find ue_context in amf_app using UE Context Key: %s",
      ue_context_key.c_str());
  if (!amf_app_inst->ran_amf_id_2_ue_context(ue_context_key, uc)) return;

  // Create PDU Session Context if not available
  std::shared_ptr<pdu_session_context> psc = {};
  if (!uc->find_pdu_session_context(smf.pdu_sess_id, psc)) {
    psc = std::shared_ptr<pdu_session_context>(new pdu_session_context());
    uc->add_pdu_session_context(smf.pdu_sess_id, psc);
    psc->up_cnx_state = up_cnx_state_e::UPCNX_STATE_DEACTIVATED;
    Logger::amf_sbi().debug("Create a PDU Session Context");
  }

  if (!psc) {
    Logger::amf_sbi().error("No PDU Session Context available");
    return;
  }

  // Store corresponding info in PDU Session Context
  psc->amf_ue_ngap_id = nc->amf_ue_ngap_id;
  psc->ran_ue_ngap_id = nc->ran_ue_ngap_id;
  psc->req_type       = smf.req_type;
  psc->pdu_session_id = smf.pdu_sess_id;
  psc->snssai.sst     = smf.snssai.sst;
  psc->snssai.sd      = smf.snssai.sd;
  psc->plmn.mcc       = smf.plmn.mcc;
  psc->plmn.mnc       = smf.plmn.mnc;

  Logger::amf_sbi().debug(
      "PDU Session Context, NSSAI SST (0x%x) SD %s", psc->snssai.sst,
      psc->snssai.sd.c_str());

  // parse binary dnn and store
  std::string dnn =
      amf_cfg->default_dnn;  // If DNN doesn't available, use the default value
  if ((smf.dnn != nullptr) && (blength(smf.dnn) > 0)) {
    oai::utils::output_wrapper::print_buffer(
        "amf_sbi", "DNN Bit String", (uint8_t*) bdata(smf.dnn),
        blength(smf.dnn));

    char* tmp = amf_conv::bstring2charString(smf.dnn);
    dnn       = tmp;
    oai::utils::utils::free_wrapper((void**) &tmp);
  }

  // Convert dnn format to plain text string
  std::string nd_dnn = {};
  if (oai::utils::dotted_to_string(dnn, nd_dnn)) dnn = nd_dnn;

  Logger::amf_sbi().debug("Requested DNN: %s", dnn.c_str());
  psc->dnn = dnn;

  std::string smf_uri_root    = {};
  std::string smf_api_version = oai::common::sbi::kDefaultSbiApiVersion;
  if (!psc->smf_info.info_available) {
    if (amf_cfg->support_features.enable_smf_selection) {
      // SMF selection via BCF (NRF has been replaced)
      // For now, use direct configuration - BCF-based NF discovery to be implemented
      Logger::amf_sbi().debug(
          "SMF Selection enabled, using configured SMF address (BCF-based discovery pending)");
      if (!smf_selection_from_configuration(
               smf_uri_root, smf_api_version)) {
        Logger::amf_sbi().error("SMF Selection, no SMF candidate is available");
        return;
      }

    } else if (!smf_selection_from_configuration(
                   smf_uri_root, smf_api_version)) {
      Logger::amf_sbi().error(
          "No SMF candidate is available (from configuration file)");
      return;
    }

    // Store SMF's info to be used with this PDU session
    psc->smf_info.info_available = true;
    psc->smf_info.uri_root       = smf_uri_root;
    psc->smf_info.api_version    = smf_api_version;
  } else {
    smf_uri_root    = psc->smf_info.uri_root;
    smf_api_version = psc->smf_info.api_version;
  }

  switch (smf.req_type & 0x07) {
    case kPduSessionInitialRequest: {
      // Check PTI
      if (blength(smf.sm_msg) < 3) {
        Logger::amf_sbi().error(
            "PDUSessionEstablishmentRequest message is too short");
        return;
      }
      uint8_t pti = ((uint8_t*) bdata(smf.sm_msg))[2];
      Logger::amf_sbi().debug(
          "Decoded PTI for PDUSessionEstablishmentRequest(0x%x)", pti);
      psc->is_n2sm_available = false;
      handle_pdu_session_initial_request(
          nc->supi, psc, smf_uri_root, smf_api_version, smf.sm_msg, dnn, uc);
    } break;
    case kExistingPduSession: {
      // TODO:
    } break;
    case kPduSessionTypeModificationRequest: {
      // TODO:
    } break;
    default: {
      // TODO: should be removed
      // send Nsmf_PDUSession_UpdateSM_Context to SMF e.g., for PDU Session
      // release request
      send_pdu_session_update_sm_context_request(
          nc->supi, psc, smf.sm_msg, dnn);
    }
  }
}

//------------------------------------------------------------------------------
void amf_sbi::send_pdu_session_update_sm_context_request(
    const std::string& supi, std::shared_ptr<pdu_session_context>& psc,
    bstring sm_msg, const std::string& dnn) {
  Logger::amf_sbi().debug(
      "Send PDU Session Update SM Context Request to SMF (SUPI %s, PDU Session "
      "ID %d, %s)",
      supi.c_str(), psc->pdu_session_id, psc->smf_info.addr.c_str());

  std::string remote_uri = {};
  if (!amf_sbi_helper::get_smf_pdu_session_context_uri(psc, remote_uri)) {
    Logger::amf_sbi().error("Could not find Nsmf_PDUSession URI");
    return;
  }
  remote_uri += NSMF_PDU_SESSION_MODIFY;

  Logger::amf_sbi().debug("SMF URI: %s", remote_uri.c_str());

  nlohmann::json pdu_session_update_request = {};
  pdu_session_update_request[oai::utils::N1_SM_CONTENT_ID]["contentId"] =
      oai::utils::N1_SM_CONTENT_ID;
  std::string json_part = pdu_session_update_request.dump();

  std::string n1sm_msg = {};
  amf_conv::octet_stream_2_hex_stream(
      (uint8_t*) bdata(sm_msg), blength(sm_msg), n1sm_msg);

  send_http_request(
      remote_uri, json_part, n1sm_msg, "", supi, psc->pdu_session_id,
      amf_cfg->support_features.http_version);
}

//------------------------------------------------------------------------------
void amf_sbi::handle_pdu_session_initial_request(
    const std::string& supi, std::shared_ptr<pdu_session_context>& psc,
    const std::string& smf_uri_root, const std::string& smf_api_version,
    bstring sm_msg, const std::string& dnn,
    const std::shared_ptr<ue_context>& uc) {
  Logger::amf_sbi().debug(
      "Handle PDU Session Establishment Request (SUPI %s, PDU Session ID %d)",
      supi.c_str(), psc->pdu_session_id);

  std::string remote_uri = amf_sbi_helper::get_smf_pdu_session_base_uri(
      smf_uri_root, smf_api_version);

  Logger::amf_sbi().debug("SMF's URI: %s", remote_uri.c_str());

  nlohmann::json session_estb_request   = {};
  session_estb_request["supi"]          = supi;
  session_estb_request["pei"]           = "imeisv-8670000000000001";
  session_estb_request["gpsi"]          = "msisdn-10000000000";
  session_estb_request["dnn"]           = dnn;
  session_estb_request["sNssai"]["sst"] = psc->snssai.sst;
  session_estb_request["sNssai"]["sd"]  = psc->snssai.sd;
  session_estb_request["pduSessionId"]  = psc->pdu_session_id;
  session_estb_request["requestType"] = "INITIAL_REQUEST";  // TODO: from SM_MSG
  session_estb_request["servingNfId"] = amf_app_inst->get_nf_instance();
  session_estb_request["servingNetwork"]["mcc"] = psc->plmn.mcc;
  session_estb_request["servingNetwork"]["mnc"] = psc->plmn.mnc;
  session_estb_request["anType"]                = "3GPP_ACCESS";  // TODO
  session_estb_request["ratType"]               = "NR";
  session_estb_request["selMode"]               = "VERIFIED";
  session_estb_request["epsInterworkingInd"]    = "NONE";

  session_estb_request["smContextStatusUri"] =
      amf_sbi_helper::get_sm_context_status_notification_uri(
          amf_cfg->sbi, supi, psc->pdu_session_id);
  session_estb_request["n1SmMsg"]["contentId"] = oai::utils::N1_SM_CONTENT_ID;

  // GUAMI
  oai::_3gpp::model::Guami guami           = {};
  oai::_3gpp::model::PlmnIdNid plmn_id_nid = {};
  std::string amf_id                       = {};
  amf_conv::get_amf_id(
      amf_cfg->guami.region_id, amf_cfg->guami.amf_set_id,
      amf_cfg->guami.amf_pointer, amf_id);
  guami.setAmfId(amf_id);
  plmn_id_nid.setMcc(psc->plmn.mcc);
  plmn_id_nid.setMnc(psc->plmn.mnc);
  guami.setPlmnId(plmn_id_nid);
  nlohmann::json guami_json = {};
  to_json(guami_json, guami);
  session_estb_request["guami"] = guami_json;

  // UE location
  oai::_3gpp::model::UserLocation user_location = {};
  oai::_3gpp::model::NrLocation nr_location     = {};
  oai::_3gpp::model::Tai tai                    = {};
  oai::_3gpp::model::PlmnId plmn_id             = {};
  plmn_id.setMcc(psc->plmn.mcc);
  plmn_id.setMnc(psc->plmn.mnc);
  tai.setPlmnId(plmn_id);
  tai.setTac(std::to_string(uc->tai.tac));
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
  nr_location.setTai(tai);
  // TODO: nr_location.setGlobalGnbId(global_ran_node_id);
  nr_location.setNcgi(ncgi);
  user_location.setNrLocation(nr_location);
  nlohmann::json user_location_json = {};
  to_json(user_location_json, user_location);
  session_estb_request["ueLocation"] = user_location_json;

  std::string json_part = session_estb_request.dump();
  Logger::amf_sbi().debug("Message body %s", json_part.c_str());

  std::string n1sm_msg = {};
  amf_conv::octet_stream_2_hex_stream(
      (uint8_t*) bdata(sm_msg), blength(sm_msg), n1sm_msg);

  send_http_request(
      remote_uri, json_part, n1sm_msg, "", supi, psc->pdu_session_id,
      amf_cfg->support_features.http_version);
}

//------------------------------------------------------------------------------
void amf_sbi::handle_itti_message(
    itti_nsmf_pdusession_release_sm_context& itti_msg) {
  std::shared_ptr<pdu_session_context> psc = {};
  if (!amf_app_inst->find_pdu_session_context(
          itti_msg.supi, itti_msg.pdu_session_id, psc))
    return;

  std::string remote_uri = {};
  if (!amf_sbi_helper::get_smf_pdu_session_context_uri(psc, remote_uri)) {
    Logger::amf_sbi().error("Could not find Nsmf_PDUSession URI");
    return;
  }
  remote_uri += NSMF_PDU_SESSION_RELEASE;
  Logger::amf_sbi().debug("SMF's URI: %s", remote_uri.c_str());

  nlohmann::json pdu_session_release_request;
  pdu_session_release_request["cause"] = "REL_DUE_TO_REACTIVATION";  // TODO:
  // pdu_session_release_request["ngApCause"] = "radioNetwork";
  // TODO: 5gMmCauseValue
  // TODO: UserLocation
  // TODO: N2SmInfo
  std::string msg_body = pdu_session_release_request.dump();

  nlohmann::json response_json = {};
  uint32_t response_code       = 0;

  send_http_request(
      remote_uri, oai::common::sbi::method_e::POST, msg_body, response_json,
      response_code, amf_cfg->support_features.http_version);

  nlohmann::json response_data                = {};
  response_data[kSbiResponseHttpResponseCode] = response_code;
  response_data[kSbiResponseJsonData]         = response_json;

  // Notify to the result
  if (itti_msg.promise_id > 0) {
    amf_app_inst->trigger_process_response(itti_msg.promise_id, response_data);
    return;
  }
}

//------------------------------------------------------------------------------
void amf_sbi::handle_itti_message(itti_sbi_notify_subscribed_event& itti_msg) {
  Logger::amf_sbi().debug("Send notification for the subscribed events");

  for (auto i : itti_msg.event_notifs) {
    // Fill the json part
    nlohmann::json json_data         = {};
    json_data["notifyCorrelationId"] = i.get_notify_correlation_id();
    auto report_lists                = nlohmann::json::array();
    nlohmann::json report            = {};

    std::vector<oai::_3gpp::model::AmfEventReport> event_reports = {};
    i.get_reports(event_reports);
    for (auto r : event_reports) {
      auto report_type                = r.getType().getValue();
      nlohmann::json report_type_json = {};
      to_json(report_type_json, report_type);
      report["type"]            = report_type_json;
      report["state"]["active"] = true;
      if (r.supiIsSet()) {
        report["supi"] = r.getSupi();
      }
      if (r.locationIsSet()) {
        report["location"] =
            r.getLocation();  // get eutraLocation, nrLocation, n3gaLocation?
      }
      if (r.rmInfoListIsSet()) {
        report["rmInfoList"] = r.getRmInfoList();
      }
      if (r.cmInfoListIsSet()) {
        report["cmInfoList"] = r.getCmInfoList();
      }
      if (r.reachabilityIsSet()) {
        auto report_reachability = r.getReachability().getValue();
        nlohmann::json report_reachability_json = {};
        to_json(report_reachability_json, report_reachability);
        report["reachability"] = report_reachability_json;
      }
      if (r.lossOfConnectReasonIsSet()) {
        auto report_loss_of_connect_reason =
            r.getLossOfConnectReason().getValue();
        nlohmann::json report_loss_of_connect_reason_json = {};
        to_json(
            report_loss_of_connect_reason_json, report_loss_of_connect_reason);
        report["lossOfConnectReason"] = report_loss_of_connect_reason_json;
      }

      if (r.ranUeNgapIdIsSet()) {
        report["ranUeNgapId"] = r.getRanUeNgapId();
      }
      if (r.amfUeNgapIdIsSet()) {
        report["amfUeNgapId"] = r.getAmfUeNgapId();
      }
      if (r.commFailureIsSet()) {
        report["commFailure"] = r.getCommFailure();
      }

      // Timestamp
      std::time_t time_epoch_ntp = std::time(nullptr);
      uint64_t tv_ntp =
          time_epoch_ntp;            // not needed: + SECONDS_SINCE_FIRST_EPOCH;
      report["timeStamp"] = tv_ntp;  // don't convert to string, leave as int64
      report_lists.push_back(report);
    }

    json_data["reportList"] = report_lists;

    std::string body             = json_data.dump();
    nlohmann::json response_json = {};

    std::string uri        = i.get_notify_uri();
    uint32_t response_code = 0;

    send_http_request(
        uri, oai::common::sbi::method_e::POST, body, response_json,
        response_code, amf_cfg->support_features.http_version);
    // TODO: process the response
  }
  return;
}

//------------------------------------------------------------------------------
void amf_sbi::handle_itti_message(
    itti_sbi_slice_selection_subscription_data& itti_msg) {
  Logger::amf_sbi().debug(
      "Send Slice Selection Subscription Data Retrieval to UDM ");

  std::string uri =
      amf_sbi_helper::get_udm_slice_selection_subscription_data_retrieval_uri(
          amf_cfg->udm_addr, itti_msg.supi);
  nlohmann::json plmn_id = {};
  plmn_id["mcc"]         = itti_msg.plmn.mcc;
  plmn_id["mnc"]         = itti_msg.plmn.mnc;

  std::string parameters = {};
  parameters             = "?plmn-id=" + plmn_id.dump();
  uri += parameters;

  nlohmann::json response_data = {};
  uint32_t response_code       = 0;

  send_http_request(
      uri, oai::common::sbi::method_e::GET, "", response_data, response_code,
      amf_cfg->support_features.http_version);

  // Notify to the result
  if (itti_msg.promise_id > 0) {
    amf_app_inst->trigger_process_response(itti_msg.promise_id, response_data);
    return;
  }

  return;
}

//------------------------------------------------------------------------------
void amf_sbi::handle_itti_message(
    itti_sbi_network_slice_selection_information& itti_msg) {
  Logger::amf_sbi().debug(
      "Send Network Slice Selection Information Request to NSSF");

  std::string uri =
      amf_sbi_helper::get_nssf_network_slice_selection_information_uri(
          amf_cfg->nssf_addr);

  // Slice Info Request For Registration
  nlohmann::json slice_info = {};
  to_json(slice_info, itti_msg.slice_info);
  // TODO: home-plmn-id
  // nlohmann::json home_plmn_id = {};
  // home_plmn_id["mcc"]         = itti_msg.tai.plmn.mcc;
  // home_plmn_id["mnc"]         = itti_msg.tai.plmn.mnc;

  // TAI
  nlohmann::json tai   = {};
  tai["plmnId"]["mcc"] = itti_msg.tai.plmn.mcc;
  tai["plmnId"]["mnc"] = itti_msg.tai.plmn.mnc;
  tai["tac"]           = std::to_string(itti_msg.tai.tac);

  std::string parameters = {};
  parameters = "?nf-type=AMF&nf-id=" + amf_app_inst->get_nf_instance() +
               "&slice-info-request-for-registration=" + slice_info.dump() +
               "&tai=" + tai.dump();
  //"?home-plmn-id=" + home_plmn_id.dump();
  uri += parameters;

  nlohmann::json response_json = {};
  uint32_t response_code       = 0;

  send_http_request(
      uri, oai::common::sbi::method_e::GET, "", response_json, response_code,
      amf_cfg->support_features.http_version);

  nlohmann::json response_data                = {};
  response_data[kSbiResponseHttpResponseCode] = response_code;
  response_data[kSbiResponseJsonData]         = response_json;

  // Notify to the result
  if (itti_msg.promise_id > 0) {
    amf_app_inst->trigger_process_response(itti_msg.promise_id, response_data);
    return;
  }

  return;
}

//------------------------------------------------------------------------------
void amf_sbi::handle_itti_message(
    itti_sbi_network_slice_selection_discovery& itti_msg) {
  // Get NRF info from NSSF
  Logger::amf_sbi().debug(
      "Send Network Slice Selection Discovery Request to NSSF");
  nlohmann::json response_json = {};
  uint32_t response_code       = 0;

  // For now, using the existing API to get list of NRFs
  get_network_slice_information(
      itti_msg.snssai, itti_msg.plmn, std::nullopt, itti_msg.nf_instance_id,
      response_json, response_code);
  nlohmann::json response_data                = {};
  response_data[kSbiResponseHttpResponseCode] = response_code;
  if (!response_json.is_null())
    response_data[kSbiResponseJsonData] = response_json;

  // Notify to the result
  if (itti_msg.promise_id > 0) {
    amf_app_inst->trigger_process_response(itti_msg.promise_id, response_data);
    return;
  }
}

//------------------------------------------------------------------------------
void amf_sbi::handle_itti_message(itti_sbi_n1_message_notify& itti_msg) {
  Logger::amf_sbi().debug("Send N1 Message Notify to the target AMF ");

  std::string uri = itti_msg.target_amf_uri + "/ue-contexts/" + itti_msg.supi +
                    "/n1-message-notify";

  nlohmann::json json_data = {};
  json_data[oai::utils::N1_SM_CONTENT_ID]["contentId"] =
      oai::utils::N1_SM_CONTENT_ID;
  std::string json_part = json_data.dump();

  std::string n1sm_msg = {};
  amf_conv::octet_stream_2_hex_stream(
      (uint8_t*) bdata(itti_msg.registration_request),
      blength(itti_msg.registration_request), n1sm_msg);

  uint32_t response_code = 0;
  std::string n2sm_msg   = {};

  send_http_request(
      uri, json_part, n1sm_msg, n2sm_msg,
      amf_cfg->support_features.http_version, response_code);

  // TODO: handle response
  return;
}

//------------------------------------------------------------------------------
void amf_sbi::handle_itti_message(itti_sbi_n2_info_notify& itti_msg) {
  Logger::amf_sbi().debug("Send N2 Info Notify to the subscribed NF");

  nlohmann::json json_data = {};
  to_json(json_data, itti_msg.n2_info_notification);
  std::string json_part = json_data.dump();

  std::string n2_info_msg = {};
  amf_conv::octet_stream_2_hex_stream(
      (uint8_t*) bdata(itti_msg.n2_info.value()),
      blength(itti_msg.n2_info.value()), n2_info_msg);

  uint32_t response_code = 0;
  std::string n1sm_msg   = {};

  send_http_request(
      itti_msg.nf_uri, json_part, n1sm_msg, n2_info_msg,
      amf_cfg->support_features.http_version, response_code);

  if (response_code == oai::common::sbi::http_status_code::NO_CONTENT) {
    Logger::amf_sbi().debug("Sent notification successfully!");
  }
  return;
}

//------------------------------------------------------------------------------
void amf_sbi::handle_itti_message(itti_sbi_nf_instance_discovery& itti_msg) {
  Logger::amf_sbi().debug("Send NF Instance Discovery to NRF ");

  nlohmann::json json_data = {};
  std::string uri          = itti_msg.nrf_amf_set;

  // TODO: remove hardcoded values
  uri += "?target-nf-type=AMF&requester-nf-type=AMF";

  nlohmann::json response_data = {};
  uint32_t response_code       = 0;

  send_http_request(
      uri, oai::common::sbi::method_e::GET, "", response_data, response_code,
      amf_cfg->support_features.http_version);

  // Notify to the result
  if (itti_msg.promise_id > 0) {
    amf_app_inst->trigger_process_response(itti_msg.promise_id, response_data);
    return;
  }
}

//------------------------------------------------------------------------------
// NRF registration functions are deprecated - BCF is used instead
//------------------------------------------------------------------------------
void amf_sbi::handle_itti_message(
    itti_sbi_register_nf_instance_request& itti_msg) {
  Logger::amf_sbi().warn(
      "NRF registration is deprecated, BCF is used for NF registration");
  // No-op: NRF is replaced by BCF
}

//------------------------------------------------------------------------------
void amf_sbi::handle_itti_message(
    itti_sbi_update_nf_instance_request& itti_msg) {
  Logger::amf_sbi().warn(
      "NRF update is deprecated, BCF is used for NF registration");
  // No-op: NRF is replaced by BCF
}

//------------------------------------------------------------------------------
void amf_sbi::handle_itti_message(
    itti_sbi_deregister_nf_instance_request& itti_msg) {
  Logger::amf_sbi().warn(
      "NRF deregistration is deprecated, BCF is used for NF deregistration");
  // No-op: NRF is replaced by BCF
}

//------------------------------------------------------------------------------
// BCF (Blockchain Function) Registration with Extended NF Profile (DID)
//------------------------------------------------------------------------------
void amf_sbi::handle_itti_message(
    itti_sbi_bcf_register_nf_instance_request& itti_msg) {
  if (reject_outbound_request_during_shutdown(
          "new BCF registration request")) {
    Logger::amf_sbi().warn(
        "[AMF][Shutdown] Ignore pending BCF registration request because shutdown is in progress");
    return;
  }

  std::string body             = itti_msg.extended_profile.dump();
  nlohmann::json response_data = {};
  uint32_t response_code       = 0;

  // --- Latency probe: reconstruct trace_id in SBI layer ---
  auto lp_tid = LP_BUILD_ID("AMF", "BCF_REG", itti_msg.amf_instance_id);

  // 标准化日志格式 - BCF Registration
  Logger::amf_sbi().info("BCF Registration URI: %s", itti_msg.bcf_uri.c_str());
  Logger::amf_sbi().info("Send HTTP message to %s", itti_msg.bcf_uri.c_str());
  Logger::amf_sbi().info("HTTP message Body: %s", body.c_str());

  LP_MARK(lp_tid, "HTTP_SEND");

  send_http_request(
      itti_msg.bcf_uri, oai::common::sbi::method_e::PUT, body, response_data,
      response_code, amf_cfg->support_features.http_version);

  LP_MARK(lp_tid, "HTTP_STATUS_RCVD");

  // Send response to APP to process
  std::shared_ptr<itti_sbi_bcf_register_nf_instance_response> itti_msg_response =
      std::make_shared<itti_sbi_bcf_register_nf_instance_response>(
          TASK_AMF_SBI, TASK_AMF_APP);
  itti_msg_response->http_response_code = response_code;
  itti_msg_response->bcf_uri            = itti_msg.bcf_uri;

  if ((response_code == oai::common::sbi::http_status_code::CREATED) or
      (response_code == oai::common::sbi::http_status_code::OK)) {
    Logger::amf_sbi().debug(
        "BCF Registration successful, got response from BCF");
    if (itti_msg.extended_profile.contains("nfInstanceId")) {
      itti_msg_response->amf_instance_id =
          itti_msg.extended_profile["nfInstanceId"].get<std::string>();
    }
  } else {
    Logger::amf_sbi().error(
        "BCF Registration failed with response code: %d", response_code);
  }

  int ret = itti_inst->send_msg(itti_msg_response);
  if (RETURNok != ret) {
    Logger::amf_sbi().error(
        "Could not send ITTI message %s to task TASK_AMF_APP",
        itti_msg_response->get_msg_name());
  }
}

//------------------------------------------------------------------------------
void amf_sbi::handle_itti_message(
    itti_sbi_bcf_update_nf_instance_request& itti_msg) {
  if (reject_outbound_request_during_shutdown(
          "new BCF update registration request")) {
    Logger::amf_sbi().warn(
        "[AMF][Shutdown] Ignore pending BCF update request because shutdown is in progress");
    return;
  }

  Logger::amf_sbi().debug("Send NF Update to BCF");

  nlohmann::json json_data = nlohmann::json::array();
  for (auto i : itti_msg.patch_items) {
    nlohmann::json item = {};
    to_json(item, i);
    json_data.push_back(item);
  }
  std::string body             = json_data.dump();
  nlohmann::json response_data = {};
  uint32_t response_code       = 0;

  // 标准化日志格式 - BCF Update
  Logger::amf_sbi().info("BCF Registration URI: %s", itti_msg.bcf_uri.c_str());
  Logger::amf_sbi().info("Send HTTP message to %s", itti_msg.bcf_uri.c_str());
  Logger::amf_sbi().info("HTTP message Body: %s", body.c_str());

  send_http_request(
      itti_msg.bcf_uri, oai::common::sbi::method_e::PATCH, body, response_data,
      response_code, amf_cfg->support_features.http_version);

  // Send response to APP to process
  std::shared_ptr<itti_sbi_bcf_update_nf_instance_response> itti_msg_response =
      std::make_shared<itti_sbi_bcf_update_nf_instance_response>(
          TASK_AMF_SBI, TASK_AMF_APP);
  itti_msg_response->http_response_code = response_code;
  itti_msg_response->amf_instance_id    = itti_msg.amf_instance_id;
  itti_msg_response->bcf_uri            = itti_msg.bcf_uri;

  int ret = itti_inst->send_msg(itti_msg_response);
  if (RETURNok != ret) {
    Logger::amf_sbi().error(
        "Could not send ITTI message %s to task TASK_AMF_APP",
        itti_msg_response->get_msg_name());
  }
}

//------------------------------------------------------------------------------
void amf_sbi::handle_itti_message(
    itti_sbi_bcf_deregister_nf_instance_request& itti_msg) {
  nlohmann::json response_data = {};
  uint32_t response_code       = 0;

  // 标准化日志格式 - BCF Deregistration
  Logger::amf_sbi().info(
      "BCF Deregistration URI: %s", itti_msg.bcf_uri.c_str());
  Logger::amf_sbi().info("Send HTTP message to %s", itti_msg.bcf_uri.c_str());
  Logger::amf_sbi().info("HTTP message Body: %s", "{}");

  send_http_request(
      itti_msg.bcf_uri, oai::common::sbi::method_e::DELETE, "", response_data,
      response_code, amf_cfg->support_features.http_version);

  // Send response to APP to process
  std::shared_ptr<itti_sbi_bcf_deregister_nf_instance_response> itti_msg_response =
      std::make_shared<itti_sbi_bcf_deregister_nf_instance_response>(
          TASK_AMF_SBI, TASK_AMF_APP);
  itti_msg_response->amf_instance_id    = itti_msg.amf_instance_id;
  itti_msg_response->http_response_code = response_code;
  itti_msg_response->bcf_uri            = itti_msg.bcf_uri;

  int ret = itti_inst->send_msg(itti_msg_response);
  if (RETURNok != ret) {
    Logger::amf_sbi().error(
        "Could not send ITTI message %s to task TASK_AMF_APP",
        itti_msg_response->get_msg_name());
  }
}

//------------------------------------------------------------------------------
void amf_sbi::handle_itti_message(
    itti_sbi_determine_location_request& itti_msg) {
  if (reject_outbound_request_during_shutdown(
          "new determine location request", itti_msg.promise_id)) {
    return;
  }

  Logger::amf_sbi().debug("Send Determine Location Request to LMF ");

  std::string uri =
      amf_sbi_helper::get_lmf_determine_location_uri(amf_cfg->lmf_addr);

  std::string body             = itti_msg.input_data.dump();
  uint32_t response_code       = 0;
  nlohmann::json response_json = {};

  send_http_request(
      uri, oai::common::sbi::method_e::POST, body, response_json, response_code,
      amf_cfg->support_features.http_version);

  nlohmann::json response_data                = {};
  response_data[kSbiResponseHttpResponseCode] = response_code;
  response_data[kSbiResponseJsonData]         = response_json;

  // Notify to the result
  if (itti_msg.promise_id > 0) {
    amf_app_inst->trigger_process_response(itti_msg.promise_id, response_data);
    return;
  }
}

//------------------------------------------------------------------------------
void amf_sbi::handle_itti_message(
    itti_sbi_ue_authentication_request& itti_msg) {
  if (reject_outbound_request_during_shutdown(
          "new UE authentication request", itti_msg.promise_id)) {
    return;
  }

  Logger::amf_sbi().debug("Send UE Authentication Request to AUSF");

  const nlohmann::json amf_profile =
      amf_app_inst->build_amf_profile_for_ausf_request();
  const std::string amf_profile_summary =
      build_amf_profile_summary(amf_profile);
  nlohmann::json json_data = build_ue_auth_request_with_token(
      itti_msg.auth_info, amf_profile);

  // =========================================================================
  // UE Authentication Flow - Overview:
  //   Phase 1: AUSF Service Discovery (via BCF)
  //   Phase 2: Send UE Authentication Request to AUSF (with BCF token)
  // =========================================================================
  std::string ausf_uri;
  std::string ausf_did;
  std::string ausf_api_version;
  std::string auth_token;
  auto* audit = amf_app_inst ? amf_app_inst->get_security_audit() : nullptr;
  const std::string interaction_id =
      audit ? audit->make_interaction_id() : std::string();

  if (amf_cfg->register_bcf) {
    Logger::amf_sbi().info(
        "========================================================================");
    Logger::amf_sbi().info(
        "[UE Auth] === UE Authentication Flow Start ===");
    Logger::amf_sbi().info(
        "========================================================================");
    Logger::amf_sbi().info(
        "[UE Auth] SUPI: %s", itti_msg.auth_info.getSupiOrSuci().c_str());
    Logger::amf_sbi().info(
        "[UE Auth] Flow consists of: 1) AUSF Discovery, 2) UE Auth Request (with BCF token)");

    // =========================================================================
    // Phase 1: AUSF Service Discovery from BCF
    // =========================================================================
    Logger::amf_sbi().info(
        "[UE Auth] Phase 1: Starting AUSF Service Discovery from BCF");
    if (audit) {
      audit->record_event(
          "SERVICE_DISCOVERY", "discovery_requested", "started",
          interaction_id, "", "AUSF",
          {{"target_nf_type", "AUSF"},
           {"supi", itti_msg.auth_info.getSupiOrSuci()}});
    }

    // BCF is the ONLY source for AUSF discovery - no fallback to config
    if (!amf_app_inst->discover_ausf_from_bcf(
            ausf_uri, ausf_did, ausf_api_version, itti_msg.ue_snssais)) {
      Logger::amf_sbi().error(
          "[UE Auth] Phase 1 FAILED: Cannot discover AUSF from BCF!");
      Logger::amf_sbi().error(
          "[UE Auth] AUSF must be registered in BCF before UE can authenticate");
      if (audit) {
        audit->record_event(
            "SERVICE_DISCOVERY", "discovery_result_received", "failure",
            interaction_id, "", "AUSF",
            {{"target_nf_type", "AUSF"},
             {"reason", "ausf_discovery_failed"}});
      }

      // Return error to caller - no fallback to config
      nlohmann::json response_data;
      response_data[kSbiResponseHttpResponseCode] = 503;
      response_data[kSbiResponseJsonData] = {
          {"error", "ausf_discovery_failed"},
          {"message", "Failed to discover AUSF from BCF. "
                      "Ensure AUSF is registered with BCF."}
      };

      if (itti_msg.promise_id > 0) {
        amf_app_inst->trigger_process_response(itti_msg.promise_id, response_data);
      }
      return;
    }
    
    Logger::amf_sbi().info(
        "[UE Auth] Phase 1 COMPLETED: AUSF discovered successfully");
    Logger::amf_sbi().info(
        "[UE Auth]   AUSF URI: %s", ausf_uri.c_str());
    Logger::amf_sbi().info(
        "[UE Auth]   AUSF DID: %s", ausf_did.empty() ? "N/A" : ausf_did.c_str());
    Logger::amf_sbi().info(
        "[UE Auth]   AUSF API Version: %s", ausf_api_version.c_str());
    if (audit) {
      audit->record_event(
          "SERVICE_DISCOVERY", "discovery_result_received", "success",
          interaction_id, ausf_did, "AUSF",
          {{"ausf_uri", ausf_uri}, {"api_version", ausf_api_version}});
      audit->record_event(
          "TARGET_SELECTED", "target_selected", "success", interaction_id,
          ausf_did, "AUSF", {{"ausf_uri", ausf_uri}});
    }

    // =========================================================================
    // Use BCF token obtained during AMF startup (no per-UE auth needed)
    // BCF auth is done once at AMF init, token is cached and reused
    // =========================================================================
    if (amf_app_inst->is_did_auth_enabled()) {
      auth_token = get_current_bcf_access_token();
      if (!auth_token.empty()) {
        Logger::amf_sbi().debug(
            "[BCF Auth] Using BCF token for AUSF request: %s...",
            auth_token.substr(0, std::min(size_t(16), auth_token.size())).c_str());
      }
    }

    Logger::amf_sbi().info(
        "------------------------------------------------------------------------");
  } else {
    // BCF not enabled, use configured AUSF address directly
    ausf_uri = amf_cfg->ausf_addr.uri_root;
    ausf_api_version = amf_cfg->ausf_addr.api_version;
    Logger::amf_sbi().debug(
        "BCF not enabled, using configured AUSF: %s", ausf_uri.c_str());
  }

  // =========================================================================
  // Phase 2: Send UE Authentication Request to AUSF
  // =========================================================================
  if (amf_cfg->register_bcf) {
    Logger::amf_sbi().info(
        "[UE Auth] Phase 2: Sending UE Authentication Request to AUSF");
  }

  std::string uri;
  if (!ausf_uri.empty()) {
    // Construct the full URI: {ausf_uri}/nausf-auth/{api_version}/ue-authentications
    uri = ausf_uri;
    // Remove trailing slash if present
    if (!uri.empty() && uri.back() == '/') {
      uri.pop_back();
    }
    uri += "/nausf-auth/" + (ausf_api_version.empty() ? "v1" : ausf_api_version);
    uri += "/ue-authentications";
  } else {
    // Final fallback to helper function
    uri = amf_sbi_helper::get_ausf_ue_authentications_uri(amf_cfg->ausf_addr);
  }

  // =========================================================================
  // Send HTTP Request to AUSF
  // =========================================================================
  std::string body = json_data.dump();
  nlohmann::json response_json = {};
  uint32_t response_code = 0;

  Logger::amf_sbi().info(
      "[AMF][AUSF Request] Preparing UE authentication request to AUSF");
  Logger::amf_sbi().info(
      "[AMF][AUSF Request] Selected AUSF URI: %s", uri.c_str());
  Logger::amf_sbi().info(
      "[AMF][AUSF Request] servingNetworkName: %s",
      itti_msg.auth_info.getServingNetworkName().c_str());
  Logger::amf_sbi().info(
      "[AMF][AUSF Request] supiOrSuci: %s",
      itti_msg.auth_info.getSupiOrSuci().c_str());
  Logger::amf_sbi().info(
      "[AMF][AUSF Request] AMF profile summary: %s",
      amf_profile_summary.c_str());

  if (amf_cfg->register_bcf) {
    Logger::amf_sbi().info(
        "[AMF][AUSF Request] Access token present: %s",
        auth_token.empty() ? "no" : "yes");
    if (auth_token.empty()) {
      Logger::amf_sbi().error(
          "[AMF][AUSF Request] No valid access token available, aborting UE authentication request");
      if (audit) {
        audit->record_event(
            "SERVICE_REQUEST", "ausf_request_not_sent", "failure",
            interaction_id, ausf_did, "AUSF",
            {{"reason", "missing_bcf_access_token"}});
      }

      nlohmann::json response_data = {};
      response_data[kSbiResponseHttpResponseCode] =
          static_cast<uint32_t>(
              oai::common::sbi::http_status_code::SERVICE_UNAVAILABLE);
      response_data[kSbiResponseJsonData] = {
          {"error", "missing_bcf_access_token"},
          {"message",
           "No valid BCF access token available for AUSF UE authentication request."}};

      if (itti_msg.promise_id > 0) {
        amf_app_inst->trigger_process_response(
            itti_msg.promise_id, response_data);
      }
      return;
    }

    Logger::amf_sbi().info(
        "[AMF][AUSF Request] Access token found, adding Bearer header");
  } else {
    Logger::amf_sbi().info(
        "[AMF][AUSF Request] Access token present: %s",
        auth_token.empty() ? "no" : "yes");
  }

  // Prepare HTTP request
  oai::http::request http_request =
      http_client_inst->prepare_json_request(uri, body);

  // Add BCF authentication header if BCF auth is enabled
  if (amf_cfg->register_bcf && !auth_token.empty()) {
    add_bearer_token_header(http_request, auth_token);
    http_request.headers.insert(
        {"X-NF-Instance-Id", amf_app_inst->get_nf_instance_id()});
    http_request.headers.insert({"X-NF-Type", "AMF"});
    if (audit) {
      http_request.headers.insert({"X-Session-ID", audit->session_id()});
      http_request.headers.insert({"X-Interaction-ID", interaction_id});
      http_request.headers.insert({"X-Subject-DID", amf_app_inst->get_local_did()});
      http_request.headers.insert({"X-Peer-DID", ausf_did});
      http_request.headers.insert({"X-Subject-NF-Type", "AMF"});
      http_request.headers.insert({"X-Peer-NF-Type", "AUSF"});
    }
    Logger::amf_sbi().info(
        "[AMF][AUSF Request] Authorization Header added: yes");
  } else {
    Logger::amf_sbi().info(
        "[AMF][AUSF Request] Authorization Header added: no");
  }

  if (audit) {
    audit->record_event(
        "SERVICE_REQUEST", "ausf_request_sent", "success", interaction_id,
        ausf_did, "AUSF",
        {{"uri", uri},
         {"token_fingerprint",
          oai::common::audit::security_audit::fingerprint_token(auth_token)}},
        oai::common::audit::security_audit::fingerprint_token(auth_token));
  }

  // Send the request
  auto http_response = http_client_inst->send_http_request(
      oai::common::sbi::method_e::POST, http_request);

  // Process response
  response_code = http_response.status_code;
  if (http_response.status_code != oai::common::sbi::http_status_code::NO_RESPONSE) {
    try {
      response_json = nlohmann::json::parse(http_response.body);
    } catch (nlohmann::json::exception& e) {
      Logger::amf_sbi().warn("Could not parse JSON from AUSF response");
    }
  }

  if (audit) {
    const bool response_ok =
        http_response.status_code >= 200 && http_response.status_code < 300;
    audit->record_event(
        "SERVICE_RESPONSE", "ausf_response_received",
        response_ok ? "success" : "failure", interaction_id, ausf_did, "AUSF",
        {{"http_status", http_response.status_code}});
    audit->checkpoint(
        response_ok ? "ausf_service_response_received"
                    : "ausf_service_response_failed",
        interaction_id, ausf_did, "AUSF", "checkpoint");
  }

  nlohmann::json response_data = {};
  response_data[kSbiResponseHttpResponseCode] = response_code;
  response_data[kSbiResponseJsonData] = response_json;

  // Notify to the result
  if (itti_msg.promise_id > 0) {
    amf_app_inst->trigger_process_response(itti_msg.promise_id, response_data);
    return;
  }
}

//------------------------------------------------------------------------------
void amf_sbi::handle_itti_message(
    itti_sbi_ue_authentication_confirmation& itti_msg) {
  if (reject_outbound_request_during_shutdown(
          "new UE authentication confirmation request", itti_msg.promise_id)) {
    return;
  }

  Logger::amf_sbi().debug("Send UE Authentication Confirmation to AUSF ");

  std::string body = itti_msg.confirmation_data.dump();

  nlohmann::json response_json = {};
  uint32_t response_code       = 0;
  send_http_request(
      itti_msg.uri, oai::common::sbi::method_e::PUT, body, response_json,
      response_code, amf_cfg->support_features.http_version);

  nlohmann::json response_data                = {};
  response_data[kSbiResponseHttpResponseCode] = response_code;
  response_data[kSbiResponseJsonData]         = response_json;

  // Notify to the result
  if (itti_msg.promise_id > 0) {
    amf_app_inst->trigger_process_response(itti_msg.promise_id, response_data);
    return;
  }
}

//------------------------------------------------------------------------------
void amf_sbi::handle_itti_message(itti_sbi_register_with_udm& itti_msg) {
  if (reject_outbound_request_during_shutdown(
          "new UDM registration request")) {
    return;
  }

  Logger::amf_sbi().debug("Send AMF Registration for 3GPP Access towards UDM");

  std::string body = itti_msg.registration_data.dump();
  std::string uri  = amf_sbi_helper::get_udm_amf_3gpp_access_registration_uri(
      amf_cfg->udm_addr, itti_msg.supi);

  nlohmann::json response_json      = {};
  uint32_t response_code            = 0;
  oai::http::response http_response = {};
  send_http_request(uri, oai::common::sbi::method_e::PUT, body, http_response);

  nlohmann::json response_data                = {};
  response_data[kSbiResponseHttpResponseCode] = http_response.status_code;
  response_data[kSbiResponseJsonData]         = http_response.get_json();

  if (auto loc_header = http_response.headers.find("location");
      loc_header != http_response.headers.end()) {
    Logger::amf_sbi().info(
        "Location of the created resource: %s", loc_header->second.c_str());
    response_data[kSbiResponseHeaderLocation] = loc_header->second;
  }

  // Send response to APP to process
  if ((http_response.status_code == oai::common::sbi::http_status_code::OK) or
      (http_response.status_code ==
       oai::common::sbi::http_status_code::CREATED) or
      (http_response.status_code ==
       oai::common::sbi::http_status_code::ACCEPTED)) {
    std::shared_ptr<itti_sbi_register_with_udm_response> itti_msg_response =
        std::make_shared<itti_sbi_register_with_udm_response>(
            TASK_AMF_SBI, TASK_AMF_APP);
    itti_msg_response->response_data = response_data;

    int ret = itti_inst->send_msg(itti_msg_response);
    if (RETURNok != ret) {
      Logger::amf_sbi().error(
          "Could not send ITTI message %s to task TASK_AMF_APP",
          itti_msg_response->get_msg_name());
    }
  }
}

//------------------------------------------------------------------------------
void amf_sbi::handle_itti_message(itti_sbi_retrieve_am_data& itti_msg) {
  if (reject_outbound_request_during_shutdown(
          "new access and mobility subscription data retrieval",
          itti_msg.promise_id)) {
    return;
  }

  Logger::amf_sbi().debug(
      "Send Access and Mobility Subscription Data Retrieval towards UDM");

  std::string uri = amf_sbi_helper::get_udm_am_data_retrieval_uri(
      amf_cfg->udm_addr, itti_msg.supi);
  nlohmann::json plmn_id = {};
  to_json(plmn_id, itti_msg.plmn_id);
  std::string parameters = {};
  parameters             = "?plmn-id=" + plmn_id.dump();
  uri += parameters;

  oai::http::response http_response = {};
  send_http_request(uri, oai::common::sbi::method_e::GET, "", http_response);

  nlohmann::json response_data                = {};
  response_data[kSbiResponseHttpResponseCode] = http_response.status_code;
  response_data[kSbiResponseJsonData]         = http_response.get_json();
  // TODO: process headers (Cache-Control, ETag, Last-Modified)

  /*
  // Send response to APP to process
  if (http_response.status_code == oai::common::sbi::http_status_code::OK) {
    std::shared_ptr<itti_sbi_retrieve_am_data_response> itti_msg_response =
        std::make_shared<itti_sbi_retrieve_am_data_response>(
            TASK_AMF_SBI, TASK_AMF_APP);
    itti_msg_response->response_data = response_data;

    int ret = itti_inst->send_msg(itti_msg_response);
    if (RETURNok != ret) {
      Logger::amf_sbi().error(
          "Could not send ITTI message %s to task TASK_AMF_APP",
          itti_msg_response->get_msg_name());
    }
  }
  */
  // Notify to the result
  if (itti_msg.promise_id > 0) {
    amf_app_inst->trigger_process_response(itti_msg.promise_id, response_data);
    return;
  }
}

//------------------------------------------------------------------------------
void amf_sbi::handle_itti_message(
    itti_sbi_retrieve_smf_selection_subscription_data& itti_msg) {
  if (reject_outbound_request_during_shutdown(
          "new SMF selection subscription data retrieval")) {
    return;
  }

  Logger::amf_sbi().debug(
      "Send SMF Selection Subscription Data Retrieval towards UDM");

  std::string uri =
      amf_sbi_helper::get_udm_smf_selection_subscription_data_retrieval_uri(
          amf_cfg->udm_addr, itti_msg.supi);
  nlohmann::json plmn_id = {};
  to_json(plmn_id, itti_msg.plmn_id);
  std::string parameters = {};
  parameters             = "?plmn-id=" + plmn_id.dump();
  uri += parameters;

  oai::http::response http_response = {};
  send_http_request(uri, oai::common::sbi::method_e::GET, "", http_response);

  nlohmann::json response_data                = {};
  response_data[kSbiResponseHttpResponseCode] = http_response.status_code;
  response_data[kSbiResponseJsonData]         = http_response.get_json();
  // TODO: process headers (Cache-Control, ETag, Last-Modified)

  // Send response to APP to process
  if (http_response.status_code == oai::common::sbi::http_status_code::OK) {
    std::shared_ptr<itti_sbi_retrieve_smf_selection_subscription_data_response>
        itti_msg_response = std::make_shared<
            itti_sbi_retrieve_smf_selection_subscription_data_response>(
            TASK_AMF_SBI, TASK_AMF_APP);
    itti_msg_response->supi          = itti_msg.supi;
    itti_msg_response->response_data = response_data;

    int ret = itti_inst->send_msg(itti_msg_response);
    if (RETURNok != ret) {
      Logger::amf_sbi().error(
          "Could not send ITTI message %s to task TASK_AMF_APP",
          itti_msg_response->get_msg_name());
    }
  }
}

//------------------------------------------------------------------------------
bool amf_sbi::handle_itti_message(itti_sbi_pcf_discovery& itti_msg) {
  // BCF/DID architecture: NRF-based PCF discovery is removed
  // Use configuration-based PCF discovery or direct BCF query
  Logger::amf_sbi().warn(
      "NRF-based PCF discovery is removed. "
      "Use configuration-based PCF endpoint instead.");

  nlohmann::json response_data                = {};
  response_data[kSbiResponseHttpResponseCode] = 503;  // Service Unavailable
  response_data[kSbiResponseJsonData] =
      nlohmann::json({{"error", "NRF-based PCF discovery is not available"}});

  // Notify to the result
  if (itti_msg.promise_id > 0) {
    amf_app_inst->trigger_process_response(itti_msg.promise_id, response_data);
  }
  return false;
}

//------------------------------------------------------------------------------
bool amf_sbi::handle_itti_message(itti_sbi_am_policy_association& itti_msg) {
  if (reject_outbound_request_during_shutdown(
          "new PCF policy association request")) {
    return false;
  }

  Logger::amf_sbi().debug("Send AM Policy Association to PCF");

  std::shared_ptr<ue_context> uc = {};
  std::string supi               = itti_msg.policy_assoc_req.getSupi();
  if (!amf_app_inst->supi_2_ue_context(supi, uc)) {
    return false;
  }

  std::string uri =
      amf_sbi_helper::get_pcf_am_policy_association_uri(uc->pcf_addr);

  nlohmann::json json_data = {};
  to_json(json_data, itti_msg.policy_assoc_req);

  std::string body             = json_data.dump();
  nlohmann::json response_json = {};
  uint32_t response_code       = 0;

  oai::http::response http_response = {};
  send_http_request(uri, oai::common::sbi::method_e::POST, body, http_response);

  nlohmann::json response_data                = {};
  response_data[kSbiResponseHttpResponseCode] = http_response.status_code;
  response_data[kSbiResponseJsonData]         = http_response.get_json();

  // Send response to APP to process
  if (http_response.status_code ==
      oai::common::sbi::http_status_code::CREATED) {
    std::shared_ptr<itti_sbi_am_policy_association_response> itti_msg_response =
        std::make_shared<itti_sbi_am_policy_association_response>(
            TASK_AMF_SBI, TASK_AMF_APP);
    itti_msg_response->supi          = supi;
    itti_msg_response->response_data = response_data;

    if (auto loc_header = http_response.headers.find("location");
        loc_header != http_response.headers.end()) {
      Logger::amf_sbi().info(
          "Location of the created resource: %s", loc_header->second.c_str());
      response_data[kSbiResponseHeaderLocation] = loc_header->second;
    }

    int ret = itti_inst->send_msg(itti_msg_response);
    if (RETURNok != ret) {
      Logger::amf_sbi().error(
          "Could not send ITTI message %s to task TASK_AMF_APP",
          itti_msg_response->get_msg_name());
    }
  }
  return true;
}

//------------------------------------------------------------------------------
bool amf_sbi::handle_itti_message(
    itti_sbi_am_policy_association_termination& itti_msg) {
  if (reject_outbound_request_during_shutdown(
          "new PCF policy association termination request")) {
    return false;
  }

  Logger::amf_sbi().debug("Send AM Policy Association Termination to PCF");

  std::shared_ptr<ue_context> uc = {};
  if (!amf_app_inst->supi_2_ue_context(itti_msg.supi, uc)) {
    return false;
  }

  nlohmann::json response_json      = {};
  uint32_t response_code            = 0;
  oai::http::response http_response = {};

  send_http_request(
      uc->policy_association_location, oai::common::sbi::method_e::POST, "",
      http_response);

  nlohmann::json response_data                = {};
  response_data[kSbiResponseHttpResponseCode] = http_response.status_code;

  // Send response to APP to process
  if (http_response.status_code ==
      oai::common::sbi::http_status_code::NO_CONTENT) {
    std::shared_ptr<itti_sbi_am_policy_association_termination_response>
        itti_msg_response = std::make_shared<
            itti_sbi_am_policy_association_termination_response>(
            TASK_AMF_SBI, TASK_AMF_APP);
    itti_msg_response->supi          = uc->supi;
    itti_msg_response->response_data = response_data;

    int ret = itti_inst->send_msg(itti_msg_response);
    if (RETURNok != ret) {
      Logger::amf_sbi().error(
          "Could not send ITTI message %s to task TASK_AMF_APP",
          itti_msg_response->get_msg_name());
    }
  }
  return true;
}

//------------------------------------------------------------------------------
bool amf_sbi::handle_itti_message(
    itti_sbi_am_policy_association_update& itti_msg) {
  if (reject_outbound_request_during_shutdown(
          "new PCF policy association update request")) {
    return false;
  }

  Logger::amf_sbi().debug("Send AM Policy Association Update to PCF");

  std::shared_ptr<ue_context> uc = {};
  if (!amf_app_inst->supi_2_ue_context(itti_msg.supi, uc)) {
    return false;
  }

  std::string uri = uc->policy_association_location + "/update";

  nlohmann::json json_data = {};
  to_json(json_data, itti_msg.policy_assoc_update_req);

  std::string body             = json_data.dump();
  nlohmann::json response_json = {};
  uint32_t response_code       = 0;

  oai::http::response http_response = {};

  send_http_request(uri, oai::common::sbi::method_e::POST, body, http_response);

  nlohmann::json response_data                = {};
  response_data[kSbiResponseHttpResponseCode] = http_response.status_code;
  response_data[kSbiResponseJsonData]         = http_response.get_json();

  // Send response to APP to process
  if (http_response.status_code == oai::common::sbi::http_status_code::OK) {
    std::shared_ptr<itti_sbi_am_policy_association_update_response>
        itti_msg_response =
            std::make_shared<itti_sbi_am_policy_association_update_response>(
                TASK_AMF_SBI, TASK_AMF_APP);
    itti_msg_response->supi          = itti_msg.supi;
    itti_msg_response->response_data = response_data;

    int ret = itti_inst->send_msg(itti_msg_response);
    if (RETURNok != ret) {
      Logger::amf_sbi().error(
          "Could not send ITTI message %s to task TASK_AMF_APP",
          itti_msg_response->get_msg_name());
    }
  }
  return true;
}

//------------------------------------------------------------------------------
bool amf_sbi::handle_itti_message(
    itti_sbi_am_policy_association_retrieval& itti_msg) {
  if (reject_outbound_request_during_shutdown(
          "new PCF policy association retrieval request")) {
    return false;
  }

  Logger::amf_sbi().debug("Send AM Policy Association Retrieval to PCF");
  std::shared_ptr<ue_context> uc = {};
  if (!amf_app_inst->supi_2_ue_context(itti_msg.supi, uc)) {
    return false;
  }

  nlohmann::json response_json      = {};
  uint32_t response_code            = 0;
  oai::http::response http_response = {};

  send_http_request(
      uc->policy_association_location, oai::common::sbi::method_e::GET, "",
      http_response);

  nlohmann::json response_data                = {};
  response_data[kSbiResponseHttpResponseCode] = http_response.status_code;

  // Send response to APP to process
  if (http_response.status_code == oai::common::sbi::http_status_code::OK) {
    std::shared_ptr<itti_sbi_am_policy_association_termination_response>
        itti_msg_response = std::make_shared<
            itti_sbi_am_policy_association_termination_response>(
            TASK_AMF_SBI, TASK_AMF_APP);
    itti_msg_response->supi          = uc->supi;
    itti_msg_response->response_data = response_data;

    int ret = itti_inst->send_msg(itti_msg_response);
    if (RETURNok != ret) {
      Logger::amf_sbi().error(
          "Could not send ITTI message %s to task TASK_AMF_APP",
          itti_msg_response->get_msg_name());
    }
  }
  return true;
}

//------------------------------------------------------------------------------
bool amf_sbi::handle_itti_message(
    itti_sbi_ue_context_in_smf_data_retrieval& itti_msg) {
  if (reject_outbound_request_during_shutdown(
          "new UE context in SMF data retrieval request")) {
    return false;
  }

  Logger::amf_sbi().debug("Send UE Context In SMF Data Retrieval to UDM");
  std::shared_ptr<ue_context> uc = {};
  if (!amf_app_inst->supi_2_ue_context(itti_msg.supi, uc)) {
    return false;
  }

  std::string uri =
      amf_sbi_helper::get_udm_ue_context_in_smf_data_retrieval_uri(
          amf_cfg->udm_addr, itti_msg.supi);

  nlohmann::json response_json      = {};
  uint32_t response_code            = 0;
  oai::http::response http_response = {};

  send_http_request(uri, oai::common::sbi::method_e::GET, "", http_response);

  nlohmann::json response_data                = {};
  response_data[kSbiResponseHttpResponseCode] = http_response.status_code;

  // Send response to APP to process
  if (http_response.status_code == oai::common::sbi::http_status_code::OK) {
    std::shared_ptr<itti_sbi_ue_context_in_smf_data_retrieval_response>
        itti_msg_response = std::make_shared<
            itti_sbi_ue_context_in_smf_data_retrieval_response>(
            TASK_AMF_SBI, TASK_AMF_APP);
    itti_msg_response->supi          = uc->supi;
    itti_msg_response->response_data = response_data;

    itti_inst->send_msg(itti_msg_response);
  }
  return true;
}

//------------------------------------------------------------------------------
bool amf_sbi::smf_selection_from_configuration(
    std::string& smf_uri_root, std::string& smf_api_version) {
  smf_uri_root    = amf_cfg->smf_addr.uri_root;
  smf_api_version = amf_cfg->smf_addr.api_version;
  return true;
}

//------------------------------------------------------------------------------
void amf_sbi::handle_post_sm_context_response_error(
    const long code, const std::string& cause, bstring n1sm,
    const std::string& supi, uint8_t pdu_session_id) {
  oai::utils::output_wrapper::print_buffer(
      "amf_sbi", "N1 SM", (uint8_t*) bdata(n1sm), blength(n1sm));
  itti_n1n2_message_transfer_request* itti_msg =
      new itti_n1n2_message_transfer_request(TASK_AMF_SBI, TASK_AMF_APP);
  itti_msg->n1sm           = bstrcpy(n1sm);
  itti_msg->is_n2sm_set    = false;
  itti_msg->is_n1sm_set    = true;
  itti_msg->supi           = supi;
  itti_msg->pdu_session_id = pdu_session_id;
  itti_msg->is_ppi_set     = false;
  std::shared_ptr<itti_n1n2_message_transfer_request> i =
      std::shared_ptr<itti_n1n2_message_transfer_request>(itti_msg);
  int ret = itti_inst->send_msg(i);
  if (0 != ret) {
    Logger::amf_sbi().error(
        "Could not send ITTI message %s to task TASK_AMF_APP",
        i->get_msg_name());
  }
}

//-----------------------------------------------------------------------------------------------------
// NRF-based SMF discovery is removed - use configuration-based discovery
//-----------------------------------------------------------------------------------------------------
bool amf_sbi::discover_smf(
    std::string& smf_uri_root, std::string& smf_api_version,
    const snssai_t& snssai, const plmn_t& plmn, const std::string& dnn,
    const std::string& nrf_uri) {
  // BCF/DID architecture: NRF-based SMF discovery is not available
  Logger::amf_sbi().warn(
      "NRF-based SMF discovery is removed. "
      "Use smf_selection_from_configuration() instead.");
  return false;
}

//------------------------------------------------------------------------------
bool amf_sbi::send_http_request(
    const std::string& remote_uri, const std::string& json_data,
    const std::string& n1sm_msg, const std::string& n2sm_msg,
    const std::string& supi, uint8_t pdu_session_id, uint8_t http_version,
    const uint32_t& promise_id) {
  bool request_result = false;

  oai::utils::mime_parser parser           = {};
  std::string body                         = {};
  std::shared_ptr<pdu_session_context> psc = {};
  bool is_multipart                        = true;

  if (!amf_app_inst->find_pdu_session_context(supi, pdu_session_id, psc))
    return false;

  // prepare the body content
  create_multipart_content(json_data, n1sm_msg, n2sm_msg, is_multipart, body);

  oai::http::request http_request =
      http_client_inst->prepare_multipart_request(remote_uri, body);
  // Send the request and get the response
  auto http_response = http_client_inst->send_http_request(
      oai::common::sbi::method_e::POST, http_request);

  if (http_response.status_code ==
      oai::common::sbi::http_status_code::NO_RESPONSE) {
    return false;
  }

  std::string json_data_response  = {};
  std::optional<std::string> n1sm = {};
  std::optional<std::string> n2sm = {};
  nlohmann::json response_data    = {};
  bstring n1sm_hex                = nullptr;
  bstring n2sm_hex                = nullptr;

  if (http_response.body.size() > 0) {
    if (!parser.parse(http_response.body)) {
      json_data_response = http_response.body;
    } else {
      parser.get(oai::utils::JSON_CONTENT_ID_MIME, json_data_response);
      parser.get(oai::utils::N1_SM_CONTENT_ID, n1sm);
      parser.get(oai::utils::N2_SM_CONTENT_ID, n2sm);
    }
  }

  Logger::amf_sbi().info("JSON part %s", json_data_response.c_str());

  if ((http_response.status_code != oai::common::sbi::http_status_code::OK) &&
      (http_response.status_code !=
       oai::common::sbi::http_status_code::CREATED) &&
      (http_response.status_code !=
       oai::common::sbi::http_status_code::NO_CONTENT)) {
    // ERROR
    if (http_response.body.size() < 1) {
      Logger::amf_sbi().error("There's no content in the response");
      return false;
    }
    // TODO: HO

    // Transfer N1 to gNB/UE if available
    if (n1sm.has_value()) {
      try {
        response_data = nlohmann::json::parse(json_data_response);
      } catch (nlohmann::json::exception& e) {
        Logger::amf_sbi().warn("Could not get JSON content from the response");
        // Set the default Cause
        response_data["error"]["cause"] = "504 Gateway Timeout";
      }

      Logger::amf_sbi().debug(
          "Get response with json_data: %s", json_data_response.c_str());
      amf_conv::msg_str_2_msg_hex(n1sm.value(), n1sm_hex);
      oai::utils::output_wrapper::print_buffer(
          "amf_sbi", "Get response with n1sm:", (uint8_t*) bdata(n1sm_hex),
          blength(n1sm_hex));

      std::string cause = response_data["error"]["cause"];
      Logger::amf_sbi().debug(
          "Network Function services failure (with cause %s)", cause.c_str());
      handle_post_sm_context_response_error(
          http_response.status_code, cause, n1sm_hex, supi, pdu_session_id);
    }

  } else {  // Response with success code
            // Store location of the created context in case of PDU Session
            // Establishment
    if (auto loc_header = http_response.headers.find("location");
        loc_header != http_response.headers.end()) {
      Logger::amf_sbi().info(
          "Location of the created SMF context: %s",
          loc_header->second.c_str());
      psc->smf_info.context_location = loc_header->second;
    }

    try {
      response_data = nlohmann::json::parse(json_data_response);
    } catch (nlohmann::json::exception& e) {
      Logger::amf_sbi().warn("Could not get JSON content from the response");
      // TODO:
      return false;
    }

    request_result                       = true;
    nlohmann::json process_response_data = {};

    bool is_ho_procedure              = false;
    bool is_up_deactivation_procedure = false;
    bool is_service_request           = false;

    // For N2 HO
    if (response_data.find("hoState") != response_data.end()) {
      is_ho_procedure = true;

      std::string ho_state = {};
      response_data.at("hoState").get_to(ho_state);
      if (ho_state.compare("COMPLETED") == 0) {
        if (response_data.find("pduSessionId") != response_data.end())
          process_response_data["pduSessionId"] =
              response_data.at("pduSessionId");
      } else if (n2sm.has_value()) {
        process_response_data["n2sm"] = n2sm.value();
      }
    }

    // UP deactivation
    if (response_data.find("upCnxState") != response_data.end()) {
      Logger::amf_sbi().debug("UP Deactivation");
      std::string up_cnx_state = {};
      response_data.at("upCnxState").get_to(up_cnx_state);
      if (up_cnx_state.compare("DEACTIVATED") == 0) {
        is_up_deactivation_procedure = true;
        process_response_data[kSbiResponseHttpResponseCode] =
            http_response.status_code;
      }

      // Service Request
      if (up_cnx_state.compare("ACTIVATING") == 0) {
        is_service_request = true;
        process_response_data[kSbiResponseHttpResponseCode] =
            http_response.status_code;
        // Update PDU Session Context
        if (n2sm.has_value()) {
          amf_conv::msg_str_2_msg_hex(n2sm.value(), n2sm_hex);
          oai::utils::output_wrapper::print_buffer(
              "amf_sbi", "[Service Request] Get response N2 SM:",
              (uint8_t*) bdata(n2sm_hex), blength(n2sm_hex));
          psc->n2sm              = bstrcpy(n2sm_hex);
          psc->is_n2sm_available = true;
        }
      }
    }

    // Notify to the result
    if ((promise_id > 0) and (is_ho_procedure or is_up_deactivation_procedure or
                              is_service_request)) {
      amf_app_inst->trigger_process_response(promise_id, process_response_data);
      oai::utils::utils::bdestroy_wrapper(&n1sm_hex);
      return request_result;
    }

    // Transfer N1/N2 to gNB/UE if available
    if (n1sm.has_value() or n2sm.has_value()) {
      auto itti_msg = std::make_shared<itti_n1n2_message_transfer_request>(
          TASK_AMF_SBI, TASK_AMF_APP);

      itti_msg->is_n1sm_set = false;
      itti_msg->is_n2sm_set = false;
      itti_msg->is_ppi_set  = false;

      if (n1sm.has_value() > 0) {
        amf_conv::msg_str_2_msg_hex(n1sm.value(), n1sm_hex);
        oai::utils::output_wrapper::print_buffer(
            "amf_sbi", "Get response N1 SM:", (uint8_t*) bdata(n1sm_hex),
            blength(n1sm_hex));
        itti_msg->n1sm        = bstrcpy(n1sm_hex);
        itti_msg->is_n1sm_set = true;
      }

      if (n2sm.has_value() > 0) {
        amf_conv::msg_str_2_msg_hex(n2sm.value(), n2sm_hex);
        oai::utils::output_wrapper::print_buffer(
            "amf_sbi", "Get response N2 SM:", (uint8_t*) bdata(n2sm_hex),
            blength(n2sm_hex));
        itti_msg->n2sm        = bstrcpy(n2sm_hex);
        itti_msg->is_n2sm_set = true;
        itti_msg->n2sm_info_type =
            response_data["n2SmInfoType"].get<std::string>();
      }

      itti_msg->supi           = supi;
      itti_msg->pdu_session_id = pdu_session_id;

      int ret = itti_inst->send_msg(itti_msg);
      if (0 != ret) {
        Logger::amf_sbi().error(
            "Could not send ITTI message %s to task TASK_AMF_APP",
            itti_msg->get_msg_name());
      }
    }

    oai::utils::utils::bdestroy_wrapper(&n1sm_hex);
    oai::utils::utils::bdestroy_wrapper(&n2sm_hex);
  }

  return request_result;
}

//------------------------------------------------------------------------------
void amf_sbi::send_http_request(
    const std::string& remote_uri, std::string& json_data,
    std::string& n1sm_msg, std::string& n2sm_msg, uint8_t http_version,
    uint32_t& response_code, const uint32_t& promise_id) {
  uint8_t number_parts           = 0;
  oai::utils::mime_parser parser = {};
  std::string body               = {};
  bool is_multipart              = true;

  // prepare the body content
  create_multipart_content(json_data, n1sm_msg, n2sm_msg, is_multipart, body);

  oai::http::request http_request =
      http_client_inst->prepare_multipart_request(remote_uri, body);
  // Send the request and get the response
  auto http_response = http_client_inst->send_http_request(
      oai::common::sbi::method_e::POST, http_request);

  if (http_response.status_code ==
      oai::common::sbi::http_status_code::NO_RESPONSE) {
    return;
  }

  std::string json_data_response = {};
  std::string n1sm               = {};
  std::string n2sm               = {};
  nlohmann::json response_data   = {};

  // clear input
  n1sm_msg  = {};
  n2sm_msg  = {};
  json_data = {};

  Logger::amf_sbi().info(
      "Get response with HTTP code (%ld)", http_response.status_code);
  Logger::amf_sbi().info("Response body %s", http_response.body.c_str());

  if (http_response.status_code ==
      oai::common::sbi::http_status_code::NO_RESPONSE) {
    // TODO: should be removed
    Logger::amf_sbi().error(
        "Cannot get response when calling %s", remote_uri.c_str());
    return;
  }

  if (http_response.body.size() > 0) {
    number_parts =
        parser.parse(http_response.body, json_data_response, n1sm, n2sm);
  }

  if (number_parts == 0) {
    json_data_response = http_response.body;
  }

  Logger::amf_sbi().info("JSON part %s", json_data_response.c_str());

  if ((http_response.status_code != oai::common::sbi::http_status_code::OK) &&
      (http_response.status_code !=
       oai::common::sbi::http_status_code::CREATED) &&
      (http_response.status_code !=
       oai::common::sbi::http_status_code::NO_CONTENT)) {
    // TODO:

  } else {  // Response with success code
    try {
      response_data = nlohmann::json::parse(json_data_response);
    } catch (nlohmann::json::exception& e) {
      Logger::amf_sbi().warn("Could not get JSON content from the response");
      // TODO:
      return;
    }

    // Transfer N1/N2 to gNB/UE if available
    if (number_parts > 1) {
      if (n1sm.size() > 0) {
        n1sm_msg = n1sm;
      }
      if (n2sm.size() > 0) {
        n2sm_msg = n2sm;
      }
    }
  }
}

//-----------------------------------------------------------------------------------------------------
void amf_sbi::send_http_request(
    const std::string& remote_uri, const oai::common::sbi::method_e method,
    const std::string& msg_body, nlohmann::json& response_json,
    uint32_t& response_code, uint8_t http_version) {
  oai::http::request http_request =
      http_client_inst->prepare_json_request(remote_uri, msg_body);

  // Send the request and get the response
  auto http_response =
      http_client_inst->send_http_request(method, http_request);

  if (http_response.status_code ==
      oai::common::sbi::http_status_code::NO_RESPONSE) {
    Logger::amf_sbi().info(
        "Cannot get response when calling %s", remote_uri.c_str());
    return;
  }

  std::string response = http_response.body;
  bool is_response_ok  = true;
  response_code        = http_response.status_code;
  Logger::amf_sbi().info("Get response with HTTP code (%ld)", response_code);

  if ((http_response.status_code != oai::common::sbi::http_status_code::OK) and
      (http_response.status_code !=
       oai::common::sbi::http_status_code::CREATED) and
      (http_response.status_code !=
       oai::common::sbi::http_status_code::NO_CONTENT)) {
    is_response_ok = false;

    if (response.size() < 1) {
      Logger::amf_sbi().info("There's no content in the response");
      response_json = {};
      return;
    }
  }

  try {
    response_json = nlohmann::json::parse(response);
  } catch (nlohmann::json::exception& e) {
    Logger::amf_sbi().info("Could not get JSON content from the response");
    response_json = {};
  }
}

//-----------------------------------------------------------------------------------------------------
void amf_sbi::send_http_request(
    const std::string& remote_uri, const oai::common::sbi::method_e method,
    const std::string& msg_body, oai::http::response& http_response) {
  oai::http::request http_request =
      http_client_inst->prepare_json_request(remote_uri, msg_body);

  // Send the request and get the response
  http_response = http_client_inst->send_http_request(method, http_request);

  if (http_response.status_code ==
      oai::common::sbi::http_status_code::NO_RESPONSE) {
    Logger::amf_sbi().warn(
        "Cannot get response when calling %s", remote_uri.c_str());
  }

  Logger::amf_sbi().debug(
      "Get response with HTTP code: %ld", http_response.status_code);

  Logger::amf_sbi().debug("Get response with body\n, %s ", http_response.body);
  return;
}

//------------------------------------------------------------------------------
// NRF URI retrieval is removed - BCF is used for NF discovery
//------------------------------------------------------------------------------
bool amf_sbi::get_nrf_uri(
    const snssai_t& snssai, const plmn_t& plmn, const std::string& dnn,
    std::string& nrf_uri) {
  // BCF/DID architecture: NRF is not used
  Logger::amf_sbi().warn(
      "get_nrf_uri() is deprecated. NRF is replaced by BCF for NF discovery.");
  nrf_uri.clear();
  return false;
}

//------------------------------------------------------------------------------
void amf_sbi::get_network_slice_information(
    const snssai_t& snssai, const plmn_t& plmn,
    const std::optional<std::string>& dnn, const std::string& amf_instance_id,
    nlohmann::json& response_data, uint32_t& response_code) {
  // Get NSI information from NSSF
  nlohmann::json slice_info  = {};
  nlohmann::json snssai_info = {};
  snssai_info["sst"]         = snssai.sst;
  if (!snssai.sd.empty()) snssai_info["sd"] = snssai.sd;
  slice_info["sNssai"]            = snssai_info;
  slice_info["roamingIndication"] = "NON_ROAMING";
  // ToDo Add TAI

  std::string nssf_uri =
      amf_sbi_helper::get_nssf_network_slice_selection_information_uri(
          amf_cfg->nssf_addr);

  std::string parameters = {};
  parameters.append("?nf-type=AMF&nf-id=")
      .append(amf_instance_id)
      .append("&slice-info-request-for-pdu-session=")
      .append(slice_info.dump());
  nssf_uri += parameters;

  Logger::amf_sbi().debug(
      "Send Network Slice Information Retrieval, URI %s", nssf_uri.c_str());

  send_http_request(
      nssf_uri, oai::common::sbi::method_e::GET, "", response_data,
      response_code, amf_cfg->support_features.http_version);

  Logger::amf_sbi().debug(
      "NS Selection, response from NSSF, json data: \n %s",
      response_data.dump().c_str());
}

//------------------------------------------------------------------------------
void amf_sbi::create_multipart_content(
    const std::string& json_data, const std::string& n1sm_msg,
    const std::string& n2sm_msg, bool is_multipart, std::string& body) {
  oai::utils::mime_parser parser = {};
  is_multipart                   = true;

  if ((n1sm_msg.size() > 0) and (n2sm_msg.size() > 0)) {
    parser.create_multipart_related_content(
        body, json_data, oai::http::MIME_BOUNDARY, n1sm_msg, n2sm_msg);
  } else if (n1sm_msg.size() > 0) {  // only N1 content
    parser.create_multipart_related_content(
        body, json_data, oai::http::MIME_BOUNDARY, n1sm_msg,
        oai::utils::multipart_related_content_part_e::NAS);
  } else if (n2sm_msg.size() > 0) {  // only N2 content
    parser.create_multipart_related_content(
        body, json_data, oai::http::MIME_BOUNDARY, n2sm_msg,
        oai::utils::multipart_related_content_part_e::NGAP);
  } else {
    body         = json_data;
    is_multipart = false;
  }
}

//------------------------------------------------------------------------------
// BCF Authentication HTTP Methods
//------------------------------------------------------------------------------

bool amf_sbi::send_did_auth_request(
    const std::string& uri, const std::string& method, const std::string& body,
    std::string& response_body, uint32_t& response_code) {
  // Unique HTTP detail logging — only place that prints method/URL/body/response
  Logger::amf_sbi().info(
      "[BCF Auth] HTTP %s %s", method.c_str(), uri.c_str());
  Logger::amf_sbi().debug(
      "[BCF Auth] Request body: %s", body.empty() ? "{}" : body.c_str());

  try {
    oai::common::sbi::method_e http_method = oai::common::sbi::method_e::POST;
    if (method == "GET") {
      http_method = oai::common::sbi::method_e::GET;
    } else if (method == "PUT") {
      http_method = oai::common::sbi::method_e::PUT;
    } else if (method == "DELETE") {
      http_method = oai::common::sbi::method_e::DELETE;
    }

    // Directly use HTTP client to avoid duplicate logging from send_http_request
    oai::http::request http_request =
        http_client_inst->prepare_json_request(uri, body);
    auto http_response =
        http_client_inst->send_http_request(http_method, http_request);

    response_code = http_response.status_code;
    response_body = http_response.body;

    if (http_response.status_code ==
        oai::common::sbi::http_status_code::NO_RESPONSE) {
      Logger::amf_sbi().warn(
          "[BCF Auth] No response from %s", uri.c_str());
    } else {
      Logger::amf_sbi().info(
          "[BCF Auth] HTTP %d from %s", response_code, uri.c_str());
      Logger::amf_sbi().debug(
          "[BCF Auth] Response body: %s",
          response_body.empty() ? "{}" : response_body.c_str());
    }

    return true;
  } catch (const std::exception& e) {
    Logger::amf_sbi().error("[BCF Auth] Network error: %s", e.what());
    response_code = 500;
    response_body = "";
    return false;
  }
}

// BCF self-auth is now done at AMF startup, not per-UE-request.
// See amf_app::init_did_auth_module() for BCF auth initialization.
