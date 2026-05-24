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

#include <signal.h>
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>

#include <chrono>
#include <atomic>
#include <cstring>
#include <iostream>
#include <string>
#include <thread>

#include "amf_app.hpp"
#include "amf_config.hpp"
#include "amf_http1_server.hpp"
#ifdef AMF_HAS_HTTP2_SERVER
#include "amf_http2_server.hpp"
#endif
#include "amf_statistics.hpp"
#include "http_client.hpp"
#include "itti.hpp"
#include "logger.hpp"
#include "ngap_app.hpp"
#include "options.hpp"
#include "pistache/endpoint.h"
#include "pistache/http.h"
#include "pistache/router.h"

using namespace oai::config;
using namespace amf_application;

itti_mw* itti_inst    = nullptr;
amf_app* amf_app_inst = nullptr;
statistics stacs;

amf_http1_server* http1_server = nullptr;
#ifdef AMF_HAS_HTTP2_SERVER
amf_http2_server* http2_server = nullptr;
#endif

std::shared_ptr<oai::http::http_client> http_client_inst = nullptr;

std::unique_ptr<amf_config> amf_cfg;
std::unique_ptr<lttng_configuration> lttng_config_yaml;
static std::atomic<bool> g_shutdown_signal_started{false};

//------------------------------------------------------------------------------
void amf_signal_handler(int s) {
  if (g_shutdown_signal_started.exchange(true)) {
    Logger::system().warn(
        "Shutdown already in progress, ignore duplicated signal %d", s);
    return;
  }

  auto shutdown_start = std::chrono::system_clock::now();
  // Setting log level arbitrarly to debug to show the whole
  // shutdown procedure in the logs even in case of off-logging
  Logger::set_level(spdlog::level::debug);
  Logger::system().info("Caught signal %d", s);

  // Stop on-going tasks
  bool http_server_stopped = false;
  if (http1_server) {
    http1_server->shutdown();
    http_server_stopped = true;
  }

#ifdef AMF_HAS_HTTP2_SERVER
  if (http2_server) {
    http2_server->stop();
    http_server_stopped = true;
  }
#endif

  if (amf_app_inst && http_server_stopped) {
    amf_app_inst->notify_http_server_stopped();
  }

  if (amf_app_inst && !http1_server
#ifdef AMF_HAS_HTTP2_SERVER
      && !http2_server
#endif
  ) {
    amf_app_inst->notify_http_server_stopped();
  }

  if (amf_app_inst) {
    amf_app_inst->stop();
  }

  if (itti_inst) {
    itti_inst->wait_tasks_end();
  }

  if (amf_app_inst) {
    amf_app_inst->notify_shutdown_complete();
  }

  Logger::system().debug("Freeing Allocated memory...");

  // Delete instances
  if (http1_server) {
    delete http1_server;
    http1_server = nullptr;
    Logger::system().debug("HTTP/1 Server memory done.");
  }

#ifdef AMF_HAS_HTTP2_SERVER
  if (http2_server) {
    delete http2_server;
    http2_server = nullptr;
    Logger::system().debug("HTTP/2 Server memory done.");
  }
#endif

  if (amf_app_inst) {
    delete amf_app_inst;
    amf_app_inst = nullptr;
    Logger::system().debug("AMF APP memory done.");
  }

  if (itti_inst) {
    delete itti_inst;
    itti_inst = nullptr;
    Logger::system().debug("ITTI memory done.");
  }

  Logger::system().info("Freeing Allocated memory done.");
  auto elapsed = std::chrono::system_clock::now() - shutdown_start;
  auto ms_diff = std::chrono::duration_cast<std::chrono::milliseconds>(elapsed);
  Logger::system().info("Bye. Shutdown Procedure took %d ms", ms_diff.count());
  exit(0);
}

//------------------------------------------------------------------------------
int main(int argc, char** argv) {
  srand(time(NULL));

  if (!Options::parse(argc, argv)) {
    std::cout << "Options::parse() failed" << std::endl;
    return 1;
  }
  std::string conf_file_name = Options::getYamlConfig();

  std::cout << "Trying to read .yaml configuration file\n";
  lttng_config_yaml = std::make_unique<lttng_configuration>(conf_file_name);
  lttng_config_yaml->read_from_file();

#ifdef LOGGER_CAN_USE_LTTNG
  std::cout << "LTTNG Log Activation: " << lttng_config_yaml->is_lttng_active()
            << "\n";
  std::cout << "Log Level of LTTng: "
            << lttng_config_yaml->get_lttng_log_level() << "\n";
#else
  std::cout << "LTTNG Tracing disabled at build-time!\n";
  if (lttng_config_yaml->is_lttng_active())
    std::cout << "Cannot use lttng log scheme on this build variant!\n";
#endif

  Logger::set_lttng(static_cast<bool>(lttng_config_yaml->is_lttng_active()));
  Logger::init("AMF", Options::getlogStdout(), Options::getlogRotFilelog());
  Logger::amf_app().startup("Options parsed!");

  ::signal(SIGTERM, amf_signal_handler);
  ::signal(SIGINT, amf_signal_handler);

  Logger::system().debug("Parsing the configuration file, file type YAML.");
  amf_cfg = std::make_unique<amf_config>(
      conf_file_name, Options::getlogStdout(), Options::getlogRotFilelog());
  if (!amf_cfg->init()) {
    Logger::system().error("Reading the configuration failed. Exiting.");
    return 1;
  }
  // Convert from YAML to internal structure
  amf_cfg->pre_process();
  amf_cfg->display();

  itti_inst = new itti_mw();
  itti_inst->start(amf_cfg->itti.itti_timer_sched_params);

  // HTTP Client
  http_client_inst = oai::http::http_client::create_instance(
      Logger::amf_sbi(), amf_cfg->http_request_timeout, amf_cfg->sbi.if_name,
      amf_cfg->support_features.http_version, amf_cfg->enable_tls());

  amf_app_inst = new amf_app();
  amf_app_inst->start();

  Logger::amf_app().debug("Initiating AMF server endpoints");
  bool use_http2_server = (amf_cfg->support_features.http_version != 1);
#ifndef AMF_HAS_HTTP2_SERVER
  if (use_http2_server) {
    Logger::system().warn(
        "HTTP/2 requested in config, but this build does not include nghttp2-asio. Falling back to HTTP/1");
    use_http2_server = false;
  }
#endif

  if (!use_http2_server) {
    // AMF HTTP1 server
    Pistache::Address addr(
        std::string(inet_ntoa(*((struct in_addr*) &amf_cfg->sbi.addr4))),
        Pistache::Port(amf_cfg->sbi.port));
    http1_server = new amf_http1_server(addr, amf_app_inst);
    http1_server->init(2);
    std::thread amf_http1_manager(&amf_http1_server::start, http1_server);
    amf_http1_manager.join();
  }
#ifdef AMF_HAS_HTTP2_SERVER
  else {
    // AMF HTTP2 server
    http2_server = new amf_http2_server(
        oai::utils::conv::toString(amf_cfg->sbi.addr4), amf_cfg->sbi.port,
        amf_app_inst);
    std::thread amf_http2_manager(&amf_http2_server::start, http2_server);
    amf_http2_manager.join();
  }
#endif

  Logger::amf_app().debug("Initiation Done!");
  pause();
  return 0;
}
