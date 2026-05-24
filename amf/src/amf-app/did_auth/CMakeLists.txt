################################################################################
# Licensed to the OpenAirInterface (OAI) Software Alliance under one or more
# contributor license agreements.  See the NOTICE file distributed with
# this work for additional information regarding copyright ownership.
# The OpenAirInterface Software Alliance licenses this file to You under
# the OAI Public License, Version 1.1  (the "License"); you may not use this file
# except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.openairinterface.org/?page_id=698
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#-------------------------------------------------------------------------------
# For more information about the OpenAirInterface (OAI) Software Alliance:
#      contact@openairinterface.org
################################################################################

# DID Authentication Module

add_library(DID_AUTH STATIC
  did_auth.cpp
  did_auth_types.cpp
  did_auth_precheck.cpp
  did_crypto.cpp
  did_nonce_manager.cpp
  did_session_manager.cpp
  bcf_interface.cpp
  bcf_auth_client.cpp
  did_auth_http_handler.cpp
  hardware_id.cpp
  signature_utils.cpp
)

target_include_directories(DID_AUTH PUBLIC 
  ${CMAKE_CURRENT_SOURCE_DIR}
  ${SRC_TOP_DIR}/bcf
  ${SRC_TOP_DIR}/common
  ${SRC_TOP_DIR}/${MOUNTED_COMMON}/common
  ${SRC_TOP_DIR}/${MOUNTED_COMMON}/http
  ${SRC_TOP_DIR}/${MOUNTED_COMMON}/logger
  ${SRC_TOP_DIR}/${MOUNTED_COMMON}/utils
)

# Link against OpenSSL for cryptographic operations
find_package(OpenSSL REQUIRED)
target_link_libraries(DID_AUTH PUBLIC OpenSSL::SSL OpenSSL::Crypto)

# Note: HTTP/BCF client functionality is provided by external BCF project
# This module only defines interfaces for BCF interaction via callbacks

# Link against nlohmann_json
find_package(nlohmann_json QUIET)
if(nlohmann_json_FOUND)
  target_link_libraries(DID_AUTH PUBLIC nlohmann_json::nlohmann_json)
else()
  target_include_directories(DID_AUTH PUBLIC ${SRC_TOP_DIR}/${MOUNTED_COMMON}/utils)
endif()

# Compiler options
target_compile_features(DID_AUTH PUBLIC cxx_std_17)
