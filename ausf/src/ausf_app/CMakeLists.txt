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

include_directories(${SRC_TOP_DIR}/api_server/api)
include_directories(${SRC_TOP_DIR}/api_server/impl)
include_directories(${SRC_TOP_DIR}/api_server/)
include_directories(${SRC_TOP_DIR}/common/)
include_directories(${SRC_TOP_DIR}/5gaka)
include_directories(${SRC_TOP_DIR}/${MOUNTED_COMMON}/model/ausf)
include_directories(${SRC_TOP_DIR}/${MOUNTED_COMMON}/audit)
include_directories(${SRC_TOP_DIR}/${MOUNTED_COMMON}/common)
include_directories(${SRC_TOP_DIR}/${MOUNTED_COMMON}/3gpp)
include_directories(${SRC_TOP_DIR}/${MOUNTED_COMMON}/config)
include_directories(${SRC_TOP_DIR}/${MOUNTED_COMMON}/http)
include_directories(${SRC_TOP_DIR}/${MOUNTED_COMMON}/logger)
include_directories(${SRC_TOP_DIR}/${MOUNTED_COMMON}/utils)
include_directories(${SRC_TOP_DIR}/${MOUNTED_COMMON}/model/common_model)


if(DEFINED BUILD_TOP_DIR AND EXISTS "${BUILD_TOP_DIR}/ausf/used_models.cmake")
  include(${BUILD_TOP_DIR}/ausf/used_models.cmake)
endif()
include(${SRC_TOP_DIR}/${MOUNTED_COMMON}/http/http.cmake)

# DID Authentication Module
add_subdirectory(did_auth)

add_library (AUSF STATIC
  ausf_app.cpp
  ausf_config.cpp
  ausf_config_yaml.cpp  
  task_manager.cpp
  ausf_event.cpp
  ausf_profile.cpp
  ausf_bcf.cpp
  ${SRC_TOP_DIR}/${MOUNTED_COMMON}/audit/security_audit.cpp
)

# Link DID_AUTH library
target_link_libraries(AUSF PRIVATE DID_AUTH ${OAI_YAML_CPP_TARGET})
