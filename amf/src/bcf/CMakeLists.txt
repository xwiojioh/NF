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

# BCF (Blockchain Control Function) NF Discovery Library
# 
# 通用的 BCF NF 发现框架，可被任何 5G 核心网网元使用
# 此模块替代了传统的 NRF 发现功能

include_directories(${SRC_TOP_DIR}/bcf)

add_library(BCF STATIC
  ${CMAKE_CURRENT_SOURCE_DIR}/bcf_client.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/bcf_nf_discovery.cpp
)

target_include_directories(BCF PUBLIC
  ${CMAKE_CURRENT_SOURCE_DIR}
  ${SRC_TOP_DIR}/common
  ${SRC_TOP_DIR}/${MOUNTED_COMMON}/logger
)

target_link_libraries(BCF
  curl
)
