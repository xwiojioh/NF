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

# BCF (Blockchain Control Function) NF Discovery Module
# 
# 通用的 BCF NF 发现框架，可被任何 5G 核心网网元使用
# 此模块替代了传统的 NRF 发现功能

SET(BCF_DIR ${SRC_TOP_DIR}/${MOUNTED_COMMON}/bcf)

include_directories(${BCF_DIR})

## BCF used in NF_TARGET (main)
if (TARGET ${NF_TARGET})
target_include_directories(${NF_TARGET} PUBLIC ${BCF_DIR})
target_sources(${NF_TARGET} PRIVATE
        ${BCF_DIR}/bcf_client.cpp
        ${BCF_DIR}/bcf_nf_discovery.cpp
        )
endif()
