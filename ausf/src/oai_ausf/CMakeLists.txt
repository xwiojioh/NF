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
# Author: laurent THOMAS, Lionel GAUTHIER
###############################################################################

cmake_minimum_required (VERSION 3.0.2)

###########################################
# macros to define options as there is numerous options in oai
################################################
macro(add_option name val helpstr)
  if(DEFINED ${name})
    set(value ${${name}})
  else(DEFINED ${name})
    set(value ${val})
  endif()
  set(${name} ${value} CACHE STRING "${helpstr}")
  add_definitions("-D${name}=${value}")
endmacro(add_option)

macro(add_boolean_option name val helpstr)
  if(DEFINED ${name})
    set(value ${${name}})
  else(DEFINED ${name})
    set(value ${val})
  endif()
  set(${name} ${value} CACHE STRING "${helpstr}")
  set_property(CACHE ${name} PROPERTY TYPE BOOL)
  if (${value})
    add_definitions("-D${name}=1")
  else (${value})
    add_definitions("-D${name}=0")
  endif (${value})
endmacro(add_boolean_option)

macro(add_integer_option name val helpstr)
  if(DEFINED ${name})
    set(value ${${name}})
  else(DEFINED ${name})
    set(value ${val})
  endif()
  set(${name} ${value} CACHE STRING "${helpstr}")
  add_definitions("-D${name}=${value}")
endmacro(add_integer_option)

macro(add_list1_option name val helpstr)
  if(DEFINED ${name})
    set(value ${${name}})
  else(DEFINED ${name})
    set(value ${val})
  endif()
  set(${name} ${value} CACHE STRING "${helpstr}")
  set_property(CACHE ${name} PROPERTY STRINGS ${ARGN})
  if(NOT "${value}" STREQUAL "False")
    add_definitions("-D${name}=${value}")
  endif()
endmacro(add_list1_option)

macro(add_list2_option name val helpstr)
  if(DEFINED ${name})
    set(value ${${name}})
  else(DEFINED ${name})
    set(value ${val})
  endif()
  set(${name} ${value} CACHE STRING "${helpstr}")
  set_property(CACHE ${name} PROPERTY STRINGS ${ARGN})
  if(NOT "${value}" STREQUAL "False")
    add_definitions("-D${value}=1")
  endif()
endmacro(add_list2_option)

macro(add_list_string_option name val helpstr)
  if(DEFINED ${name})
    set(value ${${name}})
  else(DEFINED ${name})
    set(value ${val})
  endif()
  set(${name} ${value} CACHE STRING "${helpstr}")
  set_property(CACHE ${name} PROPERTY STRINGS ${ARGN})
  if(NOT "${value}" STREQUAL "False")
    add_definitions("-D${name}=\"${value}\"")
  endif()
endmacro(add_list_string_option)
################################################################
# Compilation flags
################################################################

# determine, whether we want a static binary
SET(STATIC_LINKING FALSE CACHE BOOL "Build a static binary?")

# do we want static libraries?
# When STATIC_LINKING is TRUE, than cmake looks for libraries ending
# with .a. This is for linux only!
IF(STATIC_LINKING)
    SET(CMAKE_FIND_LIBRARY_SUFFIXES ".a")
ENDIF(STATIC_LINKING)

################################################################
# Build type
################################################################
add_list_string_option(CMAKE_BUILD_TYPE "RelWithDebInfo" "Choose the type of build, options are: None(CMAKE_CXX_FLAGS or CMAKE_C_FLAGS used) Debug Release RelWithDebInfo MinSizeRel." Debug Release
RelWithDebInfo MinSizeRel)
Message("Build type is ${CMAKE_BUILD_TYPE}")
if (CMAKE_BUILD_TYPE STREQUAL "RelWithDebInfo")
  add_boolean_option(LOG_OAI True         "Thread safe logging API")
  add_boolean_option(LOG_OAI_MINIMAL True "Thread safe logging API, log only levels above NOTICE")
  SET(ASAN asan)
endif()
if (CMAKE_BUILD_TYPE STREQUAL "Release")
  Message("no more asan in Release Mode")
endif()
if (CMAKE_BUILD_TYPE STREQUAL "Debug")
  add_boolean_option(LOG_OAI True "Thread safe logging API")
  SET(ASAN asan)
endif()
if (CMAKE_BUILD_TYPE STREQUAL "")
   set(CMAKE_BUILD_TYPE "MinSizeRel")
endif()

################################################################
# Processor architecture
################################################################

Message("Architecture is ${CMAKE_SYSTEM_PROCESSOR}")
if (CMAKE_SYSTEM_PROCESSOR STREQUAL "armv7l")
  set(C_FLAGS_PROCESSOR "-gdwarf-2 -mfloat-abi=hard -mfpu=neon -lgcc -lrt")
elseif (CMAKE_SYSTEM_PROCESSOR STREQUAL "aarch64")
  # Tested on aarch64 system in Little Endian
  # Model ARM-Neoverse-N1
  #   flags: fp asimd evtstrm aes pmull sha1 sha2 crc32 atomics fphp asimdhp cpuid asimdrdm lrcpc dcpop asimddp ssbs
  set(C_FLAGS_PROCESSOR "-gdwarf-2 -lgcc -lrt")
else ()
  set(C_FLAGS_PROCESSOR "-msse4.2")
endif()
#
set(CMAKE_C_FLAGS
  "${CMAKE_C_FLAGS} ${C_FLAGS_PROCESSOR} -std=gnu99 -Wall -Wstrict-prototypes -fno-strict-aliasing -rdynamic -funroll-loops -Wno-packed-bitfield-compat -fPIC ")
# add autoTOOLS definitions that were maybe used!
set(CMAKE_C_FLAGS
  "${CMAKE_C_FLAGS} -DSTDC_HEADERS=1 -DHAVE_SYS_TYPES_H=1 -DHAVE_SYS_STAT_H=1 -DHAVE_STDLIB_H=1 -DHAVE_STRING_H=1 -DHAVE_MEMORY_H=1 -DHAVE_STRINGS_H=1 -DHAVE_INTTYPES_H=1 -DHAVE_STDINT_H=1 -DHAVE_UNISTD_H=1 -DHAVE_FCNTL_H=1 -DHAVE_ARPA_INET_H=1 -DHAVE_SYS_TIME_H=1 -DHAVE_SYS_SOCKET_H=1 -DHAVE_STRERROR=1 -DHAVE_SOCKET=1 -DHAVE_MEMSET=1 -DHAVE_GETTIMEOFDAY=1 -DHAVE_STDLIB_H=1 -DHAVE_MALLOC=1 -DHAVE_LIBSCTP"
)
# set a flag for changes in the source code
# these changes are related to hardcoded path to include .h files
add_definitions(-DCMAKER)
add_definitions(-DBSTRLIB_CAN_USE_STL=1 -DBSTRLIB_CAN_USE_IOSTREAM=1 -DBSTRLIB_THROWS_EXCEPTIONS=1)


if(STATIC_LINKING)
  set(CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS} -g -fstack-protector-all -DMALLOC_CHECK_=3 -O0 -fno-omit-frame-pointer")
else (STATIC_LINKING)
  set(CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS} -g -fstack-protector-all -DMALLOC_CHECK_=3 -O0 -fsanitize=address -fno-omit-frame-pointer")
endif(STATIC_LINKING)
set(CMAKE_C_FLAGS_RELEASE "${CMAKE_C_FLAGS} -O2 -fno-omit-frame-pointer -s ")
set(CMAKE_C_FLAGS_RELWITHDEBINFO "${CMAKE_C_FLAGS} -g  -O2 ")
set(CMAKE_C_FLAGS_MINSIZEREL "${CMAKE_C_FLAGS} -Os -s")

if(STATIC_LINKING)
  set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS} -std=c++17  -g -fstack-protector-all -DMALLOC_CHECK_=3 -O0 -fno-omit-frame-pointer")
else(STATIC_LINKING)
  set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS} -std=c++17  -g -fstack-protector-all -DMALLOC_CHECK_=3 -O0 -fsanitize=address -fno-omit-frame-pointer")
endif(STATIC_LINKING)
set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS} -std=c++17  -O2 -fno-omit-frame-pointer -s ")
set(CMAKE_CXX_FLAGS_RELWITHDEBINFO "${CMAKE_CXX_FLAGS} -std=c++17 -g -O2 ")
set(CMAKE_CXX_FLAGS_MINSIZEREL "${CMAKE_CXX_FLAGS} -std=c++17 -Os -s")


################################################################
# Git Version
################################################################
set(GIT_BRANCH        "UNKNOWN")
set(GIT_COMMIT_HASH   "UNKNOWN")
set(GIT_COMMIT_DATE   "UNKNOWN")

find_package(Git)
if(GIT_FOUND)
  message("git found: ${GIT_EXECUTABLE}")
  set(GIT_METADATA_DIR "${CMAKE_SOURCE_DIR}")
  if(DEFINED OPENAIRCN_DIR AND EXISTS "${OPENAIRCN_DIR}/.git")
    set(GIT_METADATA_DIR "${OPENAIRCN_DIR}")
  endif()
  # Get the current working branch
  execute_process(
    COMMAND git rev-parse --abbrev-ref HEAD
    WORKING_DIRECTORY ${GIT_METADATA_DIR}
    OUTPUT_VARIABLE GIT_BRANCH
    OUTPUT_STRIP_TRAILING_WHITESPACE
    ERROR_QUIET
  )

  # Get the latest abbreviated commit hash of the working branch
  execute_process(
    COMMAND git log -1 --format=%h
    WORKING_DIRECTORY ${GIT_METADATA_DIR}
    OUTPUT_VARIABLE GIT_COMMIT_HASH
    OUTPUT_STRIP_TRAILING_WHITESPACE
    ERROR_QUIET
  )

  # Get the latest commit date of the working branch
  execute_process(
    COMMAND git log -1 --format=%cd
    WORKING_DIRECTORY ${GIT_METADATA_DIR}
    OUTPUT_VARIABLE GIT_COMMIT_DATE
    OUTPUT_STRIP_TRAILING_WHITESPACE
    ERROR_QUIET
  )
endif()

add_definitions("-DPACKAGE_VERSION=\"Branch: ${GIT_BRANCH} Abrev. Hash: ${GIT_COMMIT_HASH} Date: ${GIT_COMMIT_DATE}\"")
add_definitions("-DPACKAGE_BUGREPORT=\"openaircn-user@lists.eurecom.fr\"")

###############################################################################
# Include CMake modules to find other library
###############################################################################

set(CMAKE_MODULE_PATH "${OPENAIRCN_DIR}/build/common-build/cmake_modules" "${CMAKE_MODULE_PATH}")
include(FindPkgConfig)

###############################################################################
# Include Check library for unit tests
###############################################################################

include(CheckCSourceCompiles)
include(CheckCSourceRuns)
include(CheckFunctionExists)
include(CheckIncludeFile)
include(CheckIncludeFiles)
include(CheckIncludeFileCXX)
include(CheckLibraryExists)
include(CheckSymbolExists)
include(CheckTypeSize)

###############################################################################
# Debug and build related options
###############################################################################

add_boolean_option( DISPLAY_LICENCE_INFO            False    "If a module has a licence banner to show")
add_boolean_option( LOG_OAI                         False    "Thread safe logging utility")

# System packages that are required
# We use either the cmake buildin, in ubuntu are in: /usr/share/cmake*/Modules/
# or cmake provide a generic interface to pkg-config that widely used
###################################

set(THREADS_PREFER_PTHREAD_FLAG ON)
#find_package(Threads REQUIRED)

#CPR
find_package(cpr REQUIRED)

find_path(NGHTTP2_ASIO_INCLUDE_DIR nghttp2/asio_http2_server.h)
find_library(NGHTTP2_ASIO_LIBRARY nghttp2_asio)

if(NGHTTP2_ASIO_INCLUDE_DIR AND NGHTTP2_ASIO_LIBRARY)
  set(AUSF_ENABLE_HTTP2 TRUE)
  include_directories(${NGHTTP2_ASIO_INCLUDE_DIR})
  message("HTTP/2 support enabled")
else()
  set(AUSF_ENABLE_HTTP2 FALSE)
  message(WARNING "nghttp2_asio headers/library not found; building AUSF with HTTP/1 support only")
endif()

if(AUSF_ENABLE_HTTP2)
  add_definitions(-DAUSF_ENABLE_HTTP2=1)
  set(AUSF_HTTP2_LINK_LIBRARIES ${NGHTTP2_ASIO_LIBRARY})
else()
  add_definitions(-DAUSF_ENABLE_HTTP2=0)
  set(AUSF_HTTP2_LINK_LIBRARIES)
endif()

# yaml-cpp
# Prefer the exported CMake target so headers and library come from the same
# installation prefix and static link ordering stays consistent.
find_package(yaml-cpp CONFIG REQUIRED)
if(TARGET yaml-cpp)
  set(OAI_YAML_CPP_TARGET yaml-cpp)
elseif(TARGET yaml-cpp::yaml-cpp)
  set(OAI_YAML_CPP_TARGET yaml-cpp::yaml-cpp)
else()
  message(FATAL_ERROR "yaml-cpp package found, but no usable CMake target was exported")
endif()

if(DEFINED YAML_CPP_INCLUDE_DIR AND NOT "${YAML_CPP_INCLUDE_DIR}" STREQUAL "")
  include_directories(${YAML_CPP_INCLUDE_DIR})
endif()

################################################################
# Add sub modules
################################################################
if(STATIC_LINKING)
    SET(BUILD_SHARED_LIBS OFF)
else(STATIC_LINKING)
    SET(BUILD_SHARED_LIBS ON)
endif(STATIC_LINKING)

ADD_SUBDIRECTORY(${CMAKE_CURRENT_SOURCE_DIR}/../../src/common ${CMAKE_CURRENT_BINARY_DIR}/common)
ADD_SUBDIRECTORY(${CMAKE_CURRENT_SOURCE_DIR}/../../src/api_server ${CMAKE_CURRENT_BINARY_DIR}/api_server)
ADD_SUBDIRECTORY(${CMAKE_CURRENT_SOURCE_DIR}/../../src/5gaka ${CMAKE_CURRENT_BINARY_DIR}/5gaka)
ADD_SUBDIRECTORY(${CMAKE_CURRENT_SOURCE_DIR}/../../src/ausf_app ${CMAKE_CURRENT_BINARY_DIR}/ausf_app)
################################################################################
# Specific part for oai_ausf folder
add_definitions("-DPACKAGE_NAME=\"AUSF\"")

include_directories(${SRC_TOP_DIR}/ausf_app)
include_directories(${SRC_TOP_DIR}/oai_ausf)
include_directories(${SRC_TOP_DIR}/common)
include_directories(${SRC_TOP_DIR}/api_server)
include_directories(${SRC_TOP_DIR}/api_server/api)
include_directories(${SRC_TOP_DIR}/api_server/impl)
include_directories(${SRC_TOP_DIR}/5gaka)
include_directories(${SRC_TOP_DIR}/${MOUNTED_COMMON}/3gpp)
include_directories(${SRC_TOP_DIR}/${MOUNTED_COMMON}/http)
include_directories(${SRC_TOP_DIR}/${MOUNTED_COMMON}/logger)
include_directories(${SRC_TOP_DIR}/${MOUNTED_COMMON}/model/ausf)
include_directories(${SRC_TOP_DIR}/${MOUNTED_COMMON}/ngap/libngap)
include_directories(${SRC_TOP_DIR}/${MOUNTED_COMMON}/utils)
include_directories(${SRC_TOP_DIR}/${MOUNTED_COMMON}/utils/bstr)

add_executable(ausf
  ${SRC_TOP_DIR}/oai_ausf/main.cpp
  ${SRC_TOP_DIR}/oai_ausf/options.cpp
  )

set(NF_TARGET ausf)

## Common modules
include(${SRC_TOP_DIR}/${MOUNTED_COMMON}/common/common.cmake)
include(${SRC_TOP_DIR}/${MOUNTED_COMMON}/http/http.cmake)
include(${SRC_TOP_DIR}/${MOUNTED_COMMON}/config/config.cmake)
include(${SRC_TOP_DIR}/${MOUNTED_COMMON}/logger/logger.cmake)
include(${SRC_TOP_DIR}/${MOUNTED_COMMON}/utils/utils.cmake)
include(${SRC_TOP_DIR}/${MOUNTED_COMMON}/model/ausf/ausf.cmake)

IF(STATIC_LINKING)
    SET(CMAKE_EXE_LINKER_FLAGS "-static")
    SET_TARGET_PROPERTIES(ausf PROPERTIES LINK_SEARCH_END_STATIC 1)
    # asan do not support static linking
    SET(ASAN)
ENDIF(STATIC_LINKING)

target_link_libraries (ausf ${ASAN} 
    -Wl,--start-group AUSF 3GPP_COMMON_TYPES 5GAKA AUSF_API -lnettle ${NETTLE_LIBRARIES} ${CRYPTO_LIBRARIES} -lfmt -lspdlog -lssl -lcrypto -lgmp -Wl,--end-group pthread m rt pistache curl ${OAI_YAML_CPP_TARGET} cpr::cpr ${AUSF_HTTP2_LINK_LIBRARIES})
    
add_boolean_option(USE_LTTNG  False "Activate the LTTNG tracer, a debugging/monitoring framework" ON)
if (USE_LTTNG)
    message("Using the lttng build variant")
    add_definitions("-DLOGGER_CAN_USE_LTTNG")
    target_link_libraries(ausf -ldl lttng-ust)
endif ()
