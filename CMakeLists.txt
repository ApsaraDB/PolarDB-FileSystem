# Copyright (c) 2017-2021, Alibaba Group Holding Limited
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

cmake_minimum_required (VERSION 2.8)
project(pfsd CXX C ASM)

message("compile pfsd for PostgreSQL")

set(CMAKE_BUILD_TYPE "Release")
#set(CMAKE_BUILD_TYPE "Debug")

include(CMakeLists-config.txt)

set(COMMON_FLAGS
  -fno-strict-aliasing
  #-fstack-protector
  #-fsanitize=address
  #-DEV_STANDALONE
  -Wall
  -Werror
  -Wno-deprecated-declarations
  -Wno-unused-result
  -Wno-format-overflow
  -Wno-misleading-indentation
  -Wno-format-truncation
  -Wno-stringop-truncation
  -Wno-int-in-bool-context
  -Wno-stringop-overflow
  -Wno-error=attributes
  -Wextra -Wno-unused-parameter -Wno-missing-field-initializers
  -Wno-missing-declarations -fno-strict-aliasing
  -Wformat -Wformat-security -Wformat-nonliteral
  -g
  )

if(${CMAKE_HOST_SYSTEM_PROCESSOR} STREQUAL "x86_64")
    set(COMMON_FLAGS ${COMMON_FLAGS}  -march=native -m64)
endif()

set(CMAKE_EXE_LINKER_FLAGS
  # Enable full RELRO - no lazy relocation (resolve everything at load time).
  # This allows the GOT to be made read-only early in the loading process.
  -Wl,-z,relro,-z,now,-z,noexecstack
  # Make the stack non-executable.
  # This is the default in most environments, but it doesn't hurt to set it explicitly.
  #-Wl,-z,noexecstack
)

set(COMMON_FLAGS ${COMMON_FLAGS}  -DPFS_DISK_IO_ONLY)

set(CXX_FLAGS
  ${COMMON_FLAGS}
  -std=c++11
  -Wno-deprecated
  -Wno-unused-local-typedefs
  -Wno-sign-compare
  -fpermissive
  -Wno-unused-variable
  -Wno-unused-function
)

set(C_FLAGS
  ${COMMON_FLAGS}
)

string(REPLACE ";" " " CMAKE_CXX_FLAGS "${CXX_FLAGS}")
string(REPLACE ";" " " CMAKE_C_FLAGS "${C_FLAGS}")

set(CMAKE_CXX_COMPILER "g++")
set(CMAKE_C_COMPILER "cc")

set(DEBUG_LEVEL 20)
set(RELEASE_LEVEL 40)

if(DEFINED ENV{POLAR_LOG_DEBUG_LEVEL})
	set(DEBUG_LEVEL $ENV{POLAR_LOG_DEBUG_LEVEL})
endif()
if(DEFINED ENV{POLAR_LOG_RELEASE_LEVEL})
	set(RELEASE_LEVEL $ENV{POLAR_LOG_RELEASE_LEVEL})
endif()

message("build log level release level "${RELEASE_LEVEL} " debug level "${DEBUG_LEVEL})
set(CMAKE_CXX_FLAGS_DEBUG "$ENV{CXXFLAGS} -O0 -ggdb -DDEBUG -DCHKSVR_LOG_LEVEL=${DEBUG_LEVEL}")
set(CMAKE_CXX_FLAGS_RELEASE "$ENV{CXXFLAGS} -O2 -finline-limit=100000 -DNDEBUG -DCHKSVR_LOG_LEVEL=${RELEASE_LEVEL}")
set(CMAKE_C_FLAGS_DEBUG "$ENV{CXXFLAGS} -O0 -ggdb -DDEBUG -DCHKSVR_LOG_LEVEL=${DEBUG_LEVEL}")
set(CMAKE_C_FLAGS_RELEASE "$ENV{CXXFLAGS} -O2 -finline-limit=100000 -DNDEBUG -DCHKSVR_LOG_LEVEL=${RELEASE_LEVEL}")

set(EXECUTABLE_OUTPUT_PATH ${PROJECT_SOURCE_DIR}/bin)
set(LIBRARY_OUTPUT_PATH ${PROJECT_SOURCE_DIR}/lib)

string(TOUPPER ${CMAKE_BUILD_TYPE} BUILD_TYPE)
message(STATUS "CXX_FLAGS = " ${CMAKE_CXX_FLAGS} " " ${CMAKE_CXX_FLAGS_${BUILD_TYPE}})
message(STATUS "C_FLAGS = " ${CMAKE_C_FLAGS} " " ${CMAKE_C_FLAGS_${BUILD_TYPE}})

execute_process(COMMAND mkdir -p ${PROJECT_SOURCE_DIR}/include)
execute_process(COMMAND cp ${PROJECT_SOURCE_DIR}/src/pfs_sdk/pfsd_sdk.h ${PROJECT_SOURCE_DIR}/include/)

add_subdirectory(src)
