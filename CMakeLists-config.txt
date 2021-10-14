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

execute_process(COMMAND git describe --long --always OUTPUT_VARIABLE RAW_GIT_DESC)
if (RAW_GIT_DESC STREQUAL "")
    set(RAW_GIT_DESC "_")
endif()
string(REPLACE "\n" "" RAW_GIT_DESC ${RAW_GIT_DESC})
message("build git version: (\"${RAW_GIT_DESC} \")")

if (CMAKE_BUILD_TYPE STREQUAL "Release")
    execute_process(COMMAND date OUTPUT_VARIABLE RAW_DATE)
    string(REPLACE "\n" "" RAW_DATE ${RAW_DATE})
    message("build date: (\"${RAW_DATE} \")")

else()
    set (RAW_DATE "debug")
endif()

set (VERSION_DETAIL "(\"pfsd-build-desc-${RAW_GIT_DESC}-${RAW_DATE}\")")

add_definitions(-DVERSION_DETAIL=${VERSION_DETAIL})
