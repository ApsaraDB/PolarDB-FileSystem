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

include_directories(
    ${PROJECT_SOURCE_DIR}/src/pfsd/
    ${PROJECT_SOURCE_DIR}/src/pfs_core/
    ${PROJECT_SOURCE_DIR}/src/trace/include/
)

link_directories(
    ${LIBRARY_OUTPUT_PATH}
)

SET(SRC_LIST_PFSD pfsd_main.cc
                  pfsd_api.cc
                  pfsd_chnl.cc
                  pfsd_chnl_shm.cc
                  pfsd_common.cc
                  pfsd_memory.cc
                  pfsd_option.cc
                  pfsd_shm.cc
                  pfsd_worker.cc
    )

# macro definition
add_definitions(
	-DPFS_IOCHNL_CLI
)


# pfsd daemon
add_executable(pfsdaemon
    ${SRC_LIST_PFSD}
    )

add_dependencies(pfsdaemon
    pfs
    )

if(${CMAKE_HOST_SYSTEM_PROCESSOR} STREQUAL "x86_64")
    set(CXXFLAGS ${CXXFLAGS}  -march=native)
endif()

target_link_libraries(pfsdaemon
    -Wl,--start-group
    -Wl,--no-as-needed
    pfs
    zlog
    pthread
    -Wl,--end-group
)

target_compile_definitions(pfsdaemon PUBLIC PFSD_SERVER)

SET_TARGET_PROPERTIES(pfsdaemon PROPERTIES LINKER_LANGUAGE CXX)

