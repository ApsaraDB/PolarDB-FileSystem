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
    ${PROJECT_SOURCE_DIR}/src/pfs_tools
    ${PROJECT_SOURCE_DIR}/src/pfs_core/
	${PROJECT_SOURCE_DIR}/src/pfsd/
	${PROJECT_SOURCE_DIR}/src/pfs_sdk/
    ${PROJECT_SOURCE_DIR}/src/trace/include/
)

link_directories(
    ${LIBRARY_OUTPUT_PATH}
)

add_executable(pfs-tools
	cmd_pfs.cc
	cmd_util.cc
	cmd_chunk.cc
	cmd_cp.cc
	cmd_dir.cc
	cmd_du.cc
	cmd_dumpfs.cc
	cmd_dumple.cc
	cmd_flushlog.cc
	cmd_fscp.cc
	cmd_fstrim.cc
	cmd_info.cc
	cmd_map.cc
	cmd_mkdir.cc
	cmd_mkfs.cc
	cmd_mount.cc
	cmd_rename.cc
	cmd_rm.cc
	cmd_usedinfo.cc
)
SET_TARGET_PROPERTIES(pfs-tools
	PROPERTIES OUTPUT_NAME pfs
)

add_definitions(-D__STDC_FORMAT_MACROS)

set(CXXFLAGS
    -Werror=no-literal-suffix
    -g
    -O0
)

if(${CMAKE_HOST_SYSTEM_PROCESSOR} STREQUAL "x86_64")
    set(CXXFLAGS ${CXXFLAGS}  -march=native)
endif()

target_link_libraries(pfs-tools
    -Wl,--start-group
    -Wl,--no-as-needed
    pfs
    pfsd
	pthread
    -Wl,--end-group
)

add_dependencies(pfs-tools
    pfs
    pfsd
)

configure_file(${PROJECT_SOURCE_DIR}/src/pfs_tools/pfsadm
    ${EXECUTABLE_OUTPUT_PATH}/pfsadm COPYONLY)
