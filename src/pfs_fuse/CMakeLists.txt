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
        ${PROJECT_SOURCE_DIR}/src/pfs_fuse/
	${PROJECT_SOURCE_DIR}/src/pfs_sdk/
	${PROJECT_SOURCE_DIR}/src/trace/include/
)

link_directories(
        ${LIBRARY_OUTPUT_PATH}
)

SET(SRC_LIST_FUSE pfs_fuse_main.cc
                  pfs_fuse.cc
    )

add_executable(pfs-fuse
        ${SRC_LIST_FUSE}
)

add_definitions(-D_FILE_OFFSET_BITS=64)

set(CXXFLAGS
    -Werror=no-literal-suffix
    -g
    -O0
)

if(${CMAKE_HOST_SYSTEM_PROCESSOR} STREQUAL "x86_64")
    set(CXXFLAGS ${CXXFLAGS}  -march=native)
endif()

target_link_libraries(pfs-fuse
    -Wl,--start-group
    -Wl,--no-as-needed
    pfsd
    pthread
    fuse
    -Wl,--end-group
)

add_dependencies(pfs-fuse
    pfsd
)
