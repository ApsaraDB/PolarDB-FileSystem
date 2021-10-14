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
    ${PROJECT_SOURCE_DIR}/src/pfs_sdk/
    ${PROJECT_SOURCE_DIR}/src/pfs_core/
    ${PROJECT_SOURCE_DIR}/src/trace/include/
)

link_directories(
    ${LIBRARY_OUTPUT_PATH}
)

SET(SRC_LIST_PFSD_SDK pfsd_common.cc
                      pfsd_chnl.cc
                      pfsd_chnl_shm.cc
                      pfsd_memory.cc
                      pfsd_sdk_file.cc
                      pfsd_sdk_mount.cc
                      pfsd_sdk.cc
                      pfsd_shm.cc
    )
# objects
add_library(tmp_object_lib OBJECT ${SRC_LIST_PFSD_SDK})
target_compile_definitions(tmp_object_lib PUBLIC PFSD_CLIENT)
set_property(TARGET tmp_object_lib PROPERTY POSITION_INDEPENDENT_CODE ON)

# lib pfsd
add_library(pfsd STATIC
    $<TARGET_OBJECTS:tmp_object_lib>
)
add_dependencies(pfsd
    tmp_object_lib
)

# lib pfsd
add_library(pfsd_test SHARED
    $<TARGET_OBJECTS:tmp_object_lib>
)
add_dependencies(pfsd_test
    tmp_object_lib
)
set_property(TARGET pfsd PROPERTY POSITION_INDEPENDENT_CODE ON)
set_property(TARGET pfsd_test PROPERTY POSITION_INDEPENDENT_CODE ON)

target_link_libraries(pfsd; rt;pthread;dl)


# pfsd shm tool
add_executable(pfsd_shm_tool
    pfsd_shm_tool.cc
    )

add_dependencies(pfsd_shm_tool
    pfsd
)

target_link_libraries(pfsd_shm_tool; pfsd;rt;pthread)

SET_TARGET_PROPERTIES(pfsd PROPERTIES LINKER_LANGUAGE CXX)
SET_TARGET_PROPERTIES(pfsd_shm_tool PROPERTIES LINKER_LANGUAGE CXX)
