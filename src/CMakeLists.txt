cmake_minimum_required(VERSION 3.5)

set(MAAT_FRAME_MAJOR_VERSION 4)
set(MAAT_FRAME_MINOR_VERSION 0)
set(MAAT_FRAME_PATCH_VERSION 0)
set(MAAT_FRAME_VERSION ${MAAT_FRAME_MAJOR_VERSION}.${MAAT_FRAME_MINOR_VERSION}.${MAAT_FRAME_PATCH_VERSION})

message(STATUS "Maat Frame, Version: ${MAAT_FRAME_VERSION}")

add_definitions(-fPIC)
set(MAAT_SRC maat_api.cpp rcu_hash.cpp maat_garbage_collection.cpp maat_config_monitor.cpp maat_rule.cpp 
    maat_kv.cpp maat_ex_data.cpp maat_table_schema.cpp maat_table_runtime.cpp maat_utils.cpp)

set(LIB_SOURCE_FILES
	${PROJECT_SOURCE_DIR}/deps/cJSON/cJSON.c)

include_directories(${PROJECT_SOURCE_DIR}/include/)
include_directories(${PROJECT_SOURCE_DIR}/deps/)
include_directories(${PROJECT_SOURCE_DIR}/scanner)
include_directories(${PROJECT_SOURCE_DIR}/src/inc_internal)

# Static Library Output
add_library(maat_frame_static STATIC ${MAAT_SRC} ${LIB_SOURCE_FILES})
set_target_properties(maat_frame_static PROPERTIES LINKER_LANGUAGE CXX)
set_target_properties(maat_frame_static PROPERTIES OUTPUT_NAME maatframe)
set_target_properties(maat_frame_static PROPERTIES CLEAN_DIRECT_OUTPUT 1)

target_link_libraries(maat_frame_static adapter-static pthread)

# Shared Library Output
#add_library(maat_frame_shared SHARED ${MAAT_SRC} ${LIB_SOURCE_FILES})
#set_target_properties(maat_frame_shared PROPERTIES LINKER_LANGUAGE CXX)
#set_target_properties(maat_frame_shared PROPERTIES OUTPUT_NAME maatframe)
#set_target_properties(maat_frame_shared PROPERTIES CLEAN_DIRECT_OUTPUT 1)
#set_target_properties(maat_frame_shared PROPERTIES VERSION ${MAAT_FRAME_MAJOR_VERSION}.${MAAT_FRAME_MINOR_VERSION})
#set_target_properties(maat_frame_shared PROPERTIES SOVERSION ${MAAT_FRAME_MAJOR_VERSION})

#target_link_libraries(maat_frame_shared hyperscan_static)

# install
set(CMAKE_INSTALL_PREFIX /opt/MESA/)
install(FILES ${PROJECT_SOURCE_DIR}/inc/Maat_rule.h DESTINATION ${CMAKE_INSTALL_PREFIX}/include/MESA/ COMPONENT HEADER)