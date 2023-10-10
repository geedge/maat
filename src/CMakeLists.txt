cmake_minimum_required(VERSION 3.5)

set(MAAT_FRAME_MAJOR_VERSION 4)
set(MAAT_FRAME_MINOR_VERSION 0)
set(MAAT_FRAME_PATCH_VERSION 14)
set(MAAT_FRAME_VERSION ${MAAT_FRAME_MAJOR_VERSION}.${MAAT_FRAME_MINOR_VERSION}.${MAAT_FRAME_PATCH_VERSION})

message(STATUS "Maat Frame, Version: ${MAAT_FRAME_VERSION}")

LINK_DIRECTORIES(/opt/MESA/lib /usr/lib64)

add_definitions(-D_GNU_SOURCE) 
add_definitions(-fPIC)
set(MAAT_SRC alignment.c json2iris.c maat_api.c rcu_hash.c maat_garbage_collection.c maat_config_monitor.c 
    maat_rule.c maat_kv.c maat_ex_data.c maat_utils.c maat_command.c maat_redis_monitor.c maat_table.c 
    maat_compile.c maat_group.c maat_ip.c maat_flag.c maat_interval.c maat_expr.c maat_plugin.c 
    maat_ip_plugin.c maat_ipport_plugin.c maat_bool_plugin.c maat_fqdn_plugin.c maat_virtual.c maat_stat.c)

set(LIB_SOURCE_FILES
	${PROJECT_SOURCE_DIR}/deps/cJSON/cJSON.c ${PROJECT_SOURCE_DIR}/deps/log/log.c)

include_directories(/opt/MESA/include/MESA/)
include_directories(${PROJECT_SOURCE_DIR}/include/)
include_directories(${PROJECT_SOURCE_DIR}/deps/)
include_directories(${PROJECT_SOURCE_DIR}/scanner)
include_directories(${PROJECT_SOURCE_DIR}/scanner/fqdn_engine)
include_directories(${PROJECT_SOURCE_DIR}/scanner/bool_matcher)
include_directories(${PROJECT_SOURCE_DIR}/scanner/ip_matcher)
include_directories(${PROJECT_SOURCE_DIR}/scanner/ipport_matcher)
include_directories(${PROJECT_SOURCE_DIR}/scanner/flag_matcher)
include_directories(${PROJECT_SOURCE_DIR}/scanner/interval_matcher)
include_directories(${PROJECT_SOURCE_DIR}/src/inc_internal)
include_directories(${PROJECT_SOURCE_DIR}/scanner/expr_matcher)
include_directories(${PROJECT_SOURCE_DIR}/scanner/expr_matcher/adapter_hs)
include_directories(${PROJECT_SOURCE_DIR}/scanner/expr_matcher/adapter_rs)

# Static Library Output
add_library(maat_frame_static STATIC ${MAAT_SRC} ${LIB_SOURCE_FILES})
set_target_properties(maat_frame_static PROPERTIES LINKER_LANGUAGE CXX)
set_target_properties(maat_frame_static PROPERTIES OUTPUT_NAME maat4)
set_target_properties(maat_frame_static PROPERTIES CLEAN_DIRECT_OUTPUT 1)

target_link_libraries(maat_frame_static hiredis-static ${MAAT_DEPEND_DYN_LIB})
target_link_libraries(maat_frame_static igraph-static)
target_link_libraries(maat_frame_static adapter-static)

# Shared Library Output
add_library(maat_frame_shared SHARED ${MAAT_SRC} ${LIB_SOURCE_FILES})
set_target_properties(maat_frame_shared PROPERTIES LINKER_LANGUAGE CXX)
set_target_properties(maat_frame_shared PROPERTIES OUTPUT_NAME maat4)
set_target_properties(maat_frame_shared PROPERTIES CLEAN_DIRECT_OUTPUT 1)
set_target_properties(maat_frame_shared PROPERTIES VERSION ${MAAT_FRAME_MAJOR_VERSION}.${MAAT_FRAME_MINOR_VERSION})
set_target_properties(maat_frame_shared PROPERTIES SOVERSION ${MAAT_FRAME_MAJOR_VERSION})
set_target_properties(maat_frame_shared PROPERTIES LINK_FLAGS "-Wl,--version-script=${CMAKE_CURRENT_LIST_DIR}/version.map")

target_link_libraries(maat_frame_shared hiredis-static ${MAAT_DEPEND_DYN_LIB})
target_link_libraries(maat_frame_shared igraph-static ${MAAT_DEPEND_DYN_LIB})
target_link_libraries(maat_frame_shared adapter-static)

# install
set(CMAKE_INSTALL_PREFIX /opt/MESA/)
install(FILES ${PROJECT_SOURCE_DIR}/include/maat.h DESTINATION ${CMAKE_INSTALL_PREFIX}/include/MESA/ COMPONENT HEADER)
install(FILES ${PROJECT_SOURCE_DIR}/include/maat_command.h DESTINATION ${CMAKE_INSTALL_PREFIX}/include/MESA/ COMPONENT HEADER)
install(TARGETS maat_frame_shared LIBRARY DESTINATION ${CMAKE_INSTALL_PREFIX}/lib/ COMPONENT LIBRARIES)