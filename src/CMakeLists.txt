cmake_minimum_required(VERSION 3.5)

set(MAAT_FRAME_MAJOR_VERSION 2)
set(MAAT_FRAME_MINOR_VERSION 7)
set(MAAT_FRAME_PATCH_VERSION 0)
set(MAAT_FRAME_VERSION ${MAAT_FRAME_MAJOR_VERSION}.${MAAT_FRAME_MINOR_VERSION}.${MAAT_FRAME_PATCH_VERSION})

message(STATUS "Maat Frame, Version: ${MAAT_FRAME_VERSION}")

add_definitions(-fPIC)
set(MAAT_SRC entry/cJSON.c  entry/config_monitor.cpp  entry/dynamic_array.cpp  entry/gram_index_engine.c  entry/interval_index.c  entry/json2iris.cpp entry/Maat_utils.cpp entry/Maat_api.cpp  entry/Maat_command.cpp  entry/Maat_rule.cpp  entry/Maat_stat.cpp  entry/map_str2int.cpp  entry/rbtree.c  entry/stream_fuzzy_hash.c  entry/bool_matcher.cpp)
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/../inc/)
include_directories(/opt/MESA/include/MESA/)

# Static Library Output
add_library(maat_frame_static STATIC ${MAAT_SRC})
set_target_properties(maat_frame_static PROPERTIES LINKER_LANGUAGE CXX)
set_target_properties(maat_frame_static PROPERTIES OUTPUT_NAME maatframe)
set_target_properties(maat_frame_static PROPERTIES CLEAN_DIRECT_OUTPUT 1)
target_include_directories(maat_frame_static PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/inc_internal/)
#target_include_directories(maat_frame_static PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/inc_internal/hiredis)
target_link_libraries(maat_frame_static hiredis-vip-static)
target_link_libraries(maat_frame_static igraph-static)

# Shared Library Output
add_library(maat_frame_shared SHARED ${MAAT_SRC})
set_target_properties(maat_frame_shared PROPERTIES LINKER_LANGUAGE CXX)
set_target_properties(maat_frame_shared PROPERTIES OUTPUT_NAME maatframe)
set_target_properties(maat_frame_shared PROPERTIES CLEAN_DIRECT_OUTPUT 1)
set_target_properties(maat_frame_shared PROPERTIES VERSION ${MAAT_FRAME_MAJOR_VERSION}.${MAAT_FRAME_MINOR_VERSION})
set_target_properties(maat_frame_shared PROPERTIES SOVERSION ${MAAT_FRAME_MAJOR_VERSION})
set_target_properties(maat_frame_shared PROPERTIES LINK_FLAGS "-Wl,--version-script=${CMAKE_CURRENT_LIST_DIR}/version.map")
target_include_directories(maat_frame_shared PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/inc_internal/)
target_include_directories(maat_frame_shared PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/inc_internal/hiredis)
target_link_libraries(maat_frame_shared hiredis-vip-static ${MAAT_DEPEND_DYN_LIB})
target_link_libraries(maat_frame_shared igraph-static ${MAAT_DEPEND_DYN_LIB})

install(FILES ${PROJECT_SOURCE_DIR}/inc/Maat_rule.h DESTINATION include/MESA/)
install(FILES ${PROJECT_SOURCE_DIR}/inc/Maat_command.h DESTINATION include/MESA/)
install(FILES ${PROJECT_SOURCE_DIR}/inc/stream_fuzzy_hash.h DESTINATION include/MESA/)
install(FILES ${PROJECT_SOURCE_DIR}/inc/gram_index_engine.h DESTINATION include/MESA/)
install(TARGETS maat_frame_shared DESTINATION /opt/MESA/lib/)
