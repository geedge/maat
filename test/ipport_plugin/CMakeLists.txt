include_directories(${PROJECT_SOURCE_DIR}/src/inc_internal)

add_executable(ipport_plugin_gtest ipport_plugin_gtest.cpp ../test_utils.cpp)
target_link_libraries(ipport_plugin_gtest maat_frame_static gtest_static)