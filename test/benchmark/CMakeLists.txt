include_directories(${PROJECT_SOURCE_DIR}/src/inc_internal)

add_executable(benchmark_gtest benchmark_gtest.cpp ../test_utils.cpp)
target_link_libraries(benchmark_gtest maat_frame_static gtest_static)