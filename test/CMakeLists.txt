include_directories(/opt/MESA/include/MESA/)
include_directories(${PROJECT_SOURCE_DIR}/include)
include_directories(${PROJECT_SOURCE_DIR}/src/inc_internal)
include_directories(${PROJECT_SOURCE_DIR}/deps)
include_directories(${PROJECT_SOURCE_DIR}/scanner)
include_directories(${PROJECT_SOURCE_DIR}/scanner/adapter_hs)
include_directories(${PROJECT_SOURCE_DIR}/scanner/ip_matcher)

add_executable(maat_api_gtest maat_api_gtest.cpp)
target_link_libraries(maat_api_gtest maat_frame_shared gtest_static)

add_executable(rcu_hash_gtest rcu_hash_gtest.cpp)
target_link_libraries(rcu_hash_gtest maat_frame_static gtest_static)

add_executable(maat_input_mode_gtest maat_input_mode_gtest.cpp)
target_link_libraries(maat_input_mode_gtest maat_frame_static gtest_static)

add_executable(maat_framework_gtest maat_framework_gtest.cpp)
target_link_libraries(maat_framework_gtest maat_frame_static gtest_static)

add_executable(maat_framework_perf_gtest maat_framework_perf_gtest.cpp)
target_link_libraries(maat_framework_perf_gtest maat_frame_static gtest_static)

add_executable(adapter_hs_gtest adapter_hs_gtest.cpp)
target_link_libraries(adapter_hs_gtest maat_frame_static gtest_static)

add_executable(maat_ex_data_gtest maat_ex_data_gtest.cpp)
target_link_libraries(maat_ex_data_gtest maat_frame_static gtest_static)

file(COPY table_info.conf DESTINATION ./)
file(COPY file_test_tableinfo.conf DESTINATION ./)
file(COPY literal_expr.conf DESTINATION ./)
file(COPY regex_expr.conf DESTINATION ./)
file(COPY maat_json.json DESTINATION ./)
file(COPY maat_json.json DESTINATION ../tools/)
file(COPY ntcrule DESTINATION ./)
file(COPY testdata DESTINATION ./)
file(COPY test_streamfiles DESTINATION ./)
file(COPY json_update DESTINATION ./)

include(GoogleTest)
gtest_discover_tests(maat_framework_gtest)