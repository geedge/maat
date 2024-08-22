include_directories(/opt/MESA/include/MESA/)
include_directories(${PROJECT_SOURCE_DIR}/include)
include_directories(${PROJECT_SOURCE_DIR}/src/inc_internal)
include_directories(${PROJECT_SOURCE_DIR}/deps)
include_directories(${PROJECT_SOURCE_DIR}/scanner)
include_directories(${PROJECT_SOURCE_DIR}/scanner/expr_matcher)
include_directories(${PROJECT_SOURCE_DIR}/scanner/expr_matcher/adapter_hs)
include_directories(${PROJECT_SOURCE_DIR}/scanner/expr_matcher/adapter_rs)
include_directories(${PROJECT_SOURCE_DIR}/scanner/ip_matcher)
include_directories(${PROJECT_SOURCE_DIR}/scanner/ipport_matcher)
include_directories(${PROJECT_SOURCE_DIR}/scanner/bool_matcher)

add_executable(rcu_hash_gtest rcu_hash_gtest.cpp)
target_link_libraries(rcu_hash_gtest maat_frame_static gtest_static)

add_executable(maat_input_mode_gtest maat_input_mode_gtest.cpp test_utils.cpp)
target_link_libraries(maat_input_mode_gtest maat_frame_static gtest_static)

add_executable(maat_framework_gtest maat_framework_gtest.cpp test_utils.cpp)
target_link_libraries(maat_framework_gtest maat_frame_static gtest_static)

add_executable(maat_framework_perf_gtest maat_framework_perf_gtest.cpp test_utils.cpp)
target_link_libraries(maat_framework_perf_gtest maat_frame_static gtest_static)

add_executable(expr_matcher_gtest expr_matcher_gtest.cpp)
target_link_libraries(expr_matcher_gtest maat_frame_static gtest_static)

add_executable(ip_matcher_gtest ip_matcher_gtest.cpp)
target_link_libraries(ip_matcher_gtest maat_frame_static gtest_static)

add_executable(ipport_matcher_gtest ipport_matcher_gtest.cpp)
target_link_libraries(ipport_matcher_gtest maat_frame_static gtest_static)

add_executable(bool_matcher_gtest bool_matcher_gtest.cpp)
target_link_libraries(bool_matcher_gtest maat_frame_static gtest_static)

add_executable(maat_ex_data_gtest maat_ex_data_gtest.cpp)
target_link_libraries(maat_ex_data_gtest maat_frame_static gtest_static)

add_subdirectory(object_nesting)
add_subdirectory(ipport_plugin)
add_subdirectory(benchmark)

configure_file(table_info.conf table_info.conf COPYONLY)
configure_file(tsg_table_info.conf tsg_table_info.conf COPYONLY)
configure_file(file_test_tableinfo.conf file_test_tableinfo.conf COPYONLY)
configure_file(expr_matcher.conf expr_matcher.conf COPYONLY)
configure_file(maat_json.json maat_json.json COPYONLY)

file(COPY ntcrule DESTINATION ./)
file(COPY tsgrule DESTINATION ./)
file(COPY testdata DESTINATION ./)
file(COPY test_streamfiles DESTINATION ./)
file(COPY json_update DESTINATION ./)
file(COPY object_nesting DESTINATION ./)
file(COPY ipport_plugin DESTINATION ./)
file(COPY benchmark DESTINATION ./)

include(GoogleTest)
gtest_discover_tests(maat_framework_gtest)