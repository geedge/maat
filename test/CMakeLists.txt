include_directories(${PROJECT_SOURCE_DIR}/src/inc_internal)
include_directories(${PROJECT_SOURCE_DIR}/deps)
include_directories(${PROJECT_SOURCE_DIR}/scanner)

add_executable(maat_api_gtest maat_api_gtest.cpp)
target_link_libraries(maat_api_gtest maat_frame_static gtest_static)

add_executable(rcu_hash_gtest rcu_hash_gtest.cpp)
target_link_libraries(rcu_hash_gtest maat_frame_static gtest_static)

add_executable(maat_framework_gtest maat_framework_gtest.cpp)
target_link_libraries(maat_framework_gtest maat_frame_static gtest_static)

file(COPY rule DESTINATION ./)
file(COPY table_info.conf DESTINATION ./)
file(COPY and_expr.conf DESTINATION ./)