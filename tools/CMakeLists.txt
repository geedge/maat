include_directories(${PROJECT_SOURCE_DIR}/src/inc_internal)
include_directories(${PROJECT_SOURCE_DIR}/deps)
include_directories(${PROJECT_SOURCE_DIR}/scanner)

add_executable(maat_redis_tool maat_redis_tool.cpp)
target_link_libraries(maat_redis_tool maat_frame_static)

install(TARGETS maat_redis_tool DESTINATION /usr/local/bin/ COMPONENT TOOLS)