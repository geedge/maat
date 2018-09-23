set(CMAKE_CXX_FLAGS ${CMAKE_CXX_FLAGS} -Wall)

include_directories(${CMAKE_CURRENT_SOURCE_DIR}/../inc/)
include_directories(/opt/MESA/include/MESA/)

add_executable(digest_gen digest_gen.c)
add_dependencies(digest_gen maat_frame_shared)
target_link_libraries(digest_gen maat_frame_shared)

add_executable(maat_redis_tool maat_redis_tool.cpp)
add_dependencies(maat_redis_tool maat_frame_shared)
target_link_libraries(maat_redis_tool maat_frame_shared)
target_include_directories(maat_redis_tool PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/../src/inc_internal/)
target_include_directories(maat_redis_tool PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/../src/inc_internal/hiredis)


