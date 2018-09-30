add_executable(digest_gen digest_gen.c)
add_dependencies(digest_gen maat_frame_shared)
target_link_libraries(digest_gen maat_frame_shared)

add_executable(maat_redis_tool maat_redis_tool.cpp)
add_dependencies(maat_redis_tool maat_frame_shared)
target_link_libraries(maat_redis_tool maat_frame_static ${MAAT_DEPEND_DYN_LIB})
target_include_directories(maat_redis_tool PRIVATE ${PROJECT_SOURCE_DIR}/src/inc_internal/)
target_include_directories(maat_redis_tool PRIVATE hiredis-vip-static)

install(TARGETS maat_redis_tool DESTINATION /usr/local/bin/)
