set(CMAKE_CXX_FLAGS ${CMAKE_CXX_FLAGS} -Wall)

include_directories(${CMAKE_CURRENT_SOURCE_DIR}/../inc/)
include_directories(/opt/MESA/include/MESA/)

add_executable(maat_test maat_test.cpp)
target_link_libraries(maat_test maat_frame_shared)

#configure_file(${CMAKE_CURRENT_SOURCE_DIR}/maat_json.json ${CMAKE_CURRENT_SOURCE_DIR}/maat_json.json COPYONLY)
configure_file(table_info.conf table_info.conf COPYONLY)
configure_file(maat_json.json maat_json.json COPYONLY)
configure_file(reset_redis4maat.sh reset_redis4maat.sh COPYONLY)
file(COPY conf DESTINATION ./)
file(COPY rule DESTINATION ./)
file(COPY testdata DESTINATION ./)
file(COPY testdata_uni2ascii DESTINATION ./)
