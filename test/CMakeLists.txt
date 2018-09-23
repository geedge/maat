add_executable(maat_test maat_test.cpp)
target_link_libraries(maat_test maat_frame_shared)

add_executable(test_maatframe test_maatframe.cpp)
target_link_libraries(test_maatframe maat_frame_shared gtest)

configure_file(table_info.conf table_info.conf COPYONLY)
configure_file(maat_json.json maat_json.json COPYONLY)
configure_file(reset_redis4maat.sh reset_redis4maat.sh COPYONLY)
file(COPY conf DESTINATION ./)
file(COPY rule DESTINATION ./)
file(COPY testdata DESTINATION ./)
file(COPY testdata_uni2ascii DESTINATION ./)
