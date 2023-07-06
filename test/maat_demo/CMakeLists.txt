include_directories(./)


add_library(gtest-static STATIC IMPORTED GLOBAL)
add_dependencies(gtest-static gtest)

set_property(TARGET gtest-static PROPERTY IMPORTED_LOCATION ${PROJECT_SOURCE_DIR}/lib/libgtest.a)
set_property(TARGET gtest-static PROPERTY INTERFACE_INCLUDE_DIRECTORIES ${PROJECT_SOURCE_DIR}/include)


add_library(maat-shared SHARED IMPORTED GLOBAL)
add_dependencies(maat-shared maat)

set_property(TARGET maat-shared PROPERTY IMPORTED_LOCATION ${PROJECT_SOURCE_DIR}/lib/libmaat4.so)
set_property(TARGET maat-shared PROPERTY INTERFACE_INCLUDE_DIRECTORIES ${PROJECT_SOURCE_DIR}/include)

add_executable(maat_demo_gtest maat_demo_gtest.cpp)
target_link_libraries(maat_demo_gtest maat-shared gtest-static pthread)

file(COPY demo_table_info.conf DESTINATION ./)
file(COPY maat_demo.json DESTINATION ./)
file(COPY testdata DESTINATION ./)