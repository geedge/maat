cmake_minimum_required (VERSION 2.6)
project (maatframe)
set(CMAKE_CXX_FLAGS ${CMAKE_CXX_FLAGS} -Wall)
include_directories(${PROJECT_SOURCE_DIR}/inc/)
include_directories(/opt/MESA/include/MESA/)

add_subdirectory (src) 
add_subdirectory (test)
add_subdirectory (tools)

