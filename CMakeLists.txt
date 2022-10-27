cmake_minimum_required (VERSION 3.5)
project(maatframe) 

include_directories(${PROJECT_SOURCE_DIR}/include)

set(CMAKE_C_FLAGS "-std=gnu99 -Wall") 
set(CMAKE_CXX_FLAGS ${CMAKE_CXX_FLAGS} "-Wall")

include_directories(include)

#add_subdirectory(source_dir [binary_dir] [EXCLUDE_FROM_ALL])
add_subdirectory(vendor)
add_subdirectory(src)
add_subdirectory(test)