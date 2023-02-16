cmake_minimum_required (VERSION 2.8)
set(lib_name maatframe)
project(maatframe) 

set(CMAKE_MODULE_PATH ${PROJECT_SOURCE_DIR}/cmake)
include(Version)

SET(CMAKE_INSTALL_PREFIX /opt/MESA/)

LINK_DIRECTORIES(/opt/MESA/lib /usr/lib64)

include_directories(${PROJECT_SOURCE_DIR}/include)
include_directories(/opt/MESA/include/)

set(CMAKE_C_FLAGS "-std=gnu99 -fgnu89-inline -fPIC -Wall") 
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fPIC -Wall")
set(MAAT_DEPEND_DYN_LIB pthread m crypto z)
include_directories(include)

enable_testing()

#add_subdirectory(source_dir [binary_dir] [EXCLUDE_FROM_ALL])
add_subdirectory(vendor)
add_subdirectory(src)
add_subdirectory(test)
add_subdirectory(tools)
add_subdirectory(scanner)

include(Package)